"""YARA rule management: upload, update from a repository, ship to agents."""
from __future__ import annotations

import io
import logging
import threading
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..auth import require_admin, require_agent, require_console
from ..database import SessionLocal, get_db
from ..models import Agent, AuditEvent, YaraRule, get_setting, set_setting, utcnow
from ..services.yara import compile_many

logger = logging.getLogger("douglas.yara")
router = APIRouter()

DEFAULT_SOURCE = "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"
SOURCE_KEY = "yara_source_url"
LAST_UPDATE_KEY = "yara_last_update"

MAX_UPLOAD_BYTES = 60 * 1024 * 1024
DOWNLOAD_TIMEOUT = 180

_SKIP_SEGMENTS = ("/tests/", "/test/", "/deprecated/", "/.github/", "/utils/")


def _iso(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def rule_dict(r: YaraRule, *, full: bool = False) -> dict:
    data = {
        "id": r.id,
        "name": r.name,
        "description": r.description or "",
        "author": r.author or "",
        "reference": r.reference or "",
        "severity": r.severity,
        "tags": r.tags or [],
        "string_count": len(r.strings or []),
        "condition_text": r.condition_text or "",
        "filesize_max": r.filesize_max,
        "enabled": bool(r.enabled),
        "source": r.source or "",
        "added_at": _iso(r.added_at),
        "added_by": r.added_by,
    }
    if full:
        data["strings"] = r.strings
        data["condition"] = r.condition
    return data


def _store(db: Session, compiled: list[dict], who: str, replace: bool) -> tuple[int, int, int]:
    if replace:
        db.query(YaraRule).delete()
        disabled: set = set()
    else:
        disabled = {
            r.id for r in db.query(YaraRule.id)
            .filter(YaraRule.enabled == False).all()  # noqa: E712
        }

    added = updated = 0
    for rule in compiled:
        existing = db.get(YaraRule, rule["id"])
        if existing is None:
            existing = YaraRule(id=rule["id"], added_by=who)
            db.add(existing)
            added += 1
        else:
            updated += 1
        for field in ("name", "description", "author", "reference", "severity",
                      "tags", "strings", "condition", "condition_text",
                      "filesize_min", "filesize_max", "source"):
            setattr(existing, field, rule[field])
        existing.enabled = rule["id"] not in disabled
    return added, updated, len(disabled)


def _group_reasons(rejected: list[dict]) -> list[dict]:
    counts: dict[str, int] = {}
    for r in rejected:
        counts[r["reason"]] = counts.get(r["reason"], 0) + 1
    return [{"reason": k, "count": v}
            for k, v in sorted(counts.items(), key=lambda kv: -kv[1])[:20]]


def _read_archive(payload: bytes) -> list[tuple[str, str]]:
    docs: list[tuple[str, str]] = []
    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        for member in zf.namelist():
            if not member.lower().endswith((".yar", ".yara")) or member.endswith("/"):
                continue
            lowered = "/" + member.lower()
            if any(seg in lowered for seg in _SKIP_SEGMENTS):
                continue
            try:
                docs.append((member, zf.read(member).decode("utf-8", errors="replace")))
            except Exception:
                continue
    return docs


# ---------------------------------------------------------------------------
# Console
# ---------------------------------------------------------------------------


@router.get("")
def list_rules(
    severity: str | None = None,
    enabled: bool | None = None,
    search: str | None = None,
    limit: int = 500,
    db: Session = Depends(get_db),
    _u=Depends(require_console),
):
    q = db.query(YaraRule)
    if severity:
        q = q.filter(YaraRule.severity == severity.upper())
    if enabled is not None:
        q = q.filter(YaraRule.enabled == enabled)
    if search:
        like = f"%{search}%"
        q = q.filter(YaraRule.name.ilike(like) | YaraRule.description.ilike(like))
    total = q.count()
    rows = q.order_by(YaraRule.name).limit(min(limit, 3000)).all()
    return {"total": total, "rules": [rule_dict(r) for r in rows]}


@router.get("/summary")
def summary(db: Session = Depends(get_db), _u=Depends(require_console)):
    rows = db.query(YaraRule).all()
    by_sev: dict[str, int] = {}
    for r in rows:
        if r.enabled:
            by_sev[r.severity] = by_sev.get(r.severity, 0) + 1
    return {
        "total": len(rows),
        "enabled": sum(1 for r in rows if r.enabled),
        "by_severity": by_sev,
        "source_url": get_setting(db, SOURCE_KEY, DEFAULT_SOURCE),
        "last_update": get_setting(db, LAST_UPDATE_KEY, ""),
        "default_source": DEFAULT_SOURCE,
        **STATE.snapshot(),
    }


@router.post("/upload")
async def upload_rules(
    file: UploadFile = File(...),
    replace: bool = False,
    db: Session = Depends(get_db),
    admin=Depends(require_admin),
):
    payload = await file.read()
    if len(payload) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Uploads are capped at 60 MB.")
    if not payload:
        raise HTTPException(status_code=400, detail="That file is empty.")

    name = (file.filename or "rules.yar").lower()
    if name.endswith(".zip"):
        try:
            documents = _read_archive(payload)
        except zipfile.BadZipFile:
            raise HTTPException(status_code=400, detail="That file is not a readable zip.")
    else:
        documents = [(file.filename or "rules.yar",
                      payload.decode("utf-8", errors="replace"))]

    if not documents:
        raise HTTPException(status_code=400, detail="No YARA rules found in that file.")

    result = compile_many(documents)
    added, updated, kept = _store(db, result["rules"], admin.username, replace)

    db.add(AuditEvent(
        kind="yara.uploaded", subject=file.filename or "rules",
        detail=f"{added} added, {updated} updated, {len(result['rejected'])} rejected "
               f"by {admin.username}",
    ))
    db.commit()

    return {
        "added": added, "updated": updated, "rejected": len(result["rejected"]),
        "kept_disabled": kept,
        "rejection_reasons": _group_reasons(result["rejected"]),
    }


class ToggleRequest(BaseModel):
    enabled: bool


@router.post("/bulk-toggle")
def bulk_toggle(
    payload: ToggleRequest,
    severity: str | None = None,
    db: Session = Depends(get_db),
    admin=Depends(require_admin),
):
    q = db.query(YaraRule)
    if severity:
        q = q.filter(YaraRule.severity == severity.upper())
    else:
        raise HTTPException(status_code=400, detail="Narrow this by severity.")
    count = q.count()
    q.update({YaraRule.enabled: payload.enabled}, synchronize_session=False)
    db.commit()
    return {"changed": count, "enabled": payload.enabled}


@router.delete("/all")
def delete_all(db: Session = Depends(get_db), admin=Depends(require_admin)):
    count = db.query(YaraRule).count()
    db.query(YaraRule).delete()
    db.add(AuditEvent(kind="yara.cleared", subject=f"{count} rules",
                      detail=f"by {admin.username}"))
    db.commit()
    return {"deleted": count}


# ---------------------------------------------------------------------------
# Update from a repository
# ---------------------------------------------------------------------------


class UpdateState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.running = False
        self.phase = "idle"
        self.detail = ""
        self.percent = 0.0
        self.result: dict | None = None
        self.error: str | None = None

    def snapshot(self) -> dict:
        return {
            "running": self.running, "phase": self.phase, "detail": self.detail,
            "percent": round(self.percent, 1), "result": self.result, "error": self.error,
        }

    def set(self, phase: str, detail: str = "", percent: float | None = None) -> None:
        self.phase = phase
        self.detail = detail
        if percent is not None:
            self.percent = percent
        from ..services.events import broadcast
        broadcast({"type": "yara.update", **self.snapshot()})


STATE = UpdateState()


def _run_update(url: str, who: str, replace: bool) -> None:
    started = time.time()
    try:
        STATE.set("downloading", url, percent=2)
        request = urllib.request.Request(url, headers={"User-Agent": "Douglas-042"})
        chunks, total = [], 0
        with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT) as resp:
            declared = int(resp.headers.get("Content-Length") or 0)
            while True:
                chunk = resp.read(512 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise ValueError("The archive exceeds the 60 MB limit.")
                chunks.append(chunk)
                if declared:
                    STATE.set("downloading",
                              f"{total / 1024 / 1024:.1f} of {declared / 1024 / 1024:.1f} MB",
                              percent=min(30.0, total / declared * 30))
        payload = b"".join(chunks)

        STATE.set("extracting", "Reading rules from the archive", percent=32)
        documents = _read_archive(payload)
        if not documents:
            raise ValueError("No .yar files found in that archive.")

        STATE.set("compiling", f"{len(documents)} files", percent=38)
        result = compile_many(documents)

        STATE.set("storing", f"{len(result['rules'])} compiled", percent=85)
        db = SessionLocal()
        try:
            added, updated, kept = _store(db, result["rules"], who, replace)
            stamp = utcnow().isoformat()
            set_setting(db, LAST_UPDATE_KEY, stamp, who=who)
            set_setting(db, SOURCE_KEY, url, who=who)
            db.add(AuditEvent(
                kind="yara.updated", subject=url,
                detail=f"{added} added, {updated} updated, "
                       f"{len(result['rejected'])} rejected by {who}",
            ))
            db.commit()
            after = db.query(YaraRule).count()
        finally:
            db.close()

        STATE.result = {
            "added": added, "updated": updated, "rejected": len(result["rejected"]),
            "kept_disabled": kept, "total_after": after,
            "seconds": round(time.time() - started, 1),
            "rejection_reasons": _group_reasons(result["rejected"]),
            "source": url, "at": stamp,
        }
        STATE.error = None
        STATE.set("complete", f"{added} added, {updated} updated", percent=100)

    except Exception as exc:  # noqa: BLE001
        if isinstance(exc, urllib.error.URLError):
            STATE.error = (
                f"Could not reach the rule source ({getattr(exc, 'reason', exc)}). "
                "This console is often run without internet access — download the "
                "archive elsewhere and use Upload rules instead."
            )
        else:
            STATE.error = f"Update failed: {exc}"
        STATE.result = None
        STATE.set("failed", STATE.error, percent=0)
        logger.warning("YARA update failed: %s", exc)
    finally:
        with STATE.lock:
            STATE.running = False


class UpdateRequest(BaseModel):
    url: str | None = None
    replace: bool = False


@router.post("/update")
def start_update(
    payload: UpdateRequest,
    db: Session = Depends(get_db),
    admin=Depends(require_admin),
):
    url = (payload.url or get_setting(db, SOURCE_KEY, DEFAULT_SOURCE)).strip()
    if not url.lower().startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="The source must be an http(s) URL.")
    with STATE.lock:
        if STATE.running:
            raise HTTPException(status_code=409, detail="An update is already running.")
        STATE.running = True
        STATE.result = None
        STATE.error = None
        STATE.percent = 0.0

    threading.Thread(target=_run_update, args=(url, admin.username, payload.replace),
                     name="yara-update", daemon=True).start()
    return {"started": True, "url": url}


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------


@router.get("/bundle")
def rule_bundle(
    agent: Agent = Depends(require_agent),
    db: Session = Depends(get_db),
):
    rows = db.query(YaraRule).filter(YaraRule.enabled == True).all()  # noqa: E712
    return JSONResponse({
        "version": 1,
        "count": len(rows),
        "rules": [
            {
                "id": r.id, "name": r.name,
                "description": (r.description or "")[:300],
                "severity": r.severity, "strings": r.strings,
                "condition": r.condition,
                "filesize_min": r.filesize_min, "filesize_max": r.filesize_max,
                "source": r.source or "",
            }
            for r in rows
        ],
    })
