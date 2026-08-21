"""Sigma rule management: upload, enable, ship to agents."""
from __future__ import annotations

import io
import json
import zipfile
from datetime import timezone

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..auth import require_admin, require_agent, require_console
from ..database import get_db
from ..models import Agent, AuditEvent, SigmaRule, get_setting, utcnow
from ..services.mitre import technique_name
from ..services.sigma import compile_many
from ..services import sigma_update

router = APIRouter()

MAX_UPLOAD_BYTES = 40 * 1024 * 1024
MAX_FILES = 8000


def _iso(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def rule_dict(r: SigmaRule, *, full: bool = False) -> dict:
    data = {
        "id": r.id,
        "title": r.title,
        "description": r.description or "",
        "author": r.author or "",
        "level": r.level,
        "severity": r.severity,
        "status": r.status or "",
        "channel": r.channel,
        "event_ids": r.event_ids or [],
        "tags": r.tags or [],
        "mitre": r.mitre or "",
        "mitre_name": technique_name(r.mitre) if r.mitre else "",
        "falsepositives": r.falsepositives or [],
        "references": r.references or [],
        "enabled": bool(r.enabled),
        "source": r.source or "",
        "added_at": _iso(r.added_at),
        "added_by": r.added_by,
        "condition_text": r.condition_text or "",
    }
    if full:
        data["selections"] = r.selections
        data["condition"] = r.condition
    return data


# ---------------------------------------------------------------------------
# Console
# ---------------------------------------------------------------------------


@router.get("")
def list_rules(
    channel: str | None = None,
    level: str | None = None,
    enabled: bool | None = None,
    search: str | None = None,
    limit: int = 500,
    db: Session = Depends(get_db),
    _u=Depends(require_console),
):
    q = db.query(SigmaRule)
    if channel:
        q = q.filter(SigmaRule.channel == channel)
    if level:
        q = q.filter(SigmaRule.level == level.lower())
    if enabled is not None:
        q = q.filter(SigmaRule.enabled == enabled)
    if search:
        like = f"%{search}%"
        q = q.filter(SigmaRule.title.ilike(like) | SigmaRule.description.ilike(like)
                     | SigmaRule.mitre.ilike(like))
    total = q.count()
    rows = q.order_by(SigmaRule.level, SigmaRule.title).limit(min(limit, 3000)).all()
    return {"total": total, "rules": [rule_dict(r) for r in rows]}


@router.get("/summary")
def summary(db: Session = Depends(get_db), _u=Depends(require_console)):
    rows = db.query(SigmaRule).all()
    by_channel: dict[str, int] = {}
    by_level: dict[str, int] = {}
    for r in rows:
        if r.enabled:
            by_channel[r.channel] = by_channel.get(r.channel, 0) + 1
            by_level[r.level] = by_level.get(r.level, 0) + 1
    return {
        "total": len(rows),
        "enabled": sum(1 for r in rows if r.enabled),
        "by_channel": by_channel,
        "by_level": by_level,
    }


# Paths that hold the repository's own test fixtures and retired rules. The
# SigmaHQ archive carries ~190 deliberately broken files under regression_data;
# reporting those as rejections tells the operator their upload half failed
# when in fact nothing is wrong.
_SKIP_SEGMENTS = (
    "/regression_data/", "/tests/", "/test/", "/deprecated/", "/unsupported/",
    "/.github/", "/documentation/",
)


def _is_fixture(path: str) -> bool:
    lowered = "/" + path.lower().replace("\\", "/")
    return any(seg in lowered for seg in _SKIP_SEGMENTS)


def _read_upload(upload: UploadFile, payload: bytes) -> list[tuple[str, str]]:
    """Accept a single .yml, or a .zip holding a whole rule repository."""
    name = (upload.filename or "rules").lower()

    if name.endswith(".zip"):
        docs: list[tuple[str, str]] = []
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                members = [
                    m for m in zf.namelist()
                    if m.lower().endswith((".yml", ".yaml"))
                    and not m.endswith("/")
                    and not _is_fixture(m)
                ]
                if len(members) > MAX_FILES:
                    raise HTTPException(
                        status_code=400,
                        detail=f"That archive holds {len(members)} rules; the limit is {MAX_FILES}.",
                    )
                for m in members:
                    try:
                        docs.append((m, zf.read(m).decode("utf-8", errors="replace")))
                    except Exception:
                        continue
        except zipfile.BadZipFile:
            raise HTTPException(status_code=400, detail="That file is not a readable zip.")
        return docs

    return [(upload.filename or "rule.yml", payload.decode("utf-8", errors="replace"))]


@router.post("/upload")
async def upload_rules(
    file: UploadFile = File(...),
    replace: bool = False,
    db: Session = Depends(get_db),
    admin=Depends(require_admin),
):
    """Compile and store rules. Rejections come back with their reasons."""
    payload = await file.read()
    if len(payload) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Uploads are capped at {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.",
        )
    if not payload:
        raise HTTPException(status_code=400, detail="That file is empty.")

    documents = _read_upload(file, payload)
    if not documents:
        raise HTTPException(status_code=400, detail="No YAML rules found in that file.")

    result = compile_many(documents)

    if replace:
        db.query(SigmaRule).delete()

    added = updated = 0
    for rule in result["rules"]:
        existing = db.get(SigmaRule, rule["id"])
        if existing is None:
            existing = SigmaRule(id=rule["id"], added_by=admin.username)
            db.add(existing)
            added += 1
        else:
            updated += 1
        existing.title = rule["title"]
        existing.description = rule["description"]
        existing.author = rule["author"]
        existing.level = rule["level"]
        existing.severity = rule["severity"]
        existing.status = rule["status"]
        existing.channel = rule["channel"]
        existing.event_ids = rule["event_ids"]
        existing.platform = rule.get("platform", "windows")
        existing.tags = rule["tags"]
        existing.mitre = rule["mitre"]
        existing.falsepositives = rule["falsepositives"]
        existing.references = rule["references"]
        existing.selections = rule["selections"]
        existing.condition = rule["condition"]
        existing.condition_text = rule["condition_text"]
        existing.source = rule["source"]

    db.add(AuditEvent(
        kind="sigma.uploaded",
        subject=file.filename or "rules",
        detail=f"{added} added, {updated} updated, {len(result['rejected'])} rejected "
               f"by {admin.username}",
    ))
    db.commit()

    # Group rejections so a repository upload does not return 4000 lines.
    reasons: dict[str, int] = {}
    for r in result["rejected"]:
        key = r["reason"]
        reasons[key] = reasons.get(key, 0) + 1
    top = sorted(reasons.items(), key=lambda kv: -kv[1])[:25]

    return {
        "added": added,
        "updated": updated,
        "rejected": len(result["rejected"]),
        "rejection_reasons": [{"reason": k, "count": v} for k, v in top],
        "examples": result["rejected"][:10],
    }


class UpdateRequest(BaseModel):
    url: str | None = None
    replace: bool = False


@router.post("/update")
def start_update(
    payload: UpdateRequest,
    db: Session = Depends(get_db),
    admin=Depends(require_admin),
):
    """Fetch the ruleset from the upstream repository and recompile it."""
    url = (payload.url or sigma_update.source_url(db)).strip()
    if not url.lower().startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="The source must be an http(s) URL.")

    started, message = sigma_update.start_update(url, admin.username, payload.replace)
    if not started:
        raise HTTPException(status_code=409, detail=message)
    return {"started": True, "url": url, "status": sigma_update.STATE.snapshot()}


@router.get("/update/status")
def update_status(db: Session = Depends(get_db), _u=Depends(require_console)):
    """Progress of a running update, plus where rules last came from."""
    return {
        **sigma_update.STATE.snapshot(),
        "source_url": sigma_update.source_url(db),
        "last_update": sigma_update.last_update(db),
        "default_source": sigma_update.DEFAULT_SOURCE,
    }


class ToggleRequest(BaseModel):
    enabled: bool


@router.post("/{rule_id}/toggle")
def toggle_rule(
    rule_id: str,
    payload: ToggleRequest,
    db: Session = Depends(get_db),
    admin=Depends(require_admin),
):
    rule = db.get(SigmaRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="No such rule.")
    rule.enabled = payload.enabled
    db.commit()
    return rule_dict(rule)


class BulkToggleRequest(BaseModel):
    channel: str | None = None
    level: str | None = None
    enabled: bool = True


@router.post("/bulk-toggle")
def bulk_toggle(
    payload: BulkToggleRequest,
    db: Session = Depends(get_db),
    admin=Depends(require_admin),
):
    """Turn a whole channel or severity on or off in one go."""
    q = db.query(SigmaRule)
    if payload.channel:
        q = q.filter(SigmaRule.channel == payload.channel)
    if payload.level:
        q = q.filter(SigmaRule.level == payload.level.lower())
    if not payload.channel and not payload.level:
        raise HTTPException(
            status_code=400,
            detail="Narrow this by channel or level; refusing to change every rule at once.",
        )
    count = q.count()
    q.update({SigmaRule.enabled: payload.enabled}, synchronize_session=False)
    db.add(AuditEvent(
        kind="sigma.bulk_toggle",
        subject=payload.channel or payload.level or "",
        detail=f"{'enabled' if payload.enabled else 'disabled'} {count} rules "
               f"by {admin.username}",
    ))
    db.commit()
    return {"changed": count, "enabled": payload.enabled}


@router.delete("/all")
def delete_all(db: Session = Depends(get_db), admin=Depends(require_admin)):
    count = db.query(SigmaRule).count()
    db.query(SigmaRule).delete()
    db.add(AuditEvent(kind="sigma.cleared", subject=f"{count} rules",
                      detail=f"by {admin.username}"))
    db.commit()
    return {"deleted": count}


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------


@router.get("/bundle")
def rule_bundle(
    agent: Agent = Depends(require_agent),
    db: Session = Depends(get_db),
):
    """The enabled ruleset, in the shape the collector's evaluator expects."""
    # Only the rules this host can evaluate. A Windows rule reads the event
    # log and a Linux rule reads auditd; sending both everywhere would ship
    # thousands of rules that can never match and make every bundle bigger for
    # no detection.
    want = (agent.platform or "windows").lower()
    rows = [
        r for r in db.query(SigmaRule).filter(SigmaRule.enabled == True).all()  # noqa: E712
        if (r.platform or "windows") == want
    ]
    return JSONResponse({
        "version": 1,
        "platform": want,
        "count": len(rows),
        "rules": [
            {
                "id": r.id,
                "title": r.title,
                "description": (r.description or "")[:400],
                "level": r.level,
                "severity": r.severity,
                "mitre": r.mitre or "",
                "channel": r.channel,
                "platform": r.platform or "windows",
                "event_ids": r.event_ids or [],
                "selections": r.selections,
                "condition": r.condition,
                "source": r.source or "",
            }
            for r in rows
        ],
    })
