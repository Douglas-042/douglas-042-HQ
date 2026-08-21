"""Fetch and compile Sigma rules from an upstream repository.

The console does not reach out on its own — this only runs when an operator
presses Update, and it says so plainly when there is no route out. An isolated
incident-response network is the normal case, not the exception, so failing to
reach GitHub is an expected outcome with a clear next step rather than an error.

Runs on a worker thread and reports progress over the existing WebSocket
channel, because downloading 10 MB and compiling ~2500 rules takes long enough
that a synchronous request would sit past most proxy timeouts.
"""
from __future__ import annotations

import io
import logging
import threading
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone

from ..database import SessionLocal
from ..models import AuditEvent, SigmaRule, get_setting, set_setting, utcnow
from .events import broadcast
from .sigma import compile_many

logger = logging.getLogger("douglas.sigma")

DEFAULT_SOURCE = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
SOURCE_KEY = "sigma_source_url"
LAST_UPDATE_KEY = "sigma_last_update"

MAX_DOWNLOAD_BYTES = 120 * 1024 * 1024
DOWNLOAD_TIMEOUT = 180

# Only Windows rules can ever fire here. Pulling in the Linux, macOS, cloud and
# network rule trees would report ~1000 rejections that are not problems.
# Paths worth extracting. Linux was excluded entirely until the collector
# could read anything on that side; now that it can, the rules come down too
# and the parser rejects the ones whose log source is not collected — which is
# the right place for that decision, since it knows what is readable.
_WANTED_MARKERS = ("/windows/", "/windows_", "/linux/", "/linux_")
_SKIP_SEGMENTS = (
    "/regression_data/", "/tests/", "/test/", "/deprecated/", "/unsupported/",
    "/.github/", "/documentation/",
)


class UpdateState:
    """Single in-flight update, observable while it runs."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.running = False
        self.phase = "idle"
        self.detail = ""
        self.percent = 0.0
        self.started_at: datetime | None = None
        self.finished_at: datetime | None = None
        self.result: dict | None = None
        self.error: str | None = None

    def snapshot(self) -> dict:
        return {
            "running": self.running,
            "phase": self.phase,
            "detail": self.detail,
            "percent": round(self.percent, 1),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "result": self.result,
            "error": self.error,
        }

    def set(self, phase: str, detail: str = "", percent: float | None = None) -> None:
        self.phase = phase
        self.detail = detail
        if percent is not None:
            self.percent = percent
        broadcast({"type": "sigma.update", **self.snapshot()})


STATE = UpdateState()


def source_url(db) -> str:
    return get_setting(db, SOURCE_KEY, DEFAULT_SOURCE)


def last_update(db) -> str:
    return get_setting(db, LAST_UPDATE_KEY, "")


def _friendly_network_error(exc: Exception) -> str:
    """Translate a transport failure into something with a next step."""
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code == 404:
            return ("The source URL returned 404. Check the address in Sigma rules, "
                    "or upload the archive by hand.")
        return f"The source returned HTTP {exc.code}. Try again or upload by hand."
    if isinstance(exc, urllib.error.URLError):
        reason = str(getattr(exc, "reason", exc))
        return (f"Could not reach the rule source ({reason}). This console is often "
                "run without internet access — download the archive on a machine "
                "that has it and use Upload rules instead.")
    return f"Download failed: {exc}"


def _extract_rules(payload: bytes) -> list[tuple[str, str]]:
    docs: list[tuple[str, str]] = []
    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        for member in zf.namelist():
            if not member.lower().endswith((".yml", ".yaml")) or member.endswith("/"):
                continue
            lowered = "/" + member.lower()
            if any(seg in lowered for seg in _SKIP_SEGMENTS):
                continue
            if not any(mark in lowered for mark in _WANTED_MARKERS):
                continue
            try:
                docs.append((member, zf.read(member).decode("utf-8", errors="replace")))
            except Exception:
                continue
    return docs


def _download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "Douglas-042"})
    chunks: list[bytes] = []
    total = 0
    with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT) as resp:
        declared = int(resp.headers.get("Content-Length") or 0)
        while True:
            chunk = resp.read(512 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_DOWNLOAD_BYTES:
                raise ValueError(
                    f"The archive exceeds the {MAX_DOWNLOAD_BYTES // (1024 * 1024)} MB limit."
                )
            chunks.append(chunk)
            if declared:
                # Downloading is the first third of the work.
                STATE.set("downloading",
                          f"{total / 1024 / 1024:.1f} of {declared / 1024 / 1024:.1f} MB",
                          percent=min(30.0, total / declared * 30))
            else:
                STATE.set("downloading", f"{total / 1024 / 1024:.1f} MB")
    return b"".join(chunks)


def _run(url: str, username: str, replace: bool) -> None:
    started = time.time()
    try:
        STATE.set("downloading", url, percent=1)
        payload = _download(url)

        STATE.set("extracting", "Reading Windows rules from the archive", percent=32)
        docs = _extract_rules(payload)
        if not docs:
            raise ValueError(
                "No Windows rules found in that archive. Check the source URL."
            )

        STATE.set("compiling", f"{len(docs)} rules", percent=38)
        compiled = compile_many(docs)

        STATE.set("storing", f"{len(compiled['rules'])} compiled", percent=82)
        db = SessionLocal()
        try:
            before = db.query(SigmaRule).count()
            if replace:
                db.query(SigmaRule).delete()

            # Preserve which rules an operator switched off. Losing that on
            # every update would make tuning pointless.
            disabled = set()
            if not replace:
                disabled = {
                    r.id for r in db.query(SigmaRule.id)
                    .filter(SigmaRule.enabled == False).all()  # noqa: E712
                }

            added = updated = 0
            for rule in compiled["rules"]:
                existing = db.get(SigmaRule, rule["id"])
                if existing is None:
                    existing = SigmaRule(id=rule["id"], added_by=username)
                    db.add(existing)
                    added += 1
                else:
                    updated += 1
                for field in ("title", "description", "author", "level", "severity",
                              "status", "channel", "event_ids", "platform", "tags", "mitre",
                              "falsepositives", "references", "selections",
                              "condition", "condition_text", "source"):
                    setattr(existing, field, rule[field])
                existing.enabled = rule["id"] not in disabled

            stamp = utcnow().isoformat()
            set_setting(db, LAST_UPDATE_KEY, stamp, who=username)
            set_setting(db, SOURCE_KEY, url, who=username)
            db.add(AuditEvent(
                kind="sigma.updated", subject=url,
                detail=f"{added} added, {updated} updated, "
                       f"{len(compiled['rejected'])} rejected by {username}",
            ))
            db.commit()
            after = db.query(SigmaRule).count()
        finally:
            db.close()

        reasons: dict[str, int] = {}
        for r in compiled["rejected"]:
            reasons[r["reason"]] = reasons.get(r["reason"], 0) + 1

        STATE.result = {
            "added": added,
            "updated": updated,
            "rejected": len(compiled["rejected"]),
            "total_before": before,
            "total_after": after,
            "kept_disabled": len(disabled),
            "seconds": round(time.time() - started, 1),
            "rejection_reasons": [
                {"reason": k, "count": v}
                for k, v in sorted(reasons.items(), key=lambda kv: -kv[1])[:20]
            ],
            "source": url,
            "at": stamp,
        }
        STATE.error = None
        STATE.set("complete", f"{added} added, {updated} updated", percent=100)
        logger.info("Sigma update finished: %s", STATE.result)

    except Exception as exc:  # noqa: BLE001 - surfaced to the operator
        STATE.error = _friendly_network_error(exc)
        STATE.result = None
        STATE.set("failed", STATE.error, percent=0)
        logger.warning("Sigma update failed: %s", exc)
    finally:
        with STATE.lock:
            STATE.running = False
            STATE.finished_at = datetime.now(timezone.utc)
        broadcast({"type": "sigma.update", **STATE.snapshot()})


def start_update(url: str, username: str, replace: bool = False) -> tuple[bool, str]:
    """Kick off an update. Returns (started, message)."""
    with STATE.lock:
        if STATE.running:
            return False, "An update is already running."
        STATE.running = True
        STATE.started_at = datetime.now(timezone.utc)
        STATE.finished_at = None
        STATE.result = None
        STATE.error = None
        STATE.percent = 0.0

    thread = threading.Thread(
        target=_run, args=(url, username, replace),
        name="sigma-update", daemon=True,
    )
    thread.start()
    return True, "Update started."
