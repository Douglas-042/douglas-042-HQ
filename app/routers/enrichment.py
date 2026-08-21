"""Reputation keys, and running lookups against what a hunt found."""
from __future__ import annotations

import logging
import threading
from datetime import timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..auth import require_admin, require_console, require_responder
from ..database import SessionLocal, get_db
from ..models import (
    AuditEvent,
    EnrichmentKey,
    IocFeed,
    IpReputation,
    Job,
    JobStatus,
    utcnow,
)
from ..services import enrichment as svc
from ..services.events import broadcast

logger = logging.getLogger("douglas.enrichment")

router = APIRouter()


def _iso(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _today() -> str:
    return utcnow().strftime("%Y-%m-%d")


def key_dict(row: EnrichmentKey | None, provider: str) -> dict:
    info = svc.PROVIDER_INFO.get(provider, {})
    base = {
        "provider": provider,
        "name": info.get("name", provider),
        "asks": info.get("asks", ""),
        "free": info.get("free", False),
        "signup": info.get("signup", ""),
        "note": info.get("note", ""),
        "default_limit": info.get("default_limit", 0),
    }
    if row is None:
        return {**base, "has_key": False, "enabled": False, "calls_today": 0,
                "daily_limit": info.get("default_limit", 0), "last_used_at": None,
                "last_error": None, "ok_count": 0, "fail_count": 0}
    return {
        **base,
        # The key itself is never returned; only whether one is stored.
        "has_key": bool(row.api_key),
        "enabled": bool(row.enabled),
        "calls_today": (row.calls_today or 0) if row.calls_date == _today() else 0,
        "daily_limit": row.daily_limit or info.get("default_limit", 0),
        "last_used_at": _iso(row.last_used_at),
        "last_error": row.last_error,
        "ok_count": row.ok_count or 0,
        "fail_count": row.fail_count or 0,
    }


def active_keys(db: Session) -> dict:
    """Providers that are enabled and usable right now.

    ThreatFox is the one provider that works without a key, so it is included
    when enabled even with no credential — that is a real free capability and
    hiding it behind a key nobody needs would be wrong.
    """
    keys: dict = {}
    for row in db.query(EnrichmentKey).filter(EnrichmentKey.enabled == True).all():  # noqa: E712
        if row.provider == "threatfox" or row.api_key:
            # Respect a spent daily quota rather than making the call and
            # collecting a 429 from the provider.
            limit = row.daily_limit or 0
            used = (row.calls_today or 0) if row.calls_date == _today() else 0
            if limit and used >= limit:
                continue
            keys[row.provider] = row.api_key or ""
    return keys


@router.get("")
def list_providers(db: Session = Depends(get_db), _u=Depends(require_console)):
    rows = {r.provider: r for r in db.query(EnrichmentKey).all()}
    providers = [key_dict(rows.get(p), p) for p in svc.PROVIDERS]

    cached = db.query(IpReputation).count()
    flagged = (
        db.query(IpReputation)
        .filter(IpReputation.label.in_(["malicious", "suspicious"]))
        .count()
    )
    return {
        "providers": providers,
        "enabled": sum(1 for p in providers if p["enabled"]),
        "cached": cached,
        "flagged": flagged,
        "cache_hours": svc.CACHE_HOURS,
        "max_per_run": svc.MAX_PER_RUN,
    }


class KeyRequest(BaseModel):
    api_key: str | None = None
    enabled: bool = True
    daily_limit: int = Field(default=0, ge=0, le=1_000_000)


# NOTE: every literal path below must be declared BEFORE the parameterised
# ones. FastAPI matches in registration order, so POST /{provider} declared
# first swallows POST /run and rejects it as an unknown provider — which is
# exactly what happened the first time this was wired up.

class EnrichRequest(BaseModel):
    addresses: list[str] = Field(default_factory=list)
    force: bool = False


@router.post("/run")
def run_enrichment(
    payload: EnrichRequest,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    """Look up the addresses this fleet has seen, or a supplied list."""
    keys = active_keys(db)
    if not keys:
        raise HTTPException(
            status_code=400,
            detail="No reputation provider is switched on. Add a key first — "
                   "AbuseIPDB's free tier is the one to start with.",
        )

    addresses = [a.strip() for a in payload.addresses if svc.is_enrichable(a.strip())]
    if not addresses:
        addresses = collect_addresses(db)
    if not addresses:
        raise HTTPException(
            status_code=400,
            detail="No external addresses to look up yet. Run a hunt first.",
        )

    result = _run_lookups(addresses, force=payload.force)
    db.add(AuditEvent(kind="enrichment.run", subject=f"{result['looked_up']} addresses",
                      detail=f"by {user.username}"))
    db.commit()

    broadcast({"type": "enrichment.done", **result})
    return result


@router.get("/reputation")
def reputation(db: Session = Depends(get_db), _u=Depends(require_console)):
    """Everything known, worst first — the triage order this feature exists for."""
    rows = (
        db.query(IpReputation)
        .order_by(IpReputation.score.desc())
        .limit(500)
        .all()
    )
    return {
        "total": len(rows),
        "addresses": [
            {
                "address": r.address,
                "score": r.score or 0,
                "label": r.label or "unknown",
                "known_good": bool(r.is_known_good),
                "verdicts": r.verdicts or {},
                "worst_provider": svc.worst_provider(r.verdicts or {}),
                "fetched_at": _iso(r.fetched_at),
                "stale": not svc.is_fresh(r.fetched_at),
                "error": r.error,
            }
            for r in rows
        ],
    }


@router.post("/{provider}")
def save_key(
    provider: str,
    payload: KeyRequest,
    db: Session = Depends(get_db),
    admin=Depends(require_admin),
):
    if provider not in svc.PROVIDERS:
        raise HTTPException(status_code=404, detail="Unknown provider.")

    row = db.get(EnrichmentKey, provider)
    if row is None:
        row = EnrichmentKey(provider=provider,
                            daily_limit=svc.PROVIDER_INFO[provider].get("default_limit", 0))
        db.add(row)

    # An omitted key leaves the stored one alone, so toggling a provider does
    # not silently wipe its credential.
    if payload.api_key is not None:
        row.api_key = payload.api_key.strip() or None

    # Enabling a provider that needs a key and has none would produce a run of
    # 401s that read like the addresses were the problem. Refuse instead, and
    # say what is missing. ThreatFox is exempt: it works without one.
    if payload.enabled and provider != "threatfox" and not row.api_key:
        raise HTTPException(
            status_code=400,
            detail=f"{svc.PROVIDER_INFO[provider]['name']} needs an API key before "
                   "it can be switched on.",
        )

    row.enabled = payload.enabled
    if payload.daily_limit:
        row.daily_limit = payload.daily_limit
    row.last_error = None
    row.updated_by = admin.username
    row.updated_at = utcnow()

    db.add(AuditEvent(kind="enrichment.key", subject=provider,
                      detail=f"{'enabled' if row.enabled else 'disabled'} by {admin.username}"))
    db.commit()
    db.refresh(row)
    return key_dict(row, provider)


@router.delete("/{provider}")
def clear_key(provider: str, db: Session = Depends(get_db), admin=Depends(require_admin)):
    if provider not in svc.PROVIDERS:
        raise HTTPException(status_code=404, detail="Unknown provider.")
    row = db.get(EnrichmentKey, provider)
    if row:
        row.api_key = None
        row.enabled = False
        row.last_error = None
        db.add(AuditEvent(kind="enrichment.key", subject=provider,
                          detail=f"key removed by {admin.username}"))
        db.commit()
    return {"cleared": provider}


class TestRequest(BaseModel):
    api_key: str | None = None


@router.post("/{provider}/test")
def test_provider(
    provider: str,
    payload: TestRequest,
    db: Session = Depends(get_db),
    admin=Depends(require_admin),
):
    """Prove a key works before it is relied on, against a known-bad address.

    Uses a documented test address rather than a customer's, so the test never
    sends anything about the estate to a third party.
    """
    if provider not in svc.PROVIDERS:
        raise HTTPException(status_code=404, detail="Unknown provider.")

    api_key = (payload.api_key or "").strip()
    if not api_key:
        row = db.get(EnrichmentKey, provider)
        api_key = (row.api_key if row else "") or ""
    if not api_key and provider != "threatfox":
        raise HTTPException(status_code=400, detail="Enter a key to test.")

    # A well-known scanning address, published for exactly this purpose.
    probe = "185.220.101.1"
    checker = svc.CHECKERS[provider]
    try:
        verdict = checker(probe, api_key)
    except svc.EnrichmentError as exc:
        message = {
            "key-rejected": "The provider rejected that key.",
            "rate-limited": "The provider is rate limiting this key right now.",
        }.get(str(exc), f"Lookup failed: {exc}")
        row = db.get(EnrichmentKey, provider)
        if row:
            row.last_error = message
            db.commit()
        raise HTTPException(status_code=400, detail=message) from exc

    row = db.get(EnrichmentKey, provider)
    if row:
        row.last_error = None
        db.commit()
    return {"ok": True, "probe": probe, "verdict": verdict,
            "message": f"{svc.PROVIDER_INFO[provider]['name']} answered: {verdict['summary']}"}


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------


def _pooled_indicators(db: Session) -> set:
    """Every indicator that would go to a host right now.

    Watch feeds are excluded here for the same reason they are excluded from a
    hunt: their values are victims, not indicators.
    """
    values: set = set()
    rows = (
        db.query(IocFeed)
        .filter(IocFeed.enabled == True, IocFeed.auto_include == True)  # noqa: E712
        .all()
    )
    for f in rows:
        if (f.mode or "indicators") == "watch":
            continue
        values.update(f.indicators or [])
    return values


def collect_addresses(db: Session, limit: int = 500) -> list[str]:
    """External addresses the fleet's most recent hunts saw.

    Read from the stored graph snapshot rather than the evidence bundle, so
    this works even when raw evidence was never uploaded.
    """
    seen: dict[str, int] = {}
    jobs = (
        db.query(Job)
        .filter(Job.status == JobStatus.COMPLETED, Job.graph.isnot(None))
        .order_by(Job.finished_at.desc())
        .limit(200)
        .all()
    )
    for job in jobs:
        data = job.graph if isinstance(job.graph, dict) else {}
        for ep in (data.get("endpoints") or []):
            addr = (ep.get("address") or "").strip()
            if not addr or not svc.is_enrichable(addr):
                continue
            seen[addr] = seen.get(addr, 0) + int(ep.get("connections") or 1)
    # Busiest first only as a tie-break for which get looked up when the cap
    # bites; the point of the feature is to reorder these afterwards.
    ordered = sorted(seen, key=lambda a: -seen[a])
    return ordered[:limit]


def _run_lookups(addresses: list[str], force: bool = False) -> dict:
    """Do the actual fetching. Runs off the request thread."""
    db = SessionLocal()
    try:
        keys = active_keys(db)
        if not keys:
            return {"looked_up": 0, "skipped": len(addresses), "error": "no providers enabled"}

        pooled = _pooled_indicators(db)
        done = 0
        remaining = 0

        for address in addresses:
            if done >= svc.MAX_PER_RUN:
                remaining += 1
                continue

            row = db.get(IpReputation, address)
            if row and not force and svc.is_fresh(row.fetched_at):
                continue

            verdicts, problem = svc.lookup(address, keys)
            score, label, known_good = svc.combine(verdicts)

            # An address on the indicator pool is already a confirmed match, and
            # no reputation score should be able to talk that down.
            if address in pooled:
                score = max(score, 95)
                label = "malicious"
                known_good = False

            if row is None:
                row = IpReputation(address=address)
                db.add(row)
            row.verdicts = verdicts
            row.score = int(score)
            row.label = label
            row.is_known_good = bool(known_good)
            row.fetched_at = utcnow()
            row.error = problem or None

            # Book-keeping per provider, so a spent quota is visible before the
            # next run rather than discovered through failures.
            today = _today()
            for provider in keys:
                key_row = db.get(EnrichmentKey, provider)
                if not key_row:
                    continue
                if key_row.calls_date != today:
                    key_row.calls_date = today
                    key_row.calls_today = 0
                key_row.calls_today = (key_row.calls_today or 0) + 1
                key_row.last_used_at = utcnow()
                if provider in verdicts:
                    key_row.ok_count = (key_row.ok_count or 0) + 1
                else:
                    key_row.fail_count = (key_row.fail_count or 0) + 1
                    if problem and provider in problem:
                        if "key-rejected" in problem:
                            key_row.last_error = "The provider rejected this key."
                            key_row.enabled = False
                        elif "rate-limited" in problem:
                            key_row.last_error = "Rate limited — pausing this provider."

            done += 1
            db.commit()

        return {"looked_up": done, "remaining": remaining,
                "providers": sorted(keys), "error": ""}
    finally:
        db.close()


def enrich_async(addresses: list[str]) -> None:
    """Fire and forget after a hunt, so an upload never waits on a provider."""

    def _go():
        try:
            result = _run_lookups(addresses)
            broadcast({"type": "enrichment.done", **result})
        except Exception as exc:  # noqa: BLE001 - never kill the thread
            logger.warning("Background enrichment failed: %s", exc)

    threading.Thread(target=_go, name="douglas-enrichment", daemon=True).start()


