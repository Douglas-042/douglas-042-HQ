"""Indicator feeds: define, refresh, and hand to hunts."""
from __future__ import annotations

from datetime import timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..auth import require_console, require_responder
from ..database import get_db
from ..models import AuditEvent, IocFeed, new_id, utcnow
from ..services import feeds as feed_service

router = APIRouter()

# Well-known public sources, offered as a starting point rather than
# configured by default — the console does not reach out on its own. Each
# preset carries the mode it makes sense in: a C2 list is an indicator feed
# (matched on hosts), a victim tracker is a watch feed (matched against your
# own name, never sent to a host).
PRESETS = [
    {
        "name": "Feodo Tracker (botnet C2)",
        "kind": "http",
        "mode": "indicators",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "note": "Active botnet command-and-control IPs from abuse.ch. The core "
                "C2 feed — a host talking to one of these is the finding you want. "
                "No key needed.",
    },
    {
        "name": "ThreatFox (IOCs)",
        "kind": "http",
        "mode": "indicators",
        "url": "https://threatfox.abuse.ch/export/json/recent/",
        "note": "Fresh IOCs from abuse.ch: C2 IPs and ip:port, malware hashes, "
                "URLs — tagged by malware family. ip:port entries are normalised "
                "to a matchable address automatically. Optional Auth-Key header.",
    },
    {
        "name": "URLhaus (malware URLs)",
        "kind": "http",
        "mode": "indicators",
        "url": "https://urlhaus.abuse.ch/downloads/text_recent/",
        "note": "Malware distribution URLs from abuse.ch. No key needed.",
    },
    {
        "name": "TweetFeed (last month)",
        "kind": "http",
        "mode": "indicators",
        "url": "https://api.tweetfeed.live/v1/month",
        "note": "Indicators curated from security researchers' posts: IPs, "
                "domains, URLs and hashes. Community-sourced, so it moves fast "
                "and is noisier than the abuse.ch feeds — good breadth, worth "
                "checking a match against a second source. No key needed.",
    },
    {
        "name": "TweetFeed (today)",
        "kind": "http",
        "mode": "indicators",
        "url": "https://api.tweetfeed.live/v1/today",
        "note": "The same source over a 24-hour window. Much smaller, so it is "
                "the one to use if the monthly feed adds more noise than you "
                "want in the pool.",
    },
    {
        "name": "USOM (TR blocklist)",
        "kind": "http",
        "mode": "indicators",
        "url": "https://www.usom.gov.tr/url-list.txt",
        "note": "Türkiye's national cyber-incident centre blocklist: malicious "
                "URLs, domains and IPs. No key needed.",
    },
    {
        "name": "abuse.ch SSL blacklist (C2 by certificate)",
        "kind": "http",
        "mode": "indicators",
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        "note": "IPs serving TLS certificates known to belong to malware C2. "
                "Catches infrastructure that changes domain but keeps its "
                "certificate. No key needed.",
    },
    {
        "name": "Emerging Threats (compromised hosts)",
        "kind": "http",
        "mode": "indicators",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "note": "Hosts observed participating in attacks. Broad and long-lived, "
                "so treat a match as a lead rather than a conclusion. No key needed.",
    },
    {
        "name": "Blocklist.de (attacking hosts)",
        "kind": "http",
        "mode": "indicators",
        "url": "https://lists.blocklist.de/lists/all.txt",
        "note": "Addresses reported for SSH, mail and web brute force. Best for "
                "spotting inbound noise; a match on an outbound connection is "
                "more interesting than one on an inbound.",
    },
    {
        "name": "CINS Army (bad actors)",
        "kind": "http",
        "mode": "indicators",
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "note": "Addresses with a poor reputation across the CINS sensor "
                "network. No key needed.",
    },
    {
        "name": "Digital Side (recent malware IOCs)",
        "kind": "http",
        "mode": "indicators",
        "url": "https://osint.digitalside.it/Threat-Intel/lists/latestips.txt",
        "note": "Addresses from recently analysed malware samples. Small and "
                "current — a good complement to the larger blocklists.",
    },
    {
        "name": "OpenPhish (phishing URLs)",
        "kind": "http",
        "mode": "indicators",
        "url": "https://openphish.com/feed.txt",
        "note": "Live phishing URLs. Matches show up against browser history "
                "and DNS rather than processes — useful after a reported click.",
    },
    {
        "name": "ransomware.live (victim watch)",
        "kind": "http",
        "mode": "watch",
        "url": "https://api.ransomware.live/v2/recentvictims",
        "note": "Ransomware victim postings and leak-site listings. This is a "
                "WATCH feed: its values are victim names and .onion sites, so they "
                "are never sent to a host — the console instead tells you if your "
                "own domains appear on it. Add your domains in Watch terms below.",
    },
    {
        "name": "MISP instance",
        "kind": "misp",
        "mode": "indicators",
        "url": "https://misp.example.local",
        "note": "Your own MISP. Needs an API key from your profile page. Pulls "
                "attributes MISP marks to_ids and applies its warninglist.",
    },
    {
        "name": "Custom feed",
        "kind": "http",
        "mode": "indicators",
        "url": "",
        "note": "Any URL returning JSON or plain text. Anything indicator-shaped "
                "in the response is picked up — IPs, domains, URLs, MD5, SHA1, "
                "SHA256 and filenames — so most vendor and community feeds work "
                "without a per-provider adapter. Add a header name if it needs "
                "a key.",
    },
]


def _iso(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def feed_dict(f: IocFeed, *, with_indicators: bool = False) -> dict:
    data = {
        "id": f.id,
        "name": f.name,
        "kind": f.kind,
        "mode": f.mode or "indicators",
        "url": f.url,
        # Never return the key itself; say whether one is set.
        "has_key": bool(f.api_key),
        "header_name": f.header_name or "",
        "tags": f.tags or "",
        "days": f.days or 30,
        "verify_tls": bool(f.verify_tls),
        "enabled": bool(f.enabled),
        "auto_include": bool(f.auto_include),
        "indicator_count": f.indicator_count or 0,
        "breakdown": f.breakdown or {},
        "watch_terms": f.watch_terms or "",
        "watch_hits": f.watch_hits or [],
        "last_fetch_at": _iso(f.last_fetch_at),
        "last_error": f.last_error,
        "created_by": f.created_by,
    }
    if with_indicators:
        data["indicators"] = f.indicators or []
    return data


@router.get("/presets")
def presets(_u=Depends(require_console)):
    return {"presets": PRESETS}


@router.get("")
def list_feeds(db: Session = Depends(get_db), _u=Depends(require_console)):
    rows = db.query(IocFeed).order_by(IocFeed.name).all()
    # Only indicator feeds contribute to the pool. A watch feed is enabled and
    # may be auto_include, but its values describe victims and must never be
    # matched against a host — so they are excluded here by mode, not by trust.
    active = [f for f in rows
              if f.enabled and f.auto_include and (f.mode or "indicators") != "watch"]
    pooled: set = set()
    for f in active:
        pooled.update(f.indicators or [])
    watch_hits = sum(len(f.watch_hits or []) for f in rows if (f.mode or "") == "watch")
    return {
        "total": len(rows),
        "enabled": sum(1 for f in rows if f.enabled),
        "pooled_indicators": len(pooled),
        "watch_feeds": sum(1 for f in rows if (f.mode or "") == "watch"),
        "watch_hits": watch_hits,
        "feeds": [feed_dict(f) for f in rows],
    }


@router.get("/pool")
def indicator_pool(db: Session = Depends(get_db), _u=Depends(require_console)):
    """Every indicator that would be attached to a hunt right now.

    Deduplicated across feeds, with the source kept so a match can be traced
    back to where the indicator came from. Watch feeds are excluded — their
    values are victim markers, not indicators, and must not reach a host.
    """
    rows = (
        db.query(IocFeed)
        .filter(IocFeed.enabled == True, IocFeed.auto_include == True)  # noqa: E712
        .all()
    )
    source_of: dict[str, list[str]] = {}
    for f in rows:
        if (f.mode or "indicators") == "watch":
            continue
        for value in (f.indicators or []):
            source_of.setdefault(value, []).append(f.name)

    return {
        "count": len(source_of),
        "feeds": [f.name for f in rows if (f.mode or "indicators") != "watch"],
        "indicators": sorted(source_of)[:50_000],
        "sources": {k: v for k, v in list(source_of.items())[:5000]},
    }


class FeedRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    kind: str = "http"
    mode: str = "indicators"
    url: str = Field(min_length=4, max_length=1000)
    api_key: str | None = None
    header_name: str = ""
    tags: str = ""
    days: int = 30
    verify_tls: bool = True
    enabled: bool = True
    auto_include: bool = True
    watch_terms: str = ""


def _validate(payload: FeedRequest) -> None:
    if payload.kind not in ("http", "misp"):
        raise HTTPException(status_code=400, detail="Kind must be http or misp.")
    if payload.mode not in ("indicators", "watch"):
        raise HTTPException(status_code=400, detail="Mode must be indicators or watch.")
    if not payload.url.lower().startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="The URL must start with http or https.")
    if not 1 <= payload.days <= 3650:
        raise HTTPException(status_code=400, detail="Lookback must be between 1 and 3650 days.")


def _apply(row: IocFeed, payload: FeedRequest) -> None:
    row.name = payload.name.strip()
    row.kind = payload.kind
    row.mode = payload.mode
    row.url = payload.url.strip()
    row.header_name = payload.header_name.strip()
    row.tags = payload.tags.strip()
    row.days = payload.days
    row.verify_tls = payload.verify_tls
    row.enabled = payload.enabled
    row.auto_include = payload.auto_include
    row.watch_terms = (payload.watch_terms or "").strip()
    # An omitted key leaves the stored one alone, so editing a feed does not
    # silently wipe its credential.
    if payload.api_key is not None:
        row.api_key = payload.api_key.strip() or None


@router.post("")
def create_feed(
    payload: FeedRequest,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    _validate(payload)
    row = IocFeed(id=new_id(), created_by=user.username, indicators=[], breakdown={})
    _apply(row, payload)
    db.add(row)
    db.add(AuditEvent(kind="feed.created", subject=row.name,
                      detail=f"{row.kind} by {user.username}"))
    db.commit()
    db.refresh(row)
    return feed_dict(row)


@router.post("/test")
def test_feed(
    payload: FeedRequest,
    _u=Depends(require_responder),
):
    """Fetch without storing, so a feed can be proven before it is saved."""
    _validate(payload)
    probe = IocFeed(
        kind=payload.kind, mode=payload.mode, url=payload.url.strip(),
        api_key=payload.api_key, header_name=payload.header_name,
        tags=payload.tags, days=payload.days, verify_tls=payload.verify_tls,
        watch_terms=payload.watch_terms,
    )

    if payload.mode == "watch":
        try:
            sample, hits = feed_service.fetch_watch(probe)
        except feed_service.FeedError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        # Prove the guard rail as part of the test: run the same values through
        # the indicator classifier and confirm none would have reached the pool.
        would_pool = sum(1 for line in sample if feed_service.classify(line))
        return {
            "mode": "watch",
            "count": len(sample),
            "hits": hits[:20],
            "sample": sample,
            "pool_note": (
                "Watch feed — none of these values are sent to a host."
                if would_pool == 0 else
                "Watch feed — values are kept out of the pool regardless of shape."
            ),
        }

    try:
        values, breakdown = feed_service.fetch(probe)
    except feed_service.FeedError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "mode": "indicators",
        "count": len(values),
        "breakdown": breakdown,
        "sample": sorted(values)[:15],
    }


@router.post("/{feed_id}")
def update_feed(
    feed_id: str,
    payload: FeedRequest,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    row = db.get(IocFeed, feed_id)
    if not row:
        raise HTTPException(status_code=404, detail="No such feed.")
    _validate(payload)
    _apply(row, payload)
    db.commit()
    db.refresh(row)
    return feed_dict(row)


@router.post("/{feed_id}/refresh")
def refresh_feed(
    feed_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    row = db.get(IocFeed, feed_id)
    if not row:
        raise HTTPException(status_code=404, detail="No such feed.")

    # A watch feed refreshes differently: it scans the source for the operator's
    # terms and stores the hits, and stores no indicators at all — so nothing it
    # returns can ever reach the pool.
    if (row.mode or "indicators") == "watch":
        try:
            _sample, hits = feed_service.fetch_watch(row)
        except feed_service.FeedError as exc:
            row.last_error = str(exc)
            row.last_fetch_at = utcnow()
            db.commit()
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        prev_hits = len(row.watch_hits or [])
        row.watch_hits = hits
        row.indicators = []          # a watch feed never holds indicators
        row.indicator_count = 0
        row.breakdown = {}
        row.last_fetch_at = utcnow()
        row.last_error = None
        db.add(AuditEvent(kind="feed.watched", subject=row.name,
                          detail=f"{len(hits)} watch hit(s) by {user.username}"))
        db.commit()
        return {
            "feed": feed_dict(row),
            "mode": "watch",
            "hits": len(hits),
            "new_hits": max(0, len(hits) - prev_hits),
        }

    try:
        values, breakdown = feed_service.fetch(row)
    except feed_service.FeedError as exc:
        # Keep whatever we had. A feed that is down should not empty the pool.
        row.last_error = str(exc)
        row.last_fetch_at = utcnow()
        db.commit()
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    previous = set(row.indicators or [])
    row.indicators = sorted(values)
    row.indicator_count = len(values)
    row.breakdown = breakdown
    row.last_fetch_at = utcnow()
    row.last_error = None
    db.add(AuditEvent(kind="feed.refreshed", subject=row.name,
                      detail=f"{len(values)} indicators by {user.username}"))
    db.commit()

    return {
        "feed": feed_dict(row),
        "added": len(values - previous),
        "removed": len(previous - values),
    }


class ToggleRequest(BaseModel):
    enabled: bool


@router.post("/{feed_id}/toggle")
def toggle_feed(
    feed_id: str,
    payload: ToggleRequest,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    row = db.get(IocFeed, feed_id)
    if not row:
        raise HTTPException(status_code=404, detail="No such feed.")
    row.enabled = payload.enabled
    db.commit()
    return feed_dict(row)


@router.delete("/{feed_id}")
def delete_feed(
    feed_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    row = db.get(IocFeed, feed_id)
    if not row:
        raise HTTPException(status_code=404, detail="No such feed.")
    db.add(AuditEvent(kind="feed.deleted", subject=row.name,
                      detail=f"by {user.username}"))
    db.delete(row)
    db.commit()
    return {"deleted": feed_id}
