"""Findings, timeline and the cross-fleet views built on top of them."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..auth import require_agent, require_console, require_responder
from ..database import get_db
from ..models import (
    Agent, AuditEvent, CLOSED_STATUSES, Finding, FindingStatus, Job, JobStatus,
    RuleState, Suppression, TimelineEvent, User, new_id, utcnow,
)
from ..services.mitre import build_matrix, technique_detail, technique_name
from ..services.rule_catalog import (
    CATALOG, TITLES, categories, category_for, category_name, guidance_for, title_for,
)
from ..services import triage

router = APIRouter()

def _iso(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def finding_dict(f: Finding, *, with_guidance: bool = False) -> dict:
    data = {
        "id": f.id,
        "job_id": f.job_id,
        "agent_id": f.agent_id,
        "hostname": f.hostname,
        "rule_id": f.rule_id,
        "severity": f.severity,
        "title": f.title,
        "evidence": f.evidence,
        "mitre": f.mitre,
        "why": f.why,
        "artifact": f.artifact,
        "occurred_at": f.occurred_at,
        "acknowledged": bool(f.acknowledged),
        "note": f.note,
        "mitre_name": technique_name(f.mitre) if f.mitre else "",
        "status": f.status.value if hasattr(f.status, "value") else str(f.status or "open"),
        "assignee": f.assignee,
        "status_changed_at": _iso(f.status_changed_at),
        "status_changed_by": f.status_changed_by,
        "suppressed_by": f.suppressed_by,
    }
    if with_guidance:
        data["guidance"] = guidance_for(f.rule_id)
    return data


@router.get("")
def list_findings(
    job_id: str | None = None,
    agent_id: str | None = None,
    severity: str | None = None,
    rule_id: str | None = None,
    search: str | None = None,
    status: str | None = None,
    assignee: str | None = None,
    latest_only: bool = True,
    limit: int = Query(default=500, le=5000),
    offset: int = 0,
    db: Session = Depends(get_db),
    _u: str = Depends(require_console),
):
    """Findings across the fleet. Defaults to each host's most recent hunt."""
    q = db.query(Finding)

    if job_id:
        q = q.filter(Finding.job_id == job_id)
    elif latest_only:
        latest = (
            db.query(Job.agent_id, func.max(Job.finished_at).label("mx"))
            .filter(Job.status == JobStatus.COMPLETED)
            .group_by(Job.agent_id)
            .subquery()
        )
        latest_ids = [
            row[0]
            for row in db.query(Job.id)
            .join(
                latest,
                (Job.agent_id == latest.c.agent_id) & (Job.finished_at == latest.c.mx),
            )
            .all()
        ]
        if latest_ids:
            q = q.filter(Finding.job_id.in_(latest_ids))

    if agent_id:
        q = q.filter(Finding.agent_id == agent_id)
    if severity:
        q = q.filter(Finding.severity == severity.upper())
    if rule_id:
        q = q.filter(Finding.rule_id == rule_id)
    if status:
        if status == "needs_review":
            # The default working set: everything nobody has ruled on yet.
            q = q.filter(Finding.status.in_(
                [FindingStatus.OPEN, FindingStatus.INVESTIGATING]))
        else:
            q = q.filter(Finding.status == FindingStatus(status))
    if assignee:
        q = q.filter(Finding.assignee == assignee)
    if search:
        like = f"%{search}%"
        q = q.filter(
            Finding.title.ilike(like)
            | Finding.evidence.ilike(like)
            | Finding.hostname.ilike(like)
            | Finding.mitre.ilike(like)
            | Finding.rule_id.ilike(like)
        )

    rows = q.all()
    total = len(rows)
    rows.sort(key=lambda f: (SEV_ORDER.get(f.severity, 9), f.hostname or "", f.rule_id or ""))
    page = rows[offset : offset + limit]

    counts = Counter(
        (f.status.value if hasattr(f.status, "value") else str(f.status)) for f in rows
    )
    return {
        "total": total,
        "status_counts": dict(counts),
        "findings": [finding_dict(f) for f in page],
    }


# ---------------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------------


class StatusRequest(BaseModel):
    status: FindingStatus
    note: str | None = None
    assignee: str | None = None


@router.post("/{finding_id}/status")
def set_status(
    finding_id: int,
    payload: StatusRequest,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="No such finding.")

    f.status = payload.status
    f.status_changed_at = utcnow()
    f.status_changed_by = user.username
    if payload.note is not None:
        f.note = payload.note
    if payload.assignee is not None:
        f.assignee = payload.assignee or None
    # A manual decision overrides a suppression, and the link is cleared so it
    # is not reopened when that suppression is later removed.
    if payload.status != FindingStatus.SUPPRESSED:
        f.suppressed_by = None

    if payload.status in CLOSED_STATUSES:
        job = db.get(Job, f.job_id)
        if job:
            triage.recalculate_job_score(db, job)
    db.commit()
    return finding_dict(f)


class BulkStatusRequest(BaseModel):
    finding_ids: list[int] = Field(default_factory=list)
    status: FindingStatus
    assignee: str | None = None


@router.post("/bulk-status")
def bulk_status(
    payload: BulkStatusRequest,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    """Rule on many findings at once — the normal way a queue gets worked."""
    if not payload.finding_ids:
        raise HTTPException(status_code=400, detail="Select at least one finding.")
    if len(payload.finding_ids) > 5000:
        raise HTTPException(status_code=400, detail="Too many at once; filter first.")

    rows = db.query(Finding).filter(Finding.id.in_(payload.finding_ids)).all()
    now = utcnow()
    for f in rows:
        f.status = payload.status
        f.status_changed_at = now
        f.status_changed_by = user.username
        if payload.assignee is not None:
            f.assignee = payload.assignee or None
        if payload.status != FindingStatus.SUPPRESSED:
            f.suppressed_by = None

    triage.recalculate_for_findings(db, rows)
    db.add(AuditEvent(kind="triage.bulk", subject=payload.status.value,
                      detail=f"{len(rows)} findings by {user.username}"))
    db.commit()
    return {"changed": len(rows), "status": payload.status.value}


@router.get("/triage/queue")
def triage_queue(db: Session = Depends(get_db), _u=Depends(require_console)):
    """What is left to look at, and who is looking at it."""
    rows = db.query(Finding).all()
    by_status = Counter(
        (f.status.value if hasattr(f.status, "value") else str(f.status)) for f in rows
    )
    open_rows = [f for f in rows if f.status == FindingStatus.OPEN]
    by_sev = Counter(f.severity for f in open_rows)
    by_assignee = Counter(f.assignee for f in rows if f.assignee)

    # Rules producing the most open findings: the fastest tuning wins are here.
    noisy = Counter(f.rule_id for f in open_rows if f.rule_id)
    titles = {f.rule_id: f.title for f in open_rows if f.rule_id}
    sevs = {f.rule_id: f.severity for f in open_rows if f.rule_id}

    return {
        "by_status": dict(by_status),
        "open_by_severity": {
            k: by_sev.get(k, 0) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        },
        "by_assignee": [{"assignee": a, "count": c} for a, c in by_assignee.most_common(20)],
        "noisiest_rules": [
            {
                "rule_id": r, "count": c,
                "title": titles.get(r, ""), "severity": sevs.get(r, "INFO"),
                "hosts": len({f.hostname for f in open_rows if f.rule_id == r}),
            }
            for r, c in noisy.most_common(15)
        ],
        "unassigned": sum(1 for f in open_rows if not f.assignee),
    }


class AckRequest(BaseModel):
    acknowledged: bool = True
    note: str | None = None


@router.post("/{finding_id}/ack")
def acknowledge(
    finding_id: int,
    payload: AckRequest,
    db: Session = Depends(get_db),
    _u=Depends(require_responder),
):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="No such finding.")
    f.acknowledged = payload.acknowledged
    if payload.note is not None:
        f.note = payload.note
    db.commit()
    return finding_dict(f)


@router.get("/timeline")
def get_timeline(
    job_id: str | None = None,
    agent_id: str | None = None,
    severity: str | None = None,
    limit: int = Query(default=1000, le=20000),
    db: Session = Depends(get_db),
    _u: str = Depends(require_console),
):
    q = db.query(TimelineEvent)
    if job_id:
        q = q.filter(TimelineEvent.job_id == job_id)
    if agent_id:
        q = q.join(Job, Job.id == TimelineEvent.job_id).filter(Job.agent_id == agent_id)
    if severity:
        q = q.filter(TimelineEvent.severity == severity.upper())
    rows = q.order_by(TimelineEvent.time_utc.desc()).limit(limit).all()
    return {
        "events": [
            {
                "time_utc": e.time_utc,
                "hostname": e.hostname,
                "source": e.source,
                "severity": e.severity,
                "description": e.description,
                "detail": e.detail,
            }
            for e in rows
        ]
    }


@router.get("/stack")
def stack_analysis(
    db: Session = Depends(get_db),
    _u: str = Depends(require_console),
):
    """Frequency analysis across the fleet.

    The fastest technique in incident response: something present on 200 hosts
    is normal, something present on one is worth a look. We stack findings by
    rule and evidence so rare combinations surface on their own.
    """
    latest = (
        db.query(Job.agent_id, func.max(Job.finished_at).label("mx"))
        .filter(Job.status == JobStatus.COMPLETED)
        .group_by(Job.agent_id)
        .subquery()
    )
    latest_ids = [
        row[0]
        for row in db.query(Job.id)
        .join(latest, (Job.agent_id == latest.c.agent_id) & (Job.finished_at == latest.c.mx))
        .all()
    ]
    if not latest_ids:
        return {"host_count": 0, "items": []}

    host_total = len(latest_ids)
    rows = db.query(Finding).filter(Finding.job_id.in_(latest_ids)).all()

    buckets: dict[tuple, set] = defaultdict(set)
    meta: dict[tuple, dict] = {}
    for f in rows:
        # Evidence usually embeds a path or IP; the first 90 chars are enough
        # to group "the same thing" without over-splitting on PIDs.
        key = (f.rule_id, (f.evidence or "")[:90])
        buckets[key].add(f.hostname)
        meta.setdefault(
            key,
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "title": f.title,
                "evidence": (f.evidence or "")[:200],
                "mitre": f.mitre,
                "mitre_name": technique_name(f.mitre) if f.mitre else "",
            },
        )

    items = []
    for key, hosts in buckets.items():
        info = dict(meta[key])
        info["host_count"] = len(hosts)
        info["percent"] = round(len(hosts) / host_total * 100, 1)
        info["hosts"] = sorted(hosts)[:12]
        info["rarity"] = (
            "unique" if len(hosts) == 1 else "rare" if len(hosts) <= 3 else "common"
        )
        items.append(info)

    items.sort(key=lambda i: (i["host_count"], SEV_ORDER.get(i["severity"], 9)))
    return {"host_count": host_total, "items": items[:600]}


@router.get("/matrix")
def attack_matrix(
    job_id: str | None = None,
    agent_id: str | None = None,
    db: Session = Depends(get_db),
    _u: str = Depends(require_console),
):
    """ATT&CK coverage for the latest scan of every host, or one hunt."""
    q = db.query(Finding)
    if job_id:
        q = q.filter(Finding.job_id == job_id)
    else:
        latest = (
            db.query(Job.agent_id, func.max(Job.finished_at).label("mx"))
            .filter(Job.status == JobStatus.COMPLETED)
            .group_by(Job.agent_id)
            .subquery()
        )
        ids = [
            r[0]
            for r in db.query(Job.id)
            .join(latest, (Job.agent_id == latest.c.agent_id) & (Job.finished_at == latest.c.mx))
            .all()
        ]
        if not ids:
            return build_matrix([])
        q = q.filter(Finding.job_id.in_(ids))
    if agent_id:
        q = q.filter(Finding.agent_id == agent_id)

    rows = [
        {"mitre": f.mitre, "severity": f.severity, "hostname": f.hostname}
        for f in q.all()
    ]
    return build_matrix(rows)


@router.get("/rules")
def builtin_rules(
    db: Session = Depends(get_db),
    _u: str = Depends(require_console),
):
    """Douglas's own detection rules, with how often each has actually fired.

    Sigma rules are visible and tunable; these were not, which made the
    built-in half of the detection surface the half nobody could inspect.
    """
    counts = Counter()
    sev_by_rule: dict[str, str] = {}
    title_by_rule: dict[str, str] = {}
    mitre_by_rule: dict[str, str] = {}
    hosts_by_rule: dict[str, set] = {}

    for f in db.query(Finding).all():
        rid = f.rule_id or ""
        if not rid or rid.startswith("SIGMA-"):
            continue
        counts[rid] += 1
        sev_by_rule.setdefault(rid, f.severity)
        title_by_rule.setdefault(rid, f.title)
        if f.mitre:
            mitre_by_rule.setdefault(rid, f.mitre)
        if f.hostname:
            hosts_by_rule.setdefault(rid, set()).add(f.hostname)

    suppressed = {
        s.rule_id for s in db.query(Suppression).filter(Suppression.active == True).all()  # noqa: E712
    }
    # Only rules somebody switched off have a row, so absence means enabled.
    disabled = {
        r.rule_id for r in db.query(RuleState).filter(RuleState.enabled == False).all()  # noqa: E712
    }

    def _entry(rid: str, guide: dict) -> dict:
        return {
            "rule_id": rid,
            # The catalogue title, so a rule that has never fired still says
            # what it detects. A live finding's title wins when there is one,
            # because it carries the specific pattern that matched.
            "title": title_by_rule.get(rid) or title_for(rid),
            "severity": sev_by_rule.get(rid, ""),
            "mitre": mitre_by_rule.get(rid, ""),
            "documented": bool(guide.get("looks_for")),
            "mitre_name": technique_name(mitre_by_rule[rid]) if rid in mitre_by_rule else "",
            "fired": counts.get(rid, 0),
            "hosts": len(hosts_by_rule.get(rid, ())),
            "suppressed": rid in suppressed,
            "enabled": rid not in disabled,
            "category": category_for(rid),
            "category_name": category_name(category_for(rid)),
            "looks_for": guide.get("looks_for", ""),
            "benign": guide.get("benign", ""),
            "next_step": guide.get("next_step", ""),
        }

    # Every rule the collector can emit, whether or not it has guidance —
    # a catalogue that only lists documented rules understates what runs.
    known = set(CATALOG) | set(TITLES) | set(counts)
    rules = [_entry(rid, CATALOG.get(rid, {})) for rid in sorted(known)]

    # Per-category rollups, so the console can show and act on a whole family
    # without counting rows itself.
    per_category: dict[str, dict] = {}
    for r in rules:
        bucket = per_category.setdefault(r["category"], {
            "total": 0, "enabled": 0, "fired": 0, "findings": 0,
        })
        bucket["total"] += 1
        bucket["enabled"] += 1 if r["enabled"] else 0
        bucket["fired"] += 1 if r["fired"] else 0
        bucket["findings"] += r["fired"]

    cats = []
    for cat in categories():
        stats = per_category.get(cat["id"])
        if not stats:
            continue
        cats.append({**cat, **stats})

    rules.sort(key=lambda r: (-r["fired"], r["rule_id"]))
    return {
        "total": len(rules),
        "documented": sum(1 for r in rules if r["looks_for"]),
        "fired": sum(1 for r in rules if r["fired"]),
        "suppressed": sum(1 for r in rules if r["suppressed"]),
        "disabled": sum(1 for r in rules if not r["enabled"]),
        "categories": cats,
        "rules": rules,
    }


class RuleToggleRequest(BaseModel):
    rule_ids: list[str] = Field(default_factory=list)
    category: str = ""
    enabled: bool = True
    note: str = ""


@router.post("/rules/toggle")
def toggle_builtin_rules(
    payload: RuleToggleRequest,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    """Switch built-in rules on or off, one at a time or a whole category.

    Turning a rule off stops it producing findings — it is not a suppression,
    which records the finding and marks it as a known decision. The distinction
    is kept visible in the console because the two leave very different trails
    behind them.
    """
    known = set(CATALOG) | set(TITLES)
    targets: set = set()

    if payload.category:
        valid = {c["id"] for c in categories()}
        if payload.category not in valid:
            raise HTTPException(status_code=400, detail="No such rule category.")
        targets |= {rid for rid in known if category_for(rid) == payload.category}

    for rid in payload.rule_ids:
        rid = (rid or "").strip().upper()
        if rid:
            targets.add(rid)

    if not targets:
        raise HTTPException(status_code=400, detail="Nothing selected.")

    unknown = sorted(t for t in targets if t not in known)
    targets &= known
    if not targets:
        raise HTTPException(
            status_code=400,
            detail=f"Not a built-in rule: {', '.join(unknown[:5])}.",
        )

    for rid in sorted(targets):
        row = db.get(RuleState, rid)
        if payload.enabled:
            # Back to the default: drop the row rather than storing "on", so
            # the table stays a list of deliberate exceptions.
            if row is not None:
                db.delete(row)
            continue
        if row is None:
            row = RuleState(rule_id=rid)
            db.add(row)
            try:
                # Flushed per row so a second request switching off the same
                # category at the same moment loses only that row, not the
                # whole batch. Both requests want the same end state, so a
                # clash here is agreement, not conflict.
                db.flush()
            except IntegrityError:
                db.rollback()
                row = db.get(RuleState, rid)
                if row is None:
                    continue
        row.enabled = False
        row.note = (payload.note or "").strip() or None
        row.updated_by = user.username
        row.updated_at = utcnow()

    label = payload.category or f"{len(targets)} rule(s)"
    db.add(AuditEvent(
        kind="rules.toggled", subject=label,
        detail=f"{'enabled' if payload.enabled else 'disabled'} by {user.username}"))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Another change to these rules landed at the same moment. "
                   "Reload and check the result.",
        ) from None

    disabled_now = db.query(RuleState).filter(RuleState.enabled == False).count()  # noqa: E712
    return {
        "changed": len(targets),
        "enabled": payload.enabled,
        "disabled_total": disabled_now,
        "skipped": unknown[:5],
    }


@router.get("/rules/categories")
def rule_categories(_u: str = Depends(require_console)):
    """The category list on its own, for anything that does not need counts."""
    return {"categories": categories()}


@router.get("/rules/bundle")
def disabled_rule_bundle(
    agent: Agent = Depends(require_agent),
    db: Session = Depends(get_db),
):
    """The rules this collector should not run, fetched at the start of a hunt.

    Sent as the disabled list rather than the enabled one deliberately. A
    collector that cannot reach this endpoint, or an older one that never asks,
    then falls back to running everything — which is the safe direction to fail
    in. The reverse would have a network hiccup silently switch off the whole
    detection set.
    """
    rows = db.query(RuleState).filter(RuleState.enabled == False).all()  # noqa: E712
    return {
        "version": 1,
        "count": len(rows),
        "disabled": sorted(r.rule_id for r in rows),
    }


@router.get("/graph")
def network_graph(
    job_id: str | None = None,
    db: Session = Depends(get_db),
    _u: str = Depends(require_console),
):
    """External endpoints and process load, assembled for the graph view.

    Merges the latest scan of every host unless one hunt is named, so a single
    picture shows where the whole estate is talking to.
    """
    q = db.query(Job).filter(Job.status == JobStatus.COMPLETED)
    if job_id:
        q = q.filter(Job.id == job_id)
    jobs = q.order_by(Job.finished_at.desc()).all()

    # One job per host: the newest. Older scans would double-count endpoints.
    seen: set = set()
    latest = []
    for j in jobs:
        if j.agent_id in seen:
            continue
        seen.add(j.agent_id)
        latest.append(j)

    endpoints: dict = {}
    processes: list = []
    hosts: list = []

    for job in latest:
        data = job.graph or {}
        hostname = job.hostname or job.agent_id
        hosts.append({
            "hostname": hostname,
            "risk_level": job.risk_level,
            "risk_score": job.risk_score or 0,
            "job_id": job.id,
        })

        for ep in (data.get("endpoints") or []):
            addr = ep.get("address")
            if not addr:
                continue
            node = endpoints.setdefault(addr, {
                "address": addr,
                "rdns": ep.get("rdns") or "",
                "connections": 0,
                "ports": set(),
                "processes": set(),
                "hosts": set(),
                "suspicious": False,
                "unsigned": False,
                "established": False,
            })
            node["connections"] += int(ep.get("connections") or 0)
            node["hosts"].add(hostname)
            for key, field in (("ports", "ports"), ("processes", "processes")):
                for part in str(ep.get(field) or "").split(","):
                    if part.strip():
                        node[key].add(part.strip())
            for flag in ("suspicious", "unsigned", "established"):
                if ep.get(flag):
                    node[flag] = True
            if not node["rdns"] and ep.get("rdns"):
                node["rdns"] = ep["rdns"]

        for pr in (data.get("processes") or []):
            pr = dict(pr)
            pr["hostname"] = hostname
            processes.append(pr)

    def _num(v):
        try:
            return float(v)
        except (TypeError, ValueError):
            return 0.0

    # Reputation and indicator context, both read from what is already stored.
    # Nothing is fetched here: a provider having a slow morning must never turn
    # into a graph that will not render.
    from ..models import IocFeed, IpReputation
    from ..services import enrichment as enrich

    reputation = {
        r.address: r
        for r in db.query(IpReputation)
        .filter(IpReputation.address.in_(list(endpoints)[:2000]))
        .all()
    } if endpoints else {}

    pooled: set = set()
    for f in (db.query(IocFeed)
              .filter(IocFeed.enabled == True, IocFeed.auto_include == True)  # noqa: E712
              .all()):
        if (f.mode or "indicators") == "watch":
            continue
        pooled.update(f.indicators or [])

    nodes = []
    for node in endpoints.values():
        rep = reputation.get(node["address"])
        ioc_match = node["address"] in pooled
        verdicts = (rep.verdicts if rep else {}) or {}

        # An indicator-list match is a confirmed identification and outranks any
        # score: a feed saying "this is a known C2" is not something a
        # reputation number gets to soften.
        if ioc_match:
            score, label = max(95, int(rep.score if rep else 0)), "malicious"
        elif rep:
            score, label = int(rep.score or 0), rep.label or "unknown"
        else:
            score, label = 0, "unrated"

        nodes.append({
            **node,
            "ports": sorted(node["ports"])[:8],
            "processes": sorted(node["processes"])[:6],
            "hosts": sorted(node["hosts"]),
            "host_count": len(node["hosts"]),
            "ioc_match": ioc_match,
            "score": score,
            "label": label,
            "known_good": bool(rep.is_known_good) if rep else False,
            "verdicts": {
                name: {"score": v.get("score", 0), "label": v.get("label", ""),
                       "summary": v.get("summary", "")}
                for name, v in verdicts.items()
            },
            "worst_provider": enrich.worst_provider(verdicts),
            "rated": rep is not None,
        })

    # Triage order. This is the whole point of enrichment: before it, the list
    # led with whichever address had the most connections, which is nearly
    # always a DNS server. Now a confirmed indicator match comes first, then
    # reputation score, and a known-good service sinks regardless of volume.
    nodes.sort(key=lambda n: (
        not n["ioc_match"],
        n["known_good"],
        -n["score"],
        not n["suspicious"],
        not n["unsigned"],
        -n["connections"],
    ))

    processes.sort(key=lambda p: -_num(p.get("memoryMB")))
    by_cpu = sorted(processes, key=lambda p: -_num(p.get("cpu")))

    return {
        "hosts": hosts,
        "endpoints": nodes[:60],
        "endpoint_total": len(nodes),
        "suspicious_endpoints": sum(1 for n in nodes if n["suspicious"]),
        "ioc_matches": sum(1 for n in nodes if n["ioc_match"]),
        "flagged": sum(1 for n in nodes if n["label"] in ("malicious", "suspicious")),
        "known_good": sum(1 for n in nodes if n["known_good"]),
        "unrated": sum(1 for n in nodes if not n["rated"]),
        "top_memory": processes[:15],
        "top_cpu": by_cpu[:15],
        "has_data": bool(nodes or processes),
    }


@router.get("/overview")
def overview(db: Session = Depends(get_db), _u: str = Depends(require_console)):
    """Everything the dashboard needs in one round trip."""
    latest = (
        db.query(Job.agent_id, func.max(Job.finished_at).label("mx"))
        .filter(Job.status == JobStatus.COMPLETED)
        .group_by(Job.agent_id)
        .subquery()
    )
    latest_jobs = (
        db.query(Job)
        .join(latest, (Job.agent_id == latest.c.agent_id) & (Job.finished_at == latest.c.mx))
        .all()
    )
    latest_ids = [j.id for j in latest_jobs]

    sev_counts = Counter()
    rule_counts = Counter()
    mitre_counts = Counter()
    rule_titles: dict[str, str] = {}
    rule_sev: dict[str, str] = {}

    if latest_ids:
        for f in db.query(Finding).filter(Finding.job_id.in_(latest_ids)).all():
            sev_counts[f.severity] += 1
            if f.rule_id:
                rule_counts[f.rule_id] += 1
                rule_titles.setdefault(f.rule_id, f.title or "")
                rule_sev.setdefault(f.rule_id, f.severity)
            if f.mitre:
                mitre_counts[f.mitre] += 1

    ranking = sorted(
        (
            {
                "agent_id": j.agent_id,
                "hostname": j.agent.hostname if j.agent else "?",
                "risk_score": j.risk_score or 0,
                "risk_level": j.risk_level or "CLEAN",
                "critical": j.critical_count or 0,
                "high": j.high_count or 0,
                "medium": j.medium_count or 0,
                "scanned_at": j.finished_at.isoformat() if j.finished_at else None,
                "job_id": j.id,
            }
            for j in latest_jobs
        ),
        key=lambda r: r["risk_score"],
        reverse=True,
    )

    return {
        "severity": {
            "CRITICAL": sev_counts.get("CRITICAL", 0),
            "HIGH": sev_counts.get("HIGH", 0),
            "MEDIUM": sev_counts.get("MEDIUM", 0),
            "LOW": sev_counts.get("LOW", 0),
            "INFO": sev_counts.get("INFO", 0),
        },
        "top_rules": [
            {
                "rule_id": r,
                "count": c,
                "title": rule_titles.get(r, ""),
                "severity": rule_sev.get(r, "INFO"),
            }
            for r, c in rule_counts.most_common(12)
        ],
        "top_mitre": [
            {"technique": m, "name": technique_name(m), "count": c}
            for m, c in mitre_counts.most_common(12)
        ],
        "ranking": ranking[:50],
        "hosts_scanned": len(latest_jobs),
    }


# NOTE: this must stay the last route in the file. FastAPI matches in
# registration order, so a parameterised path declared earlier would swallow
# /timeline, /stack, /matrix and /overview and reject them as invalid ints.
@router.get("/{finding_id}")
def get_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    _u: str = Depends(require_console),
):
    """One finding with its analyst guidance attached."""
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="No such finding.")

    # Same rule on other hosts is the fastest sanity check there is: seen
    # everywhere it is probably your build, seen once it is worth an hour.
    siblings = (
        db.query(Finding.hostname)
        .filter(Finding.rule_id == f.rule_id, Finding.id != f.id)
        .distinct()
        .limit(20)
        .all()
    )
    data = finding_dict(f, with_guidance=True)
    data["also_seen_on"] = sorted({row[0] for row in siblings if row[0]})
    data["technique"] = technique_detail(f.mitre) if f.mitre else {}
    return data
