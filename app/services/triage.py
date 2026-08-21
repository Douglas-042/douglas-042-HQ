"""Applying suppressions to findings.

Two moments matter: when results arrive from a host, and when someone writes a
new suppression. Both funnel through here so the rules mean the same thing in
each case — a suppression that only worked on future scans would leave the
existing backlog untouched, which is exactly the backlog people want gone.

Suppressed findings are excluded from the risk score. Otherwise a host stays
red after its findings have been triaged, and the score stops meaning anything.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from ..models import (
    SEVERITY_WEIGHT,
    Agent,
    Finding,
    FindingStatus,
    Job,
    Suppression,
    utcnow,
)


def active_suppressions(db: Session) -> list[Suppression]:
    return db.query(Suppression).filter(Suppression.active == True).all()  # noqa: E712


def apply_to_findings(
    db: Session,
    findings: list[Finding],
    rules: list[Suppression] | None = None,
) -> int:
    """Mark any finding covered by a suppression. Returns how many changed.

    Only OPEN findings are touched. A finding somebody already ruled on keeps
    that decision; a suppression is a default, not an override of human
    judgement.
    """
    if rules is None:
        rules = active_suppressions(db)
    if not rules:
        return 0

    changed = 0
    now = utcnow()
    for f in findings:
        if f.status != FindingStatus.OPEN:
            continue
        for rule in rules:
            if rule.matches(f.rule_id or "", f.evidence or "", f.hostname or ""):
                f.status = FindingStatus.SUPPRESSED
                f.suppressed_by = rule.id
                f.status_changed_at = now
                f.status_changed_by = "suppression"
                rule.match_count = (rule.match_count or 0) + 1
                rule.last_matched_at = now
                changed += 1
                break
    return changed


def unsuppress_for_rule(db: Session, suppression: Suppression) -> int:
    """Reopen findings this suppression had hidden.

    Used when a suppression is deleted or switched off. Anything it hid goes
    back to OPEN rather than staying invisible with no rule explaining why.
    """
    rows = (
        db.query(Finding)
        .filter(
            Finding.suppressed_by == suppression.id,
            Finding.status == FindingStatus.SUPPRESSED,
        )
        .all()
    )
    now = utcnow()
    for f in rows:
        f.status = FindingStatus.OPEN
        f.suppressed_by = None
        f.status_changed_at = now
        f.status_changed_by = "suppression removed"
    suppression.match_count = 0
    return len(rows)


def preview(db: Session, rule_id: str, evidence_contains: str, hostname: str) -> dict:
    """What a proposed suppression would hide, before it is created.

    Writing a suppression blind is how a real detection gets buried. The count
    and a sample let someone see the blast radius first.
    """
    q = db.query(Finding).filter(Finding.rule_id == rule_id)
    if hostname:
        q = q.filter(Finding.hostname == hostname)
    rows = q.all()

    needle = (evidence_contains or "").lower()
    matched = [
        f for f in rows
        if not needle or needle in (f.evidence or "").lower()
    ]
    hosts = sorted({f.hostname for f in matched if f.hostname})
    open_now = sum(1 for f in matched if f.status == FindingStatus.OPEN)

    return {
        "total": len(matched),
        "open": open_now,
        "hosts": hosts[:20],
        "host_count": len(hosts),
        "samples": [
            {
                "hostname": f.hostname,
                "severity": f.severity,
                "title": f.title,
                "evidence": (f.evidence or "")[:220],
            }
            for f in matched[:5]
        ],
        # Hiding the same rule everywhere is occasionally right and usually
        # not. Say so rather than letting the number speak for itself.
        "warning": (
            "This would hide the rule across the whole fleet. Narrow it by host "
            "or evidence unless you are certain it is noise everywhere."
            if not hostname and not evidence_contains and len(hosts) > 3
            else ""
        ),
    }


def recalculate_job_score(db: Session, job: Job) -> None:
    """Recompute a hunt's risk score from findings that still count.

    Suppressed and false-positive findings are excluded. A score that ignores
    triage keeps a cleaned-up host looking compromised.
    """
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    ignored = {FindingStatus.SUPPRESSED, FindingStatus.FALSE_POSITIVE}

    for f in db.query(Finding).filter(Finding.job_id == job.id).all():
        if f.status in ignored:
            continue
        sev = (f.severity or "INFO").upper()
        if sev in counts:
            counts[sev] += 1

    score = sum(counts[s] * w for s, w in SEVERITY_WEIGHT.items())
    if score >= 50:
        level = "CRITICAL"
    elif score >= 25:
        level = "HIGH"
    elif score >= 10:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "CLEAN"

    job.risk_score = score
    job.risk_level = level
    job.critical_count = counts["CRITICAL"]
    job.high_count = counts["HIGH"]
    job.medium_count = counts["MEDIUM"]
    job.low_count = counts["LOW"]
    job.info_count = counts["INFO"]

    # Keep the host summary in step, but only if this is its latest hunt.
    agent = db.get(Agent, job.agent_id)
    if agent:
        latest = (
            db.query(Job)
            .filter(Job.agent_id == job.agent_id, Job.status == job.status)
            .order_by(Job.finished_at.desc())
            .first()
        )
        if latest is None or latest.id == job.id:
            agent.risk_score = score
            agent.risk_level = level
            agent.critical_count = counts["CRITICAL"]
            agent.high_count = counts["HIGH"]
            agent.medium_count = counts["MEDIUM"]
            agent.low_count = counts["LOW"]


def recalculate_for_findings(db: Session, findings: list[Finding]) -> None:
    """Rescore every hunt touched by a set of findings."""
    job_ids = {f.job_id for f in findings if f.job_id}
    for job_id in job_ids:
        job = db.get(Job, job_id)
        if job:
            recalculate_job_score(db, job)
