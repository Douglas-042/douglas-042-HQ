"""Comparing two scans of the same host.

The question this answers is the one asked after every cleanup: did the
persistence actually go, and did anything new arrive. A list of findings from a
single scan cannot answer it.

The hard part is deciding when two findings are "the same finding". Matching on
evidence verbatim would mark every event-derived finding as new on every scan,
because its evidence carries a timestamp. So evidence is normalised first:
timestamps, process ids and other run-specific values are removed, leaving the
part that identifies the thing rather than the sighting.
"""
from __future__ import annotations

import re

from sqlalchemy.orm import Session

from ..models import Finding, Job, JobStatus

# Values that differ between two sightings of the same underlying problem.
_NOISE = [
    # ISO timestamps: 2026-08-16T04:20:11Z, with or without the T and Z
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?Z?"), "<time>"),
    (re.compile(r"\d{4}-\d{2}-\d{2}"), "<date>"),
    # Process and thread ids
    (re.compile(r"\b(PID|pid|TID)\s*:?\s*\d+", re.I), "<pid>"),
    (re.compile(r"\(PID \d+\)", re.I), "(<pid>)"),
    # Counters that move between runs
    # A count followed by up to two describing words: "47 failed attempts",
    # "112 events", "9 pre-auth failures".
    (re.compile(r"\b\d+\s+((?:\w+[- ]){0,2}?"
                r"(?:times|attempts|events|records|rows|failures|tickets|"
                r"connections|entries|files|hosts|members|matches))\b", re.I),
     "<count> \\1"),
    (re.compile(r"\[\s*[\d.]+\s*(KB|MB|GB)\s*\]", re.I), "[<size>]"),
    (re.compile(r"\b\d+(\.\d+)?\s*(KB|MB|GB|days?|hours?)\b", re.I), "<n> \\2"),
    # Session and logon identifiers
    (re.compile(r"\b0x[0-9a-fA-F]{4,}\b"), "<hex>"),
]


def normalise_evidence(text: str) -> str:
    """Strip the parts of a finding's evidence that change between scans."""
    value = (text or "").strip()
    for pattern, replacement in _NOISE:
        value = pattern.sub(replacement, value)
    return re.sub(r"\s+", " ", value).lower()


def finding_key(f: Finding) -> tuple[str, str]:
    return (f.rule_id or "", normalise_evidence(f.evidence or ""))


def _brief(f: Finding) -> dict:
    return {
        "id": f.id,
        "rule_id": f.rule_id,
        "severity": f.severity,
        "title": f.title,
        "evidence": f.evidence,
        "mitre": f.mitre,
        "status": f.status.value if hasattr(f.status, "value") else str(f.status or "open"),
        "occurred_at": f.occurred_at.isoformat() if f.occurred_at else None,
    }


SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def compare(db: Session, before: Job, after: Job) -> dict:
    """What changed between two completed scans."""
    old = db.query(Finding).filter(Finding.job_id == before.id).all()
    new = db.query(Finding).filter(Finding.job_id == after.id).all()

    old_map: dict[tuple[str, str], Finding] = {}
    for f in old:
        old_map.setdefault(finding_key(f), f)
    new_map: dict[tuple[str, str], Finding] = {}
    for f in new:
        new_map.setdefault(finding_key(f), f)

    appeared = [_brief(f) for k, f in new_map.items() if k not in old_map]
    resolved = [_brief(f) for k, f in old_map.items() if k not in new_map]
    persisting = [_brief(f) for k, f in new_map.items() if k in old_map]

    for group in (appeared, resolved, persisting):
        group.sort(key=lambda x: (-SEV_RANK.get(x["severity"], 0), x["rule_id"] or ""))

    def counts(rows):
        out = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for r in rows:
            sev = (r["severity"] or "INFO").upper()
            if sev in out:
                out[sev] += 1
        return out

    # A verdict, so the number does not have to be interpreted every time.
    new_serious = sum(1 for r in appeared if SEV_RANK.get(r["severity"], 0) >= 3)
    gone_serious = sum(1 for r in resolved if SEV_RANK.get(r["severity"], 0) >= 3)

    if new_serious:
        # Something new and serious leads, whatever else was cleaned up: it is
        # the thing that needs attention now. But say what was resolved too,
        # otherwise a successful cleanup reads as pure bad news.
        verdict = "worse"
        headline = (f"{new_serious} new high or critical finding"
                    f"{'' if new_serious == 1 else 's'} since the last scan.")
        if gone_serious:
            headline += (f" {gone_serious} earlier one"
                         f"{'' if gone_serious == 1 else 's'} no longer present.")
    elif gone_serious and not appeared:
        verdict = "better"
        headline = (f"{gone_serious} high or critical finding"
                    f"{'' if gone_serious == 1 else 's'} no longer present.")
    elif not appeared and not resolved:
        verdict = "unchanged"
        headline = "Nothing changed between these two scans."
    else:
        verdict = "mixed"
        headline = (f"{len(appeared)} appeared, {len(resolved)} resolved, "
                    f"{len(persisting)} unchanged.")

    return {
        "before": {
            "job_id": before.id,
            "finished_at": before.finished_at.isoformat() if before.finished_at else None,
            "risk_score": before.risk_score or 0,
            "risk_level": before.risk_level,
            "findings": len(old),
        },
        "after": {
            "job_id": after.id,
            "finished_at": after.finished_at.isoformat() if after.finished_at else None,
            "risk_score": after.risk_score or 0,
            "risk_level": after.risk_level,
            "findings": len(new),
        },
        "hostname": after.hostname or before.hostname,
        "verdict": verdict,
        "headline": headline,
        "score_delta": (after.risk_score or 0) - (before.risk_score or 0),
        "appeared": appeared[:300],
        "resolved": resolved[:300],
        "persisting": persisting[:300],
        "appeared_count": len(appeared),
        "resolved_count": len(resolved),
        "persisting_count": len(persisting),
        "appeared_by_severity": counts(appeared),
        "resolved_by_severity": counts(resolved),
    }


def latest_pair(db: Session, agent_id: str) -> tuple[Job | None, Job | None]:
    """The two most recent completed scans of a host, oldest first."""
    jobs = (
        db.query(Job)
        .filter(Job.agent_id == agent_id, Job.status == JobStatus.COMPLETED)
        .order_by(Job.finished_at.desc())
        .limit(2)
        .all()
    )
    if len(jobs) < 2:
        return (None, jobs[0] if jobs else None)
    return (jobs[1], jobs[0])
