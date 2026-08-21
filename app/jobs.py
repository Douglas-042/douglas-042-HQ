"""Hunt jobs: queue them from the console, drive them from the agent."""
from __future__ import annotations

import json
import uuid
from datetime import timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..auth import require_agent, require_console, require_responder
from ..config import settings
from ..database import get_db
from ..models import (
    SEVERITY_WEIGHT,
    Agent,
    FindingStatus,
    AgentStatus,
    AuditEvent,
    Finding,
    Job,
    JobStatus,
    TimelineEvent,
    new_id,
    utcnow,
)
from ..services.events import broadcast
from ..services import integrations as integration_svc
from ..services import triage
from ..models import IocFeed

router = APIRouter()


# --------------------------------------------------------------------------
# Serialisation
# --------------------------------------------------------------------------


def _iso(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def job_dict(j: Job) -> dict:
    return {
        "id": j.id,
        "agent_id": j.agent_id,
        "hostname": j.agent.hostname if j.agent else None,
        "batch_id": j.batch_id,
        "status": j.status.value if hasattr(j.status, "value") else str(j.status),
        "days": j.days,
        "quick": bool(j.quick),
        "collect_raw": bool(j.collect_raw),
        "progress": round(j.progress or 0, 1),
        "phase": j.phase or "",
        "phase_detail": j.phase_detail or "",
        # The live log so far. Opening the console mid-sweep should show what
        # has already run, not an empty panel that only fills from the next
        # event onward.
        "activity": (j.activity or [])[-60:],
        "modules_done": j.modules_done or 0,
        "modules_total": j.modules_total or 0,
        "created_at": _iso(j.created_at),
        "started_at": _iso(j.started_at),
        "finished_at": _iso(j.finished_at),
        "duration_seconds": j.duration_seconds,
        "error": j.error,
        "risk_score": j.risk_score or 0,
        "risk_level": j.risk_level,
        "critical_count": j.critical_count or 0,
        "high_count": j.high_count or 0,
        "medium_count": j.medium_count or 0,
        "low_count": j.low_count or 0,
        "info_count": j.info_count or 0,
        "suppressed_count": j.suppressed_count or 0,
        "has_bundle": bool(j.bundle_path),
        "bundle_size": j.bundle_size,
    }


# --------------------------------------------------------------------------
# Console: launch and inspect
# --------------------------------------------------------------------------


class LaunchRequest(BaseModel):
    agent_ids: list[str] = Field(default_factory=list)
    all_online: bool = False
    days: int = Field(default=14, ge=1, le=365)
    quick: bool = False
    collect_raw: bool = False
    no_resolve: bool = False
    max_events: int = Field(default=100000, ge=1000, le=2000000)
    ioc_list: str | None = None
    # Feeds are merged in by default: an operator who configured them expects
    # them used, and having to remember a checkbox every hunt is how indicator
    # lists quietly stop being applied.
    include_feeds: bool = True

    use_sigma: bool = True
    use_yara: bool = True
    use_custom: bool = True
    min_severity: str = "INFO"
    profile: str = "auto"


PROFILES = {"auto", "server", "workstation", "webserver", "dc"}
SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


@router.post("/launch")
def launch(payload: LaunchRequest, db: Session = Depends(get_db),
           user=Depends(require_responder)):
    """Queue a hunt on one host or across the fleet."""
    if payload.all_online:
        agents = [
            a
            for a in db.query(Agent).all()
            if not a.is_stale(settings.agent_timeout_seconds)
        ]
    else:
        agents = db.query(Agent).filter(Agent.id.in_(payload.agent_ids)).all()

    if not agents:
        raise HTTPException(
            status_code=400,
            detail="No reachable hosts selected. Check the fleet list and try again.",
        )

    batch_id = uuid.uuid4().hex
    created = []
    if payload.profile not in PROFILES:
        raise HTTPException(status_code=400,
                            detail=f"Profile must be one of: {', '.join(sorted(PROFILES))}.")
    if payload.min_severity.upper() not in SEVERITIES:
        raise HTTPException(status_code=400, detail="Unknown severity floor.")

    # Merge the pasted list with every enabled feed. Deduplicated, because a
    # hash appearing in three feeds should be one indicator, not three.
    pasted = [
        line.strip() for line in (payload.ioc_list or "").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    pooled: list[str] = []
    if payload.include_feeds:
        for feed in db.query(IocFeed).filter(
            IocFeed.enabled == True, IocFeed.auto_include == True  # noqa: E712
        ).all():
            pooled.extend(feed.indicators or [])
    merged = list(dict.fromkeys(pasted + pooled))
    combined_iocs = "\n".join(merged) if merged else None

    for agent in agents:
        busy = (
            db.query(Job)
            .filter(
                Job.agent_id == agent.id,
                Job.status.in_([JobStatus.QUEUED, JobStatus.DISPATCHED, JobStatus.RUNNING]),
            )
            .first()
        )
        if busy:
            continue
        job = Job(
            id=new_id(),
            agent_id=agent.id,
            batch_id=batch_id,
            days=payload.days,
            quick=payload.quick,
            collect_raw=payload.collect_raw,
            no_resolve=payload.no_resolve,
            max_events=payload.max_events,
            ioc_list=combined_iocs,
            use_sigma=payload.use_sigma,
            use_yara=payload.use_yara,
            use_custom=payload.use_custom,
            min_severity=payload.min_severity.upper(),
            profile=payload.profile,
            status=JobStatus.QUEUED,
            phase="Queued",
            # Name the wait. Agents poll rather than listen, so a queued hunt
            # sits idle until the next check-in — which looks like a stuck job
            # if the console does not say how long that is.
            phase_detail=(
                f"Waiting for the host to check in — up to "
                f"{settings.heartbeat_seconds}s"
            ),
        )
        db.add(job)
        created.append(job)

    db.add(
        AuditEvent(
            kind="hunt.launched",
            subject=f"{len(created)} host",
            detail=f"days={payload.days} quick={payload.quick} "
                   f"raw={payload.collect_raw} by {user.username}",
        )
    )
    db.commit()
    for j in created:
        db.refresh(j)

    broadcast({"type": "jobs.queued", "batch_id": batch_id, "count": len(created)})
    return {"batch_id": batch_id, "queued": len(created), "jobs": [job_dict(j) for j in created]}


@router.get("")
def list_jobs(
    status: str | None = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    _u: str = Depends(require_console),
):
    q = db.query(Job)
    if status:
        q = q.filter(Job.status == JobStatus(status))
    jobs = q.order_by(Job.created_at.desc()).limit(min(limit, 500)).all()
    return {"jobs": [job_dict(j) for j in jobs]}


@router.get("/active")
def active_jobs(db: Session = Depends(get_db), _u: str = Depends(require_console)):
    jobs = (
        db.query(Job)
        .filter(
            Job.status.in_(
                [JobStatus.QUEUED, JobStatus.DISPATCHED, JobStatus.RUNNING, JobStatus.UPLOADING]
            )
        )
        .order_by(Job.created_at.desc())
        .all()
    )
    return {"jobs": [job_dict(j) for j in jobs]}


@router.get("/{job_id}")
def get_job(job_id: str, db: Session = Depends(get_db), _u: str = Depends(require_console)):
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="No such hunt.")
    return {
        "job": job_dict(job),
        "manifest": job.manifest,
        "module_stats": job.module_stats,
        "collection_errors": job.collection_errors,
    }


@router.post("/{job_id}/cancel")
def cancel_job(job_id: str, db: Session = Depends(get_db),
               user=Depends(require_responder)):
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="No such hunt.")
    if job.status in (JobStatus.COMPLETED, JobStatus.FAILED):
        raise HTTPException(status_code=400, detail="This hunt already finished.")
    job.status = JobStatus.CANCELLED
    job.finished_at = utcnow()
    db.add(AuditEvent(kind="hunt.cancelled", subject=job.hostname,
                      detail=f"by {user.username}"))
    db.commit()
    broadcast({"type": "job.updated", "job": job_dict(job)})
    return {"cancelled": job_id}


# --------------------------------------------------------------------------
# Agent: progress and results
# --------------------------------------------------------------------------


class ModuleEvent(BaseModel):
    module: str
    status: str = "OK"
    ms: int = 0
    findings: int = 0
    rows: int = 0
    errors: int = 0
    ts: str = ""


class ProgressRequest(BaseModel):
    # Clamped rather than rejected. A miscounted percentage is cosmetic, but
    # refusing the post makes a running hunt look dead in the console — the
    # wrong failure for the smaller problem.
    # Nullable as well as clamped: an agent reading a progress line that has no
    # percentage sends null rather than omitting the field, and that should not
    # be the difference between a hunt that reports and one that goes quiet.
    progress: float | None = 0.0
    phase: str | None = ""
    detail: str | None = ""
    modules_done: int | None = 0
    modules_total: int | None = 0
    # Module-level events since the last report. Sent as a list because an
    # agent polls its progress file on an interval and several modules may
    # have finished in between.
    events: list[ModuleEvent] = Field(default_factory=list)


# Enough to show the sweep so far without letting a long hunt grow the row
# without limit.
MAX_ACTIVITY = 200


@router.post("/{job_id}/progress")
def report_progress(
    job_id: str,
    payload: ProgressRequest,
    agent: Agent = Depends(require_agent),
    db: Session = Depends(get_db),
):
    job = db.get(Job, job_id)
    if not job or job.agent_id != agent.id:
        raise HTTPException(status_code=404, detail="No such hunt for this host.")
    if job.status == JobStatus.CANCELLED:
        return {"cancelled": True}

    percent = max(0.0, min(100.0, float(payload.progress or 0)))

    if job.status in (JobStatus.QUEUED, JobStatus.DISPATCHED):
        job.status = JobStatus.RUNNING
        job.started_at = utcnow()

    job.progress = percent
    # Normalised on the way in, so a null never reaches a column or the
    # websocket payload the console renders.
    job.phase = payload.phase or ""
    job.phase_detail = payload.detail or ""
    job.modules_done = payload.modules_done or 0
    job.modules_total = payload.modules_total or 0

    if payload.events:
        log = list(job.activity or [])
        for event in payload.events:
            log.append({
                "module": event.module[:120],
                "status": event.status[:16],
                "ms": event.ms,
                "findings": event.findings,
                "rows": event.rows,
                "errors": event.errors,
                "ts": event.ts or utcnow().isoformat(),
            })
        job.activity = log[-MAX_ACTIVITY:]

    agent.status = AgentStatus.SCANNING
    agent.last_seen = utcnow()
    db.commit()

    broadcast(
        {
            "type": "job.progress",
            "job_id": job.id,
            "agent_id": agent.id,
            "hostname": agent.hostname,
            "progress": percent,
            "phase": job.phase,
            "detail": job.phase_detail,
            "modules_done": job.modules_done,
            "modules_total": job.modules_total,
            # Only what just happened, not the whole log: the console appends,
            # and resending 200 rows on every tick would be most of the traffic.
            "events": [e.model_dump() for e in payload.events],
        }
    )
    return {"ok": True}


def _load_json(raw: str | None, default):
    if not raw:
        return default
    try:
        parsed = json.loads(raw)
        return parsed if parsed is not None else default
    except json.JSONDecodeError:
        return default


@router.post("/{job_id}/results")
async def upload_results(
    job_id: str,
    findings: str = Form("[]"),
    timeline: str = Form("[]"),
    manifest: str = Form("{}"),
    graph: str = Form("{}"),
    module_stats: str = Form("[]"),
    errors: str = Form("[]"),
    duration_seconds: float = Form(0.0),
    bundle: UploadFile | None = File(None),
    agent: Agent = Depends(require_agent),
    db: Session = Depends(get_db),
):
    """Ingest one completed hunt. Findings drive everything downstream."""
    job = db.get(Job, job_id)
    if not job or job.agent_id != agent.id:
        raise HTTPException(status_code=404, detail="No such hunt for this host.")

    finding_rows = _load_json(findings, [])
    timeline_rows = _load_json(timeline, [])
    manifest_obj = _load_json(manifest, {})
    stats_rows = _load_json(module_stats, [])
    error_rows = _load_json(errors, [])

    if isinstance(finding_rows, dict):
        finding_rows = [finding_rows]
    if isinstance(timeline_rows, dict):
        timeline_rows = [timeline_rows]

    # Replace any prior data for this job so re-uploads stay idempotent.
    db.query(Finding).filter(Finding.job_id == job.id).delete()
    db.query(TimelineEvent).filter(TimelineEvent.job_id == job.id).delete()

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for row in finding_rows:
        if not isinstance(row, dict):
            continue
        sev = str(row.get("Severity") or row.get("severity") or "INFO").upper()
        if sev not in counts:
            sev = "INFO"
        counts[sev] += 1
        db.add(
            Finding(
                job_id=job.id,
                agent_id=agent.id,
                hostname=agent.hostname,
                rule_id=str(row.get("RuleId") or row.get("rule_id") or "")[:32],
                severity=sev,
                title=str(row.get("Title") or row.get("title") or "")[:512],
                evidence=str(row.get("Evidence") or row.get("evidence") or ""),
                mitre=str(row.get("Mitre") or row.get("mitre") or "")[:32],
                why=str(row.get("Why") or row.get("why") or ""),
                artifact=str(row.get("Artifact") or row.get("artifact") or "")[:128],
                occurred_at=str(row.get("TimeUtc") or row.get("time_utc") or "")[:64],
            )
        )

    for row in timeline_rows[:20000]:
        if not isinstance(row, dict):
            continue
        db.add(
            TimelineEvent(
                job_id=job.id,
                hostname=agent.hostname,
                time_utc=str(row.get("TimeUtc") or row.get("time_utc") or "")[:64],
                source=str(row.get("Source") or row.get("source") or "")[:64],
                severity=str(row.get("Severity") or row.get("severity") or "INFO").upper()[:16],
                description=str(row.get("Description") or row.get("description") or ""),
                detail=str(row.get("Detail") or row.get("detail") or ""),
            )
        )

    # Apply standing suppressions before scoring, so tuning carries forward to
    # every future scan instead of having to be redone by hand each time.
    db.flush()
    fresh = db.query(Finding).filter(Finding.job_id == job.id).all()
    suppressed = triage.apply_to_findings(db, fresh)
    if suppressed:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in fresh:
            if f.status == FindingStatus.SUPPRESSED:
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

    # A retry that omits the bundle keeps whatever evidence was already stored.
    # Deleting it on a partial re-upload would destroy the only copy.
    if bundle is not None and bundle.filename:
        settings.bundle_dir.mkdir(parents=True, exist_ok=True)
        target = settings.bundle_dir / f"{job.id}.zip"
        size = 0
        with target.open("wb") as fh:
            while chunk := await bundle.read(1024 * 1024):
                size += len(chunk)
                if size > settings.max_upload_mb * 1024 * 1024:
                    fh.close()
                    target.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=413,
                        detail=f"Bundle exceeds the {settings.max_upload_mb} MB limit.",
                    )
                fh.write(chunk)
        job.bundle_path = str(target)
        job.bundle_size = size

    job.status = JobStatus.COMPLETED
    job.progress = 100.0
    job.phase = "Complete"
    job.phase_detail = f"{sum(counts.values())} findings"
    job.finished_at = utcnow()
    job.duration_seconds = duration_seconds or None
    job.manifest = manifest_obj
    job.graph = _load_json(graph, {})
    job.module_stats = stats_rows
    job.collection_errors = error_rows
    job.risk_score = score
    job.risk_level = level
    job.critical_count = counts["CRITICAL"]
    job.high_count = counts["HIGH"]
    job.medium_count = counts["MEDIUM"]
    job.low_count = counts["LOW"]
    job.info_count = counts["INFO"]
    job.suppressed_count = suppressed

    agent.status = AgentStatus.ONLINE
    agent.last_seen = utcnow()
    agent.last_scan_at = job.finished_at
    agent.risk_score = score
    agent.risk_level = level
    agent.critical_count = counts["CRITICAL"]
    agent.high_count = counts["HIGH"]
    agent.medium_count = counts["MEDIUM"]
    agent.low_count = counts["LOW"]

    host_meta = (manifest_obj or {}).get("Host") or {}
    if isinstance(host_meta, dict):
        agent.domain_role = host_meta.get("DomainRole") or agent.domain_role
        agent.os_caption = host_meta.get("OS") or agent.os_caption
        agent.os_build = str(host_meta.get("OSBuild") or agent.os_build or "")
        agent.domain = host_meta.get("Domain") or agent.domain

    db.add(
        AuditEvent(
            kind="hunt.completed",
            subject=agent.hostname,
            detail=f"score={score} crit={counts['CRITICAL']} high={counts['HIGH']}",
        )
    )
    db.commit()
    db.refresh(job)

    # Forward to any SIEM the operator wired up. Best effort and off-thread:
    # a slow Wazuh must never fail a results upload that already succeeded.
    try:
        integration_svc.forward_findings(db, job, agent, fresh)
    except Exception:  # noqa: BLE001 - the hunt result is what matters
        pass

    broadcast({"type": "job.completed", "job": job_dict(job)})
    return {
        "ok": True,
        "risk_score": score,
        "risk_level": level,
        # Total recorded, not total scored. Reporting the post-suppression
        # number here made a hunt look like it found almost nothing.
        "findings": len(fresh),
        "scored": sum(counts.values()),
        "suppressed": suppressed,
    }


class FailRequest(BaseModel):
    error: str = ""


@router.post("/{job_id}/fail")
def report_failure(
    job_id: str,
    payload: FailRequest,
    agent: Agent = Depends(require_agent),
    db: Session = Depends(get_db),
):
    job = db.get(Job, job_id)
    if not job or job.agent_id != agent.id:
        raise HTTPException(status_code=404, detail="No such hunt for this host.")
    job.status = JobStatus.FAILED
    job.error = payload.error[:4000]
    job.finished_at = utcnow()
    job.phase = "Failed"
    agent.status = AgentStatus.ERROR
    agent.last_seen = utcnow()
    db.commit()
    broadcast({"type": "job.failed", "job": job_dict(job)})
    return {"ok": True}
