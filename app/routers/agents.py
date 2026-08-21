"""Agent-facing protocol plus the console's fleet views.

The agent lifecycle is deliberately small:
    enroll once  ->  heartbeat forever  ->  claim a job  ->  report  ->  upload
"""
from __future__ import annotations

from datetime import timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..auth import require_admin, require_agent, require_console
from ..config import settings
from ..database import get_db
from ..models import (
    Agent,
    AgentStatus,
    AuditEvent,
    EnrollmentToken,
    Job,
    JobStatus,
    utcnow,
)
from ..services.events import broadcast

router = APIRouter()


# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------


class EnrollRequest(BaseModel):
    token: str
    hostname: str
    platform: str = "windows"
    ip_address: str | None = None
    domain: str | None = None
    domain_role: str | None = None
    os_caption: str | None = None
    os_build: str | None = None
    architecture: str | None = None
    ps_version: str | None = None
    agent_version: str | None = None


class EnrollResponse(BaseModel):
    agent_id: str
    agent_key: str
    heartbeat_seconds: int


class HeartbeatRequest(BaseModel):
    status: str = "online"
    ip_address: str | None = None
    # What the host can actually run: auditd, a YARA binary, python3 and so on.
    # Sent on enrolment and refreshed on the heartbeat, because these change —
    # somebody installs auditd, or a hardening job removes it — and a stale
    # answer is worse than none.
    capabilities: dict | None = None


class JobInstruction(BaseModel):
    job_id: str
    days: int
    quick: bool
    collect_raw: bool
    no_resolve: bool
    max_events: int
    ioc_list: str | None = None
    use_sigma: bool = True
    use_yara: bool = True
    use_custom: bool = True
    min_severity: str = "INFO"
    profile: str = "auto"


class HeartbeatResponse(BaseModel):
    ok: bool = True
    heartbeat_seconds: int
    job: JobInstruction | None = None


# --------------------------------------------------------------------------
# Agent protocol
# --------------------------------------------------------------------------


@router.post("/enroll", response_model=EnrollResponse)
def enroll(payload: EnrollRequest, request: Request, db: Session = Depends(get_db)):
    """Join the fleet. Re-enrolling an existing hostname refreshes its key."""
    token = db.get(EnrollmentToken, payload.token)
    if not token or token.revoked:
        raise HTTPException(status_code=401, detail="Enrollment token rejected.")

    ip = payload.ip_address or (request.client.host if request.client else None)

    agent = db.query(Agent).filter(Agent.hostname == payload.hostname).first()
    if agent is None:
        agent = Agent(hostname=payload.hostname)
        db.add(agent)

    agent.platform = "linux" if payload.platform.lower().startswith("lin") else "windows"
    agent.ip_address = ip
    agent.domain = payload.domain
    agent.domain_role = payload.domain_role
    agent.os_caption = payload.os_caption
    agent.os_build = payload.os_build
    agent.architecture = payload.architecture
    agent.ps_version = payload.ps_version
    agent.agent_version = payload.agent_version
    agent.status = AgentStatus.ONLINE
    agent.last_seen = utcnow()

    token.uses = (token.uses or 0) + 1
    db.add(AuditEvent(kind="enroll", subject=agent.hostname, detail=f"from {ip}"))
    db.commit()
    db.refresh(agent)

    broadcast({"type": "agent.enrolled", "agent": _agent_dict(agent)})

    return EnrollResponse(
        agent_id=agent.id,
        agent_key=agent.agent_key,
        heartbeat_seconds=settings.heartbeat_seconds,
    )


@router.post("/heartbeat", response_model=HeartbeatResponse)
def heartbeat(
    payload: HeartbeatRequest,
    agent: Agent = Depends(require_agent),
    db: Session = Depends(get_db),
):
    """Keep-alive that doubles as the job pull. One round trip, not two."""
    agent.last_seen = utcnow()
    if payload.ip_address:
        agent.ip_address = payload.ip_address
    if payload.capabilities:
        # Kept as reported rather than merged, so removing auditd from a host
        # shows up as removed instead of lingering from an earlier heartbeat.
        agent.capabilities = {
            str(k)[:32]: v for k, v in list(payload.capabilities.items())[:40]
        }
        agent.capabilities_at = utcnow()

    running = (
        db.query(Job)
        .filter(Job.agent_id == agent.id, Job.status.in_([JobStatus.RUNNING, JobStatus.UPLOADING]))
        .first()
    )
    if running:
        agent.status = AgentStatus.SCANNING
        db.commit()
        return HeartbeatResponse(heartbeat_seconds=settings.heartbeat_seconds, job=None)

    agent.status = AgentStatus.ONLINE

    queued = (
        db.query(Job)
        .filter(Job.agent_id == agent.id, Job.status == JobStatus.QUEUED)
        .order_by(Job.created_at)
        .first()
    )
    if queued is None:
        db.commit()
        return HeartbeatResponse(heartbeat_seconds=settings.heartbeat_seconds, job=None)

    queued.status = JobStatus.DISPATCHED
    queued.dispatched_at = utcnow()
    db.commit()

    broadcast({"type": "job.dispatched", "job_id": queued.id, "agent_id": agent.id})

    return HeartbeatResponse(
        heartbeat_seconds=settings.heartbeat_seconds,
        job=JobInstruction(
            job_id=queued.id,
            days=queued.days,
            quick=bool(queued.quick),
            collect_raw=bool(queued.collect_raw),
            no_resolve=bool(queued.no_resolve),
            max_events=queued.max_events,
            ioc_list=queued.ioc_list,
            use_sigma=bool(queued.use_sigma),
            use_yara=bool(queued.use_yara),
            use_custom=bool(queued.use_custom),
            min_severity=queued.min_severity or "INFO",
            profile=queued.profile or "auto",
        ),
    )


# --------------------------------------------------------------------------
# Console views
# --------------------------------------------------------------------------


def _agent_dict(a: Agent) -> dict:
    last_seen = a.last_seen
    if last_seen and last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    stale = a.is_stale(settings.agent_timeout_seconds)
    status = a.status.value if hasattr(a.status, "value") else str(a.status)
    if stale and status != "scanning":
        status = "offline"
    return {
        "platform": a.platform or "windows",
        "id": a.id,
        "hostname": a.hostname,
        "ip_address": a.ip_address,
        "domain": a.domain,
        "domain_role": a.domain_role,
        "os_caption": a.os_caption,
        "os_build": a.os_build,
        "architecture": a.architecture,
        "ps_version": a.ps_version,
        "agent_version": a.agent_version,
        "status": status,
        "last_seen": last_seen.isoformat() if last_seen else None,
        "last_scan_at": a.last_scan_at.isoformat() if a.last_scan_at else None,
        "risk_score": a.risk_score or 0,
        "risk_level": a.risk_level or "UNKNOWN",
        "critical_count": a.critical_count or 0,
        "high_count": a.high_count or 0,
        "medium_count": a.medium_count or 0,
        "low_count": a.low_count or 0,
        "capabilities": a.capabilities or {},
        "capability_gaps": _capability_gaps(a),
        "capabilities_at": (a.capabilities_at.isoformat()
                            if a.capabilities_at else None),
    }


# What a missing capability costs, written in terms of what stops being
# detected rather than what is not installed. "auditd absent" means nothing to
# most people; "no record of what ran on this host" means something to
# everyone.
_GAP_MEANING = {
    "auditd": {
        "label": "auditd is not running",
        "costs": "Nothing records what executed on this host, so execution "
                 "rules cannot fire and a clean sweep only means the sweep "
                 "could not look.",
        "fix": "Install and start it: apt install auditd  (or dnf install audit), "
               "then systemctl enable --now auditd",
    },
    "auditd_rules": {
        "label": "auditd is running with no rules loaded",
        "costs": "It is collecting almost nothing. Execution and file-change "
                 "detections stay silent even though the service looks healthy.",
        "fix": "Load a ruleset — the Sigma-oriented starter is a good default — "
               "then: auditctl -R /etc/audit/rules.d/audit.rules",
    },
    "audit_log": {
        "label": "the audit log cannot be read",
        "costs": "auditd is running but its log is unreadable to the agent, so "
                 "nothing can be evaluated against it.",
        "fix": "Check /var/log/audit/audit.log exists and that the agent runs "
               "as root.",
    },
    "python3": {
        "label": "python3 is missing",
        "costs": "Live progress and file-content (YARA) rules both need it. The "
                 "sweep still runs and every other rule still fires; it just "
                 "reports less while it does and skips file-content matching.",
        "fix": "apt install python3  (or dnf install python3)",
    },
}


def _capability_gaps(a: Agent) -> list[dict]:
    """Capabilities this host is missing, and what each one costs.

    Only meaningful for Linux at the moment: the Windows collector carries its
    own evaluators and depends on nothing that has to be installed separately.
    """
    if (a.platform or "windows") != "linux":
        return []
    caps = a.capabilities or {}
    if not caps:
        return []

    gaps = []
    for key, meaning in _GAP_MEANING.items():
        if caps.get(key):
            continue
        # A rules gap only makes sense to report when the service is there.
        if key == "auditd_rules" and not caps.get("auditd"):
            continue
        if key == "audit_log" and not caps.get("auditd"):
            continue
        gaps.append({"id": key, **meaning})
    return gaps


@router.get("")
def list_agents(db: Session = Depends(get_db), _user: str = Depends(require_console)):
    agents = db.query(Agent).order_by(Agent.risk_score.desc(), Agent.hostname).all()
    return {"agents": [_agent_dict(a) for a in agents]}


@router.get("/summary")
def fleet_summary(db: Session = Depends(get_db), _user: str = Depends(require_console)):
    agents = db.query(Agent).all()
    dicts = [_agent_dict(a) for a in agents]
    online = sum(1 for d in dicts if d["status"] in ("online", "scanning"))
    scanning = sum(1 for d in dicts if d["status"] == "scanning")

    open_findings = (
        db.query(Job.critical_count, Job.high_count)
        .filter(Job.status == JobStatus.COMPLETED)
        .all()
    )
    active_jobs = (
        db.query(func.count(Job.id))
        .filter(Job.status.in_([JobStatus.QUEUED, JobStatus.DISPATCHED, JobStatus.RUNNING, JobStatus.UPLOADING]))
        .scalar()
        or 0
    )
    return {
        "total": len(dicts),
        "online": online,
        "offline": len(dicts) - online,
        "scanning": scanning,
        "active_jobs": active_jobs,
        "critical": sum(d["critical_count"] for d in dicts),
        "high": sum(d["high_count"] for d in dicts),
        "medium": sum(d["medium_count"] for d in dicts),
        "at_risk": sum(1 for d in dicts if d["risk_level"] in ("CRITICAL", "HIGH")),
        "scanned": sum(1 for d in dicts if d["last_scan_at"]),
        "_findings_rows": len(open_findings),
    }


@router.get("/{agent_id}")
def get_agent(agent_id: str, db: Session = Depends(get_db), _user: str = Depends(require_console)):
    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="No such host in the fleet.")
    jobs = (
        db.query(Job)
        .filter(Job.agent_id == agent_id)
        .order_by(Job.created_at.desc())
        .limit(25)
        .all()
    )
    from .jobs import job_dict

    return {"agent": _agent_dict(agent), "jobs": [job_dict(j) for j in jobs]}


@router.delete("/{agent_id}")
def remove_agent(agent_id: str, db: Session = Depends(get_db),
                 user=Depends(require_admin)):
    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="No such host in the fleet.")
    hostname = agent.hostname
    db.delete(agent)
    db.add(AuditEvent(kind="agent.removed", subject=hostname,
                      detail=f"by {user.username}"))
    db.commit()
    broadcast({"type": "agent.removed", "agent_id": agent_id})
    return {"removed": hostname}
