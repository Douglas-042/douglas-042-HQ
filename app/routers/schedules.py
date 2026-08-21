"""Scheduled hunts and scan comparison."""
from __future__ import annotations

from datetime import timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..auth import require_console, require_responder
from ..database import get_db
from ..models import Agent, AuditEvent, Job, JobStatus, Schedule, new_id
from ..services import diff as diff_service
from ..services import scheduler

router = APIRouter()


def _iso(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def schedule_dict(s: Schedule) -> dict:
    return {
        "id": s.id,
        "name": s.name,
        "enabled": bool(s.enabled),
        "frequency": s.frequency,
        "hour_utc": s.hour_utc,
        "weekday": s.weekday,
        "summary": s.summary,
        "agent_ids": s.agent_ids or [],
        "scope": "All hosts" if not s.agent_ids else f"{len(s.agent_ids)} host(s)",
        "days": s.days,
        "quick": bool(s.quick),
        "collect_raw": bool(s.collect_raw),
        "last_run_at": _iso(s.last_run_at),
        "last_run_count": s.last_run_count or 0,
        "last_error": s.last_error,
        "next_run_at": _iso(s.next_run_at),
        "created_by": s.created_by,
    }


# ---------------------------------------------------------------------------
# Schedules
# ---------------------------------------------------------------------------


@router.get("")
def list_schedules(db: Session = Depends(get_db), _u=Depends(require_console)):
    rows = db.query(Schedule).order_by(Schedule.name).all()
    return {
        "total": len(rows),
        "enabled": sum(1 for s in rows if s.enabled),
        "schedules": [schedule_dict(s) for s in rows],
    }


class ScheduleRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    frequency: str = "weekly"
    hour_utc: int = 2
    weekday: int = 6
    agent_ids: list[str] = Field(default_factory=list)
    days: int = 14
    quick: bool = False
    collect_raw: bool = False
    enabled: bool = True


def _validate(payload: ScheduleRequest) -> None:
    if payload.frequency not in ("daily", "weekly"):
        raise HTTPException(status_code=400, detail="Frequency must be daily or weekly.")
    if not 0 <= payload.hour_utc <= 23:
        raise HTTPException(status_code=400, detail="Hour must be between 0 and 23.")
    if payload.frequency == "weekly" and not 0 <= payload.weekday <= 6:
        raise HTTPException(status_code=400, detail="Weekday must be between 0 and 6.")
    if not 1 <= payload.days <= 365:
        raise HTTPException(status_code=400, detail="Lookback must be between 1 and 365 days.")


@router.post("")
def create_schedule(
    payload: ScheduleRequest,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    _validate(payload)
    row = Schedule(
        id=new_id(),
        name=payload.name.strip(),
        frequency=payload.frequency,
        hour_utc=payload.hour_utc,
        weekday=payload.weekday,
        agent_ids=payload.agent_ids,
        days=payload.days,
        quick=payload.quick,
        collect_raw=payload.collect_raw,
        enabled=payload.enabled,
        created_by=user.username,
    )
    row.next_run_at = scheduler.compute_next_run(row)
    db.add(row)
    db.add(AuditEvent(kind="schedule.created", subject=row.name,
                      detail=f"{row.summary} by {user.username}"))
    db.commit()
    db.refresh(row)
    return schedule_dict(row)


@router.post("/{schedule_id}")
def update_schedule(
    schedule_id: str,
    payload: ScheduleRequest,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    row = db.get(Schedule, schedule_id)
    if not row:
        raise HTTPException(status_code=404, detail="No such schedule.")
    _validate(payload)
    for field in ("name", "frequency", "hour_utc", "weekday", "agent_ids",
                  "days", "quick", "collect_raw", "enabled"):
        setattr(row, field, getattr(payload, field))
    row.name = row.name.strip()
    row.next_run_at = scheduler.compute_next_run(row)
    db.commit()
    db.refresh(row)
    return schedule_dict(row)


class ToggleRequest(BaseModel):
    enabled: bool


@router.post("/{schedule_id}/toggle")
def toggle_schedule(
    schedule_id: str,
    payload: ToggleRequest,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    row = db.get(Schedule, schedule_id)
    if not row:
        raise HTTPException(status_code=404, detail="No such schedule.")
    row.enabled = payload.enabled
    if payload.enabled:
        row.next_run_at = scheduler.compute_next_run(row)
    db.commit()
    return schedule_dict(row)


@router.post("/{schedule_id}/run")
def run_now(
    schedule_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    """Fire a schedule immediately without disturbing its timetable."""
    row = db.get(Schedule, schedule_id)
    if not row:
        raise HTTPException(status_code=404, detail="No such schedule.")

    launched = 0
    for agent in scheduler._targets(db, row):
        busy = (
            db.query(Job)
            .filter(Job.agent_id == agent.id,
                    Job.status.in_([JobStatus.QUEUED, JobStatus.RUNNING]))
            .first()
        )
        if busy:
            continue
        db.add(Job(id=new_id(), agent_id=agent.id,
                   status=JobStatus.QUEUED, days=row.days, quick=row.quick,
                   collect_raw=row.collect_raw,
                   batch_id=f"sched-{row.id}"))
        launched += 1
    db.commit()
    return {"launched": launched}


@router.delete("/{schedule_id}")
def delete_schedule(
    schedule_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    row = db.get(Schedule, schedule_id)
    if not row:
        raise HTTPException(status_code=404, detail="No such schedule.")
    db.add(AuditEvent(kind="schedule.deleted", subject=row.name,
                      detail=f"by {user.username}"))
    db.delete(row)
    db.commit()
    return {"deleted": schedule_id}


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------

diff_router = APIRouter()


@diff_router.get("/hosts")
def comparable_hosts(db: Session = Depends(get_db), _u=Depends(require_console)):
    """Hosts with at least two completed scans, so a comparison is possible."""
    out = []
    for agent in db.query(Agent).all():
        count = (
            db.query(Job)
            .filter(Job.agent_id == agent.id, Job.status == JobStatus.COMPLETED)
            .count()
        )
        before, after = diff_service.latest_pair(db, agent.id)
        out.append({
            "agent_id": agent.id,
            "hostname": agent.hostname,
            "scans": count,
            "comparable": bool(before and after),
            "latest_at": _iso(after.finished_at) if after else None,
        })
    out.sort(key=lambda h: (not h["comparable"], h["hostname"] or ""))
    return {"hosts": out, "comparable": sum(1 for h in out if h["comparable"])}


@diff_router.get("/{agent_id}")
def host_diff(
    agent_id: str,
    before_id: str | None = None,
    after_id: str | None = None,
    db: Session = Depends(get_db),
    _u=Depends(require_console),
):
    """What changed between two scans of one host."""
    if before_id and after_id:
        before = db.get(Job, before_id)
        after = db.get(Job, after_id)
        if not before or not after:
            raise HTTPException(status_code=404, detail="One of those hunts does not exist.")
    else:
        before, after = diff_service.latest_pair(db, agent_id)

    if not after:
        raise HTTPException(status_code=404, detail="This host has no completed scans.")
    if not before:
        raise HTTPException(
            status_code=409,
            detail="Only one scan on this host so far. A comparison needs two.",
        )

    result = diff_service.compare(db, before, after)

    scans = (
        db.query(Job)
        .filter(Job.agent_id == agent_id, Job.status == JobStatus.COMPLETED)
        .order_by(Job.finished_at.desc())
        .limit(20)
        .all()
    )
    result["available_scans"] = [
        {"job_id": j.id, "finished_at": _iso(j.finished_at),
         "risk_score": j.risk_score or 0, "risk_level": j.risk_level}
        for j in scans
    ]
    return result
