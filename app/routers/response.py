"""Queueing response actions and collecting what the host said back."""
from __future__ import annotations

from datetime import timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import IntegrityError
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..auth import require_agent, require_console, require_responder
from ..database import get_db
from ..models import Agent, AgentStatus, AuditEvent, ResponseAction, new_id, utcnow
from ..services import response as svc
from ..services.events import broadcast

router = APIRouter()


def _iso(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def action_dict(a: ResponseAction) -> dict:
    spec = svc.BY_ID.get(a.action, {})
    return {
        "id": a.id,
        "agent_id": a.agent_id,
        "hostname": a.hostname,
        "action": a.action,
        "action_name": spec.get("name", a.action),
        "group": spec.get("group", ""),
        "target": a.target or "",
        "status": a.status,
        "mutating": bool(a.mutating),
        "reason": a.reason or "",
        "output": a.output or "",
        "error": a.error,
        "exit_code": a.exit_code,
        "created_at": _iso(a.created_at),
        "dispatched_at": _iso(a.dispatched_at),
        "finished_at": _iso(a.finished_at),
        "duration_seconds": a.duration_seconds,
        "created_by": a.created_by,
    }


@router.get("/catalogue")
def catalogue(_u=Depends(require_console)):
    """What can be run, and which of it changes the host."""
    return {"actions": svc.catalogue()}


@router.get("")
def list_actions(
    agent_id: str | None = None,
    limit: int = 60,
    db: Session = Depends(get_db),
    _u=Depends(require_console),
):
    q = db.query(ResponseAction)
    if agent_id:
        q = q.filter(ResponseAction.agent_id == agent_id)
    rows = q.order_by(ResponseAction.created_at.desc()).limit(min(limit, 300)).all()
    return {
        "total": len(rows),
        "running": sum(1 for r in rows if r.status in ("queued", "running")),
        "actions": [action_dict(r) for r in rows],
    }


class ActionRequest(BaseModel):
    agent_id: str
    action: str
    target: str = ""
    reason: str = Field(default="", max_length=2000)


@router.post("")
def queue_action(
    payload: ActionRequest,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    """Queue one action against one host.

    Responder and above, for the same reason launching a hunt is: this reaches
    out and touches a production machine. Read-only actions sit behind the same
    tier deliberately — the console should not train people that some commands
    to a live host are casual.
    """
    agent = db.get(Agent, payload.agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="No such host in the fleet.")

    try:
        action_id, target = svc.validate(payload.action, payload.target, payload.reason)
    except svc.InvalidAction as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    spec = svc.BY_ID[action_id]

    # A host that is not checking in will never pick this up. Say so now rather
    # than leaving a command queued against a machine that is off.
    if agent.is_stale(600) and agent.status != AgentStatus.SCANNING:
        raise HTTPException(
            status_code=400,
            detail=f"{agent.hostname} has not checked in recently, so it would not "
                   "pick this up. Check the host is running and reachable.",
        )

    # One at a time per host. Two containment actions racing each other on the
    # same machine is a way to end up isolated and unable to explain why.
    busy = (
        db.query(ResponseAction)
        .filter(ResponseAction.agent_id == agent.id,
                ResponseAction.status.in_(["queued", "running"]))
        .first()
    )
    if busy:
        raise HTTPException(
            status_code=409,
            detail=f"{agent.hostname} is already running "
                   f"'{svc.BY_ID.get(busy.action, {}).get('name', busy.action)}'. "
                   "Wait for it to finish.",
        )

    row = ResponseAction(
        id=new_id(),
        agent_id=agent.id,
        hostname=agent.hostname,
        action=action_id,
        target=target,
        mutating=bool(spec["mutating"]),
        reason=(payload.reason or "").strip(),
        created_by=user.username,
    )
    db.add(row)
    db.add(AuditEvent(
        kind="response.queued",
        subject=f"{agent.hostname}: {spec['name']}" + (f" ({target})" if target else ""),
        detail=f"by {user.username}" + (f" — {payload.reason[:180]}" if payload.reason else "")))
    try:
        db.commit()
    except IntegrityError:
        # The busy check above is a read followed by a write, and two requests
        # arriving together both pass it. The database has the last word, and
        # what it is saying here is the same thing the check meant to say.
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail=f"{agent.hostname} picked up another action at the same "
                   "moment. Wait for it to finish and try again.",
        ) from None
    db.refresh(row)

    broadcast({"type": "response.queued", "action": action_dict(row)})
    return action_dict(row)


@router.get("/{action_id}")
def get_action(action_id: str, db: Session = Depends(get_db), _u=Depends(require_console)):
    row = db.get(ResponseAction, action_id)
    if not row:
        raise HTTPException(status_code=404, detail="No such action.")
    return action_dict(row)


@router.post("/{action_id}/cancel")
def cancel_action(
    action_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    row = db.get(ResponseAction, action_id)
    if not row:
        raise HTTPException(status_code=404, detail="No such action.")
    if row.status not in ("queued", "running"):
        raise HTTPException(status_code=400, detail="That action already finished.")
    row.status = "cancelled"
    row.finished_at = utcnow()
    db.add(AuditEvent(kind="response.cancelled", subject=f"{row.hostname}: {row.action}",
                      detail=f"by {user.username}"))
    db.commit()
    broadcast({"type": "response.updated", "action": action_dict(row)})
    return action_dict(row)


# ---------------------------------------------------------------------------
# Agent side
# ---------------------------------------------------------------------------


@router.get("/agent/next")
def next_action(
    agent: Agent = Depends(require_agent),
    db: Session = Depends(get_db),
):
    """The action this host should run now, if any.

    Polled on the heartbeat interval alongside the hunt queue. Kept as its own
    endpoint rather than folded into the heartbeat so an agent that has not
    been updated simply never asks, and response actions stay queued instead of
    breaking its heartbeat parsing.
    """
    row = (
        db.query(ResponseAction)
        .filter(ResponseAction.agent_id == agent.id, ResponseAction.status == "queued")
        .order_by(ResponseAction.created_at)
        .first()
    )
    if row is None:
        return {"action": None}

    row.status = "running"
    row.dispatched_at = utcnow()
    db.commit()
    broadcast({"type": "response.updated", "action": action_dict(row)})

    return {
        "action": {
            "id": row.id,
            "action": row.action,
            "target": row.target or "",
        }
    }


class ResultRequest(BaseModel):
    output: str = ""
    error: str = ""
    exit_code: int = 0
    duration_seconds: float = 0.0


@router.post("/agent/{action_id}/result")
def report_result(
    action_id: str,
    payload: ResultRequest,
    agent: Agent = Depends(require_agent),
    db: Session = Depends(get_db),
):
    row = db.get(ResponseAction, action_id)
    if not row or row.agent_id != agent.id:
        raise HTTPException(status_code=404, detail="No such action for this host.")

    # Output is kept whether it worked or not: a failed containment attempt is
    # exactly the transcript somebody needs.
    row.output = (payload.output or "")[:200_000]
    row.error = (payload.error or "")[:4000] or None
    row.exit_code = payload.exit_code
    row.duration_seconds = payload.duration_seconds
    row.finished_at = utcnow()
    row.status = "completed" if payload.exit_code == 0 and not payload.error else "failed"

    agent.last_seen = utcnow()
    db.add(AuditEvent(
        kind="response." + row.status,
        subject=f"{row.hostname}: {row.action}" + (f" ({row.target})" if row.target else ""),
        detail=(payload.error or "")[:200] or "ok"))
    db.commit()
    db.refresh(row)

    broadcast({"type": "response.updated", "action": action_dict(row)})
    return {"ok": True}
