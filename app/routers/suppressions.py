"""Suppression rules: standing decisions about noise.

Kept in its own router because a suppression is not a property of a finding —
it outlives any single scan and applies to findings that do not exist yet.
"""
from __future__ import annotations

from datetime import timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..auth import require_admin, require_console, require_responder
from ..database import get_db
from ..models import AuditEvent, Finding, Suppression, new_id, utcnow
from ..services import triage

router = APIRouter()


def _iso(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def suppression_dict(s: Suppression) -> dict:
    return {
        "id": s.id,
        "rule_id": s.rule_id,
        "evidence_contains": s.evidence_contains or "",
        "hostname": s.hostname or "",
        "scope": s.scope,
        "reason": s.reason,
        "active": bool(s.active),
        "match_count": s.match_count or 0,
        "created_at": _iso(s.created_at),
        "created_by": s.created_by,
        "last_matched_at": _iso(s.last_matched_at),
    }


@router.get("")
def list_suppressions(db: Session = Depends(get_db), _u=Depends(require_console)):
    rows = db.query(Suppression).order_by(Suppression.created_at.desc()).all()
    return {
        "total": len(rows),
        "active": sum(1 for s in rows if s.active),
        "hidden_findings": sum(s.match_count or 0 for s in rows),
        "suppressions": [suppression_dict(s) for s in rows],
    }


class PreviewRequest(BaseModel):
    rule_id: str
    evidence_contains: str = ""
    hostname: str = ""


@router.post("/preview")
def preview_suppression(
    payload: PreviewRequest,
    db: Session = Depends(get_db),
    _u=Depends(require_responder),
):
    """Show what a suppression would hide before it is created."""
    if not payload.rule_id:
        raise HTTPException(status_code=400, detail="Pick a rule first.")
    return triage.preview(
        db, payload.rule_id.strip(),
        payload.evidence_contains.strip(), payload.hostname.strip(),
    )


class CreateRequest(BaseModel):
    rule_id: str
    # Length is checked in the handler, not here: a schema rejection returns a
    # generic 422 and the operator never sees why a reason matters.
    reason: str = ""
    evidence_contains: str = ""
    hostname: str = ""


@router.post("")
def create_suppression(
    payload: CreateRequest,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    """Create a suppression and apply it to what already exists."""
    rule_id = payload.rule_id.strip()
    if not rule_id:
        raise HTTPException(status_code=400, detail="Pick a rule first.")
    reason = payload.reason.strip()
    if len(reason) < 8:
        raise HTTPException(
            status_code=400,
            detail="Give a reason. In six months this is the only record of why "
                   "the finding stopped being shown.",
        )

    rule = Suppression(
        id=new_id(),
        rule_id=rule_id,
        evidence_contains=payload.evidence_contains.strip() or None,
        hostname=payload.hostname.strip() or None,
        reason=reason,
        created_by=user.username,
    )
    db.add(rule)
    db.flush()

    # Apply retroactively: a suppression that only affected future scans would
    # leave the backlog people actually want gone.
    existing = db.query(Finding).filter(Finding.rule_id == rule_id).all()
    hidden = triage.apply_to_findings(db, existing, rules=[rule])
    triage.recalculate_for_findings(db, existing)

    db.add(AuditEvent(
        kind="suppression.created", subject=rule_id,
        detail=f"{rule.scope}, hid {hidden} findings, by {user.username}: {reason[:120]}",
    ))
    db.commit()
    db.refresh(rule)
    return {"suppression": suppression_dict(rule), "hidden": hidden}


class ToggleRequest(BaseModel):
    active: bool


@router.post("/{suppression_id}/toggle")
def toggle_suppression(
    suppression_id: str,
    payload: ToggleRequest,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    rule = db.get(Suppression, suppression_id)
    if not rule:
        raise HTTPException(status_code=404, detail="No such suppression.")

    rule.active = payload.active
    if payload.active:
        rows = db.query(Finding).filter(Finding.rule_id == rule.rule_id).all()
        affected = triage.apply_to_findings(db, rows, rules=[rule])
    else:
        affected = triage.unsuppress_for_rule(db, rule)
        rows = db.query(Finding).filter(Finding.rule_id == rule.rule_id).all()

    triage.recalculate_for_findings(db, rows)
    db.commit()
    return {"suppression": suppression_dict(rule), "affected": affected}


@router.delete("/{suppression_id}")
def delete_suppression(
    suppression_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    """Remove a suppression and bring back whatever it was hiding."""
    rule = db.get(Suppression, suppression_id)
    if not rule:
        raise HTTPException(status_code=404, detail="No such suppression.")

    reopened = triage.unsuppress_for_rule(db, rule)
    rows = db.query(Finding).filter(Finding.rule_id == rule.rule_id).all()
    triage.recalculate_for_findings(db, rows)

    db.add(AuditEvent(
        kind="suppression.deleted", subject=rule.rule_id,
        detail=f"reopened {reopened} findings, by {user.username}",
    ))
    db.delete(rule)
    db.commit()
    return {"deleted": suppression_id, "reopened": reopened}
