"""Cases: tying hosts, indicators and findings into one engagement."""
from __future__ import annotations

import re
from datetime import timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..auth import require_console, require_responder
from ..database import get_db
from ..models import (
    Agent,
    AuditEvent,
    Case,
    CaseNote,
    CaseStatus,
    Finding,
    FindingStatus,
    Job,
    JobStatus,
    new_id,
    utcnow,
)
from ..services.mitre import build_matrix

router = APIRouter()

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,40}$")


def _iso(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _case_findings(db: Session, case: Case) -> list[Finding]:
    """Findings from the latest completed scan of every host in the case."""
    ids = case.agent_ids or []
    if not ids:
        return []
    job_ids = []
    for agent_id in ids:
        job = (
            db.query(Job)
            .filter(Job.agent_id == agent_id, Job.status == JobStatus.COMPLETED)
            .order_by(Job.finished_at.desc())
            .first()
        )
        if job:
            job_ids.append(job.id)
    if not job_ids:
        return []
    return db.query(Finding).filter(Finding.job_id.in_(job_ids)).all()


def case_dict(db: Session, c: Case, *, full: bool = False) -> dict:
    data = {
        "id": c.id,
        "reference": c.reference,
        "name": c.name,
        "status": c.status.value if hasattr(c.status, "value") else str(c.status),
        "severity": c.severity,
        "summary": c.summary or "",
        "lead": c.lead or "",
        "agent_ids": c.agent_ids or [],
        "host_count": len(c.agent_ids or []),
        "ioc_count": len(c.iocs or []),
        "opened_at": _iso(c.opened_at),
        "closed_at": _iso(c.closed_at),
        "created_by": c.created_by,
    }
    if not full:
        return data

    findings = _case_findings(db, c)
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    open_count = 0
    for f in findings:
        sev = (f.severity or "INFO").upper()
        if sev in counts:
            counts[sev] += 1
        if f.status == FindingStatus.OPEN:
            open_count += 1

    hosts = []
    for agent_id in c.agent_ids or []:
        agent = db.get(Agent, agent_id)
        if not agent:
            continue
        hosts.append({
            "agent_id": agent.id,
            "hostname": agent.hostname,
            "risk_level": agent.risk_level,
            "risk_score": agent.risk_score or 0,
            "critical_count": agent.critical_count or 0,
            "high_count": agent.high_count or 0,
            "last_seen": _iso(agent.last_seen),
        })
    hosts.sort(key=lambda h: -(h["risk_score"] or 0))

    notes = (
        db.query(CaseNote)
        .filter(CaseNote.case_id == c.id)
        .order_by(CaseNote.created_at.desc())
        .all()
    )

    top = sorted(findings, key=lambda f: -SEV_RANK.get((f.severity or "").upper(), 0))[:30]

    data.update({
        "iocs": c.iocs or [],
        "hosts": hosts,
        "finding_counts": counts,
        "finding_total": len(findings),
        "open_findings": open_count,
        "matrix": build_matrix([
            {"mitre": f.mitre, "severity": f.severity, "hostname": f.hostname}
            for f in findings
        ]),
        "top_findings": [
            {"id": f.id, "rule_id": f.rule_id, "severity": f.severity,
             "title": f.title, "evidence": f.evidence, "hostname": f.hostname,
             "mitre": f.mitre,
             "status": f.status.value if hasattr(f.status, "value") else str(f.status)}
            for f in top
        ],
        "notes": [
            {"id": n.id, "body": n.body, "author": n.author,
             "created_at": _iso(n.created_at)}
            for n in notes
        ],
    })
    return data


@router.get("")
def list_cases(db: Session = Depends(get_db), _u=Depends(require_console)):
    rows = db.query(Case).order_by(Case.opened_at.desc()).all()
    return {
        "total": len(rows),
        "open": sum(1 for c in rows if c.status == CaseStatus.OPEN),
        "cases": [case_dict(db, c) for c in rows],
    }


class CaseRequest(BaseModel):
    reference: str = Field(min_length=2, max_length=64)
    name: str = Field(min_length=1, max_length=300)
    severity: str = "HIGH"
    summary: str = ""
    lead: str = ""
    agent_ids: list[str] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)


def _check(payload: CaseRequest) -> None:
    if not REF_RE.match(payload.reference.strip()):
        raise HTTPException(
            status_code=400,
            detail="A reference looks like IR-2026-014: letters, digits, dots, "
                   "dashes or underscores.",
        )
    if payload.severity.upper() not in SEV_RANK:
        raise HTTPException(status_code=400, detail="Pick a severity.")


@router.post("")
def create_case(
    payload: CaseRequest,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    _check(payload)
    ref = payload.reference.strip()
    if db.query(Case).filter(Case.reference == ref).first():
        raise HTTPException(status_code=409, detail="That reference is already in use.")

    row = Case(
        id=new_id(), reference=ref, name=payload.name.strip(),
        severity=payload.severity.upper(), summary=payload.summary.strip(),
        lead=payload.lead.strip() or user.username,
        agent_ids=payload.agent_ids, iocs=[i.strip() for i in payload.iocs if i.strip()],
        created_by=user.username,
    )
    db.add(row)
    db.add(AuditEvent(kind="case.opened", subject=ref,
                      detail=f"{payload.name} by {user.username}"))
    db.commit()
    db.refresh(row)
    return case_dict(db, row, full=True)


@router.get("/{case_id}")
def get_case(case_id: str, db: Session = Depends(get_db), _u=Depends(require_console)):
    row = db.get(Case, case_id)
    if not row:
        raise HTTPException(status_code=404, detail="No such case.")
    return case_dict(db, row, full=True)


@router.post("/{case_id}")
def update_case(
    case_id: str,
    payload: CaseRequest,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    row = db.get(Case, case_id)
    if not row:
        raise HTTPException(status_code=404, detail="No such case.")
    _check(payload)
    ref = payload.reference.strip()
    clash = db.query(Case).filter(Case.reference == ref, Case.id != case_id).first()
    if clash:
        raise HTTPException(status_code=409, detail="That reference is already in use.")

    row.reference = ref
    row.name = payload.name.strip()
    row.severity = payload.severity.upper()
    row.summary = payload.summary.strip()
    row.lead = payload.lead.strip()
    row.agent_ids = payload.agent_ids
    row.iocs = [i.strip() for i in payload.iocs if i.strip()]
    db.commit()
    return case_dict(db, row, full=True)


class StatusRequest(BaseModel):
    status: CaseStatus


@router.post("/{case_id}/status")
def set_status(
    case_id: str,
    payload: StatusRequest,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    row = db.get(Case, case_id)
    if not row:
        raise HTTPException(status_code=404, detail="No such case.")

    if payload.status == CaseStatus.CLOSED:
        # Closing a case with findings nobody ruled on is how a real one gets
        # forgotten. Refuse, and say how many are outstanding.
        outstanding = sum(
            1 for f in _case_findings(db, row) if f.status == FindingStatus.OPEN
        )
        if outstanding:
            raise HTTPException(
                status_code=409,
                detail=f"{outstanding} finding(s) in this case are still open. "
                       "Rule on them, or suppress them, before closing.",
            )
        row.closed_at = utcnow()
    else:
        row.closed_at = None

    row.status = payload.status
    db.add(AuditEvent(kind="case.status", subject=row.reference,
                      detail=f"{payload.status.value} by {user.username}"))
    db.commit()
    return case_dict(db, row)


class HostsRequest(BaseModel):
    agent_ids: list[str]


@router.post("/{case_id}/hosts")
def set_hosts(
    case_id: str,
    payload: HostsRequest,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    row = db.get(Case, case_id)
    if not row:
        raise HTTPException(status_code=404, detail="No such case.")
    row.agent_ids = payload.agent_ids
    db.commit()
    return case_dict(db, row, full=True)


class NoteRequest(BaseModel):
    body: str = Field(min_length=1)


@router.post("/{case_id}/notes")
def add_note(
    case_id: str,
    payload: NoteRequest,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    row = db.get(Case, case_id)
    if not row:
        raise HTTPException(status_code=404, detail="No such case.")
    note = CaseNote(id=new_id(), case_id=case_id,
                    body=payload.body.strip(), author=user.username)
    db.add(note)
    db.commit()
    return {"id": note.id, "body": note.body, "author": note.author,
            "created_at": _iso(note.created_at)}


@router.post("/{case_id}/hunt")
def hunt_case(
    case_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    """Sweep every host in the case with the case's indicator list."""
    row = db.get(Case, case_id)
    if not row:
        raise HTTPException(status_code=404, detail="No such case.")
    if not row.agent_ids:
        raise HTTPException(status_code=400, detail="This case has no hosts yet.")

    ioc_text = "\n".join(row.iocs or [])
    launched = 0
    for agent_id in row.agent_ids:
        agent = db.get(Agent, agent_id)
        if not agent:
            continue
        busy = (
            db.query(Job)
            .filter(Job.agent_id == agent_id,
                    Job.status.in_([JobStatus.QUEUED, JobStatus.RUNNING]))
            .first()
        )
        if busy:
            continue
        db.add(Job(id=new_id(), agent_id=agent_id, status=JobStatus.QUEUED,
                   days=14, ioc_list=ioc_text or None,
                   batch_id=f"case-{row.reference}"))
        launched += 1
    db.commit()
    return {"launched": launched, "iocs": len(row.iocs or [])}


@router.delete("/{case_id}")
def delete_case(
    case_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    row = db.get(Case, case_id)
    if not row:
        raise HTTPException(status_code=404, detail="No such case.")
    db.query(CaseNote).filter(CaseNote.case_id == case_id).delete()
    db.add(AuditEvent(kind="case.deleted", subject=row.reference,
                      detail=f"by {user.username}"))
    db.delete(row)
    db.commit()
    return {"deleted": case_id}
