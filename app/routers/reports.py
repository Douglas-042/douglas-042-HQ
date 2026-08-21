"""Report export, evidence bundles and the PowerShell deploy one-liner."""
from __future__ import annotations

import io
import json
import zipfile
from urllib.parse import urlparse
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response, StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..auth import require_admin, require_console, require_responder
from ..config import settings
from ..database import get_db
from ..models import (
    Agent, AuditEvent, EnrollmentToken, Finding, Job, JobStatus, TimelineEvent,
    get_setting, set_setting,
)
from ..services.report_html import render_report
from .agents import _agent_dict
from .findings import finding_dict
from .jobs import job_dict

router = APIRouter()


def _collect(db: Session, job_id: str):
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="No such hunt.")
    agent = db.get(Agent, job.agent_id)
    findings = [finding_dict(f) for f in db.query(Finding).filter(Finding.job_id == job_id).all()]
    timeline = [
        {
            "time_utc": t.time_utc,
            "source": t.source,
            "severity": t.severity,
            "description": t.description,
            "detail": t.detail,
        }
        for t in db.query(TimelineEvent).filter(TimelineEvent.job_id == job_id).all()
    ]
    return job, agent, findings, timeline


@router.get("/{job_id}/html", response_class=HTMLResponse)
def report_html(job_id: str, db: Session = Depends(get_db), _u: str = Depends(require_console)):
    """Render the report in-browser."""
    job, agent, findings, timeline = _collect(db, job_id)
    return HTMLResponse(
        render_report(
            host=_agent_dict(agent) if agent else {"hostname": "unknown"},
            job=job_dict(job),
            findings=findings,
            timeline=timeline,
            manifest=job.manifest or {},
            module_stats=job.module_stats or [],
            collection_errors=job.collection_errors or [],
        )
    )


@router.get("/{job_id}/download")
def report_download(job_id: str, db: Session = Depends(get_db), _u: str = Depends(require_console)):
    """Same report as a single self-contained .html file."""
    job, agent, findings, timeline = _collect(db, job_id)
    hostname = agent.hostname if agent else "host"
    stamp = (job.finished_at or datetime.now(timezone.utc)).strftime("%Y%m%d_%H%M")
    html = render_report(
        host=_agent_dict(agent) if agent else {"hostname": hostname},
        job=job_dict(job),
        findings=findings,
        timeline=timeline,
        manifest=job.manifest or {},
        module_stats=job.module_stats or [],
        collection_errors=job.collection_errors or [],
    )
    return Response(
        content=html,
        media_type="text/html; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="Douglas-042_{hostname}_{stamp}.html"'
        },
    )


@router.get("/{job_id}/findings.csv")
def findings_csv(job_id: str, db: Session = Depends(get_db), _u: str = Depends(require_console)):
    import csv

    job, agent, findings, _ = _collect(db, job_id)
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=[
            "hostname", "severity", "rule_id", "title", "evidence",
            "mitre", "why", "artifact", "occurred_at",
        ],
        extrasaction="ignore",
    )
    writer.writeheader()
    for f in findings:
        writer.writerow(f)
    hostname = agent.hostname if agent else "host"
    return Response(
        # BOM so Excel opens UTF-8 correctly on Turkish locale machines.
        content="\ufeff" + buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="findings_{hostname}.csv"'},
    )


@router.get("/{job_id}/bundle")
def evidence_bundle(job_id: str, db: Session = Depends(get_db),
                    _u=Depends(require_responder)):
    """The raw collector output as uploaded by the agent."""
    job = db.get(Job, job_id)
    if not job or not job.bundle_path:
        raise HTTPException(status_code=404, detail="No evidence bundle stored for this hunt.")
    path = settings.bundle_dir / f"{job_id}.zip"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Evidence bundle missing from disk.")
    hostname = job.agent.hostname if job.agent else "host"

    def stream():
        with path.open("rb") as fh:
            while chunk := fh.read(1024 * 512):
                yield chunk

    return StreamingResponse(
        stream(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="Douglas-042_{hostname}.zip"'},
    )


@router.get("/fleet/export")
def fleet_export(db: Session = Depends(get_db), _u: str = Depends(require_console)):
    """Every host's latest findings, one CSV per host plus a combined roll-up."""
    import csv
    from sqlalchemy import func

    latest = (
        db.query(Job.agent_id, func.max(Job.finished_at).label("mx"))
        .filter(Job.status == JobStatus.COMPLETED)
        .group_by(Job.agent_id)
        .subquery()
    )
    jobs = (
        db.query(Job)
        .join(latest, (Job.agent_id == latest.c.agent_id) & (Job.finished_at == latest.c.mx))
        .all()
    )
    if not jobs:
        raise HTTPException(status_code=404, detail="No completed hunts to export yet.")

    mem = io.BytesIO()
    with zipfile.ZipFile(mem, "w", zipfile.ZIP_DEFLATED) as zf:
        roll = io.StringIO()
        rw = csv.writer(roll)
        rw.writerow(["hostname", "risk_score", "risk_level", "critical", "high",
                     "medium", "low", "scanned_at"])

        for job in jobs:
            host = job.agent.hostname if job.agent else job.agent_id
            rw.writerow([host, job.risk_score, job.risk_level, job.critical_count,
                         job.high_count, job.medium_count, job.low_count,
                         job.finished_at.isoformat() if job.finished_at else ""])

            rows = db.query(Finding).filter(Finding.job_id == job.id).all()
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["severity", "rule_id", "title", "evidence", "mitre", "occurred_at"])
            for f in rows:
                w.writerow([f.severity, f.rule_id, f.title, f.evidence, f.mitre, f.occurred_at])
            zf.writestr(f"hosts/{host}_findings.csv", "\ufeff" + buf.getvalue())

            agent = job.agent
            zf.writestr(
                f"reports/{host}.html",
                render_report(
                    host=_agent_dict(agent) if agent else {"hostname": host},
                    job=job_dict(job),
                    findings=[finding_dict(f) for f in rows],
                    timeline=[
                        {
                            "time_utc": t.time_utc, "source": t.source,
                            "severity": t.severity, "description": t.description,
                            "detail": t.detail,
                        }
                        for t in db.query(TimelineEvent).filter(TimelineEvent.job_id == job.id).all()
                    ],
                    manifest=job.manifest or {},
                    module_stats=job.module_stats or [],
                    collection_errors=job.collection_errors or [],
                ),
            )

        zf.writestr("FLEET_ROLLUP.csv", "\ufeff" + roll.getvalue())

    mem.seek(0)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    return StreamingResponse(
        mem,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="Douglas-042_fleet_{stamp}.zip"'},
    )


# ---------------------------------------------------------------------------
# Deployment
# ---------------------------------------------------------------------------


PUBLIC_URL_KEY = "public_url"


# Addresses that mean "this machine" to whoever is looking at the console and
# mean nothing at all to a host on the other side of the network. Baked into a
# deploy command they produce an agent that downloads fine and can never call
# home, with an error that never explains why.
_UNREACHABLE_HOSTS = {"0.0.0.0", "127.0.0.1", "localhost", "::", "[::]", "::1", "[::1]"}


def _lan_address() -> str:
    """This machine's address on the network hosts can actually reach.

    Found by asking the routing table which local address would be used to
    reach the outside world. No packet is sent — a UDP socket has no handshake
    — so this works on an isolated network with no internet access.
    """
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("10.255.255.255", 1))
        return sock.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return ""
    finally:
        sock.close()


def _detected_url(request: Request) -> str:
    """The address agents should call back on.

    Normally the address this browser reached the console on, which has the
    advantage of being proven reachable. But someone browsing to 0.0.0.0 or
    localhost is looking at the console from the same machine it runs on, and
    that address is useless to every other host — so substitute the real one.
    """
    base = str(request.base_url).rstrip("/")

    try:
        from urllib.parse import urlsplit, urlunsplit

        parts = urlsplit(base)
        if (parts.hostname or "").lower() in _UNREACHABLE_HOSTS:
            lan = _lan_address()
            if lan:
                netloc = f"{lan}:{parts.port}" if parts.port else lan
                return urlunsplit((parts.scheme, netloc, "", "", "")).rstrip("/")
    except Exception:  # noqa: BLE001 - never break deploy over a URL parse
        pass

    return base


def _server_url(request: Request, db: Session | None = None) -> str:
    """Where agents should call back.

    Priority: what an admin set in the console, then the environment, then the
    address the current request arrived on. Auto-detection is last but it is
    also the only one that cannot be stale, so it is what we fall back to
    rather than failing.
    """
    if db is not None:
        saved = get_setting(db, PUBLIC_URL_KEY)
        if saved:
            return saved.rstrip("/")
    if settings.public_url:
        return settings.public_url.rstrip("/")
    return _detected_url(request)


def _tls_warning(configured: str, request: Request) -> str:
    """Catch the https-without-TLS mistake before it reaches fifty servers.

    Setting https:// when nothing terminates TLS produces a bare "connection
    was closed" on the agent side, which names neither the cause nor the fix.
    We can spot it: if this very request arrived over plain http on the same
    host, there is no TLS listener there.
    """
    if not configured.startswith("https://"):
        return ""
    if request.url.scheme != "http":
        return ""
    here = urlparse(_detected_url(request))
    there = urlparse(configured)
    if here.hostname != there.hostname:
        # Different host, so this console cannot say anything about its TLS.
        return ""
    if here.port != there.port:
        return ""
    return (
        "This address uses https, but the console is answering over plain http "
        "on the same host and port. Agents will fail with 'the underlying "
        "connection was closed'. Use http:// unless you have put TLS in front "
        "of the console."
    )


def _url_source(request: Request, db: Session) -> str:
    if get_setting(db, PUBLIC_URL_KEY):
        return "manual"
    if settings.public_url:
        return "environment"
    return "auto"


def _normalise_url(raw: str) -> str:
    """Accept what people actually type: bare IPs, host:port, full URLs."""
    text = (raw or "").strip().rstrip("/")
    if not text:
        raise HTTPException(status_code=400, detail="Enter an address.")
    if "://" not in text:
        text = "http://" + text
    parsed = urlparse(text)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="Use http:// or https://.")
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="That address has no host in it.")
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{parsed.hostname}{port}"


def _active_token(db: Session) -> str:
    tok = db.query(EnrollmentToken).filter(EnrollmentToken.revoked == False).first()  # noqa: E712
    if tok:
        return tok.token
    tok = EnrollmentToken(label="default")
    if settings.enrollment_token:
        tok.token = settings.enrollment_token
    db.add(tok)
    db.commit()
    return tok.token


class AddressRequest(BaseModel):
    url: str


@router.put("/deploy/address")
def set_address(
    payload: AddressRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(require_admin),
):
    """Pin the callback address agents are told to use."""
    url = _normalise_url(payload.url)
    set_setting(db, PUBLIC_URL_KEY, url, who=admin.username)
    db.add(AuditEvent(kind="settings.address", subject=url,
                      detail=f"by {admin.username}"))
    db.commit()
    return {"server_url": url, "source": "manual",
            "detected_url": _detected_url(request),
            "mismatch": url != _detected_url(request),
            "tls_warning": _tls_warning(url, request)}


@router.delete("/deploy/address")
def clear_address(
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(require_admin),
):
    """Go back to detecting the address from whatever the browser used."""
    set_setting(db, PUBLIC_URL_KEY, "", who=admin.username)
    db.add(AuditEvent(kind="settings.address", subject="auto-detect",
                      detail=f"by {admin.username}"))
    db.commit()
    return {"server_url": _server_url(request, db), "source": _url_source(request, db),
            "detected_url": _detected_url(request), "mismatch": False}


@router.get("/deploy/command", response_class=PlainTextResponse)
def deploy_command(request: Request, db: Session = Depends(get_db),
                   _u=Depends(require_admin)):
    """The one-liner an operator pastes into an elevated PowerShell prompt."""
    url = _server_url(request, db)
    token = _active_token(db)
    return f"iex (irm '{url}/api/v1/reports/deploy/script?token={token}')"


@router.get("/deploy/info")
def deploy_info(request: Request, db: Session = Depends(get_db),
                _u=Depends(require_admin)):
    url = _server_url(request, db)
    detected = _detected_url(request)
    token = _active_token(db)
    return {
        "server_url": url,
        "detected_url": detected,
        "source": _url_source(request, db),
        # An address agents cannot reach is the single most common reason a
        # deployment silently fails, so surface the disagreement rather than
        # letting someone paste a broken command onto fifty servers.
        "mismatch": url.rstrip("/") != detected.rstrip("/"),
        "tls_warning": _tls_warning(url, request),
        "token": token,
        "oneliner": f"iex (irm '{url}/api/v1/reports/deploy/script?token={token}')",
        "manual": (
            f"Invoke-WebRequest '{url}/api/v1/reports/deploy/agent' "
            f"-OutFile douglas-agent.ps1\n"
            f".\\douglas-agent.ps1 -Server '{url}' -Token '{token}' -Install"
        ),
        "gpo": (
            f"powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "
            f"\"iex (irm '{url}/api/v1/reports/deploy/script?token={token}')\""
        ),
    }
