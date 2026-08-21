"""Douglas-042 hunt console — FastAPI application."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from urllib.parse import urlparse
from datetime import timezone

from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .auth import SESSION_COOKIE, authenticate, hash_password, issue_session, read_session, require_console
from .config import settings
from .database import SessionLocal, get_db, init_db
from .models import Agent, AgentStatus, AuditEvent, EnrollmentToken, Job, JobStatus, Role, User, utcnow
from .routers import agents as agents_router
from .routers import findings as findings_router
from .routers import jobs as jobs_router
from .routers import reports as reports_router
from .routers import response as response_router
from .routers import sigma as sigma_router
from .routers import suppressions as suppressions_router
from .routers import cases as cases_router
from .routers import custom_rules as custom_rules_router
from .routers import enrichment as enrichment_router
from .routers import feeds as feeds_router
from .routers import integrations as integrations_router
from .routers import schedules as schedules_router
from .routers import yara as yara_router
from .routers import users as users_router
from .services import events

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s :: %(message)s",
)
logger = logging.getLogger("douglas")


async def _reaper() -> None:
    """Mark hosts offline once they stop checking in, and time out dead hunts."""
    while True:
        try:
            await asyncio.sleep(30)
            db: Session = SessionLocal()
            try:
                changed = False
                for agent in db.query(Agent).all():
                    stale = agent.is_stale(settings.agent_timeout_seconds)
                    if stale and agent.status != AgentStatus.OFFLINE:
                        agent.status = AgentStatus.OFFLINE
                        changed = True

                # A hunt whose host vanished mid-run should not spin forever.
                cutoff = settings.agent_timeout_seconds * 6
                for job in (
                    db.query(Job)
                    .filter(Job.status.in_([JobStatus.RUNNING, JobStatus.DISPATCHED]))
                    .all()
                ):
                    ref = job.dispatched_at or job.created_at
                    if not ref:
                        continue
                    if ref.tzinfo is None:
                        ref = ref.replace(tzinfo=timezone.utc)
                    if (utcnow() - ref).total_seconds() > max(cutoff, 3600 * 4):
                        job.status = JobStatus.FAILED
                        job.error = "The host stopped reporting before the hunt finished."
                        job.finished_at = utcnow()
                        changed = True

                if changed:
                    db.commit()
                    events.broadcast({"type": "fleet.refresh"})
            finally:
                db.close()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pragma: no cover
            logger.warning("reaper cycle failed: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    from .services import scheduler
    scheduler.start()
    events.bind_loop(asyncio.get_running_loop())

    db = SessionLocal()
    try:
        # First run: turn the env-var credentials into a real admin account.
        # After this, accounts are managed in the console and the env vars are
        # ignored, so changing them later cannot silently reopen a way in.
        existing_admin = db.query(User).first()
        if existing_admin is not None:
            # The account already exists, so DOUGLAS_CONSOLE_PASSWORD is not
            # read. Say so at startup: otherwise editing .env and then failing
            # to sign in looks like the file was ignored for no reason.
            if existing_admin.email != settings.console_email.strip().lower():
                logger.warning(
                    "Console accounts already exist (admin: %s). Values in .env are "
                    "only read when the database is empty, so changes there have no "
                    "effect now. Reset a password with: python -m app.manage passwd %s"
                    "  — or delete the data directory to start fresh.",
                    existing_admin.email or existing_admin.username,
                    existing_admin.username,
                )

        if not existing_admin:
            admin = User(
                username=settings.console_user.strip().lower(),
                email=settings.console_email.strip().lower(),
                full_name="Initial administrator",
                password_hash=hash_password(settings.console_password),
                role=Role.ADMIN,
                # Any password that shipped with the package must be replaced
                # at first sign-in. Checking only one of them meant changing
                # the default in .env quietly disabled the forced change.
                must_change_password=(
                    settings.console_password.strip().lower()
                    in {"douglas", "douglas042", "change-this-now", "changeme", "admin"}
                ),
                created_by="system",
            )
            db.add(admin)
            db.commit()
            logger.info("Created the initial admin account: %s", admin.username)
            if admin.must_change_password:
                logger.warning(
                    "The default password is still in use. Change it at first sign-in."
                )

        if not db.query(EnrollmentToken).first():
            tok = EnrollmentToken(label="default")
            if settings.enrollment_token:
                tok.token = settings.enrollment_token
            db.add(tok)
            db.commit()
            logger.info("Enrollment token ready: %s", tok.token)
    finally:
        db.close()

    task = asyncio.create_task(_reaper())
    logger.info("Douglas-042 console %s ready", settings.version)
    try:
        yield
        scheduler.stop()
    finally:
        task.cancel()


app = FastAPI(
    title="Douglas-042 Hunt Console",
    version=settings.version,
    lifespan=lifespan,
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

app.include_router(agents_router.router, prefix="/api/v1/agents", tags=["agents"])
app.include_router(jobs_router.router, prefix="/api/v1/jobs", tags=["jobs"])
app.include_router(findings_router.router, prefix="/api/v1/findings", tags=["findings"])
app.include_router(reports_router.router, prefix="/api/v1/reports", tags=["reports"])
app.include_router(users_router.router, prefix="/api/v1/users", tags=["users"])
app.include_router(sigma_router.router, prefix="/api/v1/sigma", tags=["sigma"])
app.include_router(suppressions_router.router, prefix="/api/v1/suppressions",
                   tags=["suppressions"])
app.include_router(yara_router.router, prefix="/api/v1/yara", tags=["yara"])
app.include_router(schedules_router.router, prefix="/api/v1/schedules", tags=["schedules"])
app.include_router(feeds_router.router, prefix="/api/v1/feeds", tags=["feeds"])
app.include_router(enrichment_router.router, prefix="/api/v1/enrichment",
                   tags=["enrichment"])
app.include_router(response_router.router, prefix="/api/v1/response",
                   tags=["response"])
app.include_router(integrations_router.router, prefix="/api/v1/integrations",
                   tags=["integrations"])
app.include_router(integrations_router.token_router, prefix="/api/v1/tokens",
                   tags=["tokens"])
app.include_router(schedules_router.diff_router, prefix="/api/v1/diff", tags=["diff"])
app.include_router(custom_rules_router.router, prefix="/api/v1/custom-rules",
                   tags=["custom-rules"])
app.include_router(cases_router.router, prefix="/api/v1/cases", tags=["cases"])


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/v1/auth/login")
def login(payload: LoginRequest, response: Response, db: Session = Depends(get_db)):
    user, reason = authenticate(db, payload.username, payload.password)
    if user is None:
        db.add(AuditEvent(kind="login.failed", subject=payload.username[:64]))
        db.commit()
        raise HTTPException(status_code=401, detail=reason)

    response.set_cookie(
        SESSION_COOKIE,
        issue_session(user.id),
        httponly=True,
        samesite="lax",
        max_age=settings.session_hours * 3600,
        path="/",
    )
    db.add(AuditEvent(kind="login", subject=user.username))
    db.commit()
    return {
        "user": user.username,
        "full_name": user.full_name,
        "role": user.role.value,
        "must_change_password": bool(user.must_change_password),
        "version": settings.version,
    }


@app.post("/api/v1/auth/logout")
def logout(response: Response):
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@app.get("/api/v1/auth/me")
def whoami(user: User = Depends(require_console)):
    return {
        "user": user.username,
        "full_name": user.full_name,
        "email": user.email,
        "role": user.role.value,
        "must_change_password": bool(user.must_change_password),
        "version": settings.version,
    }


# ---------------------------------------------------------------------------
# Live updates
# ---------------------------------------------------------------------------


@app.websocket("/api/v1/stream")
async def stream(ws: WebSocket):
    uid = read_session(ws.cookies.get(SESSION_COOKIE))
    user = None
    if uid:
        db = SessionLocal()
        try:
            found = db.get(User, uid)
            if found and found.active:
                user = found.username
        finally:
            db.close()
    if not user:
        await ws.close(code=4401)
        return
    await ws.accept()
    events.register(ws)
    try:
        await ws.send_json({"type": "hello", "version": settings.version})
        while True:
            # The client sends periodic pings; this also detects dead sockets.
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        events.unregister(ws)


# ---------------------------------------------------------------------------
# Agent distribution
# ---------------------------------------------------------------------------


@app.get("/api/v1/reports/deploy/agent", response_class=PlainTextResponse)
def serve_agent_script():
    """Agents fetch themselves from here; no console session required."""
    path = settings.agent_dir / "douglas-agent.ps1"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Agent script not bundled with this server.")
    return PlainTextResponse(
        path.read_text(encoding="utf-8"), media_type="text/plain; charset=utf-8"
    )


@app.get("/api/v1/reports/deploy/collector/linux")
def linux_collector():
    """The Linux collector script."""
    path = settings.agent_dir / "douglas-042.sh"
    if not path.exists():
        raise HTTPException(status_code=404,
                            detail="Linux collector not bundled with this server.")
    return PlainTextResponse(path.read_text(encoding="utf-8"),
                             media_type="text/x-shellscript; charset=utf-8")


@app.get("/api/v1/reports/deploy/agent/linux")
def linux_agent():
    """The Linux agent script."""
    path = settings.agent_dir / "douglas-agent.sh"
    if not path.exists():
        raise HTTPException(status_code=404,
                            detail="Linux agent not bundled with this server.")
    return PlainTextResponse(path.read_text(encoding="utf-8"),
                             media_type="text/x-shellscript; charset=utf-8")


@app.get("/api/v1/reports/deploy/yara-helper")
def yara_helper():
    """The file-content matcher the Linux collector runs.

    Served alongside the collector rather than embedded in it: it is Python,
    the collector is shell, and inlining one inside the other makes both
    harder to read and impossible to test on its own.
    """
    path = settings.agent_dir / "douglas-yara.py"
    if not path.exists():
        raise HTTPException(status_code=404,
                            detail="YARA helper not bundled with this server.")
    return PlainTextResponse(path.read_text(encoding="utf-8"),
                             media_type="text/x-python; charset=utf-8")


@app.get("/api/v1/reports/deploy/sigma-helper")
def sigma_helper():
    """The Sigma evaluator the Linux collector runs."""
    path = settings.agent_dir / "douglas-sigma.py"
    if not path.exists():
        raise HTTPException(status_code=404,
                            detail="Sigma helper not bundled with this server.")
    return PlainTextResponse(path.read_text(encoding="utf-8"),
                             media_type="text/x-python; charset=utf-8")


@app.get("/api/v1/reports/deploy/collector/linux/version")
def linux_collector_version():
    """Hash of the Linux collector, so the agent only downloads on a change."""
    import hashlib

    path = settings.agent_dir / "douglas-042.sh"
    if not path.exists():
        raise HTTPException(status_code=404,
                            detail="Linux collector not bundled with this server.")
    data = path.read_bytes()
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


@app.get("/api/v1/reports/deploy/agent/linux/version")
def linux_agent_version():
    """Hash of the Linux agent, for its own self-update."""
    import hashlib

    path = settings.agent_dir / "douglas-agent.sh"
    if not path.exists():
        raise HTTPException(status_code=404,
                            detail="Linux agent not bundled with this server.")
    data = path.read_bytes()
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


@app.get("/api/v1/reports/deploy/agent/version")
def agent_version():
    """Hash of the agent script this console serves.

    The collector already had this. The agent did not, so a fix to the agent
    never reached a host that had already enrolled.
    """
    import hashlib

    path = settings.agent_dir / "douglas-agent.ps1"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Agent not bundled with this server.")
    data = path.read_bytes()
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


@app.get("/api/v1/reports/deploy/scanner/version")
def scanner_version():
    """Hash of the collector currently served.

    Agents compare this before every hunt. Without it a host keeps running
    whatever collector it was installed with, and console-side updates never
    reach the fleet — which is exactly what happened in the field.
    """
    import hashlib

    linux_path = settings.agent_dir / "douglas-042.sh"
    path = settings.agent_dir / "Douglas-042.ps1"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Collector not bundled with this server.")
    data = path.read_bytes()
    result = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }
    # Linux agents read sha256_linux; serving both from one endpoint keeps the
    # two agents asking the same question.
    if linux_path.exists():
        linux_data = linux_path.read_bytes()
        result["sha256_linux"] = hashlib.sha256(linux_data).hexdigest()
        result["size_linux"] = len(linux_data)
    return result


@app.get("/api/v1/reports/deploy/scanner", response_class=PlainTextResponse)
def serve_scanner_script():
    path = settings.agent_dir / "Douglas-042.ps1"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Collector not bundled with this server.")
    return PlainTextResponse(
        path.read_text(encoding="utf-8"), media_type="text/plain; charset=utf-8"
    )


@app.get("/api/v1/reports/deploy/script", response_class=PlainTextResponse)
def serve_bootstrap(token: str, request: Request, platform: str = "windows",
                    db: Session = Depends(get_db)):
    """The bootstrap an operator pipes into iex or bash. Validates the token first."""
    row = db.get(EnrollmentToken, token)
    if not row or row.revoked:
        raise HTTPException(status_code=401, detail="Enrollment token rejected.")

    # Use the address this very request arrived on, not the configured one.
    #
    # The target machine just fetched this script from that URL, so it is
    # proven reachable from there. A configured address is only a claim, and
    # when the two disagree the script would download fine and then fail on
    # its next call for reasons the error message never explains.
    #
    # Behind a reverse proxy this still resolves correctly, because uvicorn
    # runs with --proxy-headers and honours X-Forwarded-Proto and Host.
    from .routers.reports import _detected_url

    # Same substitution as the deploy screen: a bootstrap script that hardcodes
    # 0.0.0.0 produces an agent that can never reach the console.
    base = _detected_url(request)
    parsed = urlparse(base)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if platform.lower().startswith("lin"):
        # Linux: a shell script piped into bash. Same shape as the Windows one,
        # same checks — refuse without root, name the failure if the console is
        # unreachable rather than dying on a redirect.
        script = f"""#!/usr/bin/env bash
# Douglas-042 agent bootstrap (Linux)
set -uo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this as root: the agent reads paths an unprivileged user cannot." >&2
    exit 1
fi

DIR=/var/lib/douglas042
mkdir -p "$DIR" || exit 1
AGENT="$DIR/douglas-agent.sh"

echo "Console: {base}"
echo "Downloading the Douglas-042 agent..."
if ! curl -sSf --max-time 60 -o "$AGENT" '{base}/api/v1/reports/deploy/agent/linux'; then
    echo
    echo "Could not reach {base} from this host." >&2
    echo
    echo "Check that the console address is reachable from here:"
    echo "  curl -v {base}/health"
    exit 1
fi

chmod 755 "$AGENT"
exec bash "$AGENT" --server '{base}' --token '{token}' --install
"""
        return PlainTextResponse(script, media_type="text/plain; charset=utf-8")

    script = f"""# Douglas-042 agent bootstrap
$ErrorActionPreference = 'Stop'
try {{
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.SecurityProtocolType]::Tls12 -bor [Net.ServicePointManager]::SecurityProtocol
}} catch {{ }}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
$adm = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
if (-not ($pr.IsInRole($adm) -or $id.User.Value -eq 'S-1-5-18')) {{
    Write-Host 'Run this from an elevated PowerShell prompt.' -ForegroundColor Red
    return
}}

$dir = Join-Path $env:ProgramData 'Douglas042'
if (-not (Test-Path $dir)) {{ $null = New-Item $dir -ItemType Directory -Force }}
$agent = Join-Path $dir 'douglas-agent.ps1'

Write-Host "Console: {base}" -ForegroundColor DarkGray
Write-Host 'Downloading the Douglas-042 agent...' -ForegroundColor Cyan
try {{
    Invoke-WebRequest -Uri '{base}/api/v1/reports/deploy/agent' -OutFile $agent -UseBasicParsing
}} catch {{
    Write-Host ''
    Write-Host "Could not reach {base} from this host." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor DarkGray
    Write-Host ''
    Write-Host 'Check that the console address is reachable from here:' -ForegroundColor Yellow
    Write-Host '  Test-NetConnection {host} -Port {port}' -ForegroundColor Yellow
    return
}}

& $agent -Server '{base}' -Token '{token}' -Install
"""
    return PlainTextResponse(script, media_type="text/plain; charset=utf-8")


# ---------------------------------------------------------------------------
# Console shell
# ---------------------------------------------------------------------------

app.mount("/static", StaticFiles(directory=str(settings.static_dir)), name="static")


@app.get("/api/v1/meta")
def console_meta():
    """Constants the console needs so the browser is not repeating them.

    The password floor was written into three separate strings and drifted
    from the value the server actually enforced.
    """
    from .auth import MIN_PASSWORD_LENGTH

    return {"min_password_length": MIN_PASSWORD_LENGTH}


# GET and HEAD are registered separately rather than as one api_route. A single
# function serving both gets one operation id for two operations, which makes
# FastAPI warn and produces an OpenAPI document client generators choke on.
# HEAD is kept out of the schema: uptime monitors use it, readers of the API
# docs do not need to see it twice.
@app.head("/health", include_in_schema=False)
@app.get("/health")
def health():
    """Also reports the build stamp so you can tell which code is live."""
    return {
        "status": "ok",
        "version": settings.version,
        "build": settings.build_stamp,
        "clients": events.client_count(),
    }


def _console_shell() -> HTMLResponse:
    """Serve the console shell with cache-busted asset URLs.

    Browsers hold on to app.js and views.js hard. After an upgrade that left
    people staring at the old UI and concluding the new build had not shipped,
    so the shell is never cached and the assets carry a build stamp.
    """
    html = (settings.static_dir / "index.html").read_text(encoding="utf-8")
    html = html.replace("__BUILD__", settings.build_stamp)
    return HTMLResponse(
        html,
        headers={
            "Cache-Control": "no-store, must-revalidate",
            "Pragma": "no-cache",
        },
    )


# HEAD included because uptime monitors and load balancers commonly probe with
# it, and kept out of the schema for the same reason as /health above.
@app.head("/", include_in_schema=False)
@app.get("/", response_class=HTMLResponse)
def index():
    return _console_shell()


@app.exception_handler(404)
async def spa_fallback(request: Request, exc):
    if request.url.path.startswith(("/api", "/static")):
        return JSONResponse({"detail": getattr(exc, "detail", "Not found")}, status_code=404)
    return _console_shell()
