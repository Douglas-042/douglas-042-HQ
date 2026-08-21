"""Wazuh forwarding and API tokens."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..auth import require_admin, require_console
from ..database import get_db
from ..models import ApiToken, AuditEvent, Integration, Role, new_id, utcnow
from ..services import integrations as svc

router = APIRouter()
token_router = APIRouter()


def _iso(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def integration_dict(i: Integration) -> dict:
    return {
        "id": i.id,
        "name": i.name,
        "kind": i.kind,
        "transport": i.transport,
        "url": i.url or "",
        "host": i.host or "",
        "port": i.port or 514,
        "format": i.format or "json",
        "index_name": i.index_name or "",
        "sourcetype": i.sourcetype or "",
        "recipients": i.recipients or "",
        "mail_from": i.mail_from or "",
        "mail_user": i.mail_user or "",
        "use_tls": bool(i.use_tls),
        "use_ssl": bool(i.use_ssl),
        "has_key": bool(i.api_key),
        "verify_tls": bool(i.verify_tls),
        "min_severity": i.min_severity,
        "enabled": bool(i.enabled),
        "sent_count": i.sent_count or 0,
        "failed_count": i.failed_count or 0,
        "last_attempt_at": _iso(i.last_attempt_at),
        "last_success_at": _iso(i.last_success_at),
        "last_error": i.last_error,
        "created_by": i.created_by,
    }


@router.get("")
def list_integrations(db: Session = Depends(get_db), _u=Depends(require_console)):
    rows = db.query(Integration).order_by(Integration.name).all()
    return {
        "total": len(rows),
        "enabled": sum(1 for i in rows if i.enabled),
        "integrations": [integration_dict(i) for i in rows],
    }


class IntegrationRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    kind: str = "wazuh"
    transport: str = "http"
    url: str = ""
    host: str = ""
    port: int = 514
    api_key: str | None = None
    verify_tls: bool = True
    min_severity: str = "MEDIUM"
    enabled: bool = True
    format: str = "json"
    index_name: str = ""
    sourcetype: str = ""
    recipients: str = ""
    mail_from: str = ""
    mail_user: str = ""
    use_tls: bool = True
    use_ssl: bool = False


FORMATS = {"json", "splunk", "leef", "cef", "ndjson",
           "slack", "teams", "pagerduty", "thehive", "elastic", "sentinel"}
TRANSPORTS = ("http", "syslog", "syslog_tcp", "email")

# Which fields each destination needs, and what to call them there. Declared
# here rather than in the console so the labels can never drift from what the
# sender actually reads — the Sentinel workspace ID and the PagerDuty routing
# key both live in general-purpose columns, and a form that mislabels them
# produces an integration that fails with a confusing error.
FORMAT_FIELDS = {
    "sentinel": {
        "index_name": "Workspace ID",
        "sourcetype": "Log type (table name, without the _CL suffix)",
        "api_key": "Primary or secondary shared key",
        "url": None,
    },
    "pagerduty": {
        "sourcetype": "Integration routing key",
        "index_name": "Console URL to link back to (optional)",
        "api_key": None,
        "url": "Events API URL (https://events.pagerduty.com/v2/enqueue)",
    },
    "slack": {
        "url": "Incoming webhook URL",
        "index_name": "Console URL for the button (optional)",
        "api_key": None, "sourcetype": None,
    },
    "teams": {
        "url": "Workflow or connector webhook URL",
        "index_name": "Console URL for the button (optional)",
        "api_key": None, "sourcetype": None,
    },
    "thehive": {
        "url": "TheHive base URL",
        "api_key": "API key",
        "index_name": None, "sourcetype": None,
    },
    "elastic": {
        "url": "Bulk endpoint (https://host:9200/_bulk)",
        "index_name": "Index name",
        "api_key": "API key",
        "sourcetype": None,
    },
    "splunk": {
        "url": "HEC endpoint (/services/collector/event)",
        "api_key": "HEC token",
        "index_name": "Index", "sourcetype": "Sourcetype",
    },
}


def _validate(payload: IntegrationRequest) -> None:
    if payload.transport not in TRANSPORTS:
        raise HTTPException(
            status_code=400,
            detail=f"Transport must be one of: {', '.join(TRANSPORTS)}.")
    if payload.format not in FORMATS:
        raise HTTPException(status_code=400,
                            detail=f"Format must be one of: {', '.join(sorted(FORMATS))}.")

    if payload.transport == "http":
        if not payload.url.lower().startswith(("http://", "https://")):
            raise HTTPException(status_code=400,
                                detail="An http integration needs an http(s) URL.")
    elif payload.transport in ("syslog", "syslog_tcp"):
        if not payload.host.strip():
            raise HTTPException(status_code=400, detail="A syslog integration needs a host.")
        if not 1 <= payload.port <= 65535:
            raise HTTPException(status_code=400, detail="Port must be between 1 and 65535.")
    else:
        if not payload.host.strip():
            raise HTTPException(status_code=400, detail="Email needs an SMTP server.")
        if not payload.recipients.strip():
            raise HTTPException(status_code=400, detail="Email needs at least one recipient.")
        if "@" not in payload.recipients:
            raise HTTPException(status_code=400, detail="That does not look like an address.")

    if payload.min_severity.upper() not in svc.WAZUH_LEVEL:
        raise HTTPException(status_code=400, detail="Unknown severity floor.")


def _apply(row: Integration, payload: IntegrationRequest) -> None:
    row.name = payload.name.strip()
    row.kind = payload.kind
    row.transport = payload.transport
    row.url = payload.url.strip()
    row.host = payload.host.strip()
    row.port = payload.port
    row.verify_tls = payload.verify_tls
    row.min_severity = payload.min_severity.upper()
    row.enabled = payload.enabled
    row.format = payload.format
    row.index_name = payload.index_name.strip()
    row.sourcetype = payload.sourcetype.strip()
    row.recipients = payload.recipients.strip()
    row.mail_from = payload.mail_from.strip()
    row.mail_user = payload.mail_user.strip()
    row.use_tls = payload.use_tls
    row.use_ssl = payload.use_ssl
    if payload.api_key is not None:
        row.api_key = payload.api_key.strip() or None


@router.post("")
def create_integration(
    payload: IntegrationRequest,
    db: Session = Depends(get_db),
    admin=Depends(require_admin),
):
    _validate(payload)
    row = Integration(id=new_id(), created_by=admin.username)
    _apply(row, payload)
    db.add(row)
    db.add(AuditEvent(kind="integration.created", subject=row.name,
                      detail=f"{row.kind}/{row.transport} by {admin.username}"))
    db.commit()
    db.refresh(row)
    return integration_dict(row)


@router.post("/test")
def test_integration(
    payload: IntegrationRequest,
    admin=Depends(require_admin),
):
    """Send one sample event so a connection is proven before it is saved."""
    _validate(payload)
    probe = Integration(
        transport=payload.transport, url=payload.url.strip(), host=payload.host.strip(),
        port=payload.port, api_key=payload.api_key, verify_tls=payload.verify_tls,
        format=payload.format, index_name=payload.index_name.strip(),
        sourcetype=payload.sourcetype.strip(), recipients=payload.recipients.strip(),
        mail_from=payload.mail_from.strip(), mail_user=payload.mail_user.strip(),
        use_tls=payload.use_tls, use_ssl=payload.use_ssl,
    )
    sample = {
        "integration": "douglas042",
        "douglas": {
            "rule_id": "DGL-TEST", "title": "Douglas-042 connection test",
            "severity": "INFO", "level": 3,
            "evidence": "This event confirms Douglas can reach this destination.",
            "mitre": "", "why": "Sent by an operator from the console.",
        },
        "agent": {"name": "douglas-console", "id": "console", "ip": ""},
    }
    ok, detail = svc.deliver(probe, [sample])
    if not ok:
        raise HTTPException(status_code=400, detail=f"Could not deliver: {detail}")
    where = {"email": "the inbox", "syslog": "the receiver"}.get(
        payload.transport, "the destination")
    return {"ok": True, "message": f"Test event delivered. Look for it in {where}."}


@router.get("/formats")
def list_formats(_u=Depends(require_console)):
    """What each destination expects, so nobody has to guess."""
    formats = [
        {"id": "json", "name": "Wazuh / generic JSON", "group": "siem",
         "note": "One object per finding under an `events` array. What Wazuh's "
                 "integrator and most collectors read."},
        {"id": "splunk", "name": "Splunk HEC", "group": "siem",
         "note": "Splunk's HTTP Event Collector envelope. Point the URL at "
                 "/services/collector/event and use the HEC token as the key."},
        {"id": "sentinel", "name": "Microsoft Sentinel", "group": "siem",
         "note": "Log Analytics data collector. Needs the workspace ID and a "
                 "shared key — the request is signed, not bearer-authenticated. "
                 "The table appears in Sentinel with a _CL suffix."},
        {"id": "elastic", "name": "Elasticsearch / OpenSearch", "group": "siem",
         "note": "Bulk index. Point the URL at /_bulk and give an index name; "
                 "each finding becomes a document with an @timestamp."},
        {"id": "leef", "name": "QRadar (LEEF 2.0)", "group": "siem",
         "note": "One LEEF line per finding. QRadar maps these onto its own "
                 "fields without a custom DSM."},
        {"id": "cef", "name": "CEF (ArcSight and others)", "group": "siem",
         "note": "The common event format most non-Splunk products accept."},
        {"id": "ndjson", "name": "Newline-delimited JSON", "group": "siem",
         "note": "One JSON object per line. For Loki, Vector, or anything "
                 "reading a stream."},

        {"id": "slack", "name": "Slack", "group": "notify",
         "note": "Incoming webhook. Sends a readable summary rather than a "
                 "record dump, and caps how many findings go in one message — "
                 "a channel that gets a hundred lines pasted into it is a "
                 "channel people mute. Set the severity floor to HIGH or above."},
        {"id": "teams", "name": "Microsoft Teams", "group": "notify",
         "note": "Workflow or connector webhook, sent as an Adaptive Card. "
                 "Same advice on the severity floor as Slack."},
        {"id": "pagerduty", "name": "PagerDuty", "group": "notify",
         "note": "Events API v2. One incident per batch with a dedup key built "
                 "from the host and rule, so a noisy rule is one incident to "
                 "work rather than forty pages. CRITICAL only, realistically."},

        {"id": "thehive", "name": "TheHive", "group": "case",
         "note": "Creates one alert per finding so each can be triaged "
                 "separately. Re-sending updates the existing alert instead of "
                 "duplicating work somebody already closed."},
    ]
    return {
        "formats": formats,
        "fields": FORMAT_FIELDS,
        "transports": [
            {"id": "http", "name": "HTTP POST"},
            {"id": "syslog", "name": "Syslog (UDP)"},
            {"id": "syslog_tcp", "name": "Syslog (TCP)",
             "note": "UDP drops silently under load. Use TCP if you would "
                     "rather a lost finding be an error than a silence."},
            {"id": "email", "name": "Email (SMTP)"},
        ],
        "groups": [
            {"id": "siem", "name": "Send everything to a SIEM",
             "note": "Indexed and searchable later. A low severity floor is fine here."},
            {"id": "notify", "name": "Tell someone now",
             "note": "Written for a human to read without opening anything. "
                     "Keep the severity floor high or people stop reading it."},
            {"id": "case", "name": "Open a case",
             "note": "Creates work somebody is expected to pick up."},
        ],
    }


@router.post("/{integration_id}")
def update_integration(
    integration_id: str,
    payload: IntegrationRequest,
    db: Session = Depends(get_db),
    admin=Depends(require_admin),
):
    row = db.get(Integration, integration_id)
    if not row:
        raise HTTPException(status_code=404, detail="No such integration.")
    _validate(payload)
    _apply(row, payload)
    db.commit()
    db.refresh(row)
    return integration_dict(row)


@router.delete("/{integration_id}")
def delete_integration(
    integration_id: str,
    db: Session = Depends(get_db),
    admin=Depends(require_admin),
):
    row = db.get(Integration, integration_id)
    if not row:
        raise HTTPException(status_code=404, detail="No such integration.")
    db.add(AuditEvent(kind="integration.deleted", subject=row.name,
                      detail=f"by {admin.username}"))
    db.delete(row)
    db.commit()
    return {"deleted": integration_id}


# ---------------------------------------------------------------------------
# API tokens
# ---------------------------------------------------------------------------


def token_dict(t: ApiToken) -> dict:
    return {
        "id": t.id,
        "name": t.name,
        "prefix": t.prefix,
        "role": t.role.value if hasattr(t.role, "value") else str(t.role),
        "enabled": bool(t.enabled),
        "use_count": t.use_count or 0,
        "last_used_at": _iso(t.last_used_at),
        "expires_at": _iso(t.expires_at),
        "created_at": _iso(t.created_at),
        "created_by": t.created_by,
    }


@token_router.get("")
def list_tokens(db: Session = Depends(get_db), admin=Depends(require_admin)):
    rows = db.query(ApiToken).order_by(ApiToken.name).all()
    return {"total": len(rows), "tokens": [token_dict(t) for t in rows]}


class TokenRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    role: str = "viewer"
    expires_days: int = 0  # 0 means it does not expire


@token_router.post("")
def create_token(
    payload: TokenRequest,
    db: Session = Depends(get_db),
    admin=Depends(require_admin),
):
    try:
        role = Role(payload.role.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail="Unknown role.")
    if role == Role.ADMIN:
        raise HTTPException(
            status_code=400,
            detail="Tokens cannot hold admin. Account management should need a person.",
        )

    raw = svc.new_token()
    row = ApiToken(
        id=new_id(),
        name=payload.name.strip(),
        fingerprint=svc.token_fingerprint(raw),
        prefix=raw[:12],
        role=role,
        created_by=admin.username,
    )
    if payload.expires_days > 0:
        row.expires_at = datetime.now(timezone.utc) + timedelta(days=payload.expires_days)

    db.add(row)
    db.add(AuditEvent(kind="token.created", subject=row.name,
                      detail=f"{role.value} by {admin.username}"))
    db.commit()
    db.refresh(row)

    # The only time the token itself is ever returned.
    return {"token": raw, "detail": token_dict(row)}


class ToggleRequest(BaseModel):
    enabled: bool


@token_router.post("/{token_id}/toggle")
def toggle_token(
    token_id: str,
    payload: ToggleRequest,
    db: Session = Depends(get_db),
    admin=Depends(require_admin),
):
    row = db.get(ApiToken, token_id)
    if not row:
        raise HTTPException(status_code=404, detail="No such token.")
    row.enabled = payload.enabled
    db.commit()
    return token_dict(row)


@token_router.delete("/{token_id}")
def delete_token(
    token_id: str,
    db: Session = Depends(get_db),
    admin=Depends(require_admin),
):
    row = db.get(ApiToken, token_id)
    if not row:
        raise HTTPException(status_code=404, detail="No such token.")
    db.add(AuditEvent(kind="token.revoked", subject=row.name,
                      detail=f"by {admin.username}"))
    db.delete(row)
    db.commit()
    return {"deleted": token_id}
