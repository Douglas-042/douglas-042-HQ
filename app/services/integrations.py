"""Sending findings to Wazuh, and letting other tools read Douglas.

Two directions, both optional:

  outbound  Findings are forwarded to Wazuh so they surface in the SIEM an
            analyst already watches. A hunting console nobody opens is a
            hunting console nobody reads.

  inbound   API tokens let Wazuh, a scheduler or a script call Douglas without
            a browser session.

Delivery is best-effort and never blocks a hunt. If Wazuh is down, the finding
is still recorded here and the failure is shown on the integration, rather than
the upload being rejected.
"""
from __future__ import annotations

import json
import logging
import secrets
import socket
import threading
import urllib.error
import urllib.request
from datetime import timezone

logger = logging.getLogger("douglas.integrations")

SEND_TIMEOUT = 20

# Douglas severities mapped onto the Wazuh rule levels an analyst expects.
# Wazuh treats 12+ as high priority by default, so critical lands above that.
WAZUH_LEVEL = {
    "CRITICAL": 14,
    "HIGH": 12,
    "MEDIUM": 8,
    "LOW": 5,
    "INFO": 3,
}


def new_token() -> str:
    """A token the operator sees exactly once."""
    return "dgl_" + secrets.token_urlsafe(36)


def token_fingerprint(token: str) -> str:
    """Stored instead of the token, so the database never holds a usable key."""
    import hashlib

    return hashlib.sha256(token.encode()).hexdigest()


def _iso(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def build_event(finding, job, agent) -> dict:
    """One finding, in the shape Wazuh's JSON decoder reads cleanly."""
    return {
        "integration": "douglas042",
        "douglas": {
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity,
            "level": WAZUH_LEVEL.get((finding.severity or "INFO").upper(), 3),
            "evidence": (finding.evidence or "")[:2000],
            "mitre": finding.mitre or "",
            "why": (finding.why or "")[:500],
            "artifact": finding.artifact or "",
            "occurred_at": _iso(getattr(finding, "occurred_at", None)),
            "job_id": job.id if job else None,
            "risk_score": (job.risk_score or 0) if job else 0,
        },
        "agent": {
            "name": (agent.hostname if agent else None) or (job.hostname if job else ""),
            "id": agent.id if agent else "",
            "ip": (agent.ip_address if agent else "") or "",
        },
    }


# ---------------------------------------------------------------------------
# Formats
#
# Every SIEM claims to accept JSON and then wants its own envelope. Rather than
# a connector per product, the same event is rendered into whichever dialect the
# destination speaks. What travels is always the finding — a decision Douglas
# made — never raw event log, which the SIEM already has.
# ---------------------------------------------------------------------------


def _cef_escape(value: str) -> str:
    return (str(value).replace("\\", "\\\\").replace("|", "\\|")
            .replace("=", "\\=").replace("\n", " "))


def to_splunk_hec(event: dict, index: str = "", sourcetype: str = "") -> dict:
    """Splunk's HTTP Event Collector envelope.

    Splunk wants the payload under `event` with its own metadata alongside;
    posting a bare object gets a 400 that says nothing useful.
    """
    d = event["douglas"]
    payload = {
        "time": None,
        "host": event["agent"]["name"] or "douglas",
        "source": "douglas-042",
        "sourcetype": sourcetype or "douglas:finding",
        "event": {**d, "agent": event["agent"]},
    }
    if index:
        payload["index"] = index
    payload = {k: v for k, v in payload.items() if v is not None}
    return payload


def to_leef(event: dict) -> str:
    """QRadar's LEEF 2.0, one line per finding.

    QRadar parses LEEF natively and maps the attributes onto its own fields
    without anyone writing a DSM extension, which is the difference between an
    integration that works on day one and a support ticket.
    """
    d = event["douglas"]
    a = event["agent"]
    header = "|".join([
        "LEEF:2.0", "Behind24", "Douglas-042", "2.0",
        str(d.get("rule_id") or "DGL"),
    ])
    attrs = {
        "devTime": d.get("occurred_at") or "",
        "sev": min(10, max(1, int(d.get("level", 3) * 10 / 14))),
        "cat": d.get("severity") or "INFO",
        "identSrc": a.get("ip") or "",
        "identHostName": a.get("name") or "",
        "resource": d.get("artifact") or "",
        "mitreTechnique": d.get("mitre") or "",
        "title": d.get("title") or "",
        "evidence": (d.get("evidence") or "")[:900],
        "why": (d.get("why") or "")[:400],
        "riskScore": d.get("risk_score", 0),
        "jobId": d.get("job_id") or "",
    }
    body = "\t".join(f"{k}={str(v)}".replace("\n", " ") for k, v in attrs.items() if v != "")
    return f"{header}|{body}"


def to_cef(event: dict) -> str:
    """CEF, understood by ArcSight and most things that are not Splunk."""
    d = event["douglas"]
    a = event["agent"]
    # CEF severity is 0-10; our level is 0-14.
    sev = min(10, max(0, int(d.get("level", 3) * 10 / 14)))
    header = "|".join([
        "CEF:0", "Behind24", "Douglas-042", "2.0",
        _cef_escape(d.get("rule_id") or "DGL"),
        _cef_escape(d.get("title") or "Finding"),
        str(sev),
    ])
    ext = {
        "dvchost": a.get("name") or "",
        "src": a.get("ip") or "",
        "rt": d.get("occurred_at") or "",
        "cs1Label": "MITRE", "cs1": d.get("mitre") or "",
        "cs2Label": "Artifact", "cs2": d.get("artifact") or "",
        "cs3Label": "Why", "cs3": (d.get("why") or "")[:400],
        "msg": (d.get("evidence") or "")[:900],
        "cn1Label": "RiskScore", "cn1": d.get("risk_score", 0),
    }
    body = " ".join(f"{k}={_cef_escape(v)}" for k, v in ext.items() if v != "")
    return f"{header}|{body}"


# ---------------------------------------------------------------------------
# Chat, paging and case destinations
#
# These differ from the SIEM formats above in what they are for. A SIEM wants
# every finding, indexed and searchable later. A chat channel or a pager wants
# the few that somebody should look at now, written so a human reads it without
# opening anything — which is why these render a sentence rather than a record,
# and why their severity floor should be set higher than a SIEM's.
# ---------------------------------------------------------------------------

_SEV_COLOUR = {
    "CRITICAL": "#FF2D55", "HIGH": "#FF7A00", "MEDIUM": "#FFC531",
    "LOW": "#22D9F5", "INFO": "#7A93B8",
}


def _headline(events: list[dict]) -> tuple[str, str]:
    """A one-line summary and the worst severity across a batch."""
    worst, rank = "INFO", -1
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    hosts: set = set()
    for e in events:
        sev = (e.get("douglas", {}).get("severity") or "INFO").upper()
        if order.index(sev) > rank if sev in order else False:
            worst, rank = sev, order.index(sev)
        name = e.get("agent", {}).get("name") or ""
        if name:
            hosts.add(name)

    count = len(events)
    where = (next(iter(hosts)) if len(hosts) == 1
             else f"{len(hosts)} hosts" if hosts else "the fleet")
    return f"{count} {worst} finding{'' if count == 1 else 's'} on {where}", worst


def to_slack(events: list[dict], console_url: str = "") -> dict:
    """Slack incoming webhook.

    Blocks rather than a wall of text, and capped at a handful of findings: a
    channel that gets a hundred lines pasted into it is a channel people mute,
    and a muted channel is worse than no integration at all.
    """
    summary, worst = _headline(events)
    shown = events[:8]
    lines = []
    for e in shown:
        d = e.get("douglas", {})
        host = e.get("agent", {}).get("name") or "?"
        lines.append(
            f"*{d.get('severity', 'INFO')}*  `{d.get('rule_id', '')}`  "
            f"{d.get('title', '')}\n_{host}_ — {(d.get('evidence') or '')[:160]}"
        )

    blocks = [
        {"type": "header",
         "text": {"type": "plain_text", "text": f"Douglas-042: {summary}"[:150]}},
        {"type": "section",
         "text": {"type": "mrkdwn", "text": "\n\n".join(lines)[:2900]}},
    ]
    if len(events) > len(shown):
        blocks.append({"type": "context", "elements": [
            {"type": "mrkdwn",
             "text": f"and {len(events) - len(shown)} more — open the console for the rest"}]})
    if console_url:
        blocks.append({"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": "Open Douglas"},
             "url": console_url}]})

    return {"text": f"Douglas-042: {summary}", "blocks": blocks}


def to_teams(events: list[dict], console_url: str = "") -> dict:
    """Microsoft Teams, as an Adaptive Card inside the workflow envelope."""
    summary, worst = _headline(events)
    facts = []
    for e in events[:8]:
        d = e.get("douglas", {})
        facts.append({
            "title": f"{d.get('severity', 'INFO')} · {d.get('rule_id', '')}",
            "value": f"{d.get('title', '')} — {e.get('agent', {}).get('name', '?')}: "
                     f"{(d.get('evidence') or '')[:160]}",
        })

    body = [
        {"type": "TextBlock", "size": "Large", "weight": "Bolder",
         "text": f"Douglas-042: {summary}"[:150],
         "color": "Attention" if worst in ("CRITICAL", "HIGH") else "Default"},
        {"type": "FactSet", "facts": facts},
    ]
    if len(events) > 8:
        body.append({"type": "TextBlock", "isSubtle": True, "wrap": True,
                     "text": f"and {len(events) - 8} more"})

    card = {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.4",
        "body": body,
    }
    if console_url:
        card["actions"] = [{"type": "Action.OpenUrl", "title": "Open Douglas",
                            "url": console_url}]

    return {"type": "message", "attachments": [
        {"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}


def to_pagerduty(events: list[dict], routing_key: str, console_url: str = "") -> dict:
    """PagerDuty Events API v2.

    One event per batch rather than per finding, with a dedup key built from
    the host and rule: forty findings from one noisy rule should be one
    incident somebody works, not forty pages at three in the morning.
    """
    summary, worst = _headline(events)
    first = events[0].get("douglas", {}) if events else {}
    host = events[0].get("agent", {}).get("name", "") if events else ""
    severity = {"CRITICAL": "critical", "HIGH": "error",
                "MEDIUM": "warning"}.get(worst, "info")

    return {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": f"douglas/{host}/{first.get('rule_id', 'batch')}"[:250],
        "client": "Douglas-042",
        "client_url": console_url or "",
        "payload": {
            "summary": summary[:1024],
            "severity": severity,
            "source": host or "douglas-042",
            "component": first.get("artifact", "") or "hunt",
            "class": first.get("rule_id", "") or "",
            "custom_details": {
                "findings": [
                    {
                        "rule": e.get("douglas", {}).get("rule_id"),
                        "severity": e.get("douglas", {}).get("severity"),
                        "title": e.get("douglas", {}).get("title"),
                        "host": e.get("agent", {}).get("name"),
                        "evidence": (e.get("douglas", {}).get("evidence") or "")[:300],
                    }
                    for e in events[:20]
                ],
                "total": len(events),
            },
        },
    }


def to_thehive(events: list[dict]) -> list[dict]:
    """TheHive alerts — one per finding, so each can be triaged on its own.

    sourceRef is the finding's own identity rather than a timestamp, so a
    re-sent batch updates the existing alert instead of filling the queue with
    copies of work somebody already closed.
    """
    alerts = []
    for e in events[:50]:
        d = e.get("douglas", {})
        host = e.get("agent", {}).get("name") or ""
        sev = (d.get("severity") or "INFO").upper()
        alerts.append({
            "type": "douglas-finding",
            "source": "Douglas-042",
            "sourceRef": f"{d.get('job_id', '')}-{d.get('rule_id', '')}-{host}"[:128],
            "title": f"[{sev}] {d.get('title', '')}"[:256],
            "description": (
                f"**Host:** {host}\n\n"
                f"**Rule:** {d.get('rule_id', '')}\n\n"
                f"**Evidence:**\n```\n{(d.get('evidence') or '')[:1500]}\n```\n\n"
                f"{d.get('why', '')}"
            ),
            "severity": {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2}.get(sev, 1),
            "tags": [t for t in ["douglas-042", d.get("rule_id", ""),
                                 d.get("mitre", "")] if t],
            "observables": (
                [{"dataType": "other", "data": (d.get("evidence") or "")[:400]}]
                if d.get("evidence") else []
            ),
        })
    return alerts


def to_elastic_bulk(events: list[dict], index: str) -> bytes:
    """Elasticsearch _bulk: an action line and a document line per event."""
    index = index or "douglas-findings"
    out: list[str] = []
    for e in events:
        out.append(json.dumps({"index": {"_index": index}}))
        d = dict(e.get("douglas", {}))
        d["host"] = e.get("agent", {}).get("name", "")
        d["host_ip"] = e.get("agent", {}).get("ip", "")
        d["@timestamp"] = d.get("occurred_at") or _now_iso()
        out.append(json.dumps(d))
    # A bulk body has to end with a newline or Elasticsearch rejects it.
    return ("\n".join(out) + "\n").encode()


def _now_iso() -> str:
    from datetime import datetime, timezone as _tz

    return datetime.now(_tz.utc).isoformat()


def to_sentinel(events: list[dict]) -> bytes:
    """Microsoft Sentinel via the Log Analytics collector: a plain JSON array."""
    rows = []
    for e in events:
        d = dict(e.get("douglas", {}))
        d["Host"] = e.get("agent", {}).get("name", "")
        d["HostIp"] = e.get("agent", {}).get("ip", "")
        rows.append(d)
    return json.dumps(rows).encode()


def send_sentinel(workspace_id: str, shared_key: str, log_type: str,
                  events: list[dict]) -> tuple[int, str]:
    """Log Analytics wants an HMAC over a canonical string, not a bearer token.

    Kept separate from send_http because the signature covers the body length
    and the date header, so it cannot be built until the body exists — the one
    destination where auth is not just another header to attach.
    """
    import base64
    import hashlib
    import hmac
    from email.utils import formatdate

    if not workspace_id or not shared_key:
        return 0, "Sentinel needs a workspace ID and a shared key."

    body = to_sentinel(events)
    rfc1123 = formatdate(timeval=None, localtime=False, usegmt=True)
    canonical = (
        f"POST\n{len(body)}\napplication/json\n"
        f"x-ms-date:{rfc1123}\n/api/logs"
    )
    try:
        decoded = base64.b64decode(shared_key)
    except Exception:
        return 0, "That shared key is not valid base64."

    signature = base64.b64encode(
        hmac.new(decoded, canonical.encode("utf-8"), hashlib.sha256).digest()
    ).decode()

    url = (f"https://{workspace_id}.ods.opinsights.azure.com/api/logs"
           "?api-version=2016-04-01")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"SharedKey {workspace_id}:{signature}",
        "Log-Type": (log_type or "Douglas042")[:100],
        "x-ms-date": rfc1123,
        "time-generated-field": "occurred_at",
    }
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=SEND_TIMEOUT) as resp:
            return resp.status, ""
    except urllib.error.HTTPError as exc:
        return exc.code, f"Sentinel rejected it: HTTP {exc.code}"
    except urllib.error.URLError as exc:
        return 0, f"Could not reach Sentinel ({getattr(exc, 'reason', exc)})"


def render(events: list[dict], fmt: str, index: str = "",
           sourcetype: str = "") -> tuple[bytes, str]:
    """Turn events into the body and content type a destination expects."""
    fmt = (fmt or "json").lower()

    if fmt == "splunk":
        # HEC takes concatenated JSON objects, not an array.
        body = "".join(
            json.dumps(to_splunk_hec(e, index, sourcetype)) for e in events
        ).encode()
        return body, "application/json"

    if fmt == "leef":
        return ("\n".join(to_leef(e) for e in events)).encode(), "text/plain"

    if fmt == "cef":
        return ("\n".join(to_cef(e) for e in events)).encode(), "text/plain"

    if fmt == "ndjson":
        return ("\n".join(json.dumps(e) for e in events)).encode(), "application/x-ndjson"

    if fmt == "slack":
        return json.dumps(to_slack(events, index)).encode(), "application/json"

    if fmt == "teams":
        return json.dumps(to_teams(events, index)).encode(), "application/json"

    if fmt == "pagerduty":
        # The routing key travels in the body for this one, so it is passed
        # through the sourcetype slot the console labels "Routing key".
        return json.dumps(to_pagerduty(events, sourcetype, index)).encode(), "application/json"

    if fmt == "thehive":
        # TheHive takes one alert per request, so the caller sends them in a
        # loop; this renders the first and is only used for a preview.
        alerts = to_thehive(events)
        return json.dumps(alerts[0] if alerts else {}).encode(), "application/json"

    if fmt == "elastic":
        return to_elastic_bulk(events, index), "application/x-ndjson"

    if fmt == "sentinel":
        return to_sentinel(events), "application/json"

    # Default: what Wazuh and generic collectors read.
    return json.dumps({"events": events}).encode(), "application/json"


def auth_header(fmt: str, api_key: str) -> dict:
    """Each product spells its own authorisation differently."""
    if not api_key:
        return {}
    if fmt == "splunk":
        return {"Authorization": f"Splunk {api_key}"}
    if fmt == "elastic":
        # Elastic accepts either; an API key is the one to prefer, and a value
        # holding a colon is a base64 user:pass that means basic auth.
        return {"Authorization": f"ApiKey {api_key}"}
    if fmt in ("slack", "teams", "pagerduty"):
        # The URL is the credential for a webhook, and PagerDuty carries its
        # routing key in the body. Sending a bearer token to any of them is at
        # best ignored and at worst a 400.
        return {}
    return {"Authorization": f"Bearer {api_key}"}


def send_http(url: str, events: list[dict], api_key: str = "",
              verify_tls: bool = True, fmt: str = "json",
              index: str = "", sourcetype: str = "") -> tuple[int, str]:
    """POST events to a Wazuh integration endpoint or any JSON collector."""
    payload, content_type = render(events, fmt, index, sourcetype)
    headers = {"Content-Type": content_type, "User-Agent": "Douglas-042",
               **auth_header(fmt, api_key)}

    ctx = None
    if not verify_tls:
        import ssl

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    request = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=SEND_TIMEOUT, context=ctx) as resp:
            return resp.status, ""
    except urllib.error.HTTPError as exc:
        return exc.code, f"HTTP {exc.code}"
    except urllib.error.URLError as exc:
        return 0, str(getattr(exc, "reason", exc))


def send_syslog(host: str, port: int, events: list[dict],
                fmt: str = "json") -> tuple[int, str]:
    """One JSON object per datagram, which is how Wazuh's logcollector reads it.

    Offered because plenty of Wazuh deployments have no HTTP integration
    configured but every one of them accepts syslog.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(SEND_TIMEOUT)
        for event in events:
            if fmt == "leef":
                line = to_leef(event)
            elif fmt == "cef":
                line = to_cef(event)
            else:
                line = "douglas042: " + json.dumps(event, separators=(",", ":"))
            # Datagrams over ~1200 bytes get fragmented or dropped on the way.
            if len(line) > 1200:
                trimmed = dict(event)
                trimmed["douglas"] = dict(event["douglas"])
                trimmed["douglas"]["evidence"] = trimmed["douglas"]["evidence"][:600]
                trimmed["douglas"]["why"] = ""
                if fmt == "leef":
                    line = to_leef(trimmed)
                elif fmt == "cef":
                    line = to_cef(trimmed)
                else:
                    line = "douglas042: " + json.dumps(trimmed, separators=(",", ":"))
            sock.sendto(line.encode("utf-8", errors="replace"), (host, port))
        sock.close()
        return 200, ""
    except Exception as exc:  # noqa: BLE001 - reported on the integration row
        return 0, str(exc)


def send_email(integration, events: list[dict]) -> tuple[int, str]:
    """A readable summary rather than raw JSON.

    Nobody triages from an inbox, so the mail exists to make someone open the
    console. It leads with the worst finding and the host, and stops there.
    """
    import smtplib
    from email.message import EmailMessage

    if not integration.host or not integration.recipients:
        return 0, "email needs a server and at least one recipient"

    by_sev: dict[str, list] = {}
    for e in events:
        by_sev.setdefault(e["douglas"]["severity"], []).append(e)

    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    worst = next((s for s in order if by_sev.get(s)), "INFO")
    hosts = sorted({e["agent"]["name"] for e in events if e["agent"]["name"]})
    lead = by_sev[worst][0]["douglas"]

    subject = (f"[Douglas-042] {worst}: {lead['title']}"
               f" on {hosts[0] if hosts else 'a host'}")
    if len(events) > 1:
        subject += f" (+{len(events) - 1} more)"

    lines = [
        f"{len(events)} finding{'s' if len(events) != 1 else ''} "
        f"across {len(hosts)} host{'s' if len(hosts) != 1 else ''}.",
        "",
        "By severity: " + ", ".join(
            f"{s} {len(by_sev[s])}" for s in order if by_sev.get(s)),
        "",
        "Most serious:",
    ]
    for e in (by_sev[worst])[:10]:
        d = e["douglas"]
        lines += [
            f"  [{d['severity']}] {d['rule_id']}  {d['title']}",
            f"      host: {e['agent']['name']}",
            f"      {d['evidence'][:200]}",
        ]
        if d.get("why"):
            lines.append(f"      {d['why'][:200]}")
        lines.append("")
    if len(by_sev[worst]) > 10:
        lines.append(f"  ... and {len(by_sev[worst]) - 10} more at this severity.")
    lines += ["", "Open the console to triage these."]

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = integration.mail_from or "douglas042@localhost"
    message["To"] = integration.recipients
    message.set_content("\n".join(lines))

    try:
        port = integration.port or 25
        if integration.use_ssl:
            server = smtplib.SMTP_SSL(integration.host, port, timeout=SEND_TIMEOUT)
        else:
            server = smtplib.SMTP(integration.host, port, timeout=SEND_TIMEOUT)
            if integration.use_tls:
                server.starttls()
        try:
            if integration.mail_user and integration.api_key:
                server.login(integration.mail_user, integration.api_key)
            server.send_message(message)
        finally:
            server.quit()
        return 200, ""
    except Exception as exc:  # noqa: BLE001 - shown on the integration row
        return 0, str(exc)[:300]


def deliver(integration, events: list[dict]) -> tuple[bool, str]:
    """Send by whichever transport this integration is configured for."""
    if not events:
        return True, ""

    fmt = getattr(integration, "format", None) or "json"
    index = getattr(integration, "index_name", "") or ""
    sourcetype = getattr(integration, "sourcetype", "") or ""

    # Sentinel signs the body, so it cannot go through the generic sender.
    if fmt == "sentinel":
        code, detail = send_sentinel(index, integration.api_key or "",
                                     sourcetype, events)
    # TheHive takes one alert per request. Sent in a loop, and a partial
    # failure is reported as one: some alerts landing is not success, but it
    # is not the same as none landing either.
    elif fmt == "thehive":
        base = (integration.url or "").rstrip("/")
        url = base if base.endswith("/alert") else base + "/api/alert"
        sent, failed, last = 0, 0, ""
        for alert in to_thehive(events):
            body = json.dumps(alert).encode()
            request = urllib.request.Request(
                url, data=body, method="POST",
                headers={"Content-Type": "application/json",
                         "Authorization": f"Bearer {integration.api_key or ''}",
                         "User-Agent": "Douglas-042"})
            try:
                ctx = _tls_context(bool(integration.verify_tls))
                with urllib.request.urlopen(request, timeout=SEND_TIMEOUT,
                                            context=ctx) as resp:
                    if 200 <= resp.status < 300:
                        sent += 1
                    else:
                        failed += 1
            except urllib.error.HTTPError as exc:
                # 409 means TheHive already has this alert, which is the
                # deduplication working rather than a failure.
                if exc.code == 409:
                    sent += 1
                else:
                    failed += 1
                    last = f"HTTP {exc.code}"
            except Exception as exc:  # noqa: BLE001
                failed += 1
                last = str(exc)[:120]
        if failed and not sent:
            return False, last or "no alerts were accepted"
        if failed:
            return False, f"{sent} of {sent + failed} alerts accepted; last error: {last}"
        return True, ""

    elif integration.transport == "email":
        code, detail = send_email(integration, events)
    elif integration.transport == "syslog_tcp":
        code, detail = send_syslog_tcp(integration.host or "",
                                       integration.port or 514, events, fmt)
    elif integration.transport == "syslog":
        code, detail = send_syslog(integration.host or "", integration.port or 514,
                                   events, fmt)
    else:
        code, detail = send_http(
            integration.url or "", events, integration.api_key or "",
            bool(integration.verify_tls), fmt, index, sourcetype,
        )

    if 200 <= code < 300:
        return True, ""
    return False, detail or f"delivery failed ({code})"


def _tls_context(verify: bool):
    if verify:
        return None
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def send_syslog_tcp(host: str, port: int, events: list[dict],
                    fmt: str = "cef") -> tuple[int, str]:
    """Syslog over TCP.

    UDP is the default because it is what most collectors listen on, but it
    drops silently under load — and a SIEM feed that quietly loses findings is
    worse than one that fails loudly. TCP is the option for anyone who would
    rather know.
    """
    if not host:
        return 0, "No syslog host configured."

    lines = []
    for event in events:
        payload = (to_cef(event) if fmt != "leef" else to_leef(event))
        lines.append(payload)

    try:
        with socket.create_connection((host, int(port or 514)), timeout=SEND_TIMEOUT) as sock:
            for line in lines:
                # Octet counting, which is the framing RFC 6587 recommends and
                # what a collector expecting TCP syslog will parse. Newline
                # framing breaks on any message containing one.
                body = line.encode("utf-8", errors="replace")[:8000]
                sock.sendall(f"{len(body)} ".encode() + body)
        return 200, ""
    except OSError as exc:
        return 0, f"Could not reach {host}:{port} ({exc})"


def deliver_async(integration_id: str, events: list[dict]) -> None:
    """Fire and forget, so a slow SIEM never holds up a results upload."""

    def _run():
        from ..database import SessionLocal
        from ..models import Integration, utcnow

        db = SessionLocal()
        try:
            row = db.get(Integration, integration_id)
            if not row or not row.enabled:
                return
            ok, detail = deliver(row, events)
            row.last_attempt_at = utcnow()
            if ok:
                row.last_success_at = utcnow()
                row.sent_count = (row.sent_count or 0) + len(events)
                row.last_error = None
            else:
                row.last_error = detail[:400]
                row.failed_count = (row.failed_count or 0) + len(events)
                logger.warning("Integration '%s' failed: %s", row.name, detail)
            db.commit()
        except Exception as exc:  # pragma: no cover - never kill the thread
            logger.warning("Integration delivery error: %s", exc)
        finally:
            db.close()

    threading.Thread(target=_run, name="douglas-integration", daemon=True).start()


def forward_findings(db, job, agent, findings) -> None:
    """Push a completed hunt's findings to every enabled integration."""
    from ..models import Integration

    rows = db.query(Integration).filter(Integration.enabled == True).all()  # noqa: E712
    if not rows:
        return

    for row in rows:
        floor = WAZUH_LEVEL.get((row.min_severity or "MEDIUM").upper(), 8)
        selected = [
            f for f in findings
            if WAZUH_LEVEL.get((f.severity or "INFO").upper(), 0) >= floor
        ]
        if not selected:
            continue
        # A cap per hunt: forwarding 3000 findings turns the SIEM into the same
        # unreadable list the console already learned to trim.
        events = [build_event(f, job, agent) for f in selected[:500]]
        deliver_async(row.id, events)
