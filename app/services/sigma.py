"""Compile Sigma rules into a plan the PowerShell agent can execute.

The hard work happens here rather than on the agent: YAML parsing, condition
grammar, field mapping and logsource resolution are all things Python does well
and PowerShell does badly. What crosses the wire is a small JSON structure with
three primitives — field, operator, values — plus a boolean tree over named
selections. The agent evaluator only has to understand those.

Deliberately narrow. Sigma's full grammar includes aggregations, correlation
and timeframes that need a search backend to answer. A rule using them is
rejected with a reason rather than silently half-matched, because a detection
that quietly tests less than it claims is worse than no detection.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Field mapping
# ---------------------------------------------------------------------------

# Sigma field name -> the Data element name Windows actually writes.
# The agent reads events as XML and keys on these, so the mapping stays true
# regardless of property ordering, which differs between OS builds.
FIELD_MAP: dict[str, str] = {
    # Process creation (Security 4688 / Sysmon 1)
    "Image": "NewProcessName",
    "ProcessName": "NewProcessName",
    "CommandLine": "ProcessCommandLine",
    "ParentImage": "ParentProcessName",
    "ParentCommandLine": "ParentCommandLine",
    "ParentProcessName": "ParentProcessName",
    "User": "SubjectUserName",
    "SubjectUserName": "SubjectUserName",
    "TargetUserName": "TargetUserName",
    "IntegrityLevel": "MandatoryLabel",
    "OriginalFileName": "OriginalFileName",
    "CurrentDirectory": "CurrentDirectory",
    "LogonId": "SubjectLogonId",
    # Network
    "DestinationIp": "DestAddress",
    "DestinationPort": "DestPort",
    "SourceIp": "SourceAddress",
    "SourcePort": "SourcePort",
    "DestinationHostname": "DestinationHostname",
    "Initiated": "Initiated",
    "Protocol": "Protocol",
    # Services
    "ServiceName": "ServiceName",
    "ServiceFileName": "ImagePath",
    "ImagePath": "ImagePath",
    "StartType": "StartType",
    "ServiceType": "ServiceType",
    "AccountName": "AccountName",
    # Registry
    "TargetObject": "TargetObject",
    "Details": "Details",
    "EventType": "EventType",
    # Files and images
    "TargetFilename": "TargetFilename",
    "ImageLoaded": "ImageLoaded",
    "Signed": "Signed",
    "Signature": "Signature",
    "Hashes": "Hashes",
    # Logon
    "LogonType": "LogonType",
    "IpAddress": "IpAddress",
    "WorkstationName": "WorkstationName",
    "AuthenticationPackageName": "AuthenticationPackageName",
    "LogonProcessName": "LogonProcessName",
    "Status": "Status",
    "SubStatus": "SubStatus",
    "TicketEncryptionType": "TicketEncryptionType",
    "ServiceSid": "ServiceSid",
    # Pipes and WMI
    "PipeName": "PipeName",
    "Query": "Query",
    "Operation": "Operation",
    "Consumer": "Consumer",
    "Destination": "Destination",
    # PowerShell
    "ScriptBlockText": "ScriptBlockText",
    "Payload": "Payload",
    "ContextInfo": "ContextInfo",
    "HostApplication": "HostApplication",
    # Scheduled tasks
    "TaskName": "TaskName",
    # Generic
    "EventID": "EventID",
    "Channel": "Channel",
    "Provider_Name": "Provider_Name",
    "SourceImage": "SourceImage",
    "TargetImage": "TargetImage",
    "GrantedAccess": "GrantedAccess",
    "CallTrace": "CallTrace",
    "StartModule": "StartModule",
    "StartFunction": "StartFunction",
}

# logsource -> (channel, default event ids)
# Only the sources the collector can actually read are listed; anything else is
# rejected up front rather than compiling into a rule that can never fire.
LOGSOURCE_MAP: dict[tuple[str | None, str | None], tuple[str, list[int]]] = {
    (None, "process_creation"): ("Security", [4688]),
    (None, "process_access"): ("Microsoft-Windows-Sysmon/Operational", [10]),
    (None, "network_connection"): ("Microsoft-Windows-Sysmon/Operational", [3]),
    (None, "image_load"): ("Microsoft-Windows-Sysmon/Operational", [7]),
    (None, "file_event"): ("Microsoft-Windows-Sysmon/Operational", [11]),
    (None, "registry_event"): ("Microsoft-Windows-Sysmon/Operational", [12, 13, 14]),
    (None, "registry_set"): ("Microsoft-Windows-Sysmon/Operational", [13]),
    (None, "registry_add"): ("Microsoft-Windows-Sysmon/Operational", [12]),
    (None, "pipe_created"): ("Microsoft-Windows-Sysmon/Operational", [17, 18]),
    (None, "wmi_event"): ("Microsoft-Windows-Sysmon/Operational", [19, 20, 21]),
    (None, "create_remote_thread"): ("Microsoft-Windows-Sysmon/Operational", [8]),
    (None, "dns_query"): ("Microsoft-Windows-Sysmon/Operational", [22]),
    (None, "ps_script"): ("Microsoft-Windows-PowerShell/Operational", [4104]),
    (None, "ps_module"): ("Microsoft-Windows-PowerShell/Operational", [4103]),
    (None, "ps_classic_start"): ("Windows PowerShell", [400]),
    ("security", None): ("Security", []),
    ("system", None): ("System", []),
    ("application", None): ("Application", []),
    ("sysmon", None): ("Microsoft-Windows-Sysmon/Operational", []),
    ("powershell", None): ("Microsoft-Windows-PowerShell/Operational", []),
    ("powershell-classic", None): ("Windows PowerShell", []),
    ("taskscheduler", None): ("Microsoft-Windows-TaskScheduler/Operational", []),
    ("wmi", None): ("Microsoft-Windows-WMI-Activity/Operational", []),
    ("bits-client", None): ("Microsoft-Windows-Bits-Client/Operational", []),
    ("terminalservices-localsessionmanager", None):
        ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", []),
    ("windefend", None): ("Microsoft-Windows-Windows Defender/Operational", []),
    ("codeintegrity-operational", None):
        ("Microsoft-Windows-CodeIntegrity/Operational", []),
    ("ntlm", None): ("Microsoft-Windows-NTLM/Operational", []),
    ("printservice-admin", None): ("Microsoft-Windows-PrintService/Admin", []),
    ("smbclient-security", None): ("Microsoft-Windows-SmbClient/Security", []),
}

LEVEL_TO_SEVERITY = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "informational": "INFO",
    "info": "INFO",
}

# Modifiers we can evaluate on the agent. Anything else is a rejection.
SUPPORTED_MODIFIERS = {
    "contains", "startswith", "endswith", "re", "all", "cidr",
    "base64", "base64offset", "windash", "lt", "lte", "gt", "gte",
    # No-ops for us: matching is already case-insensitive, which is what most
    # backends do and what these modifiers ask for either way.
    "i", "cased",
    # Placeholder expansion. Upstream backends substitute a site-specific list
    # (%Admins_Workstations% and similar). With nothing to substitute, the
    # placeholder is dropped and the remaining values still match — better than
    # rejecting the rule outright over a variable this deployment never set.
    "expand",
}
# These change the *value* rather than the comparison and are applied here.
VALUE_MODIFIERS = {"base64", "base64offset", "windash"}


class UnsupportedRule(Exception):
    """Raised with a human-readable reason the rule cannot be compiled."""


# ---------------------------------------------------------------------------
# Condition grammar
# ---------------------------------------------------------------------------

_TOKEN = re.compile(r"\s*(\(|\)|\band\b|\bor\b|\bnot\b|\ball\b|\b1\b|\bof\b|[\w*]+)")


def _tokenize(condition: str) -> list[str]:
    tokens = []
    pos = 0
    while pos < len(condition):
        m = _TOKEN.match(condition, pos)
        if not m:
            break
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


def _expand_wildcard(pattern: str, names: list[str]) -> list[str]:
    if pattern in ("them", "*"):
        return list(names)
    if "*" not in pattern:
        return [pattern] if pattern in names else []
    rx = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
    return [n for n in names if rx.match(n)]


def _parse_condition(condition: str, selection_names: list[str]) -> dict:
    """Parse Sigma's condition mini-language into a boolean tree.

    Supports: named selections, and/or/not, parentheses, `all of x*`,
    `1 of x*` and `them`. Aggregations are refused by the caller.
    """
    tokens = _tokenize(condition)
    if not tokens:
        raise UnsupportedRule("the condition is empty")

    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def parse_or() -> dict:
        node = parse_and()
        while peek() == "or":
            take()
            right = parse_and()
            node = {"op": "or", "args": [node, right]}
        return node

    def parse_and() -> dict:
        node = parse_not()
        while peek() == "and":
            take()
            right = parse_not()
            node = {"op": "and", "args": [node, right]}
        return node

    def parse_not() -> dict:
        if peek() == "not":
            take()
            return {"op": "not", "args": [parse_not()]}
        return parse_atom()

    def parse_atom() -> dict:
        tok = peek()
        if tok is None:
            raise UnsupportedRule("the condition ends unexpectedly")
        if tok == "(":
            take()
            node = parse_or()
            if peek() != ")":
                raise UnsupportedRule("unbalanced parentheses in the condition")
            take()
            return node
        if tok in ("all", "1"):
            quantifier = take()
            if peek() != "of":
                raise UnsupportedRule(f"expected 'of' after '{quantifier}'")
            take()
            pattern = take()
            matched = _expand_wildcard(pattern, selection_names)
            if not matched:
                raise UnsupportedRule(f"'{pattern}' matches no defined selection")
            op = "and" if quantifier == "all" else "or"
            if len(matched) == 1:
                return {"sel": matched[0]}
            return {"op": op, "args": [{"sel": n} for n in matched]}
        name = take()
        if name not in selection_names:
            raise UnsupportedRule(f"the condition references an undefined selection '{name}'")
        return {"sel": name}

    tree = parse_or()
    if pos != len(tokens):
        raise UnsupportedRule(f"could not parse the whole condition near '{tokens[pos]}'")
    return tree


# ---------------------------------------------------------------------------
# Detection compilation
# ---------------------------------------------------------------------------


def _apply_value_modifiers(values: list[str], modifiers: list[str]) -> list[str]:
    import base64 as b64

    out = list(values)
    if "windash" in modifiers:
        expanded = []
        for v in out:
            expanded.append(v)
            for dash in ("-", "/", "\u2013", "\u2014", "\u2015"):
                if v.startswith("-"):
                    expanded.append(dash + v[1:])
        out = list(dict.fromkeys(expanded))
    if "base64" in modifiers:
        out = [b64.b64encode(v.encode()).decode() for v in out]
    if "base64offset" in modifiers:
        offsets = []
        for v in out:
            for pad in range(3):
                enc = b64.b64encode((" " * pad + v).encode()).decode()
                start = (pad * 4) // 3
                offsets.append(enc[start:].rstrip("="))
        out = list(dict.fromkeys(offsets))
    return out


def _compile_field(key: str, raw_value: Any) -> dict:
    parts = key.split("|")
    field = parts[0]
    modifiers = [m.lower() for m in parts[1:]]

    unknown = [m for m in modifiers if m not in SUPPORTED_MODIFIERS]
    if unknown:
        raise UnsupportedRule(f"unsupported modifier '{unknown[0]}' on field '{field}'")

    values = raw_value if isinstance(raw_value, list) else [raw_value]
    values = ["" if v is None else str(v) for v in values]

    if "expand" in modifiers:
        # %placeholder% entries have no local definition; keep the literals.
        values = [v for v in values if not (v.startswith("%") and v.endswith("%"))]
        if not values:
            raise UnsupportedRule(
                f"'{field}' only holds placeholders this deployment has not defined"
            )

    value_mods = [m for m in modifiers if m in VALUE_MODIFIERS]
    if value_mods:
        values = _apply_value_modifiers(values, value_mods)

    comparison = "equals"
    for candidate in ("contains", "startswith", "endswith", "re", "cidr",
                      "lt", "lte", "gt", "gte"):
        if candidate in modifiers:
            comparison = candidate
            break

    # `all` flips list semantics from "any of these" to "every one of these".
    match = "all" if "all" in modifiers else "any"

    return {
        "field": FIELD_MAP.get(field, field),
        "sigma_field": field,
        "op": comparison,
        "match": match,
        "values": values,
        # Sigma treats a missing/null value as "field is absent".
        "null_check": raw_value is None,
    }


def _compile_selection(block: Any) -> list[list[dict]]:
    """A selection is OR over list entries, AND over map keys."""
    if isinstance(block, dict):
        return [[_compile_field(k, v) for k, v in block.items()]]
    if isinstance(block, list):
        groups = []
        for entry in block:
            if isinstance(entry, dict):
                groups.append([_compile_field(k, v) for k, v in entry.items()])
            else:
                # A bare list of strings means "keyword search" across the record.
                groups.append([{
                    "field": "*", "sigma_field": "keywords", "op": "contains",
                    "match": "any", "values": [str(entry)], "null_check": False,
                }])
        return groups
    raise UnsupportedRule("a selection must be a map or a list")


# Linux logsource -> (source, record types)
#
# Far shorter than the Windows table, and deliberately so. A Sigma rule is only
# worth compiling if the host can be read for it: on Windows the event log is
# always there, but on Linux the equivalent depends on auditd being installed
# with rules loaded, and most of what upstream Sigma writes for Linux assumes an
# audit configuration that very few estates run.
#
# So only two sources are accepted, both of which exist on an ordinary host:
#
#   auditd   execve records — what actually ran, with its arguments. This is
#            the one that carries most of the value, and the capability check
#            tells the operator when it is missing rather than letting rules
#            fail silently.
#
#   text     auth.log / secure / journald — logins, sudo, ssh, cron. These are
#            line-oriented, so a rule against them is evaluated as a match over
#            the message rather than over parsed fields.
#
# Everything else is rejected at compile time with a reason, exactly as an
# unsupported Windows source is. A rule that can never fire is worse than a
# rule that was never loaded, because the empty result looks like a clean one.
LINUX_LOGSOURCE_MAP: dict[tuple[str | None, str | None], tuple[str, list[str]]] = {
    (None, "process_creation"): ("auditd", ["EXECVE", "SYSCALL"]),
    ("auditd", None): ("auditd", ["EXECVE", "SYSCALL", "PATH"]),
    ("auth", None): ("text", ["auth"]),
    ("authpriv", None): ("text", ["auth"]),
    ("sshd", None): ("text", ["auth"]),
    ("sudo", None): ("text", ["auth"]),
    ("cron", None): ("text", ["cron"]),
    ("syslog", None): ("text", ["syslog"]),
    (None, "syslog"): ("text", ["syslog"]),
}

# Field names Linux Sigma rules use, mapped onto what the collector produces.
# auditd calls the executable `exe` and the command name `comm`; a rule written
# against `Image` or `CommandLine` is using the Windows spelling and means the
# same thing, so both resolve.
LINUX_FIELD_MAP = {
    "image": "exe",
    "exe": "exe",
    "commandline": "cmdline",
    "cmdline": "cmdline",
    "command": "cmdline",
    "comm": "comm",
    "processname": "comm",
    "parentimage": "parent_exe",
    "parentcommandline": "parent_cmdline",
    "user": "user",
    "uid": "uid",
    "auid": "auid",
    "type": "type",
    "key": "key",
    "syscall": "syscall",
    "cwd": "cwd",
    "path": "path",
    "name": "path",
    "message": "message",
    "msg": "message",
    "a0": "a0", "a1": "a1", "a2": "a2", "a3": "a3",
}


def _resolve_logsource(logsource: dict) -> tuple[str, list[int], str]:
    """Returns (channel, event ids, platform).

    The platform decides which hosts a rule is sent to. A Windows rule on a
    Linux host and a Linux rule on a Windows host both compile to something
    that can never match, so they are separated here rather than shipped
    everywhere and left to fail quietly.
    """
    category = (logsource.get("category") or "").lower() or None
    service = (logsource.get("service") or "").lower() or None
    product = (logsource.get("product") or "").lower() or None

    if product == "linux":
        for key in ((service, category), (None, category), (service, None)):
            if key in LINUX_LOGSOURCE_MAP:
                source, _types = LINUX_LOGSOURCE_MAP[key]
                return source, [], "linux"
        label = service or category or "unspecified"
        raise UnsupportedRule(
            f"Linux log source '{label}' is not one this tool can read. Only "
            "auditd execution records and the auth/cron/syslog text logs are "
            "collected."
        )

    if product and product not in ("windows", ""):
        raise UnsupportedRule(f"product '{product}' is not Windows or Linux")

    for key in ((service, category), (None, category), (service, None)):
        if key in LOGSOURCE_MAP:
            channel, ids = LOGSOURCE_MAP[key]
            return channel, ids, "windows"

    label = service or category or "unspecified"
    raise UnsupportedRule(f"log source '{label}' is not collected by this tool")


def compile_rule(text: str, source: str = "") -> dict:
    """Compile one Sigma YAML document. Raises UnsupportedRule with a reason."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise UnsupportedRule(f"invalid YAML: {str(exc)[:120]}") from exc

    if not isinstance(doc, dict):
        raise UnsupportedRule("the file does not contain a Sigma rule")

    title = doc.get("title")
    detection = doc.get("detection")
    if not title or not isinstance(detection, dict):
        raise UnsupportedRule("missing a title or detection block")

    condition = detection.get("condition")
    if condition is None:
        raise UnsupportedRule("the detection block has no condition")
    if isinstance(condition, list):
        # Several conditions mean OR between them.
        condition = " or ".join(f"({c})" for c in condition)
    condition = str(condition)

    if "|" in condition or " near " in condition:
        raise UnsupportedRule(
            "aggregation and correlation conditions need a search backend"
        )

    selections = {
        name: _compile_selection(block)
        for name, block in detection.items()
        if name not in ("condition", "timeframe")
    }
    if not selections:
        raise UnsupportedRule("the detection block defines no selections")

    tree = _parse_condition(condition, list(selections))
    channel, event_ids, platform = _resolve_logsource(doc.get("logsource") or {})

    tags = [str(t) for t in (doc.get("tags") or [])]
    techniques = sorted({
        t.split(".", 1)[1].upper().replace("attack.", "")
        for t in tags if t.lower().startswith("attack.t")
    })
    mitre = techniques[0] if techniques else ""

    rule_id = str(doc.get("id") or "")
    stable_id = rule_id or hashlib.sha256(
        (title + condition).encode()).hexdigest()[:16]

    return {
        "id": stable_id,
        "title": str(title)[:300],
        "description": str(doc.get("description") or "")[:1000],
        "author": str(doc.get("author") or "")[:200],
        "level": str(doc.get("level") or "medium").lower(),
        "severity": LEVEL_TO_SEVERITY.get(
            str(doc.get("level") or "medium").lower(), "MEDIUM"),
        "status": str(doc.get("status") or "")[:32],
        "tags": tags,
        "mitre": mitre,
        "falsepositives": [str(f) for f in (doc.get("falsepositives") or [])][:8],
        "references": [str(r) for r in (doc.get("references") or [])][:8],
        "channel": channel,
        "event_ids": event_ids,
        # Which hosts this rule is sent to. A Windows rule on a Linux host
        # compiles to something that can never match, and vice versa.
        "platform": platform,
        "selections": selections,
        "condition": tree,
        "condition_text": condition,
        "source": source,
    }


def compile_many(documents: list[tuple[str, str]]) -> dict:
    """Compile a batch. Returns compiled rules and per-file rejection reasons."""
    compiled: list[dict] = []
    rejected: list[dict] = []
    seen: set[str] = set()

    for name, text in documents:
        # A single file may hold several rules separated by ---.
        try:
            docs = list(yaml.safe_load_all(text))
        except yaml.YAMLError as exc:
            rejected.append({"file": name, "reason": f"invalid YAML: {str(exc)[:120]}"})
            continue

        chunks = [text] if len(docs) <= 1 else text.split("\n---")
        for chunk in chunks:
            if not chunk.strip():
                continue
            try:
                rule = compile_rule(chunk, source=name)
            except UnsupportedRule as exc:
                rejected.append({"file": name, "reason": str(exc)})
                continue
            except Exception as exc:  # pragma: no cover - defensive
                rejected.append({"file": name, "reason": f"could not compile: {exc}"})
                continue
            if rule["id"] in seen:
                continue
            seen.add(rule["id"])
            compiled.append(rule)

    return {"rules": compiled, "rejected": rejected}
