"""Rules an operator writes in the console.

Sigma covers event logs and YARA covers file content. Neither can express
"a service whose binary is unsigned and sits outside Program Files", because
that question is asked of an artifact table rather than a log or a file. That
is what the collector produces most of, and until now the only rules that could
read it were the ones compiled into the collector.

A custom rule is a set of conditions over the columns of one artifact CSV.
Deliberately small: field, operator, value, joined with and/or. No expression
language, because an operator writing a rule at 3am should not also be
debugging syntax.
"""
from __future__ import annotations

import re

# Artifacts worth writing rules against, with the columns they carry. Shown in
# the console so nobody has to guess a field name.
ARTIFACT_FIELDS: dict[str, dict] = {
    "03_processes": {
        "label": "Running processes",
        "fields": ["PID", "PPID", "ParentName", "Name", "Path", "CommandLine",
                   "User", "StartTimeUtc", "Signed", "Signer", "SigStatus",
                   "IsMicrosoft", "SHA256", "SuspiciousPath", "IsLolBas",
                   "IsDiscovery", "IsExfilTool", "CPU", "WorkingSetMB"],
    },
    "05_services": {
        "label": "Services",
        "fields": ["Name", "DisplayName", "State", "StartMode", "StartName",
                   "PathName", "BinaryPath", "ServiceDll", "Signed", "Signer",
                   "SigStatus", "IsMicrosoft", "SHA256", "BinaryWriteUtc",
                   "SuspiciousPath", "UnquotedPath", "Description"],
    },
    "06_scheduled_tasks": {
        "label": "Scheduled tasks",
        "fields": ["TaskName", "TaskPath", "State", "Author", "RunAsUser",
                   "RunLevel", "Actions", "BinaryPath", "Triggers", "Signed",
                   "Signer", "SigStatus", "IsMicrosoft", "SHA256",
                   "LastRunUtc", "SuspiciousPath"],
    },
    "07_autoruns": {
        "label": "Autorun entries",
        "fields": ["Category", "Location", "User", "Name", "Value",
                   "BinaryPath", "BinaryExists", "BinaryWriteUtc", "Signed",
                   "Signer", "SigStatus", "IsMicrosoft", "SHA256", "SuspiciousPath"],
    },
    "04_tcp_connections": {
        "label": "Network connections",
        "fields": ["Protocol", "LocalAddress", "LocalPort", "RemoteAddress",
                   "RemotePort", "State", "PID", "ProcessName", "ProcessPath",
                   "ProcessUser", "Signed", "SHA256", "SuspiciousPath",
                   "RemoteIsPrivate", "RemoteRDNS"],
    },
    "04_external_endpoints": {
        "label": "External endpoints",
        "fields": ["Address", "RDNS", "Connections", "Ports", "Processes",
                   "Paths", "Sources", "Suspicious", "Unsigned"],
    },
    "02_local_users": {
        "label": "Local accounts",
        "fields": ["Name", "SID", "Enabled", "Description", "LastLogonUtc",
                   "PasswordLastSetUtc", "PasswordRequired",
                   "UserMayChangePassword", "PrincipalSource"],
    },
    "09_drivers": {
        "label": "Drivers",
        "fields": ["Name", "DisplayName", "State", "StartMode", "PathName",
                   "Signed", "Signer", "SigStatus", "IsMicrosoft", "SHA256",
                   "WriteUtc", "SuspiciousPath"],
    },
    "13_recent_files": {
        "label": "Recently written files",
        "fields": ["FullName", "Extension", "SizeKB", "CreatedUtc",
                   "ModifiedUtc", "Signed", "Signer", "SigStatus",
                   "IsMicrosoft", "SHA256", "ZoneId", "DownloadUrl",
                   "TimestompSuspect", "SuspiciousPath"],
    },
    "19_memory_summary": {
        "label": "In-memory code",
        "fields": ["PID", "Process", "Path", "User", "Regions", "TotalKB",
                   "RwxRegions", "SuspiciousPath", "Signed"],
    },
    "10_smb_shares": {
        "label": "SMB shares",
        "fields": ["Name", "Path", "Description", "ShareType", "Special", "Access"],
    },
}

OPERATORS = {
    "equals": "is exactly",
    "not_equals": "is not",
    "contains": "contains",
    "not_contains": "does not contain",
    "starts_with": "starts with",
    "ends_with": "ends with",
    "regex": "matches the pattern",
    "is_true": "is true",
    "is_false": "is false",
    "is_empty": "is empty",
    "is_not_empty": "is not empty",
    "gt": "is greater than",
    "lt": "is less than",
}

VALUELESS = {"is_true", "is_false", "is_empty", "is_not_empty"}

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class InvalidRule(Exception):
    """Raised with a message an operator can act on."""


def validate(rule: dict) -> None:
    artifact = rule.get("artifact")
    if artifact not in ARTIFACT_FIELDS:
        raise InvalidRule(
            f"'{artifact}' is not an artifact rules can be written against."
        )
    if (rule.get("severity") or "").upper() not in SEVERITIES:
        raise InvalidRule("Pick a severity.")
    if not (rule.get("title") or "").strip():
        raise InvalidRule("Give the rule a title; it becomes the finding's headline.")

    conditions = rule.get("conditions") or []
    if not conditions:
        raise InvalidRule("A rule needs at least one condition.")
    if len(conditions) > 12:
        raise InvalidRule("Twelve conditions is the limit; split the rule instead.")

    known = ARTIFACT_FIELDS[artifact]["fields"]
    for i, cond in enumerate(conditions, 1):
        field = cond.get("field")
        if field not in known:
            raise InvalidRule(
                f"Condition {i}: '{field}' is not a column of {artifact}."
            )
        op = cond.get("op")
        if op not in OPERATORS:
            raise InvalidRule(f"Condition {i}: '{op}' is not an operator.")
        if op not in VALUELESS and not str(cond.get("value") or "").strip():
            raise InvalidRule(f"Condition {i}: {OPERATORS[op]} needs a value.")
        if op == "regex":
            try:
                re.compile(str(cond.get("value")))
            except re.error as exc:
                raise InvalidRule(f"Condition {i}: that pattern will not compile ({exc}).")


def _truthy(value: str) -> bool:
    return str(value).strip().lower() in ("true", "1", "yes")


def _number(value):
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def evaluate_condition(row: dict, cond: dict) -> bool:
    """Evaluate one condition against one artifact row."""
    raw = row.get(cond["field"])
    value = "" if raw is None else str(raw)
    target = str(cond.get("value") or "")
    op = cond["op"]

    if op == "is_empty":
        return value.strip() == ""
    if op == "is_not_empty":
        return value.strip() != ""
    if op == "is_true":
        return _truthy(value)
    if op == "is_false":
        return value.strip() != "" and not _truthy(value)

    low, tlow = value.lower(), target.lower()
    if op == "equals":
        return low == tlow
    if op == "not_equals":
        return low != tlow
    if op == "contains":
        return tlow in low
    if op == "not_contains":
        return tlow not in low
    if op == "starts_with":
        return low.startswith(tlow)
    if op == "ends_with":
        return low.endswith(tlow)
    if op == "regex":
        try:
            return bool(re.search(target, value, re.IGNORECASE))
        except re.error:
            return False
    if op in ("gt", "lt"):
        a, b = _number(value), _number(target)
        if a is None or b is None:
            return False
        return a > b if op == "gt" else a < b
    return False


def evaluate(rule: dict, row: dict) -> tuple[bool, list[dict]]:
    """Run a rule against one row. Returns (matched, per-condition results).

    The per-condition detail is what makes the rule testable: "did not match"
    is not useful feedback, "condition 3 failed because Signer was empty" is.
    """
    match_all = (rule.get("match") or "all") == "all"
    results = []
    for cond in rule.get("conditions") or []:
        hit = evaluate_condition(row, cond)
        results.append({
            "field": cond["field"],
            "op": cond["op"],
            "value": cond.get("value", ""),
            "actual": str(row.get(cond["field"], ""))[:200],
            "matched": hit,
        })

    hits = [r["matched"] for r in results]
    matched = all(hits) if match_all else any(hits)
    return matched, results


def describe(rule: dict) -> str:
    """A one-line plain reading of the rule, shown next to it in the console."""
    joiner = " and " if (rule.get("match") or "all") == "all" else " or "
    parts = []
    for cond in rule.get("conditions") or []:
        label = OPERATORS.get(cond["op"], cond["op"])
        if cond["op"] in VALUELESS:
            parts.append(f"{cond['field']} {label}")
        else:
            parts.append(f"{cond['field']} {label} '{cond.get('value')}'")
    artifact = ARTIFACT_FIELDS.get(rule.get("artifact"), {}).get("label", rule.get("artifact"))
    return f"In {artifact}: " + joiner.join(parts)
