"""Bulk import and export of the rules an operator writes.

Writing rules one at a time in a form is fine for the first three. It is the
wrong tool for a set: a consultancy with a house rule pack, someone moving a
tuned console to a new deployment, or an analyst who would rather write twenty
rules in an editor than click through twenty dialogs.

Three formats are accepted, chosen because they are what people already have
rather than because a parser was easy to write:

    JSON   What this console exports. Round-trips exactly, so export from one
           deployment and import into another is lossless.

    YAML   What someone hand-writing rules reaches for, and what Sigma looks
           like — which matters, because anyone writing detections here has
           almost certainly written a Sigma rule before.

    CSV    What comes out of a spreadsheet. Conditions live in one column using
           the compact syntax below, because a nested structure cannot survive
           a spreadsheet and pretending otherwise produces broken files.

Conditions can be written either as a list of objects or as one compact line:

    Signed is_false; PathName not_contains "Program Files"

The compact form exists for the CSV case but is accepted everywhere, since a
person writing YAML by hand would rather type one line than six.

Import is deliberately two-step. The preview says what would happen to each
rule — added, replaced, skipped, rejected and why — before anything is written.
A bulk import that silently overwrote a tuned rule set would be the kind of
mistake nobody notices until the next hunt comes back quiet.

One bad rule never rejects the file. Rules are validated individually and the
good ones import; a file of thirty rules with one typo should not be an
all-or-nothing failure, because the fix is then to find the typo with no help
from the tool.
"""
from __future__ import annotations

import csv
import io
import json
import re

import yaml

from . import custom_rules as engine

# Operator names, taken from the engine so this can never drift from what is
# actually accepted.
OPERATOR_NAMES = tuple(engine.OPERATORS)

MAX_RULES_PER_IMPORT = 500
# Ceiling on the raw text before any parser touches it.
MAX_IMPORT_BYTES = 5 * 1024 * 1024

# Prefixes the console reserves so a custom rule can never be mistaken for a
# built-in one in a finding list.
RESERVED_PREFIXES = ("DGL-", "SIGMA-", "YARA-")

RULE_ID_RE = re.compile(r"^[A-Z][A-Z0-9]{1,7}-[A-Za-z0-9_.-]{1,16}$")

# Field names accepted for each part of a rule. Real files come from real
# people, and "id" versus "rule_id" is not a difference worth failing over.
ALIASES = {
    "rule_id": ("rule_id", "id", "ruleid", "rule"),
    "title": ("title", "name", "detection"),
    "severity": ("severity", "level", "sev"),
    "mitre": ("mitre", "technique", "attack", "mitre_id"),
    "why": ("why", "description", "rationale", "note"),
    "artifact": ("artifact", "source", "table", "logsource"),
    "match": ("match", "condition", "logic"),
    "conditions": ("conditions", "when", "where", "filters", "detection_logic"),
    "enabled": ("enabled", "active", "on"),
}


class ImportError_(Exception):
    """A problem with the file as a whole, not with one rule inside it."""


def _pick(row: dict, key: str, default=None):
    lowered = {str(k).strip().lower(): v for k, v in row.items()}
    for alias in ALIASES[key]:
        if alias in lowered and lowered[alias] not in (None, ""):
            value = lowered[alias]
            # Undo the apostrophe _csv_safe adds to values a spreadsheet would
            # run as a formula, so an export/import round trip returns exactly
            # what went in rather than accumulating a quote each time.
            if isinstance(value, str) and value[:2] in ("'=", "'+", "'-", "'@"):
                value = value[1:]
            return value
    return default


# ---------------------------------------------------------------------------
# Compact condition syntax
# ---------------------------------------------------------------------------

_COMPACT = re.compile(
    r"""^\s*
        (?P<field>[A-Za-z_][A-Za-z0-9_]*)      # column name
        \s+
        (?P<op>[a-z_]+)                        # operator
        (?:\s+(?P<value>.+?))?                 # value, optional for is_true etc
        \s*$""",
    re.VERBOSE,
)


def parse_conditions(raw) -> list[dict]:
    """Accept conditions as a list of objects or as one compact line."""
    if raw in (None, "", []):
        return []

    if isinstance(raw, dict):
        raw = [raw]

    if isinstance(raw, list):
        out = []
        for item in raw:
            if isinstance(item, str):
                out.extend(parse_conditions(item))
                continue
            if not isinstance(item, dict):
                raise ValueError(f"a condition must be an object or a line, got {type(item).__name__}")
            lowered = {str(k).strip().lower(): v for k, v in item.items()}
            field = lowered.get("field") or lowered.get("column") or lowered.get("key")
            op = lowered.get("op") or lowered.get("operator") or lowered.get("test")
            value = lowered.get("value", lowered.get("val", ""))
            out.append({
                "field": str(field or "").strip(),
                "op": str(op or "").strip().lower(),
                "value": "" if value is None else str(value),
            })
        return out

    if not isinstance(raw, str):
        raise ValueError("conditions must be a list or a line of text")

    # Compact form: "Signed is_false; PathName not_contains \"Program Files\""
    #
    # Split on semicolons and newlines first. YAML folds an indented block into
    # a single space-joined line, so a rule written as
    #
    #     when:
    #       Signed is_false
    #       PathName not_contains "Program Files"
    #
    # arrives here as one string with the conditions run together. Without the
    # second pass below that became a single condition whose value swallowed
    # the rest — and it validated, so the rule saved and quietly matched the
    # wrong thing. Silent wrongness is the failure worth spending code on.
    parts: list[str] = []
    for chunk in re.split(r"[;\n]", raw):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts.extend(_split_run_on(chunk))

    out = []
    for part in parts:
        m = _COMPACT.match(part)
        if not m:
            raise ValueError(
                f"could not read the condition {part.strip()!r}. Expected "
                "FIELD OPERATOR VALUE, for example: PathName contains \"Temp\""
            )
        value = (m.group("value") or "").strip()
        # Strip one layer of matching quotes, so a value with spaces survives.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        out.append({
            "field": m.group("field").strip(),
            "op": m.group("op").strip().lower(),
            "value": value,
        })
    return out


def _split_run_on(chunk: str) -> list[str]:
    """Break a line holding several conditions back into one each.

    A condition starts with a field name followed by a known operator, so the
    start of the next one is findable even after YAML has joined them. Quoted
    values are skipped over, because a quoted string may legitimately contain
    something that looks like the start of a condition.
    """
    ops = "|".join(sorted((re.escape(o) for o in OPERATOR_NAMES), key=len, reverse=True))
    starts = [
        m.start()
        for m in re.finditer(rf"(?<!\S)[A-Za-z_][A-Za-z0-9_]*\s+(?:{ops})(?!\S)", chunk)
        if not _inside_quotes(chunk, m.start())
    ]
    if len(starts) <= 1:
        return [chunk]
    bounds = starts + [len(chunk)]
    return [chunk[bounds[i]:bounds[i + 1]].strip() for i in range(len(starts))]


def _inside_quotes(text: str, index: int) -> bool:
    quote = None
    for i, ch in enumerate(text[:index]):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
    return quote is not None


def render_conditions(conditions: list[dict]) -> str:
    """The compact form, for CSV export and for showing a rule in one line."""
    parts = []
    for c in conditions or []:
        op = c.get("op", "")
        value = str(c.get("value") or "")
        if op in engine.VALUELESS or not value:
            parts.append(f"{c.get('field','')} {op}")
        elif " " in value:
            parts.append(f'{c.get("field","")} {op} "{value}"')
        else:
            parts.append(f"{c.get('field','')} {op} {value}")
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# Parsing a whole file
# ---------------------------------------------------------------------------


def _rows_from_json(text: str) -> list[dict]:
    data = json.loads(text)
    if isinstance(data, dict):
        # Either a bundle {"rules": [...]} or a single rule.
        if "rules" in data and isinstance(data["rules"], list):
            return [r for r in data["rules"] if isinstance(r, dict)]
        return [data]
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    raise ImportError_("That JSON is neither a rule nor a list of rules.")


def _rows_from_yaml(text: str) -> list[dict]:
    # Multi-document support, because a file of rules separated by --- is how
    # anyone who has written Sigma will lay this out.
    docs = [d for d in yaml.safe_load_all(text) if d is not None]
    rows: list[dict] = []
    for doc in docs:
        if isinstance(doc, dict):
            if "rules" in doc and isinstance(doc["rules"], list):
                rows.extend(r for r in doc["rules"] if isinstance(r, dict))
            else:
                rows.append(doc)
        elif isinstance(doc, list):
            rows.extend(r for r in doc if isinstance(r, dict))
    if not rows:
        raise ImportError_("No rules found in that YAML.")
    return rows


def _rows_from_csv(text: str) -> list[dict]:
    # Sniff the delimiter: exports from European spreadsheets use semicolons,
    # and a file that silently parses as one giant column is a confusing way
    # to be told the delimiter was wrong.
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    rows = [r for r in reader if any((v or "").strip() for v in r.values())]
    if not rows:
        raise ImportError_("That CSV has no data rows.")
    return rows


def parse(text: str, filename: str = "") -> tuple[list[dict], str]:
    """Read a file of rules. Returns (raw rows, detected format)."""
    text = (text or "").strip()
    if not text:
        raise ImportError_("The file is empty.")

    # A cap before any parser sees the text. Five megabytes is far more than a
    # rule pack needs — five hundred rules is well under one — and it stops a
    # pasted log file or a malformed upload from being held in memory and run
    # through three parsers in turn.
    if len(text) > MAX_IMPORT_BYTES:
        raise ImportError_(
            f"That file is {len(text) // (1024 * 1024)} MB; the limit is "
            f"{MAX_IMPORT_BYTES // (1024 * 1024)} MB. A rule pack should be a "
            "few kilobytes — check this is the file you meant."
        )

    name = (filename or "").lower()
    # Extension first when there is one, because it is the author's own
    # statement of intent; sniffing is the fallback, not the default.
    if name.endswith(".json"):
        order = ("json", "yaml", "csv")
    elif name.endswith((".yaml", ".yml")):
        order = ("yaml", "json", "csv")
    elif name.endswith((".csv", ".tsv")):
        order = ("csv", "json", "yaml")
    elif text[:1] in "[{":
        order = ("json", "yaml", "csv")
    else:
        order = ("yaml", "csv", "json")

    errors = []
    for fmt in order:
        try:
            if fmt == "json":
                return _rows_from_json(text), "json"
            if fmt == "yaml":
                return _rows_from_yaml(text), "yaml"
            return _rows_from_csv(text), "csv"
        except ImportError_ as exc:
            errors.append(f"{fmt}: {exc}")
        except (json.JSONDecodeError, yaml.YAMLError, csv.Error) as exc:
            errors.append(f"{fmt}: {str(exc)[:120]}")

    raise ImportError_(
        "Could not read that as JSON, YAML or CSV. " + errors[0] if errors
        else "Could not read that file."
    )


# ---------------------------------------------------------------------------
# Normalising and checking one rule
# ---------------------------------------------------------------------------


def normalise(row: dict) -> dict:
    """Turn one raw row into the shape the rule engine expects."""
    enabled = _pick(row, "enabled", True)
    if isinstance(enabled, str):
        enabled = enabled.strip().lower() not in ("false", "0", "no", "off", "")

    match = str(_pick(row, "match", "all") or "all").strip().lower()
    if match not in ("all", "any"):
        # "and"/"or" is what people write when nobody told them the vocabulary.
        match = "any" if match in ("or", "any of them") else "all"

    return {
        "rule_id": str(_pick(row, "rule_id", "") or "").strip().upper(),
        "title": str(_pick(row, "title", "") or "").strip(),
        "severity": str(_pick(row, "severity", "MEDIUM") or "MEDIUM").strip().upper(),
        "mitre": str(_pick(row, "mitre", "") or "").strip(),
        "why": str(_pick(row, "why", "") or "").strip(),
        "artifact": str(_pick(row, "artifact", "") or "").strip(),
        "match": match,
        "conditions": parse_conditions(_pick(row, "conditions", [])),
        "enabled": bool(enabled),
    }


def check(rule: dict) -> str:
    """Validate one rule. Returns "" when it is fine, else a plain reason."""
    rid = rule.get("rule_id") or ""
    if not rid:
        return "No rule id. Give it one like ACME-001."
    if not RULE_ID_RE.match(rid):
        return (f"'{rid}' is not a usable rule id. Use a prefix, a dash, then "
                "letters or digits — ACME-001, or ACME-webshell.")
    if rid.startswith(RESERVED_PREFIXES):
        return ("DGL, SIGMA and YARA are reserved so a custom rule is never "
                "mistaken for a built-in one. Use your own prefix.")
    if rule.get("mitre") and not re.match(r"^T\d{4}(\.\d{3})?$", rule["mitre"]):
        return f"'{rule['mitre']}' is not a MITRE id. They look like T1055 or T1055.012."

    artifact = rule.get("artifact") or ""
    if artifact not in engine.ARTIFACT_FIELDS:
        known = ", ".join(sorted(engine.ARTIFACT_FIELDS)[:4])
        return (f"'{artifact}' is not an artifact rules can read. "
                f"Try one of: {known}, …")

    try:
        engine.validate(rule)
    except engine.InvalidRule as exc:
        return str(exc)
    return ""


def plan(rows: list[dict], existing_ids: set, on_conflict: str = "skip") -> dict:
    """Work out what an import would do, without doing any of it.

    Every rule gets an outcome and, when it is not going to import, a reason
    that names the rule rather than the file. "Rule 14 failed" is not something
    anyone can act on.
    """
    if not rows:
        # A file that parses but holds nothing is a real case — an empty JSON
        # array, a CSV with only a header — and reporting "0 rules read" with
        # no explanation looks like the import silently did nothing.
        raise ImportError_(
            "That file parsed, but there are no rules in it. Check it is a list "
            "of rules, or a CSV with a header and at least one data row."
        )

    if len(rows) > MAX_RULES_PER_IMPORT:
        raise ImportError_(
            f"That file holds {len(rows)} rules; the limit is {MAX_RULES_PER_IMPORT} "
            "in one import. Split it."
        )

    items: list[dict] = []
    seen_in_file: set = set()
    taken = set(existing_ids)

    for index, row in enumerate(rows, 1):
        try:
            rule = normalise(row)
        except ValueError as exc:
            items.append({"line": index, "rule_id": str(_pick(row, "rule_id", "") or "?"),
                          "title": "", "action": "rejected", "reason": str(exc)})
            continue

        problem = check(rule)
        if problem:
            items.append({"line": index, "rule_id": rule["rule_id"] or "?",
                          "title": rule["title"], "action": "rejected",
                          "reason": problem})
            continue

        rid = rule["rule_id"]

        if rid in seen_in_file:
            items.append({"line": index, "rule_id": rid, "title": rule["title"],
                          "action": "rejected",
                          "reason": "This id appears twice in the same file."})
            continue
        seen_in_file.add(rid)

        if rid in existing_ids:
            if on_conflict == "replace":
                action, reason = "replace", "A rule with this id already exists; it will be overwritten."
            elif on_conflict == "rename":
                suffix = 2
                while f"{rid}.{suffix}" in taken:
                    suffix += 1
                new_id = f"{rid}.{suffix}"
                # A renamed rule must still be a legal id, or the import would
                # succeed here and fail on write.
                if RULE_ID_RE.match(new_id):
                    rule["rule_id"] = new_id
                    taken.add(new_id)
                    action, reason = "add", f"Imported as {new_id}; {rid} was taken."
                else:
                    action, reason = "skipped", f"{rid} exists and the id is too long to rename."
            else:
                action, reason = "skipped", "A rule with this id already exists."
        else:
            action, reason = "add", ""
            taken.add(rid)

        items.append({
            "line": index,
            "rule_id": rule["rule_id"],
            "title": rule["title"],
            "severity": rule["severity"],
            "artifact": rule["artifact"],
            "artifact_label": engine.ARTIFACT_FIELDS[rule["artifact"]]["label"],
            "summary": engine.describe(rule),
            "action": action,
            "reason": reason,
            "rule": rule,
        })

    return {
        "total": len(items),
        "add": sum(1 for i in items if i["action"] == "add"),
        "replace": sum(1 for i in items if i["action"] == "replace"),
        "skipped": sum(1 for i in items if i["action"] == "skipped"),
        "rejected": sum(1 for i in items if i["action"] == "rejected"),
        "items": items,
    }


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


def to_bundle(rules: list[dict]) -> dict:
    """The JSON this console produces, and will read back unchanged."""
    return {
        "version": 1,
        "kind": "douglas-custom-rules",
        "count": len(rules),
        "rules": [
            {
                "rule_id": r["rule_id"],
                "title": r["title"],
                "severity": r["severity"],
                "mitre": r.get("mitre", ""),
                "why": r.get("why", ""),
                "artifact": r["artifact"],
                "match": r.get("match", "all"),
                "conditions": r.get("conditions", []),
                "enabled": bool(r.get("enabled", True)),
            }
            for r in rules
        ],
    }


def to_yaml(rules: list[dict]) -> str:
    return yaml.safe_dump(to_bundle(rules), sort_keys=False, allow_unicode=True)


def _csv_safe(value) -> str:
    """Neutralise a value that a spreadsheet would treat as a formula.

    A rule title is free text and can come from an imported pack somebody else
    wrote. Excel, LibreOffice and Sheets all execute a cell beginning with
    =, +, - or @ when the file is opened, so exporting such a title verbatim
    turns "share your rule set" into code execution on whoever opens it.

    The fix is the standard one: prefix with an apostrophe, which the
    spreadsheet strips on display and which keeps the value readable. Tab and
    carriage return get the same treatment because both are also treated as
    formula leaders by some versions.
    """
    text = "" if value is None else str(value)
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


def to_csv(rules: list[dict]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["rule_id", "title", "severity", "mitre", "artifact",
                     "match", "conditions", "why", "enabled"])
    for r in rules:
        writer.writerow([
            _csv_safe(r["rule_id"]), _csv_safe(r["title"]), _csv_safe(r["severity"]),
            _csv_safe(r.get("mitre", "")), _csv_safe(r["artifact"]),
            _csv_safe(r.get("match", "all")),
            _csv_safe(render_conditions(r.get("conditions", []))),
            _csv_safe(r.get("why", "")),
            "true" if r.get("enabled", True) else "false",
        ])
    return out.getvalue()


# ---------------------------------------------------------------------------
# A starter pack
#
# Not shipped enabled — these are examples of the shape, written against
# artifacts every host produces, so someone can import them, read them, and
# edit one into the rule they actually wanted. An empty rule screen with a
# blank form teaches nobody what a good rule looks like.
# ---------------------------------------------------------------------------

# The template the text editor opens with. Deliberately a complete, working
# rule rather than a skeleton of empty keys: the fastest way to learn the shape
# is to change one that already works.
RULE_TEMPLATE = """id: ACME-001
title: Unsigned service binary outside Program Files
severity: HIGH
mitre: T1543.003
artifact: 05_services
match: all
when:
  Signed is_false
  PathName not_contains "Program Files"
  PathName not_contains "System32"
why: >
  Legitimate services are signed and installed under Program Files or
  System32. Neither being true is how most service persistence looks.
"""

STARTER_PACK = [
    {
        "rule_id": "EX-001",
        "title": "Unsigned service binary outside Program Files",
        "severity": "HIGH",
        "mitre": "T1543.003",
        "why": "Legitimate services are signed and installed under Program Files "
               "or System32. Neither being true is how most service-based "
               "persistence looks.",
        "artifact": "05_services",
        "match": "all",
        "conditions": "Signed is_false; PathName not_contains \"Program Files\"; "
                      "PathName not_contains \"System32\"",
        "enabled": False,
    },
    {
        "rule_id": "EX-002",
        "title": "Process running from a user's Temp directory",
        "severity": "HIGH",
        "mitre": "T1204",
        "why": "Temp is where a download lands and where a dropper runs from. "
               "Installers do it too, so check the signature and the parent.",
        "artifact": "03_processes",
        "match": "any",
        "conditions": "Path contains \\Temp\\; Path contains \\AppData\\Local\\Temp",
        "enabled": False,
    },
    {
        "rule_id": "EX-003",
        "title": "Scheduled task running as SYSTEM from a writable directory",
        "severity": "CRITICAL",
        "mitre": "T1053.005",
        "why": "A task running as SYSTEM whose binary sits somewhere a normal "
               "user can write is a privilege escalation waiting to be used.",
        "artifact": "06_scheduled_tasks",
        "match": "all",
        "conditions": "RunAsUser contains SYSTEM; SuspiciousPath is_true",
        "enabled": False,
    },
    {
        "rule_id": "EX-004",
        "title": "Local account that needs no password",
        "severity": "CRITICAL",
        "mitre": "T1078.003",
        "why": "An enabled account with no password requirement is usable by "
               "anyone who can reach the host.",
        "artifact": "02_local_users",
        "match": "all",
        "conditions": "Enabled is_true; PasswordRequired is_false",
        "enabled": False,
    },
    {
        "rule_id": "EX-005",
        "title": "Outbound connection from an unsigned binary",
        "severity": "MEDIUM",
        "mitre": "T1071",
        "why": "Most software that talks to the internet is signed. An unsigned "
               "process with an external connection is worth one look.",
        "artifact": "04_tcp_connections",
        "match": "all",
        "conditions": "Signed is_false; RemoteIsPrivate is_false",
        "enabled": False,
    },
    {
        "rule_id": "EX-006",
        "title": "Executable written to a web root",
        "severity": "CRITICAL",
        "mitre": "T1505.003",
        "why": "A web server writing an executable into content it serves is "
               "how a webshell arrives.",
        "artifact": "13_recent_files",
        "match": "all",
        "conditions": "FullName contains inetpub; Extension contains exe",
        "enabled": False,
    },
]
