#!/usr/bin/env python3
"""Sigma matching for the Linux collector.

Two sources, both chosen because an ordinary host can actually be read for
them:

    auditd   execve records — what ran, with its arguments and the user who
             ran it. Parsed out of /var/log/audit/audit.log, where the
             arguments arrive hex-encoded and split across a0, a1, a2… and
             have to be reassembled before a rule can look at a command line.

    text     auth.log, secure, cron and the journal. Line-oriented, so a rule
             against these is evaluated over the message rather than parsed
             fields.

The console has already rejected any rule whose log source is neither of these,
with a reason the operator can read. So everything arriving here is evaluable,
and a rule that produces nothing produced nothing because the host was clean —
not because it was quietly unsupported. That distinction is the whole reason
the capability check exists.

Reads:  a bundle (JSON), plus the audit log and text logs to scan
Writes: one JSON object per line on stdout, one per match

Severity floors, per-rule caps and disabled rules are not decided here. They
belong to the collector's finding(), so both platforms share one set of rules
about rules.
"""
from __future__ import annotations

import binascii
import glob
import json
import os
import re
import sys

MAX_LINES = 400_000
MAX_HITS_PER_RULE = 15
# An execve record's arguments are capped when reassembled: a command line
# longer than this is either generated or an attempt to bury something past
# where anyone reads, and either way the first 8k decides it.
MAX_CMDLINE = 8192


# ---------------------------------------------------------------------------
# auditd
# ---------------------------------------------------------------------------

_AUDIT_KV = re.compile(r'(\w+)=("[^"]*"|\S+)')


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


def _maybe_hex(value: str) -> str:
    """auditd hex-encodes any value containing a space or a quote.

    An unquoted, even-length, all-hex value is one of those. Decoding it is
    what turns a0=2F62696E2F7368 back into /bin/sh — without this every rule
    matching on a command line silently never fires.
    """
    if len(value) < 2 or len(value) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", value):
        return value
    try:
        return binascii.unhexlify(value).decode("utf-8", errors="replace")
    except Exception:
        return value


def _parse_audit(path: str, limit: int = MAX_LINES) -> list[dict]:
    """Group audit records into events, keyed by their msg=audit(...) id.

    One execve produces several records — SYSCALL, EXECVE, CWD, PATH — that
    share an id. A rule expects to see them as one event, so they are merged.
    """
    events: dict[str, dict] = {}
    order: list[str] = []

    try:
        handle = open(path, "r", encoding="utf-8", errors="replace")
    except OSError:
        return []

    with handle:
        for count, line in enumerate(handle):
            if count > limit:
                break
            if "msg=audit(" not in line:
                continue
            rtype = ""
            m = re.match(r"type=(\S+)", line)
            if m:
                rtype = m.group(1)
            mid = ""
            m = re.search(r"msg=audit\(([^)]*)\)", line)
            if m:
                mid = m.group(1)
            if not mid:
                continue

            event = events.get(mid)
            if event is None:
                event = {"id": mid, "types": [], "args": {}}
                events[mid] = event
                order.append(mid)
                if len(order) > limit:
                    events.pop(order.pop(0), None)
            event["types"].append(rtype)
            event.setdefault("type", rtype)

            for key, raw in _AUDIT_KV.findall(line):
                value = _unquote(raw)
                if key in ("a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"):
                    event["args"][key] = _maybe_hex(value)
                    event[key] = event["args"][key]
                elif key in ("exe", "comm", "cwd", "name", "key", "proctitle"):
                    event[key if key != "name" else "path"] = _maybe_hex(value)
                elif key in ("uid", "auid", "euid", "pid", "ppid", "syscall",
                             "success", "res", "terminal", "tty"):
                    event[key] = value

    out = []
    for mid in order:
        event = events.get(mid)
        if not event:
            continue
        # Reassemble the command line from the argument vector, which is how a
        # Sigma rule expects to see it.
        args = [event["args"][k] for k in sorted(event["args"]) if event["args"].get(k)]
        if args:
            event["cmdline"] = " ".join(args)[:MAX_CMDLINE]
        elif event.get("proctitle"):
            event["cmdline"] = event["proctitle"][:MAX_CMDLINE]
        event["type"] = "EXECVE" if "EXECVE" in event["types"] else event.get("type", "")
        event["message"] = event.get("cmdline") or event.get("exe") or ""
        out.append(event)
    return out


# ---------------------------------------------------------------------------
# Text logs
# ---------------------------------------------------------------------------

TEXT_LOGS = [
    "/var/log/auth.log", "/var/log/secure", "/var/log/cron",
    "/var/log/syslog", "/var/log/messages",
]


def _parse_text(paths: list[str], limit: int = MAX_LINES) -> list[dict]:
    events = []
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    events.append({"message": line, "source": path,
                                   "type": "text"})
                    if len(events) >= limit:
                        return events
        except OSError:
            continue
    return events


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------


def _record_of(event: dict) -> dict:
    """The event as a field map a rule can be tested against.

    Both spellings are present on purpose: upstream Sigma writes `Image` and
    `CommandLine` even in some Linux rules, and the console maps those onto the
    Windows names before storing. So the record answers to the auditd name, the
    Sigma name and the Windows name for the same value, and a rule matches
    whichever its author happened to use.
    """
    record = dict(event)

    exe = event.get("exe") or ""
    cmdline = event.get("cmdline") or ""
    comm = event.get("comm") or ""
    message = event.get("message") or ""

    aliases = {
        "Image": exe, "NewProcessName": exe, "exe": exe,
        "CommandLine": cmdline, "ProcessCommandLine": cmdline, "cmdline": cmdline,
        "ProcessName": comm, "comm": comm,
        "ParentImage": event.get("parent_exe", ""),
        "ParentProcessName": event.get("parent_exe", ""),
        "ParentCommandLine": event.get("parent_cmdline", ""),
        "TargetFilename": event.get("path", ""),
        "CurrentDirectory": event.get("cwd", ""),
        "User": event.get("user") or event.get("uid", ""),
        "message": message, "msg": message,
    }
    for key, value in aliases.items():
        if value:
            record.setdefault(key, value)

    # Keyword searches test the whole record, exactly as the Windows evaluator
    # does with its flattened copy.
    record["__all"] = " ".join(str(v) for v in event.values() if v)
    return record


def _numeric(value: str) -> bool:
    return bool(re.fullmatch(r"-?\d+(\.\d+)?", str(value).strip()))


def _test_field(record: dict, cond: dict) -> bool:
    """One field test. Mirrors Test-DSigmaField so both platforms agree."""
    field = str(cond.get("field") or "")

    if cond.get("null_check"):
        return field not in record or not str(record.get(field) or "")

    if field == "*":
        actual = str(record.get("__all") or "")
    elif field in record:
        actual = str(record.get(field) or "")
    else:
        # Try the original Sigma spelling before giving up: a Linux rule stored
        # with a mapped Windows field name still has to find its value here.
        alt = str(cond.get("sigma_field") or "")
        if alt and alt in record:
            actual = str(record.get(alt) or "")
        else:
            return False

    op = str(cond.get("op") or "equals")
    need_all = str(cond.get("match") or "any") == "all"
    values = cond.get("values") or []
    if not isinstance(values, list):
        values = [values]

    low = actual.lower()
    hits = 0
    for raw in values:
        val = str(raw)
        vlow = val.lower()
        if op == "equals":
            hit = low == vlow
        elif op == "contains":
            hit = vlow in low
        elif op == "startswith":
            hit = low.startswith(vlow)
        elif op == "endswith":
            hit = low.endswith(vlow)
        elif op == "re":
            try:
                hit = bool(re.search(val, actual, re.IGNORECASE))
            except re.error:
                hit = False
        elif op == "cidr":
            hit = _cidr_match(actual, val)
        elif op in ("lt", "lte", "gt", "gte"):
            if not _numeric(actual) or not _numeric(val):
                hit = False
            else:
                a, b = float(actual), float(val)
                hit = {"lt": a < b, "lte": a <= b,
                       "gt": a > b, "gte": a >= b}[op]
        else:
            hit = low == vlow

        if hit:
            if not need_all:
                return True
            hits += 1
        elif need_all:
            return False

    return hits == len(values) if need_all else False


def _cidr_match(address: str, cidr: str) -> bool:
    try:
        import ipaddress

        return ipaddress.ip_address(address.strip()) in ipaddress.ip_network(
            cidr.strip(), strict=False)
    except Exception:
        return False


def _test_selection(record: dict, groups) -> bool:
    """Groups are OR'd; the fields inside a group are AND'd."""
    if groups is None:
        return False
    if isinstance(groups, dict):
        groups = [[groups]]
    for group in groups:
        if isinstance(group, dict):
            group = [group]
        if all(_test_field(record, cond) for cond in group):
            return True
    return False


def _evaluate(node, record: dict, selections: dict) -> bool:
    if not isinstance(node, dict):
        return False
    if "const" in node:
        return bool(node["const"])
    if "sel" in node:
        return _test_selection(record, selections.get(node["sel"]))

    op = node.get("op")
    args = node.get("args") or []
    if op == "and":
        return all(_evaluate(a, record, selections) for a in args)
    if op == "or":
        return any(_evaluate(a, record, selections) for a in args)
    if op == "not":
        return not _evaluate(args[0], record, selections) if args else False
    if op == "count":
        names = node.get("ids") or []
        matched = sum(1 for n in names if _test_selection(record, selections.get(n)))
        try:
            return matched >= int(node.get("need", 1))
        except (TypeError, ValueError):
            return False
    return False


def _summarise(event: dict) -> str:
    bits = []
    for key in ("exe", "cmdline", "comm", "path", "uid", "auid"):
        if event.get(key):
            bits.append(f"{key}={event[key]}")
    return " ".join(bits)[:400] or (event.get("message") or "")[:400]


def scan(bundle_path: str, audit_log: str) -> int:
    try:
        with open(bundle_path, "r", encoding="utf-8") as fh:
            bundle = json.load(fh)
    except Exception as exc:
        print(f"could not read the rule bundle: {exc}", file=sys.stderr)
        return 2

    rules = [r for r in bundle.get("rules", []) if r.get("selections")]
    if not rules:
        return 0

    audit_rules = [r for r in rules if (r.get("channel") or "") == "auditd"]
    text_rules = [r for r in rules if (r.get("channel") or "") == "text"]

    counts: dict[str, int] = {}
    scanned = 0

    def run(events: list[dict], subset: list[dict]) -> None:
        nonlocal scanned
        scanned += len(events)
        for event in events:
            record = _record_of(event)
            for rule in subset:
                rid = rule.get("id", "")
                if counts.get(rid, 0) >= MAX_HITS_PER_RULE:
                    continue
                try:
                    if not _evaluate(rule.get("condition") or {}, record,
                                     rule.get("selections") or {}):
                        continue
                except Exception:
                    # One malformed rule must not stop the rest.
                    continue
                counts[rid] = counts.get(rid, 0) + 1
                print(json.dumps({
                    "id": rid,
                    "title": rule.get("title", ""),
                    "severity": rule.get("severity") or "MEDIUM",
                    "mitre": rule.get("mitre") or "",
                    "evidence": _summarise(event),
                    "source": rule.get("channel") or "",
                }), flush=True)

    if audit_rules:
        run(_parse_audit(audit_log or "/var/log/audit/audit.log"), audit_rules)
    if text_rules:
        present = [p for p in TEXT_LOGS if os.path.isfile(p)]
        present += sorted(glob.glob("/var/log/auth.log.1"))[:1]
        run(_parse_text(present), text_rules)

    print(json.dumps({"events": scanned, "rules": len(rules)}), file=sys.stderr)
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: douglas-sigma.py BUNDLE.json [AUDIT_LOG]", file=sys.stderr)
        return 2
    return scan(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "")


if __name__ == "__main__":
    sys.exit(main())
