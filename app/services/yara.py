"""Compile a practical subset of YARA into a plan the agent can run.

There is no YARA engine in PowerShell. The options were to ship yara64.exe with
every agent — an extra binary that draws EDR attention on a host you are trying
to investigate quietly — or to compile the part of the language that matters for
file detection into simple string matching. This does the second.

What compiles: text strings, hex strings with wildcards, regular expressions,
the usual modifiers (nocase, wide, ascii, fullword), and conditions built from
`any of them`, `all of them`, `N of ($x*)`, individual identifiers, and boolean
operators over those, optionally with a `filesize` bound.

What does not: the pe, math, hash and elf modules, `for` loops, `at`/`in`
offsets, and string counts. Those need a real engine, and a rule that silently
tests less than it claims is worse than one that is honestly refused — so they
are rejected with a reason, the same way unsupported Sigma rules are.
"""
from __future__ import annotations

import binascii
import hashlib
import re

# ---------------------------------------------------------------------------
# Tokenising a rule file
# ---------------------------------------------------------------------------

_RULE_RE = re.compile(
    r"(?:^|\n)\s*(?:(?P<mods>(?:private|global)\s+)*)rule\s+(?P<name>[A-Za-z_]\w*)"
    r"\s*(?::\s*(?P<tags>[^{]+?))?\s*\{",
    re.MULTILINE,
)

_UNSUPPORTED_TOKENS = [
    (re.compile(r"\bpe\s*\."), "the pe module"),
    (re.compile(r"\belf\s*\."), "the elf module"),
    (re.compile(r"\bmath\s*\."), "the math module"),
    (re.compile(r"\bhash\s*\."), "the hash module"),
    (re.compile(r"\bcuckoo\s*\."), "the cuckoo module"),
    (re.compile(r"\bmagic\s*\."), "the magic module"),
    (re.compile(r"\bdotnet\s*\."), "the dotnet module"),
    (re.compile(r"\bfor\s+(any|all|\d+)\b"), "for loops"),
    (re.compile(r"\bthem\s+(at|in)\b"), "offset constraints"),
    (re.compile(r"\$\w*\s+at\s+"), "offset constraints"),
    (re.compile(r"\bentrypoint\b"), "entrypoint references"),
    (re.compile(r"\buint(8|16|32)\s*\("), "integer reads"),
    (re.compile(r"\bint(8|16|32)\s*\("), "integer reads"),
]


class UnsupportedRule(Exception):
    """Raised with a human-readable reason the rule cannot be compiled."""


def _find_rule_bodies(text: str) -> list[tuple[str, str, list[str]]]:
    """Return (name, body, tags) for each rule, brace-matched."""
    out = []
    for m in _RULE_RE.finditer(text):
        start = m.end() - 1  # at the opening brace
        depth = 0
        end = None
        in_str = None
        i = start
        while i < len(text):
            ch = text[i]
            if in_str:
                if ch == "\\":
                    i += 2
                    continue
                if ch == in_str:
                    in_str = None
            elif ch in '"/':
                # A slash could start a regex or a comment; only treat quotes
                # as string starts, comments are stripped before this runs.
                if ch == '"':
                    in_str = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
            i += 1
        if end is None:
            continue
        tags = (m.group("tags") or "").split()
        out.append((m.group("name"), text[start + 1 : end], tags))
    return out


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    # Keep // inside quoted strings and regexes intact.
    cleaned = []
    for line in text.split("\n"):
        out, in_str, i = [], None, 0
        while i < len(line):
            ch = line[i]
            if in_str:
                out.append(ch)
                if ch == "\\" and i + 1 < len(line):
                    out.append(line[i + 1])
                    i += 2
                    continue
                if ch == in_str:
                    in_str = None
            elif ch in '"/':
                if ch == "/" and i + 1 < len(line) and line[i + 1] == "/":
                    break
                out.append(ch)
                if ch == '"':
                    in_str = ch
            else:
                out.append(ch)
            i += 1
        cleaned.append("".join(out))
    return "\n".join(cleaned)


# ---------------------------------------------------------------------------
# Strings section
# ---------------------------------------------------------------------------

_STRING_RE = re.compile(
    r'(?P<id>\$[\w*]*)\s*=\s*(?P<value>"(?:[^"\\]|\\.)*"|\{[^}]*\}|/(?:[^/\\\n]|\\.)*/[a-z]*)'
    r'(?P<mods>(?:\s+(?:nocase|wide|ascii|fullword|xor|base64|base64wide|private)(?:\([^)]*\))?)*)'
)


def _parse_hex_string(raw: str) -> dict:
    """Turn a YARA hex string into a regex over the file's hex representation.

    Matching happens against the file rendered as hex, which makes wildcards
    (?? and ranges) trivial and avoids binary-safety problems in PowerShell.
    """
    body = raw.strip()[1:-1]
    body = re.sub(r"\s+", "", body)
    if "(" in body or "|" in body:
        raise UnsupportedRule("hex alternation is not supported")

    parts = []
    i = 0
    while i < len(body):
        if body[i] == "?":
            # ?? is any byte; a half-wildcard like 4? is also legal.
            if i + 1 < len(body) and body[i + 1] == "?":
                parts.append("..")
                i += 2
            else:
                parts.append(".")
                i += 1
        elif body[i] == "[":
            close = body.find("]", i)
            if close < 0:
                raise UnsupportedRule("malformed hex jump")
            span = body[i + 1 : close]
            if "-" in span:
                lo, _, hi = span.partition("-")
                lo = int(lo or 0)
                hi = int(hi) if hi else lo + 64
            else:
                lo = hi = int(span)
            parts.append(f"(?:..){{{lo},{hi}}}")
            i = close + 1
        else:
            ch = body[i]
            if ch not in "0123456789abcdefABCDEF":
                raise UnsupportedRule(f"unexpected character in hex string: {ch!r}")
            parts.append(re.escape(ch.lower()))
            i += 1
    return {"kind": "hex", "pattern": "".join(parts)}


def _parse_string(sid: str, value: str, mods: str) -> dict:
    modifiers = set(re.findall(r"nocase|wide|ascii|fullword|xor|base64wide|base64|private", mods))
    if "xor" in modifiers:
        raise UnsupportedRule("the xor modifier needs a real engine")

    if value.startswith("{"):
        entry = _parse_hex_string(value)
    elif value.startswith("/"):
        end = value.rfind("/")
        pattern, flags = value[1:end], value[end + 1 :]
        entry = {
            "kind": "regex",
            "pattern": pattern,
            "nocase": "i" in flags or "nocase" in modifiers,
        }
    else:
        raw = value[1:-1]
        text = (
            raw.replace("\\\\", "\x00")
            .replace('\\"', '"')
            .replace("\\n", "\n")
            .replace("\\r", "\r")
            .replace("\\t", "\t")
            .replace("\x00", "\\")
        )
        text = re.sub(r"\\x([0-9a-fA-F]{2})",
                      lambda m: chr(int(m.group(1), 16)), text)
        entry = {
            "kind": "text",
            "value": text,
            "nocase": "nocase" in modifiers,
            "fullword": "fullword" in modifiers,
            # `wide` means UTF-16LE; the agent reads files as both encodings, so
            # this only records which forms are acceptable.
            "wide": "wide" in modifiers,
            "ascii": "ascii" in modifiers or "wide" not in modifiers,
            "base64": "base64" in modifiers or "base64wide" in modifiers,
        }
    entry["id"] = sid
    return entry


# ---------------------------------------------------------------------------
# Condition
# ---------------------------------------------------------------------------

_COND_TOKEN = re.compile(
    r"\s*(\(|\)|\band\b|\bor\b|\bnot\b|\ball\b|\bany\b|\bthem\b|\bof\b|"
    r"\bfilesize\b|[<>]=?|==|\d+\w*|\$[\w*]*|[A-Za-z_]\w*)"
)

_SIZE_UNITS = {"kb": 1024, "mb": 1024 * 1024, "gb": 1024 * 1024 * 1024}


def _expand(pattern: str, ids: list[str]) -> list[str]:
    if pattern == "them" or pattern == "$*":
        return list(ids)
    if "*" not in pattern:
        return [pattern] if pattern in ids else []
    rx = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
    return [i for i in ids if rx.match(i)]


def _parse_condition(condition: str, ids: list[str]) -> tuple[dict, dict]:
    """Return (tree, size_bounds). Raises UnsupportedRule with a reason."""
    for rx, label in _UNSUPPORTED_TOKENS:
        if rx.search(condition):
            raise UnsupportedRule(f"{label} need a real YARA engine")

    tokens = [m.group(1) for m in _COND_TOKEN.finditer(condition)]
    if not tokens:
        raise UnsupportedRule("the condition is empty")

    pos = 0
    size: dict = {}

    def peek(offset=0):
        return tokens[pos + offset] if pos + offset < len(tokens) else None

    def take():
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def parse_or():
        node = parse_and()
        while peek() == "or":
            take()
            node = {"op": "or", "args": [node, parse_and()]}
        return node

    def parse_and():
        node = parse_not()
        while peek() == "and":
            take()
            node = {"op": "and", "args": [node, parse_not()]}
        return node

    def parse_not():
        if peek() == "not":
            take()
            return {"op": "not", "args": [parse_not()]}
        return parse_atom()

    def parse_atom():
        nonlocal size
        tok = peek()
        if tok is None:
            raise UnsupportedRule("the condition ends unexpectedly")

        if tok == "(":
            take()
            node = parse_or()
            if peek() != ")":
                raise UnsupportedRule("unbalanced parentheses")
            take()
            return node

        # filesize < 2MB  — recorded as a bound rather than a match node.
        if tok == "filesize":
            take()
            op = take()
            raw = take()
            m = re.match(r"(\d+)\s*(kb|mb|gb)?", raw, re.I)
            if not m:
                raise UnsupportedRule("could not read the filesize bound")
            value = int(m.group(1)) * _SIZE_UNITS.get((m.group(2) or "").lower(), 1)
            if op in ("<", "<="):
                size["max"] = value
            elif op in (">", ">="):
                size["min"] = value
            return {"const": True}

        # any/all/N of (...)
        if tok in ("any", "all") or re.fullmatch(r"\d+", tok or ""):
            quant = take()
            if peek() != "of":
                # A bare number that is not a quantifier: treat as always true
                # rather than guessing.
                return {"const": True}
            take()
            group = []
            if peek() == "(":
                take()
                while peek() and peek() != ")":
                    t = take()
                    if t not in (",",):
                        group.extend(_expand(t, ids))
                if peek() == ")":
                    take()
            else:
                group = _expand(take(), ids)

            group = [g for g in dict.fromkeys(group)]
            if not group:
                raise UnsupportedRule("a quantifier matches no defined string")
            if quant == "all":
                need = len(group)
            elif quant == "any":
                need = 1
            else:
                need = int(quant)
            return {"op": "count", "need": need, "ids": group}

        if tok.startswith("$"):
            sid = take()
            matched = _expand(sid, ids)
            if not matched:
                raise UnsupportedRule(f"the condition references an undefined string '{sid}'")
            if len(matched) == 1:
                return {"str": matched[0]}
            return {"op": "count", "need": 1, "ids": matched}

        # Anything else — a rule reference, an external variable — is refused
        # rather than assumed true.
        raise UnsupportedRule(f"unsupported term in the condition: '{tok}'")

    tree = parse_or()
    if pos != len(tokens):
        raise UnsupportedRule(f"could not parse the whole condition near '{tokens[pos]}'")
    return tree, size


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def compile_rule(name: str, body: str, tags: list[str], source: str = "") -> dict:
    meta = {}
    for m in re.finditer(r'(\w+)\s*=\s*("(?:[^"\\]|\\.)*"|true|false|\d+)', body):
        section = body[: m.start()]
        if "meta:" in section and "strings:" not in section.split("meta:")[-1]:
            value = m.group(2)
            meta[m.group(1).lower()] = value[1:-1] if value.startswith('"') else value

    cond_match = re.search(r"\bcondition\s*:(.*)$", body, re.DOTALL)
    if not cond_match:
        raise UnsupportedRule("the rule has no condition")
    condition = cond_match.group(1).strip()

    # Check for unsupported constructs before anything else. A rule using the
    # pe module rejected as "no usable strings" is technically true and tells
    # the operator nothing about why it cannot run here.
    for rx, label in _UNSUPPORTED_TOKENS:
        if rx.search(condition):
            raise UnsupportedRule(f"{label} need a real YARA engine")

    strings_part = ""
    sm = re.search(r"\bstrings\s*:(.*?)\bcondition\s*:", body, re.DOTALL)
    if sm:
        strings_part = sm.group(1)

    strings = []
    for m in _STRING_RE.finditer(strings_part):
        strings.append(_parse_string(m.group("id"), m.group("value"), m.group("mods") or ""))

    if not strings:
        raise UnsupportedRule("no usable strings; this rule matches on structure alone")

    ids = [s["id"] for s in strings]
    tree, size = _parse_condition(condition, ids)

    severity = "HIGH"
    level = (meta.get("severity") or meta.get("level") or "").lower()
    if level in ("critical", "high", "medium", "low", "info"):
        severity = level.upper()

    return {
        "id": hashlib.sha256(f"{name}|{source}".encode()).hexdigest()[:16],
        "name": name,
        "description": meta.get("description", "")[:500],
        "author": meta.get("author", "")[:200],
        "reference": meta.get("reference", "")[:300],
        "tags": tags,
        "severity": severity,
        "strings": strings,
        "condition": tree,
        "condition_text": condition[:400],
        "filesize_min": size.get("min"),
        "filesize_max": size.get("max"),
        "source": source,
    }


def compile_many(documents: list[tuple[str, str]]) -> dict:
    compiled: list[dict] = []
    rejected: list[dict] = []
    seen: set[str] = set()

    for name, text in documents:
        try:
            cleaned = _strip_comments(text)
            bodies = _find_rule_bodies(cleaned)
        except Exception as exc:  # pragma: no cover - defensive
            rejected.append({"file": name, "reason": f"could not read the file: {exc}"})
            continue

        if not bodies:
            rejected.append({"file": name, "reason": "no rules found in this file"})
            continue

        for rule_name, body, tags in bodies:
            try:
                rule = compile_rule(rule_name, body, tags, source=name)
            except UnsupportedRule as exc:
                rejected.append({"file": f"{name}:{rule_name}", "reason": str(exc)})
                continue
            except Exception as exc:  # pragma: no cover - defensive
                rejected.append({"file": f"{name}:{rule_name}",
                                 "reason": f"could not compile: {exc}"})
                continue
            if rule["id"] in seen:
                continue
            seen.add(rule["id"])
            compiled.append(rule)

    return {"rules": compiled, "rejected": rejected}
