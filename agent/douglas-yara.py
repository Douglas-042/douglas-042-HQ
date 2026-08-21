#!/usr/bin/env python3
"""YARA matching for the Linux collector.

Why this exists rather than shelling out to the real yara binary: the console
parses uploaded rules into a simplified structure before storing them, and
anything it cannot represent is rejected at upload time with a reason. So the
bundle that reaches a host only ever contains rules the simplified engine can
evaluate — running the full engine over a reconstructed .yar would not find
anything more, and reconstructing the source risks the two disagreeing about
what a rule means.

Evaluating the same parsed bundle the Windows collector evaluates is the
stronger guarantee: a rule that fires on a Windows host fires on a Linux host
for the same reason, because both are reading the same structure with the same
rules rather than two engines that happen to agree most of the time.

Reads:  a bundle (JSON) and a list of paths to scan
Writes: one JSON object per line on stdout, one per match

Nothing here decides severity floors, per-rule caps or whether a rule is
switched off. Those belong to the collector's finding() and are applied there,
so the two platforms cannot drift on the rules about rules.
"""
from __future__ import annotations

import binascii
import json
import os
import re
import sys

# A file bigger than this is not read. YARA rules in this set look for strings
# near the start of a file; pulling a 400 MB core dump through memory to prove
# otherwise costs more than the answer is worth.
MAX_READ = 16 * 1024 * 1024
# Matching stops after this many hits per rule. A rule that matches five
# thousand files is describing the estate, not an intrusion, and the report is
# unreadable either way.
MAX_HITS_PER_RULE = 20


def _decode_all(blob: bytes) -> tuple[str, str]:
    """The file as ASCII-ish text and as UTF-16LE text.

    Both, because `wide` in YARA means UTF-16LE and a rule may ask for either
    or both. Decoding once here is much cheaper than per-string.
    """
    ascii_text = blob.decode("latin-1", errors="replace")
    try:
        wide_text = blob.decode("utf-16-le", errors="replace")
    except Exception:
        wide_text = ""
    return ascii_text, wide_text


def _match_text(spec: dict, ascii_text: str, wide_text: str, hexed: str) -> bool:
    value = spec.get("value") or ""
    if not value:
        return False
    nocase = bool(spec.get("nocase"))
    fullword = bool(spec.get("fullword"))

    haystacks = []
    if spec.get("ascii", True):
        haystacks.append(ascii_text)
    if spec.get("wide"):
        haystacks.append(wide_text)
    if spec.get("base64"):
        import base64

        for variant in range(3):
            padded = b"\x00" * variant + value.encode("latin-1", errors="replace")
            encoded = base64.b64encode(padded).decode()
            # The middle of the encoding is the part that survives the offset,
            # which is how YARA's base64 modifier behaves.
            if encoded[4:-4] and encoded[4:-4] in ascii_text:
                return True

    needle = value
    for hay in haystacks:
        if not hay:
            continue
        if fullword:
            flags = re.IGNORECASE if nocase else 0
            if re.search(rf"(?<!\w){re.escape(needle)}(?!\w)", hay, flags):
                return True
        elif nocase:
            if needle.lower() in hay.lower():
                return True
        elif needle in hay:
            return True
    return False


def _match_regex(spec: dict, ascii_text: str, wide_text: str) -> bool:
    pattern = spec.get("pattern") or ""
    if not pattern:
        return False
    flags = re.IGNORECASE if spec.get("nocase") else 0
    try:
        compiled = re.compile(pattern, flags)
    except re.error:
        # A pattern this engine cannot compile is reported as no match rather
        # than crashing the sweep. The console validated it against Python's
        # own regex module at upload, so this is close to unreachable.
        return False
    return bool(compiled.search(ascii_text) or (wide_text and compiled.search(wide_text)))


def _match_hex(spec: dict, hexed: str) -> bool:
    pattern = (spec.get("pattern") or "").lower()
    if not pattern:
        return False
    # Wildcards from the parser arrive as '??' per nibble pair.
    if "?" in pattern:
        regex = pattern.replace("?", ".")
        try:
            return bool(re.search(regex, hexed))
        except re.error:
            return False
    return pattern in hexed


def _string_hits(rule: dict, blob: bytes) -> dict:
    ascii_text, wide_text = _decode_all(blob)
    hexed = binascii.hexlify(blob).decode()

    hits = {}
    for spec in rule.get("strings", []):
        sid = spec.get("id") or ""
        kind = spec.get("kind") or "text"
        if kind == "hex":
            hits[sid] = _match_hex(spec, hexed)
        elif kind == "regex":
            hits[sid] = _match_regex(spec, ascii_text, wide_text)
        else:
            hits[sid] = _match_text(spec, ascii_text, wide_text, hexed)
    return hits


def _evaluate(node: dict, hits: dict) -> bool:
    """Walk the condition the console produced.

    Deliberately the same shape the Windows evaluator walks: and/or/not,
    string references, quantifiers, and a const for anything folded away at
    parse time such as a filesize bound.
    """
    if not isinstance(node, dict):
        return False
    if "const" in node:
        return bool(node["const"])
    if "str" in node:
        return bool(hits.get(node["str"]))

    op = node.get("op")
    args = node.get("args") or []

    if op == "and":
        return all(_evaluate(a, hits) for a in args)
    if op == "or":
        return any(_evaluate(a, hits) for a in args)
    if op == "not":
        return not _evaluate(args[0], hits) if args else False
    if op == "count":
        # The console folds any/all/N-of into one node: the ids in the group
        # and how many of them have to hit. Read from the parser rather than
        # assumed — an earlier version guessed a different shape and every
        # "all of them" rule silently never fired, which is the worst way for a
        # detection to be wrong.
        ids = node.get("ids") or []
        matched = sum(1 for sid in ids if hits.get(sid))
        try:
            need = int(node.get("need", 1))
        except (TypeError, ValueError):
            return False
        return matched >= need
    return False


def _size_ok(rule: dict, size: int) -> bool:
    low = rule.get("filesize_min")
    high = rule.get("filesize_max")
    if low is not None and size < low:
        return False
    if high is not None and size > high:
        return False
    return True


def scan(bundle_path: str, targets: list[str]) -> int:
    try:
        with open(bundle_path, "r", encoding="utf-8") as fh:
            bundle = json.load(fh)
    except Exception as exc:
        print(json.dumps({"error": f"could not read the rule bundle: {exc}"}))
        return 2

    rules = [r for r in bundle.get("rules", []) if r.get("strings")]
    if not rules:
        return 0

    counts = {r.get("name", ""): 0 for r in rules}
    scanned = 0

    for path in targets:
        try:
            stat = os.stat(path)
        except OSError:
            continue
        if not os.path.isfile(path) or stat.st_size == 0 or stat.st_size > MAX_READ:
            continue

        # Rules that could not match on size are skipped before the file is
        # read, which is most of the saving on a large tree.
        applicable = [r for r in rules
                      if _size_ok(r, stat.st_size)
                      and counts.get(r.get("name", ""), 0) < MAX_HITS_PER_RULE]
        if not applicable:
            continue

        try:
            with open(path, "rb") as fh:
                blob = fh.read(MAX_READ)
        except OSError:
            continue
        scanned += 1

        for rule in applicable:
            hits = _string_hits(rule, blob)
            if not any(hits.values()):
                # Every rule here needs at least one string, so no string means
                # no match without walking the condition.
                continue
            if not _evaluate(rule.get("condition") or {}, hits):
                continue

            name = rule.get("name", "")
            counts[name] = counts.get(name, 0) + 1
            matched = [sid for sid, ok in hits.items() if ok][:6]
            print(json.dumps({
                "rule": name,
                "severity": rule.get("severity") or "HIGH",
                "path": path,
                "size": stat.st_size,
                "strings": matched,
                "description": (rule.get("description") or "")[:200],
            }), flush=True)

    print(json.dumps({"scanned": scanned, "rules": len(rules)}), file=sys.stderr)
    return 0


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: douglas-yara.py BUNDLE.json FILELIST", file=sys.stderr)
        return 2
    bundle_path, list_path = sys.argv[1], sys.argv[2]
    try:
        with open(list_path, "r", encoding="utf-8", errors="replace") as fh:
            targets = [l.strip() for l in fh if l.strip()]
    except OSError as exc:
        print(f"could not read the file list: {exc}", file=sys.stderr)
        return 2
    return scan(bundle_path, targets)


if __name__ == "__main__":
    sys.exit(main())
