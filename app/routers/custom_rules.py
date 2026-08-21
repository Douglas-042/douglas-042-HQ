"""Custom detection rules written in the console."""
from __future__ import annotations

import re
from datetime import timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..auth import require_agent, require_console, require_responder
from ..database import get_db
from ..models import Agent, AuditEvent, CustomRule, Finding, new_id, utcnow
from ..services import custom_rules as engine
from ..services import rule_import as importer

router = APIRouter()

RULE_ID_RE = re.compile(r"^[A-Z][A-Z0-9]{1,7}-[A-Za-z0-9_.-]{1,16}$")


def _iso(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def rule_dict(r: CustomRule, fired: int = 0) -> dict:
    payload = {
        "id": r.id,
        "rule_id": r.rule_id,
        "title": r.title,
        "severity": r.severity,
        "mitre": r.mitre or "",
        "why": r.why or "",
        "artifact": r.artifact,
        "artifact_label": engine.ARTIFACT_FIELDS.get(r.artifact, {}).get("label", r.artifact),
        "match": r.match,
        "conditions": r.conditions or [],
        "enabled": bool(r.enabled),
        "fired": fired,
        "created_at": _iso(r.created_at),
        "created_by": r.created_by,
    }
    payload["description"] = engine.describe(payload)
    return payload


@router.get("/schema")
def schema(_u=Depends(require_console)):
    """Which artifacts can be targeted and what columns they carry."""
    return {
        "artifacts": [
            {"name": name, "label": meta["label"], "fields": meta["fields"]}
            for name, meta in sorted(
                engine.ARTIFACT_FIELDS.items(), key=lambda kv: kv[1]["label"])
        ],
        "operators": [{"op": k, "label": v, "needs_value": k not in engine.VALUELESS}
                      for k, v in engine.OPERATORS.items()],
        "severities": engine.SEVERITIES,
    }


@router.get("")
def list_rules(db: Session = Depends(get_db), _u=Depends(require_console)):
    rows = db.query(CustomRule).order_by(CustomRule.rule_id).all()
    counts = {}
    for r in rows:
        counts[r.rule_id] = (
            db.query(Finding).filter(Finding.rule_id == r.rule_id).count()
        )
    return {
        "total": len(rows),
        "enabled": sum(1 for r in rows if r.enabled),
        "rules": [rule_dict(r, counts.get(r.rule_id, 0)) for r in rows],
    }


class Condition(BaseModel):
    field: str
    op: str
    value: str = ""


class RuleRequest(BaseModel):
    rule_id: str = Field(min_length=3, max_length=32)
    title: str = Field(min_length=1, max_length=300)
    severity: str = "MEDIUM"
    mitre: str = ""
    why: str = ""
    artifact: str
    match: str = "all"
    conditions: list[Condition] = Field(default_factory=list)
    enabled: bool = True


def _as_dict(payload: RuleRequest) -> dict:
    return {
        "rule_id": payload.rule_id.strip().upper(),
        "title": payload.title.strip(),
        "severity": payload.severity.upper(),
        "mitre": payload.mitre.strip(),
        "why": payload.why.strip(),
        "artifact": payload.artifact,
        "match": "any" if payload.match == "any" else "all",
        "conditions": [c.model_dump() for c in payload.conditions],
        "enabled": payload.enabled,
    }


def _check(data: dict) -> None:
    if not RULE_ID_RE.match(data["rule_id"]):
        raise HTTPException(
            status_code=400,
            detail="Rule id looks like CUSTOM-001 or ACME-webshell: a prefix, "
                   "a dash, then letters, digits, dots or dashes.",
        )
    if data["rule_id"].startswith(("DGL-", "SIGMA-", "YARA-")):
        raise HTTPException(
            status_code=400,
            detail="DGL, SIGMA and YARA are reserved so a custom rule is never "
                   "mistaken for a built-in one. Use your own prefix.",
        )
    if data["mitre"] and not re.match(r"^T\d{4}(\.\d{3})?$", data["mitre"]):
        raise HTTPException(status_code=400, detail="MITRE ids look like T1055 or T1055.012.")
    try:
        engine.validate(data)
    except engine.InvalidRule as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("")
def create_rule(
    payload: RuleRequest,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    data = _as_dict(payload)
    _check(data)
    if db.query(CustomRule).filter(CustomRule.rule_id == data["rule_id"]).first():
        raise HTTPException(status_code=409, detail="That rule id is already in use.")

    row = CustomRule(id=new_id(), created_by=user.username, **data)
    db.add(row)
    db.add(AuditEvent(kind="rule.created", subject=data["rule_id"],
                      detail=f"{data['title']} by {user.username}"))
    try:
        db.commit()
    except IntegrityError:
        # The check above is a read followed by a write; two requests can both
        # pass it. The unique index is what actually decides, and a duplicate
        # id is a 409 rather than a stack trace.
        db.rollback()
        raise HTTPException(status_code=409,
                            detail="That rule id is already in use.") from None
    db.refresh(row)
    return rule_dict(row)


# NOTE: every literal path below must be declared before the parameterised
# ones. FastAPI matches in registration order, so POST /{rule_pk} declared
# first would swallow /test and reject it as an unknown rule.
# ---------------------------------------------------------------------------
# Bulk import and export
# ---------------------------------------------------------------------------


class ImportRequest(BaseModel):
    # Either paste the text or upload a file; both land here.
    text: str = ""
    filename: str = ""
    # skip: leave an existing rule alone (the safe default)
    # replace: overwrite it
    # rename: import alongside it as ID.2
    on_conflict: str = "skip"


@router.post("/import/preview")
def preview_import(
    payload: ImportRequest,
    db: Session = Depends(get_db),
    _u=Depends(require_console),
):
    """Say what an import would do, without writing anything.

    Separated from the import itself because a bulk write over a tuned rule set
    is not something anyone should discover after the fact. The preview names
    each rule and its outcome, so a file with one bad row can be fixed rather
    than guessed at.
    """
    if payload.on_conflict not in ("skip", "replace", "rename"):
        raise HTTPException(status_code=400,
                            detail="on_conflict must be skip, replace or rename.")
    try:
        rows, fmt = importer.parse(payload.text, payload.filename)
        existing = {r.rule_id for r in db.query(CustomRule).all()}
        result = importer.plan(rows, existing, payload.on_conflict)
    except importer.ImportError_ as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # The parsed rule bodies are only needed by the write step.
    items = [{k: v for k, v in item.items() if k != "rule"} for item in result["items"]]
    return {**result, "items": items, "format": fmt}


@router.post("/import")
def do_import(
    payload: ImportRequest,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    """Import a file of rules. Rules are validated one by one.

    A single bad rule does not reject the file: the good ones are written and
    the bad ones come back named, with the reason. An all-or-nothing import of
    thirty rules turns one typo into a hunt for it.
    """
    if payload.on_conflict not in ("skip", "replace", "rename"):
        raise HTTPException(status_code=400,
                            detail="on_conflict must be skip, replace or rename.")

    try:
        rows, fmt = importer.parse(payload.text, payload.filename)
        existing_rows = {r.rule_id: r for r in db.query(CustomRule).all()}
        result = importer.plan(rows, set(existing_rows), payload.on_conflict)
    except importer.ImportError_ as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    added = replaced = 0
    for item in result["items"]:
        if item["action"] not in ("add", "replace"):
            continue
        data = item["rule"]
        if item["action"] == "replace":
            row = existing_rows[data["rule_id"]]
            for key, value in data.items():
                setattr(row, key, value)
            row.updated_at = utcnow()
            replaced += 1
        else:
            # Each new rule is committed on its own so one clash cannot discard
            # the rules that imported cleanly beside it. A duplicate here means
            # a concurrent import won the race, which is the same outcome as
            # the skip policy and is reported that way.
            db.add(CustomRule(id=new_id(), created_by=user.username, **data))
            try:
                db.flush()
                added += 1
            except IntegrityError:
                db.rollback()
                item["action"] = "skipped"
                item["reason"] = "Another import added this id at the same moment."
                result["skipped"] += 1

    db.add(AuditEvent(
        kind="rules.imported",
        subject=f"{added} added, {replaced} replaced",
        detail=f"{fmt} file by {user.username}"))
    db.commit()

    items = [{k: v for k, v in item.items() if k != "rule"} for item in result["items"]]
    return {
        "format": fmt,
        "added": added,
        "replaced": replaced,
        "skipped": result["skipped"],
        "rejected": result["rejected"],
        "items": items,
    }


@router.post("/check")
def check_rule_text(
    payload: ImportRequest,
    db: Session = Depends(get_db),
    _u=Depends(require_console),
):
    """Validate one hand-written rule and say precisely what is wrong with it.

    Separate from the import preview because the two are answering different
    questions. Import asks "what would this file do to my rule set"; this asks
    "is what I am typing right yet", and the answer has to point at the line
    rather than at the rule — somebody mid-sentence needs to know which word
    the parser choked on, not that rule 1 of 1 failed.
    """
    text = (payload.text or "").strip()
    if not text:
        return {"ok": False, "errors": [{"line": 1, "message": "Nothing written yet."}],
                "summary": "", "rule": None}

    lines = text.splitlines()

    def line_of(needle: str, default: int = 1) -> int:
        """Which line mentions this value, so an error can point at it."""
        probe = (needle or "").strip().lower()
        if not probe:
            return default
        for number, line in enumerate(lines, start=1):
            if probe in line.lower():
                return number
        return default

    try:
        rows, fmt = importer.parse(text, payload.filename or "rule.yaml")
    except importer.ImportError_ as exc:
        return {"ok": False, "summary": "", "rule": None,
                "errors": [{"line": 1, "message": str(exc)}]}

    if len(rows) != 1:
        return {
            "ok": False, "summary": "", "rule": None,
            "errors": [{"line": 1, "message":
                        f"This is {len(rows)} rules. Write one here, or use "
                        "Import for a file of them."}],
        }

    try:
        rule = importer.normalise(rows[0])
    except ValueError as exc:
        # A malformed condition: point at the condition block.
        return {"ok": False, "summary": "", "rule": None,
                "errors": [{"line": line_of("when", line_of("conditions")),
                            "message": str(exc)}]}

    problem = importer.check(rule)
    if problem:
        # Aim the error at whichever field it is about.
        anchor = 1
        low = problem.lower()
        if "rule id" in low or "prefix" in low or "reserved" in low:
            anchor = line_of("id")
        elif "artifact" in low:
            anchor = line_of("artifact")
        elif "mitre" in low:
            anchor = line_of("mitre")
        elif "severity" in low:
            anchor = line_of("severity")
        elif "condition" in low or "operator" in low or "field" in low:
            anchor = line_of("when", line_of("conditions"))
        elif "title" in low:
            anchor = line_of("title")
        return {"ok": False, "summary": "", "rule": None,
                "errors": [{"line": anchor, "message": problem}]}

    existing = db.query(CustomRule).filter(CustomRule.rule_id == rule["rule_id"]).first()

    return {
        "ok": True,
        "format": fmt,
        "rule": rule,
        # What the rule will actually do, in a sentence. A rule that validates
        # and does something other than what its author meant is the failure
        # this catches.
        "summary": engine.describe(rule),
        "artifact_label": engine.ARTIFACT_FIELDS[rule["artifact"]]["label"],
        "exists": bool(existing),
        "errors": [],
    }


@router.get("/export")
def export_rules(
    fmt: str = "json",
    db: Session = Depends(get_db),
    _u=Depends(require_console),
):
    """Every rule written here, in a form this console will read back."""
    rows = db.query(CustomRule).order_by(CustomRule.rule_id).all()
    rules = [
        {
            "rule_id": r.rule_id, "title": r.title, "severity": r.severity,
            "mitre": r.mitre or "", "why": r.why or "", "artifact": r.artifact,
            "match": r.match, "conditions": r.conditions or [],
            "enabled": bool(r.enabled),
        }
        for r in rows
    ]

    stamp = utcnow().strftime("%Y%m%d")
    if fmt == "yaml":
        return PlainTextResponse(
            importer.to_yaml(rules), media_type="text/yaml; charset=utf-8",
            headers={"Content-Disposition":
                     f'attachment; filename="douglas-rules_{stamp}.yaml"'})
    if fmt == "csv":
        return PlainTextResponse(
            importer.to_csv(rules), media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition":
                     f'attachment; filename="douglas-rules_{stamp}.csv"'})

    return JSONResponse(
        importer.to_bundle(rules),
        headers={"Content-Disposition":
                 f'attachment; filename="douglas-rules_{stamp}.json"'})


@router.get("/import/help")
def import_help(_u=Depends(require_console)):
    """What a rule file may contain, and one worked example of each format.

    Served from the server rather than written into the console so the field
    names and operators shown are the ones actually accepted — a hand-written
    help page drifts from the validator and then teaches people to write files
    that get rejected.
    """
    sample = importer.STARTER_PACK[0]
    return {
        "formats": [
            {"id": "json", "name": "JSON",
             "note": "What this console exports. Import it back unchanged."},
            {"id": "yaml", "name": "YAML",
             "note": "For writing by hand. Several rules in one file, separated "
                     "by --- , the way a Sigma pack is laid out."},
            {"id": "csv", "name": "CSV",
             "note": "For a spreadsheet. One rule per row, conditions in a "
                     "single column using the compact syntax."},
        ],
        "fields": [
            {"name": "rule_id", "required": True,
             "note": "Your own prefix, then a dash: ACME-001. DGL, SIGMA and "
                     "YARA are reserved."},
            {"name": "title", "required": True,
             "note": "Becomes the finding's headline."},
            {"name": "severity", "required": False,
             "note": "CRITICAL, HIGH, MEDIUM, LOW or INFO. Defaults to MEDIUM."},
            {"name": "artifact", "required": True,
             "note": "Which collected table the rule reads."},
            {"name": "conditions", "required": True,
             "note": "A list of {field, op, value}, or one compact line."},
            {"name": "match", "required": False,
             "note": "all (default) or any."},
            {"name": "mitre", "required": False, "note": "T1055 or T1055.012."},
            {"name": "why", "required": False,
             "note": "Shown under the finding to whoever reads it."},
            {"name": "enabled", "required": False, "note": "Defaults to true."},
        ],
        "artifacts": [
            {"name": name, "label": meta["label"], "fields": meta["fields"]}
            for name, meta in sorted(engine.ARTIFACT_FIELDS.items(),
                                     key=lambda kv: kv[1]["label"])
        ],
        "operators": [
            {"op": k, "label": v, "needs_value": k not in engine.VALUELESS}
            for k, v in engine.OPERATORS.items()
        ],
        "compact_syntax": 'FIELD OPERATOR VALUE, separated by ; — for example: '
                          'Signed is_false; PathName not_contains "Program Files"',
        "examples": {
            "yaml": importer.to_yaml([{**sample,
                                       "conditions": importer.parse_conditions(sample["conditions"])}]),
            "csv": importer.to_csv([{**sample,
                                     "conditions": importer.parse_conditions(sample["conditions"])}]),
        },
        "starter_pack_size": len(importer.STARTER_PACK),
        "max_rules": importer.MAX_RULES_PER_IMPORT,
    }


@router.post("/import/starter-pack")
def import_starter_pack(
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    """Load a handful of worked examples, switched off.

    An empty rule screen and a blank form teach nobody what a good rule looks
    like. These import disabled so nothing starts firing on an estate because
    somebody pressed a button to read an example.
    """
    existing = {r.rule_id for r in db.query(CustomRule).all()}
    plan = importer.plan(importer.STARTER_PACK, existing, "skip")

    added = 0
    for item in plan["items"]:
        if item["action"] != "add":
            continue
        db.add(CustomRule(id=new_id(), created_by=user.username, **item["rule"]))
        added += 1

    db.add(AuditEvent(kind="rules.starter", subject=f"{added} examples",
                      detail=f"by {user.username}"))
    db.commit()
    return {"added": added, "skipped": plan["skipped"],
            "note": "Imported switched off. Open one to see how it is built."}


# ---------------------------------------------------------------------------
# Testing
# ---------------------------------------------------------------------------


class TestRequest(BaseModel):
    rule: RuleRequest
    sample: dict = Field(default_factory=dict)


@router.post("/test")
def test_rule(
    payload: TestRequest,
    db: Session = Depends(get_db),
    _u=Depends(require_console),
):
    """Run a rule against a sample row and say exactly why it did or did not match.

    A rule you cannot try before saving is a rule you find out about on the next
    incident. "Did not match" is useless on its own, so every condition reports
    its own verdict and the value it actually saw.
    """
    data = _as_dict(payload.rule)
    try:
        engine.validate(data)
    except engine.InvalidRule as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    matched, detail = engine.evaluate(data, payload.sample or {})
    failed = [d for d in detail if not d["matched"]]

    if matched:
        explanation = "This row would raise a finding."
    elif data["match"] == "all" and failed:
        first = failed[0]
        seen = first["actual"] or "(empty)"
        explanation = (
            f"No finding: {first['field']} {engine.OPERATORS.get(first['op'], first['op'])}"
            f"{'' if first['op'] in engine.VALUELESS else f' {first['value']!r}'} "
            f"was not satisfied — the row has {seen!r}."
        )
    else:
        explanation = "No finding: none of the conditions matched this row."

    return {
        "matched": matched,
        "explanation": explanation,
        "conditions": detail,
        "description": engine.describe(data),
    }


@router.get("/sample/{artifact}")
def sample_row(
    artifact: str,
    db: Session = Depends(get_db),
    _u=Depends(require_console),
):
    """A blank row for the chosen artifact, so the test form starts filled in."""
    meta = engine.ARTIFACT_FIELDS.get(artifact)
    if not meta:
        raise HTTPException(status_code=404, detail="No such artifact.")
    return {"artifact": artifact, "label": meta["label"],
            "fields": meta["fields"],
            "sample": {f: "" for f in meta["fields"]}}


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------


@router.get("/bundle")
def rule_bundle(
    agent: Agent = Depends(require_agent),
    db: Session = Depends(get_db),
):
    rows = db.query(CustomRule).filter(CustomRule.enabled == True).all()  # noqa: E712
    return JSONResponse({
        "version": 1,
        "count": len(rows),
        "rules": [
            {
                "rule_id": r.rule_id, "title": r.title, "severity": r.severity,
                "mitre": r.mitre or "", "why": r.why or "",
                "artifact": r.artifact, "match": r.match,
                "conditions": r.conditions or [],
            }
            for r in rows
        ],
    })


@router.post("/{rule_pk}")
def update_rule(
    rule_pk: str,
    payload: RuleRequest,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    row = db.get(CustomRule, rule_pk)
    if not row:
        raise HTTPException(status_code=404, detail="No such rule.")
    data = _as_dict(payload)
    _check(data)

    clash = (
        db.query(CustomRule)
        .filter(CustomRule.rule_id == data["rule_id"], CustomRule.id != rule_pk)
        .first()
    )
    if clash:
        raise HTTPException(status_code=409, detail="That rule id is already in use.")

    for k, v in data.items():
        setattr(row, k, v)
    row.updated_at = utcnow()
    db.commit()
    db.refresh(row)
    return rule_dict(row)


class ToggleRequest(BaseModel):
    enabled: bool


@router.post("/{rule_pk}/toggle")
def toggle_rule(
    rule_pk: str,
    payload: ToggleRequest,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    row = db.get(CustomRule, rule_pk)
    if not row:
        raise HTTPException(status_code=404, detail="No such rule.")
    row.enabled = payload.enabled
    db.commit()
    return rule_dict(row)


@router.delete("/{rule_pk}")
def delete_rule(
    rule_pk: str,
    db: Session = Depends(get_db),
    user=Depends(require_responder),
):
    row = db.get(CustomRule, rule_pk)
    if not row:
        raise HTTPException(status_code=404, detail="No such rule.")
    db.add(AuditEvent(kind="rule.deleted", subject=row.rule_id,
                      detail=f"by {user.username}"))
    db.delete(row)
    db.commit()
    return {"deleted": rule_pk}
