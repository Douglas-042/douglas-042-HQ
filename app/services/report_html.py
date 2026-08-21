"""Standalone HTML report generator.

Everything is inlined — no CDN, no external font, no fetch — because these
reports get read on isolated incident-response networks and get emailed to
people who will open them from a downloads folder six months from now.
"""
from __future__ import annotations

import base64
import html
import re
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from ..config import settings
from .mitre import build_matrix, technique_name

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COLOR = {
    "CRITICAL": "#FF2D55",
    "HIGH": "#FF7A00",
    "MEDIUM": "#FFC531",
    "LOW": "#3DA5FF",
    "INFO": "#5D7A9E",
}


def _num(value, default: float = 0.0) -> float:
    """Coerce a value that may have travelled through CSV.

    The agent reads the collector's output with Import-Csv, which types every
    field as a string. Anything arithmetic downstream has to survive "48200"
    just as well as 48200, or the report generator dies on a value the report
    only ever displays.
    """
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _esc(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


_LOGO_CACHE: str | None = None


def _logo_data_uri() -> str:
    """Inline the logo so the report survives being emailed around.

    Cached because fleet exports render one report per host, and a smaller
    report-sized asset is used so a 200-host export stays reasonable.
    """
    global _LOGO_CACHE
    if _LOGO_CACHE is not None:
        return _LOGO_CACHE
    for name in ("logo-report.png", "logo.png"):
        path = settings.static_dir / "img" / name
        if path.exists():
            try:
                _LOGO_CACHE = "data:image/png;base64," + base64.b64encode(
                    path.read_bytes()).decode()
                return _LOGO_CACHE
            except Exception:
                continue
    _LOGO_CACHE = ""
    return _LOGO_CACHE


# ---------------------------------------------------------------------------
# Executive summary
# ---------------------------------------------------------------------------

# Rules grouped by what an attacker was doing, so the summary can talk about
# behaviour rather than rule numbers.
ATTACK_STAGES = {
    "Initial access": {
        "DGL-240", "DGL-241", "DGL-044", "DGL-146", "DGL-162", "DGL-190", "DGL-002",
    },
    "Execution": {
        "DGL-043", "DGL-143", "DGL-144", "DGL-145", "DGL-150", "DGL-151",
        "DGL-042", "DGL-047", "DGL-260", "DGL-261", "DGL-264",
    },
    "Persistence": {
        "DGL-001", "DGL-030", "DGL-031", "DGL-033", "DGL-060", "DGL-062", "DGL-063",
        "DGL-070", "DGL-071", "DGL-072", "DGL-073", "DGL-074", "DGL-075",
        "DGL-080", "DGL-081", "DGL-082", "DGL-083", "DGL-084", "DGL-085",
        "DGL-086", "DGL-087", "DGL-088", "DGL-089", "DGL-090", "DGL-091",
        "DGL-180", "DGL-181", "DGL-182", "DGL-200", "DGL-201", "DGL-173", "DGL-175",
    },
    "Credential access": {
        "DGL-210", "DGL-220", "DGL-221", "DGL-222", "DGL-223", "DGL-224", "DGL-114",
    },
    "Defense evasion": {
        "DGL-014", "DGL-015", "DGL-110", "DGL-111", "DGL-112", "DGL-113", "DGL-115",
        "DGL-116", "DGL-117", "DGL-172", "DGL-183", "DGL-184", "DGL-185",
        "DGL-202", "DGL-204", "DGL-205", "DGL-232",
    },
    "Lateral movement": {
        "DGL-050", "DGL-064", "DGL-160", "DGL-161", "DGL-163", "DGL-164", "DGL-165",
        "DGL-191", "DGL-192", "DGL-152", "DGL-262", "DGL-100", "DGL-212",
    },
    "Collection & exfiltration": {
        "DGL-045", "DGL-053", "DGL-054", "DGL-055", "DGL-203", "DGL-250", "DGL-251",
        "DGL-051", "DGL-052",
    },
    "Visibility gaps": {
        "DGL-016", "DGL-017", "DGL-018", "DGL-019", "DGL-140", "DGL-141", "DGL-263",
    },
}

STAGE_GUIDANCE = {
    "Initial access": "Determine how the host was first reached and close that path before rebuilding.",
    "Execution": "Recover the command lines and decoded payloads below; they name the tooling in use.",
    "Persistence": "Every mechanism must be removed or the host will be re-compromised after cleanup.",
    "Credential access": "Assume every credential used on this host is known to the attacker. Rotate them.",
    "Defense evasion": "Security controls were altered. Restore them and treat surrounding data as incomplete.",
    "Lateral movement": "Other systems are likely involved. Extend collection to the hosts named here.",
    "Collection & exfiltration": "Data may have left the environment. This drives breach-notification decisions.",
    "Visibility gaps": "These are not attacker actions but blind spots that limit what this report can prove.",
}


def build_executive_summary(host: dict, findings: list[dict], manifest: dict) -> dict:
    """Turn a pile of findings into something a manager can act on."""
    sev = Counter(f.get("severity", "INFO") for f in findings)
    crit, high = sev.get("CRITICAL", 0), sev.get("HIGH", 0)

    stages: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        rid = f.get("rule_id") or ""
        for stage, ids in ATTACK_STAGES.items():
            if rid in ids:
                stages[stage].append(f)
                break

    ordered_stages = [s for s in ATTACK_STAGES if s in stages]
    attack_stages = [s for s in ordered_stages if s != "Visibility gaps"]

    if crit == 0 and high == 0:
        verdict = "No confirmed compromise indicators"
        posture = (
            "This collection did not surface evidence of attacker activity on "
            f"{host.get('hostname', 'the host')}. Lower-severity items are hygiene "
            "and hardening observations rather than incident findings."
        )
        urgency = "routine"
    elif crit == 0:
        verdict = "Suspicious activity requiring review"
        posture = (
            f"{high} high-severity findings were recorded. None on their own confirm "
            "compromise, but the combination warrants analyst review before the host "
            "is returned to normal operation."
        )
        urgency = "review"
    elif crit <= 3:
        verdict = "Likely compromise"
        posture = (
            f"{crit} critical findings were recorded on {host.get('hostname', 'this host')}. "
            "Each represents behaviour that does not occur during normal operation. "
            "Treat the host as compromised until an analyst rules the findings out."
        )
        urgency = "urgent"
    else:
        verdict = "Active compromise"
        posture = (
            f"{crit} critical and {high} high findings span "
            f"{len(attack_stages)} stages of attacker activity. This pattern is consistent "
            "with hands-on-keyboard intrusion rather than commodity malware. Isolate the "
            "host and preserve evidence before remediation."
        )
        urgency = "critical"

    # Anti-forensics deserves its own callout: it changes how much the rest of
    # the report can be trusted.
    tamper_ids = {"DGL-014", "DGL-172", "DGL-185", "DGL-183", "DGL-184", "DGL-110", "DGL-112"}
    tampering = [f for f in findings if (f.get("rule_id") or "") in tamper_ids]

    lateral_ids = {"DGL-191", "DGL-165", "DGL-160", "DGL-262", "DGL-064", "DGL-050"}
    lateral = [f for f in findings if (f.get("rule_id") or "") in lateral_ids]

    actions: list[dict] = []
    if crit > 0:
        actions.append(
            {
                "priority": "Now",
                "text": "Isolate the host from the network without powering it off. "
                "Shutting down destroys memory-resident evidence.",
            }
        )
    if tampering:
        actions.append(
            {
                "priority": "Now",
                "text": "Logging or security controls were altered on this host. "
                "Absence of evidence in this report cannot be read as evidence of absence.",
            }
        )
    if "Credential access" in stages:
        actions.append(
            {
                "priority": "Now",
                "text": "Rotate every credential that has authenticated to this host, "
                "including service accounts and cached domain credentials.",
            }
        )
    if lateral:
        # Pull hostnames and addresses out of the evidence rather than dumping
        # the whole string; the action needs targets, not raw log lines.
        targets: set[str] = set()
        for f in lateral:
            for m in re.finditer(
                r"\b(?:\d{1,3}(?:\.\d{1,3}){3}|[A-Za-z0-9][A-Za-z0-9-]{1,30}"
                r"(?:\.[A-Za-z0-9-]{2,30}){1,4})\b",
                f.get("evidence") or "",
            ):
                tok = m.group(0)
                if tok.lower().endswith((".exe", ".dll", ".ps1", ".dat", ".log")):
                    continue
                if tok.startswith(("127.", "0.0.0.0")):
                    continue
                targets.add(tok)
        if targets:
            listed = ", ".join(sorted(targets)[:6])
            actions.append(
                {
                    "priority": "Next",
                    "text": f"Extend collection to the systems named in lateral-movement "
                    f"findings: {listed}.",
                }
            )
        else:
            actions.append(
                {
                    "priority": "Next",
                    "text": f"Review the {len(lateral)} lateral-movement findings below "
                    "and collect from every system they reference.",
                }
            )
    if "Persistence" in stages:
        actions.append(
            {
                "priority": "Next",
                "text": f"Remove all {len(stages['Persistence'])} persistence mechanisms listed "
                "below. Rebuilding without removing them re-introduces the attacker.",
            }
        )
    if "Collection & exfiltration" in stages:
        actions.append(
            {
                "priority": "Next",
                "text": "Assess data exposure. Archive creation and outbound transfers were "
                "observed and may trigger notification obligations.",
            }
        )
    if "Visibility gaps" in stages:
        actions.append(
            {
                "priority": "Follow-up",
                "text": "Close the telemetry gaps noted below so the next investigation "
                "starts with better evidence.",
            }
        )
    if not actions:
        actions.append(
            {
                "priority": "Follow-up",
                "text": "No incident response action required. Review the hardening "
                "observations at your normal cadence.",
            }
        )

    scope = (manifest.get("Scope") or {}).get("NotCollected") or []

    return {
        "verdict": verdict,
        "urgency": urgency,
        "posture": posture,
        "stages": [
            {
                "name": name,
                "count": len(stages[name]),
                "critical": sum(1 for f in stages[name] if f.get("severity") == "CRITICAL"),
                "guidance": STAGE_GUIDANCE.get(name, ""),
                "examples": sorted(
                    stages[name], key=lambda f: SEV_ORDER.get(f.get("severity"), 9)
                )[:3],
            }
            for name in ordered_stages
        ],
        "actions": actions,
        "tampering": len(tampering) > 0,
        "not_collected": scope,
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _bar_chart(timeline: list[dict]) -> tuple[str, str]:
    buckets: Counter = Counter()
    for e in timeline:
        raw = e.get("time_utc") or ""
        if len(raw) >= 13:
            buckets[raw[:13]] += 1
    if not buckets:
        return "", ""
    keys = sorted(buckets)
    peak = max(buckets.values()) or 1
    width = max(2, min(14, 1100 // max(1, len(keys))))
    bars = []
    for i, k in enumerate(keys):
        h = max(2, round(buckets[k] / peak * 128))
        bars.append(
            f'<rect x="{i * width}" y="{138 - h}" width="{max(1, width - 1)}" height="{h}" '
            f'fill="url(#bg)"><title>{_esc(k)}:00 — {buckets[k]} events</title></rect>'
        )
    busiest = max(buckets, key=lambda k: buckets[k])
    note = f"Peak activity at {busiest}:00 UTC with {buckets[busiest]} events."
    return "".join(bars), note


def _mitre_cell(technique: str | None) -> str:
    """Show the technique name beside its id.

    A bare T1055 means nothing to most readers of this report, and reports get
    read by people who are not the analyst who ran the hunt.
    """
    tid = (technique or "").strip()
    if not tid:
        return '<td class="mono muted"></td>'
    name = technique_name(tid)
    if name == tid:
        return f'<td class="mono muted">{_esc(tid)}</td>'
    return (f'<td class="mono muted">{_esc(tid)}'
            f'<div class="tname">{_esc(name)}</div></td>')


def _findings_rows(findings: list[dict]) -> str:
    out = []
    for f in findings:
        sev = f.get("severity", "INFO")
        out.append(
            f'<tr class="row" data-sev="{_esc(sev)}">'
            f'<td><span class="pill" style="background:{SEV_COLOR.get(sev, "#5D7A9E")}">{_esc(sev)}</span></td>'
            f'<td class="mono muted">{_esc(f.get("rule_id"))}</td>'
            f'<td><div class="ttl">{_esc(f.get("title"))}</div>'
            + (f'<div class="why">{_esc(f.get("why"))}</div>' if f.get("why") else "")
            + "</td>"
            f'<td class="mono ev">{_esc(f.get("evidence"))}</td>'
            + _mitre_cell(f.get("mitre"))
            + f'<td class="mono muted">{_esc(f.get("occurred_at"))}</td>'
            "</tr>"
        )
    return "".join(out) or '<tr><td colspan="6" class="muted">No findings recorded.</td></tr>'


def _timeline_rows(timeline: list[dict], limit: int = 600) -> str:
    ranked = sorted(
        timeline,
        key=lambda e: (SEV_ORDER.get(e.get("severity", "INFO"), 9), e.get("time_utc") or ""),
    )[:limit]
    ranked.sort(key=lambda e: e.get("time_utc") or "")
    out = []
    for e in ranked:
        sev = e.get("severity", "INFO")
        out.append(
            f'<tr class="row" data-sev="{_esc(sev)}">'
            f'<td class="mono">{_esc(e.get("time_utc"))}</td>'
            f'<td><span class="pill sm" style="background:{SEV_COLOR.get(sev, "#5D7A9E")}">{_esc(sev)}</span></td>'
            f'<td class="mono muted">{_esc(e.get("source"))}</td>'
            f'<td>{_esc(e.get("description"))}</td>'
            f'<td class="mono ev">{_esc(e.get("detail"))}</td>'
            "</tr>"
        )
    return "".join(out) or '<tr><td colspan="5" class="muted">No timeline events.</td></tr>'


def _matrix_block(findings: list[dict]) -> str:
    """The ATT&CK matrix, printed as columns rather than an interactive grid.

    Kept simple on purpose: this has to survive being printed to PDF and read
    on a phone, so it is a plain flex row of columns with no script behind it.
    """
    m = build_matrix(findings)
    if not m["technique_count"]:
        return ""

    cols = []
    for c in m["columns"]:
        cells = "".join(
            f'<div class="mcell s-{_esc(t["severity"])}">'
            f'<div class="mid">{_esc(t["id"])}</div>'
            f'<div class="mnm">{_esc(t["name"])}</div>'
            f'<div class="mct">{t["count"]}</div></div>'
            for t in c["techniques"]
        ) or '<div class="mempty">&mdash;</div>'
        cols.append(
            f'<div class="mcol{"" if c["techniques"] else " dimcol"}">'
            f'<div class="mhead">{_esc(c["tactic"])}</div>'
            f'<div class="mbody">{cells}</div></div>'
        )

    return (
        f'<div class="mstats">{m["technique_count"]} techniques across '
        f'{m["tactics_hit"]} of {m["tactic_count"]} tactics</div>'
        f'<div class="matrix">{"".join(cols)}</div>'
    )


def _stage_blocks(summary: dict) -> str:
    out = []
    for st in summary["stages"]:
        chips = "".join(
            f'<li><span class="pill sm" style="background:{SEV_COLOR.get(x.get("severity"), "#5D7A9E")}">'
            f'{_esc(x.get("severity"))}</span> {_esc(x.get("title"))}</li>'
            for x in st["examples"]
        )
        accent = "#FF2D55" if st["critical"] else "#22D9F5"
        out.append(
            f'<div class="stage" style="--accent:{accent}">'
            f'<div class="stage-h"><span class="stage-n">{_esc(st["name"])}</span>'
            f'<span class="stage-c">{st["count"]}</span></div>'
            f'<p class="stage-g">{_esc(st["guidance"])}</p>'
            f"<ul class=\"stage-l\">{chips}</ul></div>"
        )
    return "".join(out)


def render_report(
    *,
    host: dict,
    job: dict,
    findings: list[dict],
    timeline: list[dict],
    manifest: dict,
    module_stats: list[dict] | None = None,
    collection_errors: list[dict] | None = None,
) -> str:
    findings = sorted(findings, key=lambda f: SEV_ORDER.get(f.get("severity", "INFO"), 9))
    summary = build_executive_summary(host, findings, manifest or {})
    sev = Counter(f.get("severity", "INFO") for f in findings)

    urgency_color = {
        "critical": "#FF2D55",
        "urgent": "#FF7A00",
        "review": "#FFC531",
        "routine": "#2BD9A0",
    }[summary["urgency"]]

    bars, peak_note = _bar_chart(timeline)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    def _stamp(value: str | None) -> str:
        """ISO timestamps are for machines; the header is for people."""
        if not value:
            return generated
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00")).strftime(
                "%Y-%m-%d %H:%M"
            )
        except ValueError:
            return str(value)[:16].replace("T", " ")

    collected = _stamp(job.get("finished_at"))

    actions_html = "".join(
        f'<li class="act act-{_esc(a["priority"]).lower()}">'
        f'<span class="act-p">{_esc(a["priority"])}</span>'
        f'<span class="act-t">{_esc(a["text"])}</span></li>'
        for a in summary["actions"]
    )

    scope_html = "".join(f"<li>{_esc(s)}</li>" for s in summary["not_collected"])

    module_stats = [m for m in (module_stats or []) if isinstance(m, dict)]
    collection_errors = [e for e in (collection_errors or []) if isinstance(e, dict)]

    errors_html = "".join(
        f'<tr><td class="mono">{_esc(e.get("Module"))}</td>'
        f'<td class="mono muted">{_esc(e.get("Type"))}</td>'
        f'<td class="mono ev">{_esc(e.get("Message"))}</td></tr>'
        for e in (collection_errors or [])[:150]
    ) or '<tr><td colspan="3" class="muted">Every module completed without error.</td></tr>'

    stats_html = "".join(
        f'<tr><td class="mono">{_esc(m.get("Module"))}</td>'
        f'<td class="mono">{_esc(m.get("Status"))}</td>'
        f'<td class="mono">{round(_num(m.get("DurationMs")) / 1000, 1)}s</td></tr>'
        for m in sorted(
            module_stats or [],
            key=lambda m: _num(m.get("DurationMs")),
            reverse=True,
        )[:40]
    ) or '<tr><td colspan="3" class="muted">No module statistics recorded.</td></tr>'

    tamper_banner = (
        '<div class="warn"><b>Evidence integrity caution.</b> Logging or security '
        "controls were modified on this host. Sections of this report may be "
        "incomplete as a direct result — absence of a finding is not proof that "
        "the activity did not occur.</div>"
        if summary["tampering"]
        else ""
    )

    matrix_block = _matrix_block(findings)

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Douglas-042 — {_esc(host.get('hostname'))}</title>
<style>
*{{box-sizing:border-box}}
:root{{
  --void:#050B18; --panel:#0A1428; --edge:#16294A; --line:#1E3557;
  --electric:#1B7FE8; --cyan:#22D9F5; --silver:#E8F1FF; --slate:#7A93B8;
  --urgency:{urgency_color};
}}
body{{margin:0;background:var(--void);color:var(--silver);
  font:15px/1.6 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif}}
.mono{{font-family:ui-monospace,"Cascadia Mono",Consolas,monospace;font-size:12.5px}}
.muted{{color:var(--slate)}}
.wrap{{max-width:1500px;margin:0 auto;padding:0 32px}}

header{{border-bottom:1px solid var(--line);
  background:radial-gradient(1100px 380px at 12% -60%,rgba(27,127,232,.30),transparent 70%),var(--panel)}}
.head{{display:flex;align-items:center;gap:28px;padding:26px 0;flex-wrap:wrap}}
.logo{{height:52px;filter:drop-shadow(0 0 22px rgba(34,217,245,.55))}}
.hmeta{{display:flex;gap:26px;flex-wrap:wrap;font-size:12.5px;color:var(--slate);
  margin-left:auto;text-align:right}}
.hmeta b{{color:var(--silver);display:block;font-size:14px;font-weight:600}}

.verdict{{padding:30px 0 34px;border-bottom:1px solid var(--line);
  background:linear-gradient(180deg,rgba(27,127,232,.09),transparent)}}
.vgrid{{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(280px,.85fr);gap:38px;align-items:start}}
.eyebrow{{font-size:11px;letter-spacing:.22em;text-transform:uppercase;color:var(--cyan);
  margin-bottom:12px;font-weight:700}}
h1{{margin:0 0 14px;font-size:clamp(28px,3.4vw,42px);line-height:1.08;letter-spacing:-.02em;
  font-style:italic;color:var(--urgency);text-shadow:0 0 34px color-mix(in srgb,var(--urgency) 45%,transparent)}}
.posture{{font-size:16.5px;line-height:1.65;color:#C6D8F2;max-width:74ch;margin:0}}

.scores{{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}}
.score{{background:var(--panel);border:1px solid var(--edge);border-radius:10px;padding:14px 16px}}
.score .n{{font-size:30px;font-weight:800;line-height:1;font-style:italic}}
.score .l{{font-size:10.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--slate);margin-top:6px}}
.score.risk{{grid-column:1/-1;border-color:var(--urgency);
  box-shadow:0 0 0 1px color-mix(in srgb,var(--urgency) 26%,transparent),
             inset 0 0 40px color-mix(in srgb,var(--urgency) 9%,transparent)}}
.score.risk .n{{color:var(--urgency)}}

.warn{{margin-top:22px;background:rgba(255,45,85,.09);border:1px solid rgba(255,45,85,.42);
  border-left:3px solid #FF2D55;border-radius:0 8px 8px 0;padding:14px 18px;font-size:14px;color:#FFD9E1}}

section{{padding:36px 0;border-bottom:1px solid var(--line)}}
h2{{font-size:12px;letter-spacing:.2em;text-transform:uppercase;color:var(--cyan);
  margin:0 0 6px;font-weight:700}}
.lede{{color:var(--slate);font-size:14px;margin:0 0 22px;max-width:82ch}}

.acts{{list-style:none;padding:0;margin:0;display:grid;gap:9px}}
.act{{display:flex;gap:16px;align-items:baseline;background:var(--panel);
  border:1px solid var(--edge);border-left:3px solid var(--slate);border-radius:0 8px 8px 0;padding:14px 18px}}
.act-now{{border-left-color:#FF2D55}} .act-next{{border-left-color:#FF7A00}}
.act-follow-up{{border-left-color:var(--electric)}}
.act-p{{font-size:10.5px;letter-spacing:.14em;text-transform:uppercase;font-weight:700;
  min-width:76px;color:var(--silver)}}
.act-t{{color:#C6D8F2;font-size:14.5px}}

.stages{{display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));gap:12px}}
.stage{{background:var(--panel);border:1px solid var(--edge);border-radius:10px;padding:16px 18px;
  border-top:2px solid var(--accent)}}
.stage-h{{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}}
.stage-n{{font-weight:700;font-size:15px;font-style:italic}}
.stage-c{{font-size:22px;font-weight:800;color:var(--accent);font-style:italic}}
.stage-g{{font-size:12.5px;color:var(--slate);margin:0 0 12px;line-height:1.5}}
.stage-l{{list-style:none;padding:0;margin:0;display:grid;gap:6px;font-size:12.5px}}
.stage-l li{{display:flex;gap:8px;align-items:baseline;color:#B8CCE8}}

table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{text-align:left;padding:10px 12px;background:var(--panel);color:var(--slate);
  font-size:11px;letter-spacing:.1em;text-transform:uppercase;position:sticky;top:0;
  border-bottom:1px solid var(--line);white-space:nowrap;cursor:pointer;user-select:none}}
th:hover{{color:var(--cyan)}}
td{{padding:9px 12px;border-bottom:1px solid rgba(30,53,87,.5);vertical-align:top}}
tr:hover td{{background:rgba(27,127,232,.06)}}
.scroll{{max-height:70vh;overflow:auto;border:1px solid var(--edge);border-radius:10px}}
.pill{{padding:2px 9px;border-radius:4px;font-size:10px;font-weight:800;color:#050B18;
  letter-spacing:.06em;white-space:nowrap}}
.pill.sm{{font-size:9px;padding:1px 7px}}
.ttl{{font-weight:600}}
.why{{color:var(--slate);font-size:12px;margin-top:3px}}
.tname{{color:var(--slate);font-size:10.5px;margin-top:2px;font-family:inherit;
  max-width:150px;line-height:1.3}}
.ev{{color:#8FD9F5;word-break:break-all;max-width:520px}}

.filters{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;align-items:center}}
.fbtn{{background:var(--panel);border:1px solid var(--edge);color:var(--slate);
  padding:7px 14px;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600;
  font-family:inherit;transition:.15s}}
.fbtn:hover{{border-color:var(--cyan);color:var(--silver)}}
.fbtn.on{{background:var(--electric);border-color:var(--electric);color:#fff;
  box-shadow:0 0 18px rgba(27,127,232,.5)}}
input[type=search]{{flex:1;min-width:240px;background:var(--void);border:1px solid var(--edge);
  border-radius:6px;padding:8px 14px;color:var(--silver);font-size:13px;font-family:inherit}}
input[type=search]:focus{{outline:none;border-color:var(--cyan);box-shadow:0 0 0 3px rgba(34,217,245,.14)}}

svg.chart{{width:100%;height:140px;background:var(--panel);border:1px solid var(--edge);border-radius:10px}}
.mstats{{font-size:12.5px;color:var(--slate);margin-bottom:12px;font-family:ui-monospace,monospace}}
.matrix{{display:flex;gap:8px;overflow-x:auto;padding-bottom:10px;align-items:flex-start}}
.mcol{{flex:0 0 168px;min-width:168px}}
.mcol.dimcol{{opacity:.4}}
.mhead{{background:var(--panel);border:1px solid var(--edge);border-radius:6px 6px 0 0;
  padding:7px 9px;font-size:10.5px;font-weight:700;color:var(--silver);line-height:1.3}}
.mbody{{border:1px solid var(--edge);border-top:0;border-radius:0 0 6px 6px;padding:6px;
  display:flex;flex-direction:column;gap:4px;min-height:44px}}
.mcell{{border-left:3px solid var(--accent,#5D7A9E);border-radius:3px;padding:6px 8px;
  background:rgba(22,41,74,.5);position:relative}}
.mid{{font-family:ui-monospace,monospace;font-size:10px;color:#22D9F5;font-weight:600}}
.mnm{{font-size:10.5px;color:#C6D8F2;line-height:1.3;margin-top:2px}}
.mct{{position:absolute;top:6px;right:8px;font-size:10px;font-weight:700;color:var(--slate)}}
.mcell.s-CRITICAL{{--accent:#FF2D55;background:rgba(255,45,85,.13)}}
.mcell.s-HIGH{{--accent:#FF7A00;background:rgba(255,122,0,.11)}}
.mcell.s-MEDIUM{{--accent:#FFC531;background:rgba(255,197,49,.09)}}
.mcell.s-LOW{{--accent:#3DA5FF;background:rgba(61,165,255,.08)}}
.mcell.s-INFO{{--accent:#5D7A9E}}
.mempty{{color:#3E5273;font-size:11px;text-align:center;padding:10px 0}}
@media print{{.matrix{{flex-wrap:wrap}}.mcol{{flex:0 0 150px}}}}
footer{{padding:26px 0 40px;color:#3E5273;font-size:12px}}
@media print{{
  body{{background:#fff;color:#111}} .filters,input{{display:none}}
  .scroll{{max-height:none;overflow:visible}} h1{{color:#000;text-shadow:none}}
  .stage,.act,.score{{border-color:#bbb;background:#fff}} .muted,.stage-g{{color:#555}}
  .ev{{color:#0a4}} section{{border-color:#ddd}}
}}
@media(max-width:900px){{.vgrid{{grid-template-columns:1fr}}.wrap{{padding:0 18px}}}}
</style></head><body>

<header><div class="wrap head">
  <img class="logo" src="{_logo_data_uri()}" alt="Douglas-042">
  <div class="hmeta">
    <span><b>{_esc(host.get('hostname'))}</b>{_esc(host.get('ip_address') or '')}</span>
    <span><b>{_esc(host.get('domain_role') or 'Unknown role')}</b>{_esc(host.get('domain') or 'workgroup')}</span>
    <span><b>{_esc(host.get('os_caption') or '')}</b>build {_esc(host.get('os_build') or '?')}</span>
    <span><b>{_esc(collected)}</b>collected (UTC)</span>
    <span><b>{_esc(job.get('days'))} days</b>lookback window</span>
  </div>
</div></header>

<div class="verdict"><div class="wrap vgrid">
  <div>
    <div class="eyebrow">Executive summary</div>
    <h1>{_esc(summary['verdict'])}</h1>
    <p class="posture">{_esc(summary['posture'])}</p>
    {tamper_banner}
  </div>
  <div class="scores">
    <div class="score risk"><div class="n">{int(_num(job.get('risk_score')))}</div>
      <div class="l">Risk score — {_esc(job.get('risk_level') or 'CLEAN')}</div></div>
    <div class="score"><div class="n" style="color:#FF2D55">{sev.get('CRITICAL', 0)}</div><div class="l">Critical</div></div>
    <div class="score"><div class="n" style="color:#FF7A00">{sev.get('HIGH', 0)}</div><div class="l">High</div></div>
    <div class="score"><div class="n" style="color:#FFC531">{sev.get('MEDIUM', 0)}</div><div class="l">Medium</div></div>
    <div class="score"><div class="n" style="color:#3DA5FF">{sev.get('LOW', 0)}</div><div class="l">Low</div></div>
  </div>
</div></div>

<section><div class="wrap">
  <h2>What to do</h2>
  <p class="lede">Ordered by urgency. "Now" items should happen before the host is
  touched further; they preserve evidence and stop the bleeding.</p>
  <ul class="acts">{actions_html}</ul>
</div></section>

<section><div class="wrap">
  <h2>Attacker activity by stage</h2>
  <p class="lede">Findings grouped by what the activity accomplishes rather than by
  which rule fired. A single stage may be a false positive; several stages together
  describe an intrusion.</p>
  <div class="stages">{_stage_blocks(summary)}</div>
</div></section>

<section><div class="wrap">
  <h2>ATT&amp;CK coverage</h2>
  <p class="lede">Techniques observed on this host, arranged by tactic. Columns read
  left to right along the kill chain. A single lit column is usually noise; a path
  running across several is an intrusion.</p>
  {matrix_block}
</div></section>

<section><div class="wrap">
  <h2>Findings</h2>
  <p class="lede">{len(findings)} findings, most severe first. Each row carries the
  evidence it was derived from so conclusions can be verified independently.</p>
  <div class="filters">
    <button class="fbtn on" onclick="flt('',this)">All {len(findings)}</button>
    <button class="fbtn" onclick="flt('CRITICAL',this)">Critical {sev.get('CRITICAL', 0)}</button>
    <button class="fbtn" onclick="flt('HIGH',this)">High {sev.get('HIGH', 0)}</button>
    <button class="fbtn" onclick="flt('MEDIUM',this)">Medium {sev.get('MEDIUM', 0)}</button>
    <button class="fbtn" onclick="flt('LOW',this)">Low {sev.get('LOW', 0)}</button>
    <input type="search" placeholder="Search paths, users, addresses, MITRE IDs" oninput="srch(this.value)">
  </div>
  <div class="scroll"><table id="findings"><thead><tr>
    <th onclick="srt('findings',0)">Severity</th><th onclick="srt('findings',1)">Rule</th>
    <th onclick="srt('findings',2)">Finding</th><th>Evidence</th>
    <th onclick="srt('findings',4)">MITRE</th><th onclick="srt('findings',5)">Time (UTC)</th>
  </tr></thead><tbody>{_findings_rows(findings)}</tbody></table></div>
</div></section>

<section><div class="wrap">
  <h2>Timeline</h2>
  <p class="lede">Hourly event density. {_esc(peak_note)} Attacker activity tends to
  cluster into a narrow window; a spike is where to start reading.</p>
  <svg class="chart" viewBox="0 0 1100 140" preserveAspectRatio="none">
    <defs><linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#22D9F5"/><stop offset="100%" stop-color="#1B7FE8"/>
    </linearGradient></defs>{bars}
  </svg>
  <div class="scroll" style="margin-top:14px"><table id="timeline"><thead><tr>
    <th onclick="srt('timeline',0)">Time (UTC)</th><th onclick="srt('timeline',1)">Severity</th>
    <th onclick="srt('timeline',2)">Source</th><th>Event</th><th>Detail</th>
  </tr></thead><tbody>{_timeline_rows(timeline)}</tbody></table></div>
</div></section>

<section><div class="wrap">
  <h2>Collection coverage</h2>
  <p class="lede">What ran, what failed, and what this collection could not reach.
  "No data" and "the command failed" are different statements; this section keeps
  them apart.</p>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:18px">
    <div><div class="eyebrow">Slowest modules</div>
      <div class="scroll" style="max-height:320px"><table><thead><tr>
      <th>Module</th><th>Status</th><th>Time</th></tr></thead><tbody>{stats_html}</tbody></table></div></div>
    <div><div class="eyebrow">Errors and skips</div>
      <div class="scroll" style="max-height:320px"><table><thead><tr>
      <th>Module</th><th>Type</th><th>Detail</th></tr></thead><tbody>{errors_html}</tbody></table></div></div>
  </div>
  <div style="margin-top:20px"><div class="eyebrow">Out of scope</div>
    <ul class="muted" style="font-size:13px;line-height:1.9">{scope_html}</ul>
    <p class="muted" style="font-size:13px;max-width:80ch">This collection ran against a
    live system. File access times and Prefetch entries were affected by the collection
    itself; if a forensic image is taken, treat this report's timestamp as the boundary.</p>
  </div>
</div></section>

<footer><div class="wrap">
  Douglas-042 v{_esc(settings.version)} · OnBT / Behind24 Blue Team ·
  Report generated {generated} UTC · Job {_esc(job.get('id'))}
</div></footer>

<script>
function flt(s,btn){{
  document.querySelectorAll('.fbtn').forEach(b=>b.classList.remove('on'));
  if(btn)btn.classList.add('on');
  document.querySelectorAll('#findings tr.row').forEach(r=>{{
    r.style.display=(!s||r.dataset.sev===s)?'':'none';
  }});
}}
function srch(q){{
  q=q.toLowerCase();
  document.querySelectorAll('tr.row').forEach(r=>{{
    r.style.display=(!q||r.innerText.toLowerCase().includes(q))?'':'none';
  }});
}}
const dir={{}};
function srt(id,col){{
  const t=document.getElementById(id),tb=t.tBodies[0];
  const rows=[...tb.rows]; const k=id+col; dir[k]=!dir[k]; const d=dir[k]?1:-1;
  rows.sort((a,b)=>{{
    const x=(a.cells[col]?.innerText||'').trim(),y=(b.cells[col]?.innerText||'').trim();
    const nx=parseFloat(x),ny=parseFloat(y);
    if(!isNaN(nx)&&!isNaN(ny))return (nx-ny)*d;
    return x.localeCompare(y)*d;
  }});
  rows.forEach(r=>tb.appendChild(r));
}}
</script></body></html>"""
