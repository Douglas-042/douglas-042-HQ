#!/usr/bin/env bash
# =============================================================================
#  Douglas-042 Linux Agent
#
#  Enrols with the console, checks in, runs hunts and uploads results. The
#  Linux counterpart of douglas-agent.ps1, speaking the same API.
#
#  Dependencies: curl and coreutils. Deliberately no python, no jq — the host
#  under investigation is not the place to start installing things, and a
#  dependency that is missing at 3am is an agent that does not run.
#
#  Usage:
#    ./douglas-agent.sh --server URL --token TOKEN --install
#    ./douglas-agent.sh --status
#    ./douglas-agent.sh --once
#    ./douglas-agent.sh --uninstall
# =============================================================================

set -uo pipefail

VERSION="2.0.0"
ROOT="/var/lib/douglas042"
CFG="$ROOT/agent.json"
LOGF="$ROOT/agent.log"
COLLECTOR="$ROOT/douglas-042.sh"
WORKDIR="$ROOT/work"
SERVICE_NAME="douglas042-agent"

SERVER=""
TOKEN=""
MODE="run"
HEARTBEAT_SECONDS=60
# How often to ask for a queued response action. Deliberately much shorter
# than the heartbeat: containment is typed by somebody watching the screen.
IR_POLL_SECONDS=5
INSECURE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --server)    SERVER="$2"; shift 2 ;;
        --token)     TOKEN="$2"; shift 2 ;;
        --install)   MODE="install"; shift ;;
        --uninstall) MODE="uninstall"; shift ;;
        --status)    MODE="status"; shift ;;
        --once)      MODE="once"; shift ;;
        --insecure)  INSECURE=1; shift ;;
        -h|--help)   sed -n '2,18p' "$0"; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

mkdir -p "$ROOT" "$WORKDIR" 2>/dev/null

HAVE_PY=0
command -v python3 >/dev/null 2>&1 && HAVE_PY=1

log() {
    local level="$1"; shift
    printf '%s [%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$level" "$*" >> "$LOGF" 2>/dev/null
    case "$level" in
        ERROR) printf '  [x] %s\n' "$*" >&2 ;;
        WARN)  printf '  [!] %s\n' "$*" ;;
        OK)    printf '  [+] %s\n' "$*" ;;
        *)     printf '  [*] %s\n' "$*" ;;
    esac
}

curl_opts() {
    printf '%s' "-sS --max-time 120"
    [ "$INSECURE" -eq 1 ] && printf '%s' " -k"
}

# Minimal JSON field reader. Written rather than pulled in, because requiring
# jq on an incident host is a dependency that will be missing exactly when it
# matters. Handles the flat string and number fields this API returns.
json_get() {
    # json_get JSON KEY
    printf '%s' "$1" | tr ',' '\n' | grep -m1 "\"$2\"" | \
        sed -e 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*//' \
            -e 's/^"//' -e 's/"[[:space:]]*[}]*[[:space:]]*$//' \
            -e 's/[[:space:]]*[}]*[[:space:]]*$//'
}

json_has() {
    printf '%s' "$1" | grep -q "\"$2\""
}

json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\r' | \
        sed ':a;N;$!ba;s/\n/\\n/g'
}

read_config() {
    [ -r "$CFG" ] || return 1
    AGENT_ID="$(json_get "$(cat "$CFG")" agent_id)"
    AGENT_KEY="$(json_get "$(cat "$CFG")" agent_key)"
    SERVER_URL="$(json_get "$(cat "$CFG")" server)"
    [ -n "$AGENT_ID" ] && [ -n "$AGENT_KEY" ] && [ -n "$SERVER_URL" ]
}

api() {
    # api METHOD PATH [BODY]
    local method="$1" path="$2" body="${3:-}"
    local args="-X $method -H 'Content-Type: application/json'"
    if [ -n "$body" ]; then
        curl $(curl_opts) -X "$method" \
            -H "Content-Type: application/json" \
            -H "X-Agent-Id: ${AGENT_ID:-}" \
            -H "X-Agent-Key: ${AGENT_KEY:-}" \
            -d "$body" "${SERVER_URL}${path}" 2>/dev/null
    else
        curl $(curl_opts) -X "$method" \
            -H "X-Agent-Id: ${AGENT_ID:-}" \
            -H "X-Agent-Key: ${AGENT_KEY:-}" \
            "${SERVER_URL}${path}" 2>/dev/null
    fi
}

# --- Enrolment --------------------------------------------------------------
enrol() {
    local server="$1" token="$2"
    server="${server%/}"

    local os_name ip_addr
    os_name="$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-Linux}")"
    ip_addr="$(hostname -I 2>/dev/null | awk '{print $1}')"

    local body resp
    body="{\"token\":\"$(json_escape "$token")\",\"hostname\":\"$(hostname)\",\"platform\":\"linux\",\"os\":\"$(json_escape "$os_name")\",\"ip_address\":\"${ip_addr:-}\"}"

    resp="$(curl $(curl_opts) -X POST -H "Content-Type: application/json" \
            -d "$body" "${server}/api/v1/agents/enroll" 2>&1)"

    if ! json_has "$resp" "agent_id"; then
        log ERROR "Enrolment refused by the console: ${resp:0:200}"
        return 1
    fi

    AGENT_ID="$(json_get "$resp" agent_id)"
    AGENT_KEY="$(json_get "$resp" agent_key)"
    SERVER_URL="$server"

    umask 077
    printf '{"agent_id":"%s","agent_key":"%s","server":"%s"}\n' \
        "$AGENT_ID" "$AGENT_KEY" "$server" > "$CFG"
    chmod 600 "$CFG"
    log OK "Enrolled as $AGENT_ID"
}

# --- Collector staging ------------------------------------------------------
update_collector() {
    local remote local_hash remote_hash
    remote="$(api GET /api/v1/reports/deploy/scanner/version)"
    remote_hash="$(json_get "$remote" sha256_linux)"
    [ -n "$remote_hash" ] || remote_hash="$(json_get "$remote" sha256)"
    [ -n "$remote_hash" ] || return 0

    if [ -r "$COLLECTOR" ]; then
        local_hash="$(sha256sum "$COLLECTOR" 2>/dev/null | cut -d' ' -f1)"
        [ "$local_hash" = "$remote_hash" ] && return 0
    fi

    # The file-content matcher travels with the collector. Fetched here so a
    # console that gains YARA support does not need every host redeployed.
    for helper in yara sigma; do
        # Verified as parseable Python before replacing a working copy: a
        # truncated download that overwrote the evaluator would take file and
        # log rules out of every sweep on this host without saying so.
        curl $(curl_opts) -H "X-Agent-Id: $AGENT_ID" -H "X-Agent-Key: $AGENT_KEY" \
             -o "$ROOT/douglas-$helper.py.new" \
             "${SERVER_URL}/api/v1/reports/deploy/$helper-helper" 2>/dev/null \
          && python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" \
               "$ROOT/douglas-$helper.py.new" 2>/dev/null \
          && mv "$ROOT/douglas-$helper.py.new" "$ROOT/douglas-$helper.py" \
          && chmod 755 "$ROOT/douglas-$helper.py"
        rm -f "$ROOT/douglas-$helper.py.new" 2>/dev/null
    done

    log INFO "Fetching the collector from the console"
    if curl $(curl_opts) -H "X-Agent-Id: $AGENT_ID" -H "X-Agent-Key: $AGENT_KEY" \
         -o "$COLLECTOR.new" "${SERVER_URL}/api/v1/reports/deploy/collector/linux" 2>/dev/null; then
        # Verify before replacing. A truncated download that overwrote a working
        # collector would take this host out of the fleet quietly.
        if bash -n "$COLLECTOR.new" 2>/dev/null; then
            mv "$COLLECTOR.new" "$COLLECTOR"
            chmod 755 "$COLLECTOR"
            log OK "Collector updated"
        else
            log WARN "Downloaded collector does not parse; keeping the current one"
            rm -f "$COLLECTOR.new"
        fi
    else
        rm -f "$COLLECTOR.new"
    fi
}

# --- Running a hunt ---------------------------------------------------------
run_hunt() {
    local job="$1"
    local job_id days quick profile min_sev ioc_list progress_file out_dir
    job_id="$(json_get "$job" job_id)"
    days="$(json_get "$job" days)"
    quick="$(json_get "$job" quick)"
    profile="$(json_get "$job" profile)"
    min_sev="$(json_get "$job" min_severity)"

    [ -n "$job_id" ] || return 1
    log OK "Hunt $job_id starting (window ${days:-14} days)"

    rm -rf "${WORKDIR:?}"/* 2>/dev/null
    progress_file="$WORKDIR/progress.jsonl"
    : > "$progress_file"

    # Indicators, if the console sent any
    local ioc_arg=""
    if json_has "$job" "ioc_list"; then
        local iocs
        iocs="$(printf '%s' "$job" | sed -n 's/.*"ioc_list"[[:space:]]*:[[:space:]]*"\(.*\)".*/\1/p')"
        if [ -n "$iocs" ] && [ "$iocs" != "null" ]; then
            printf '%b\n' "$iocs" > "$WORKDIR/iocs.txt"
            ioc_arg="--ioc $WORKDIR/iocs.txt"
        fi
    fi

    # Rules switched off in the console. Fetched every hunt so a change takes
    # effect on the next sweep with nothing to redeploy. A failed fetch leaves
    # the file absent, and the collector then runs every rule — the safe
    # direction, since the reverse would silently disable detection.
    # Findings stream here as the collector produces them, so the console
    # fills in during the sweep rather than staying empty until the bundle
    # uploads at the end.
    local live_file="$WORKDIR/live-findings.jsonl"
    : > "$live_file"
    local live_seen_file="$WORKDIR/.live-seen"
    printf '0' > "$live_seen_file"

    local disabled_arg=""
    local disabled_file="$WORKDIR/disabled-rules.txt"
    local rb
    rb="$(api GET /api/v1/findings/rules/bundle)"
    if [ -n "$rb" ] && json_has "$rb" "disabled"; then
        printf '%s' "$rb" \
            | tr ',[]' '\n\n\n' \
            | sed -n 's/.*"\(DGL-[A-Za-z0-9_.-]*\)".*/\1/p' \
            > "$disabled_file" 2>/dev/null
        if [ -s "$disabled_file" ]; then
            disabled_arg="--disabled-rules $disabled_file"
            log INFO "Rules switched off in the console: $(wc -l < "$disabled_file" | tr -d ' ')"
        fi
    fi

    local args="--output $WORKDIR --days ${days:-14}"
    [ "$quick" = "true" ] && args="$args --quick"
    [ -n "$profile" ] && [ "$profile" != "auto" ] && args="$args --profile $profile"
    [ -n "$min_sev" ] && [ "$min_sev" != "INFO" ] && args="$args --min-severity $min_sev"
    # File-content rules. Fetched per hunt like the others, and skipped
    # silently when the console has none — an estate that never uploaded a
    # YARA rule should not see a warning about it every sweep.
    local yara_arg=""
    if [ "$(json_get "$job" use_yara)" != "false" ]; then
        local yb yfile
        yfile="$WORKDIR/yara.json"
        yb="$(api GET /api/v1/yara/bundle)"
        if [ -n "$yb" ] && json_has "$yb" "rules"; then
            printf '%s' "$yb" > "$yfile"
            local ycount
            ycount="$(json_get "$yb" count)"
            if [ -n "$ycount" ] && [ "$ycount" != "0" ] 2>/dev/null; then
                yara_arg="--yara $yfile"
                log INFO "File-content rules loaded: $ycount"
            fi
        fi
    fi

    # Sigma rules compiled for this platform. The console filters the bundle
    # by platform, so a Linux host never receives the Windows ruleset.
    local sigma_arg=""
    if [ "$(json_get "$job" use_sigma)" != "false" ]; then
        local sb sfile
        sfile="$WORKDIR/sigma.json"
        sb="$(api GET /api/v1/sigma/bundle)"
        if [ -n "$sb" ] && json_has "$sb" "rules"; then
            printf '%s' "$sb" > "$sfile"
            local scount
            scount="$(json_get "$sb" count)"
            if [ -n "$scount" ] && [ "$scount" != "0" ] 2>/dev/null; then
                sigma_arg="--sigma $sfile"
                log INFO "Sigma rules loaded for linux: $scount"
            fi
        fi
    fi

    args="$args --progress $progress_file $ioc_arg $disabled_arg --live-findings $live_file $yara_arg $sigma_arg"

    # Report progress while the collector works, so a long sweep does not look
    # like a hung agent in the console.
    # The field is "progress", not "percent". Sending the wrong name failed
    # validation on every tick and the console showed a hunt that never moved.
    # Tracked in a file so the flush below knows where the watcher stopped;
    # the watcher runs in a subshell and its variables do not survive it.
    local seen_file="$WORKDIR/.progress-seen"
    printf '0' > "$seen_file"
    ( local seen=0
      local live_seen=0
      while [ -f "$progress_file" ]; do
        sleep 10

        # Findings first. A sweep can produce a CRITICAL in its second minute
        # and finish in its eighth; waiting for the bundle to say so is the
        # wrong shape for an incident.
        local live_total live_new=""
        live_total="$(wc -l < "$live_file" 2>/dev/null || echo 0)"
        if [ "$live_total" -gt "$live_seen" ]; then
            live_new="$(tail -n +"$((live_seen + 1))" "$live_file" 2>/dev/null | head -200)"
            live_seen="$live_total"
            printf '%s' "$live_seen" > "$live_seen_file"
        fi

        local total
        total="$(wc -l < "$progress_file" 2>/dev/null || echo 0)"
        # A tick with new findings but no new module event still gets posted:
        # the findings are the point.
        if [ "$total" -le "$seen" ] && [ -z "$live_new" ]; then continue; fi

        # Every new line since the last post: several modules can finish inside
        # one interval and the console's log should not lose the ones between.
        local fresh
        fresh="$(tail -n +"$((seen + 1))" "$progress_file" 2>/dev/null)"
        seen="$total"
        printf '%s' "$seen" > "$seen_file"

        printf '%s' "$live_new" > "$WORKDIR/.live-batch"

        local body
        body="$(printf '%s' "$fresh" | python3 -c '
import json, os, sys

lines = [l for l in sys.stdin.read().splitlines() if l.strip()]
latest, events = None, []

# Findings the collector wrote since the last tick. Already JSON objects, so
# they are validated and passed through rather than rebuilt.
findings = []
try:
    with open(os.environ.get("DGL_LIVE_BATCH", ""), "r") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except Exception:
                continue
except Exception:
    pass
for line in lines:
    try:
        obj = json.loads(line)
    except Exception:
        continue
    latest = obj
    if obj.get("module"):
        events.append({
            "module": obj.get("module", ""), "status": obj.get("status", "OK"),
            "ms": int(obj.get("ms", 0)), "findings": int(obj.get("findings", 0)),
            "rows": int(obj.get("rows", 0)), "errors": int(obj.get("errors", 0)),
            "ts": obj.get("ts", ""),
        })
if latest is None and not findings:
    sys.exit(1)
latest = latest or {}
pct = float(latest.get("percent", 0) or 0)
pct = 0.0 if pct < 0 else (100.0 if pct > 100 else pct)
print(json.dumps({
    "progress": pct,
    "phase": latest.get("phase", ""),
    "detail": latest.get("detail", ""),
    "events": events,
    "findings": findings[:200],
}))
' 2>/dev/null)"
        [ -n "$body" ] || continue
        api POST "/api/v1/jobs/$job_id/progress" "$body" >/dev/null

        # A sweep runs for minutes and the main loop is blocked for all of it.
        # Wanting to isolate a host part-way through a hunt is not an unusual
        # request — it is the most likely moment to want it — so the watcher
        # answers response actions too.
        poll_ir_action
      done ) &
    local watcher=$!

    # shellcheck disable=SC2086
    bash "$COLLECTOR" $args >> "$LOGF" 2>&1
    local rc=$?

    kill "$watcher" 2>/dev/null

    # Flush whatever finished between the last poll and the collector exiting.
    # Without this the log stops several modules short of the truth, and the
    # ones missing are the late phases — file system, web roots, logs — which
    # are usually the interesting half.
    if [ -f "$progress_file" ]; then
        local tail_body
        tail_body="$(tail -n +"$(( $(cat "$seen_file" 2>/dev/null || echo 0) + 1 ))" "$progress_file" 2>/dev/null | python3 -c '
import json, sys

lines = [l for l in sys.stdin.read().splitlines() if l.strip()]
latest, events = None, []
for line in lines:
    try:
        obj = json.loads(line)
    except Exception:
        continue
    latest = obj
    if obj.get("module"):
        events.append({
            "module": obj.get("module", ""), "status": obj.get("status", "OK"),
            "ms": int(obj.get("ms", 0)), "findings": int(obj.get("findings", 0)),
            "rows": int(obj.get("rows", 0)), "errors": int(obj.get("errors", 0)),
            "ts": obj.get("ts", ""),
        })
if not events:
    sys.exit(1)
print(json.dumps({
    "progress": float(latest.get("percent", 99)) if latest else 99.0,
    "phase": (latest or {}).get("phase", "Finishing"),
    "detail": "Collection finished",
    "events": events,
}))
' 2>/dev/null)"
        if [ -n "$tail_body" ]; then
            api POST "/api/v1/jobs/$job_id/progress" "$tail_body" >/dev/null
        fi
    fi

    rm -f "$progress_file"

    out_dir="$(find "$WORKDIR" -maxdepth 1 -type d -name 'DOUGLAS_*' 2>/dev/null | sort | tail -1)"
    if [ -z "$out_dir" ] || [ ! -r "$out_dir/FINDINGS.csv" ]; then
        log ERROR "The collector produced no output (exit $rc)"
        api POST "/api/v1/jobs/$job_id/fail" \
            "{\"error\":\"Collector produced no output (exit $rc)\"}" >/dev/null
        return 1
    fi

    upload_results "$job_id" "$out_dir"
}

upload_results() {
    local job_id="$1" dir="$2"
    local bundle="$dir.tar.gz"

    tar czf "$bundle" -C "$(dirname "$dir")" "$(basename "$dir")" 2>/dev/null

    # The console expects JSON in these fields, not the CSV files themselves.
    # Posting the raw CSV parses as invalid JSON, falls back to an empty list,
    # and the hunt lands with zero findings while curl still reports success —
    # which is exactly how this went unnoticed the first time.
    csv_to_json() {
        local f="$1"
        if [ ! -r "$f" ]; then printf '[]'; return; fi
        if [ "$HAVE_PY" -eq 1 ]; then
            python3 -c '
import csv, json, sys
try:
    with open(sys.argv[1], newline="", encoding="utf-8", errors="replace") as fh:
        print(json.dumps(list(csv.DictReader(fh))))
except Exception:
    print("[]")
' "$f" 2>/dev/null || printf '[]'
        else
            printf '[]'
        fi
    }

    # Written to files and passed with @, not inlined. A findings list from a
    # busy host runs to hundreds of kilobytes and "curl -F field=$value"
    # overflows the argument list — which fails before the request is even
    # made, so the console never hears why.
    local staging="$dir/.upload"
    mkdir -p "$staging"
    csv_to_json "$dir/FINDINGS.csv"           > "$staging/findings.json"
    csv_to_json "$dir/TIMELINE.csv"           > "$staging/timeline.json"
    csv_to_json "$dir/logs/module_stats.csv"  > "$staging/stats.json"
    build_graph "$dir"                        > "$staging/graph.json"
    if [ -r "$dir/MANIFEST.json" ]; then
        cp "$dir/MANIFEST.json" "$staging/manifest.json"
    else
        printf '{}' > "$staging/manifest.json"
    fi
    printf '[]' > "$staging/errors.json"

    local curl_args=(
        -sS --max-time 600 -w '%{http_code}' -o /dev/null
        -H "X-Agent-Id: $AGENT_ID" -H "X-Agent-Key: $AGENT_KEY"
        -F "findings=<$staging/findings.json"
        -F "timeline=<$staging/timeline.json"
        -F "manifest=<$staging/manifest.json"
        -F "module_stats=<$staging/stats.json"
        -F "graph=<$staging/graph.json"
        -F "errors=<$staging/errors.json"
        -F "duration_seconds=${HUNT_SECONDS:-0}"
    )
    [ "$INSECURE" -eq 1 ] && curl_args+=(-k)
    [ -r "$bundle" ] && curl_args+=(-F "bundle=@$bundle;type=application/gzip")

    # Check the status code. curl exits 0 on a 4xx without -f, so trusting the
    # exit code alone reports success for an upload the console rejected.
    local code
    # stderr to its own file rather than appended to the log inline: mixing the
    # two streams was losing the status code, and a failed upload with no code
    # is a failure nobody can diagnose.
    local err_file="$staging/curl.err"
    code="$(curl "${curl_args[@]}" "${SERVER_URL}/api/v1/jobs/$job_id/results" 2>"$err_file")"
    if [ -s "$err_file" ]; then
        while IFS= read -r line; do log DEBUG "curl: $line"; done < "$err_file"
    fi

    if [ "${code:-0}" -ge 200 ] && [ "${code:-0}" -lt 300 ]; then
        local n
        n="$(grep -o 'RuleId' "$staging/findings.json" 2>/dev/null | wc -l | tr -d ' ')"
        log OK "Results uploaded for hunt $job_id (${n:-0} findings)"
    else
        log ERROR "Upload rejected for hunt $job_id (HTTP ${code:-none})"
        api POST "/api/v1/jobs/$job_id/fail" \
            "$(printf '{"error":"Upload rejected with HTTP %s"}' "${code:-none}")" >/dev/null
    fi

    rm -f "$bundle"
    [ "${KEEP_DIR:-0}" = "1" ] || rm -rf "$dir"
}

build_graph() {
    # The same compact snapshot the Windows agent sends, so the console graph
    # works identically whichever platform the host runs.
    local dir="$1"
    if [ "$HAVE_PY" -ne 1 ]; then printf '{}'; return; fi
    python3 - "$dir" <<'PYGRAPH' 2>/dev/null || printf '{}'
import csv, json, os, sys

art = os.path.join(sys.argv[1], "artifacts")
out = {"endpoints": [], "processes": [], "dns": []}


def rows(name):
    path = os.path.join(art, name)
    if not os.path.exists(path):
        return []
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            return list(csv.DictReader(fh))
    except Exception:
        return []


grouped = {}
for r in rows("04_external_endpoints.csv"):
    addr = (r.get("Address") or "").strip()
    if not addr:
        continue
    node = grouped.setdefault(addr, {
        "address": addr, "rdns": "", "connections": 0,
        "ports": set(), "processes": set(), "paths": "",
        "suspicious": False, "unsigned": False, "established": True,
    })
    node["connections"] += 1
    if r.get("Port"):
        node["ports"].add(str(r["Port"]))
    if r.get("Process"):
        node["processes"].add(r["Process"])

out["endpoints"] = [
    {**n,
     "ports": ",".join(sorted(n["ports"])[:6]),
     "processes": ",".join(sorted(n["processes"])[:4])}
    for n in sorted(grouped.values(), key=lambda x: -x["connections"])[:80]
]


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


procs = [
    {"pid": r.get("Pid", ""),
     "name": os.path.basename(r.get("Exe") or "") or (r.get("Command") or "")[:40],
     "path": r.get("Exe", ""), "user": r.get("User", ""),
     "cpu": r.get("Cpu", "0"), "memoryMB": r.get("MemMB", "0"),
     "threads": "", "handles": "",
     "signed": True, "suspicious": r.get("SuspiciousPath") == "1",
     "parent": r.get("Ppid", "")}
    for r in rows("03_processes.csv")
]
out["processes"] = sorted(procs, key=lambda p: -num(p["memoryMB"]))[:40]

print(json.dumps(out))
PYGRAPH
}

# ============================================================================
#  Incident response actions
#
#  Short commands run against this host from the console, separate from the
#  hunt queue because they are a different kind of work: quick, sometimes
#  destructive, and read line by line by whoever asked for them.
#
#  Every action prints a transcript rather than a status code. During an
#  incident "it worked" is not useful; what the host actually said is.
#
#  Nothing here shells out to a value from the console without quoting it, and
#  the console validated the shape first — a pid is digits, a path has no
#  metacharacters. Two layers, because one of them is on the machine under
#  investigation.
# ============================================================================

IR_QUARANTINE="/var/lib/douglas042/quarantine"

ir_processes() {
    echo "PID     PPID    USER            COMMAND"
    ps -eo pid,ppid,user:16,args --sort=-pcpu 2>/dev/null | tail -n +2 | head -200
}

ir_connections() {
    echo "== Established and listening =="
    if command -v ss >/dev/null 2>&1; then
        ss -tunap 2>/dev/null | head -200
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tunap 2>/dev/null | head -200
    else
        echo "Neither ss nor netstat is present on this host."
        return 1
    fi
}

ir_process_tree() {
    local pid="$1"
    [ -d "/proc/$pid" ] || { echo "No process with pid $pid is running."; return 1; }

    echo "== Process $pid =="
    ps -o pid,ppid,user,lstart,args -p "$pid" 2>/dev/null
    echo
    echo "== Command line =="
    tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null; echo
    echo
    echo "== Executable =="
    ls -l "/proc/$pid/exe" 2>/dev/null || echo "  (unreadable)"
    echo
    echo "== Ancestry =="
    local cur="$pid" depth=0
    while [ -n "$cur" ] && [ "$cur" != "0" ] && [ "$depth" -lt 12 ]; do
        ps -o pid,user,args -p "$cur" 2>/dev/null | tail -n +2 | sed "s/^/$(printf '%*s' "$depth" '')/"
        cur="$(ps -o ppid= -p "$cur" 2>/dev/null | tr -d ' ')"
        depth=$((depth + 2))
    done
    echo
    echo "== Open network sockets =="
    ss -tunap 2>/dev/null | grep -F "pid=$pid," || echo "  none"
}

ir_file_info() {
    local path="$1"
    [ -e "$path" ] || { echo "No such file: $path"; return 1; }
    echo "== $path =="
    ls -l --time-style=full-iso "$path" 2>/dev/null
    echo
    echo "Type    : $(file -b "$path" 2>/dev/null || echo unknown)"
    echo "SHA256  : $(sha256sum "$path" 2>/dev/null | cut -d' ' -f1)"
    echo "MD5     : $(md5sum "$path" 2>/dev/null | cut -d' ' -f1)"
    echo
    echo "== Timestamps (UTC) =="
    stat -c '  modified: %y' "$path" 2>/dev/null
    stat -c '  changed : %z' "$path" 2>/dev/null
    stat -c '  accessed: %x' "$path" 2>/dev/null
    echo
    echo "== Processes with it open =="
    if command -v lsof >/dev/null 2>&1; then
        lsof -- "$path" 2>/dev/null | head -20 || echo "  none"
    else
        echo "  lsof is not installed"
    fi
}

ir_persistence() {
    echo "== systemd units enabled =="
    systemctl list-unit-files --state=enabled --no-pager 2>/dev/null | head -60 \
        || echo "  systemd not present"
    echo
    echo "== cron =="
    for f in /etc/crontab /etc/cron.d/*; do
        [ -r "$f" ] || continue
        echo "-- $f"
        grep -vE '^\s*(#|$)' "$f" 2>/dev/null | head -20
    done
    echo "-- user crontabs"
    for u in $(cut -d: -f1 /etc/passwd 2>/dev/null); do
        local ct
        ct="$(crontab -l -u "$u" 2>/dev/null | grep -vE '^\s*(#|$)')"
        [ -n "$ct" ] && { echo "   [$u]"; printf '%s\n' "$ct" | head -10; }
    done
    echo
    echo "== authorized_keys =="
    for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
        [ -r "$f" ] || continue
        echo "-- $f"
        awk '{print "   " substr($0,1,90)}' "$f" 2>/dev/null | head -10
    done
    echo
    echo "== rc.local and profile scripts =="
    for f in /etc/rc.local /etc/profile /etc/bash.bashrc; do
        [ -r "$f" ] && echo "-- $f ($(stat -c %y "$f" 2>/dev/null | cut -d' ' -f1))"
    done
}

ir_kill_process() {
    local pid="$1"
    [ -d "/proc/$pid" ] || { echo "No process with pid $pid is running."; return 1; }

    local name cmd
    name="$(cat "/proc/$pid/comm" 2>/dev/null)"
    cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | cut -c1-160)"

    # Killing the init system or a kernel thread takes the host down rather
    # than the intrusion. Refuse, rather than warn — nobody reads warnings at
    # the moment this gets used.
    case "$(printf '%s' "$name" | tr 'A-Z' 'a-z')" in
        systemd|init|kthreadd)
            echo "Refusing to kill $name (pid $pid): stopping it takes the host down."
            return 1 ;;
    esac
    if [ "$pid" -eq 1 ]; then
        echo "Refusing to kill pid 1."
        return 1
    fi

    echo "Target : pid $pid  ($name)"
    echo "Command: $cmd"
    echo
    kill -TERM "$pid" 2>/dev/null
    sleep 2
    if [ -d "/proc/$pid" ]; then
        echo "It did not exit on SIGTERM; sending SIGKILL."
        kill -KILL "$pid" 2>/dev/null
        sleep 1
    fi
    if [ -d "/proc/$pid" ]; then
        echo "RESULT : still running. It may be in uninterruptible sleep."
        return 1
    fi
    echo "RESULT : stopped."
    echo
    echo "If it had persistence it will come back — check persistence next."
}

ir_quarantine_file() {
    local path="$1"
    [ -f "$path" ] || { echo "No such file: $path"; return 1; }

    mkdir -p "$IR_QUARANTINE" 2>/dev/null
    chmod 700 "$IR_QUARANTINE" 2>/dev/null

    local hash stamp base dest
    hash="$(sha256sum "$path" 2>/dev/null | cut -d' ' -f1)"
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    base="$(basename "$path")"
    dest="$IR_QUARANTINE/${stamp}_${base}"

    echo "Source : $path"
    echo "SHA256 : $hash"

    # Moved rather than deleted: the call may have been wrong, and whoever does
    # the analysis needs the sample.
    if ! mv "$path" "$dest" 2>/dev/null; then
        echo "RESULT : could not move it. It may be in use or on a read-only mount."
        return 1
    fi
    chmod 000 "$dest" 2>/dev/null
    printf '%s\n' "$path" > "$dest.origin" 2>/dev/null

    echo "Moved  : $dest"
    echo "RESULT : quarantined, permissions cleared, original path recorded in $dest.origin"
}

ir_disable_account() {
    local user="$1"
    id "$user" >/dev/null 2>&1 || { echo "No local account named $user."; return 1; }

    echo "Account: $user"
    # Locked and shell removed: locking alone still allows key-based SSH.
    if command -v usermod >/dev/null 2>&1; then
        usermod -L "$user" 2>/dev/null && echo "  password login locked"
        usermod -s /usr/sbin/nologin "$user" 2>/dev/null && echo "  shell set to nologin"
    else
        passwd -l "$user" >/dev/null 2>&1 && echo "  password login locked"
    fi
    if command -v chage >/dev/null 2>&1; then
        chage -E0 "$user" 2>/dev/null && echo "  account expired"
    fi
    echo
    echo "Existing sessions are not closed by this. Current logins:"
    who 2>/dev/null | grep -w "$user" || echo "  none"
    echo
    echo "RESULT : disabled, not deleted — the account and its history stay for the investigation."
}

ir_stop_service() {
    local svc="$1"
    command -v systemctl >/dev/null 2>&1 || { echo "systemd is not present on this host."; return 1; }
    systemctl list-unit-files 2>/dev/null | grep -q "^$svc" \
        || systemctl status "$svc" >/dev/null 2>&1 \
        || { echo "No service named $svc."; return 1; }

    echo "Service: $svc"
    echo "Before : $(systemctl is-active "$svc" 2>/dev/null) / $(systemctl is-enabled "$svc" 2>/dev/null)"
    systemctl stop "$svc" 2>&1 | sed 's/^/  /'
    systemctl disable "$svc" 2>&1 | sed 's/^/  /'
    echo "After  : $(systemctl is-active "$svc" 2>/dev/null) / $(systemctl is-enabled "$svc" 2>/dev/null)"
    echo
    echo "RESULT : stopped and disabled. Stopping alone would only last until the next reboot."
}

# --- Containment ------------------------------------------------------------
# Isolation keeps one path open on purpose: the console. A host cut off from
# everything including its own agent cannot be released remotely, and somebody
# would have to walk to it.

ir_console_host() {
    printf '%s' "${SERVER_URL:-}" | sed -e 's|^https\{0,1\}://||' -e 's|[:/].*$||'
}

ir_isolate() {
    local console_ip console_host
    console_host="$(ir_console_host)"
    console_ip="$(getent hosts "$console_host" 2>/dev/null | awk '{print $1; exit}')"
    [ -n "$console_ip" ] || console_ip="$console_host"

    if [ -z "$console_ip" ]; then
        echo "Refusing to isolate: the console address could not be resolved, so"
        echo "this host would have no way back and would need visiting in person."
        return 1
    fi

    echo "Console: $console_host ($console_ip) — this stays reachable."
    echo

    if command -v nft >/dev/null 2>&1 && nft list tables >/dev/null 2>&1; then
        nft add table inet douglas042 2>/dev/null
        nft 'add chain inet douglas042 input { type filter hook input priority -10 ; policy drop ; }' 2>/dev/null
        nft 'add chain inet douglas042 output { type filter hook output priority -10 ; policy drop ; }' 2>/dev/null
        nft add rule inet douglas042 input ct state established,related accept 2>/dev/null
        nft add rule inet douglas042 input iif lo accept 2>/dev/null
        nft add rule inet douglas042 output oif lo accept 2>/dev/null
        nft add rule inet douglas042 output ip daddr "$console_ip" accept 2>/dev/null
        nft add rule inet douglas042 input ip saddr "$console_ip" accept 2>/dev/null
        echo "Applied with nftables (table inet douglas042)."
    elif command -v iptables >/dev/null 2>&1; then
        iptables -N DOUGLAS042 2>/dev/null
        iptables -F DOUGLAS042 2>/dev/null
        iptables -A DOUGLAS042 -o lo -j ACCEPT 2>/dev/null
        iptables -A DOUGLAS042 -d "$console_ip" -j ACCEPT 2>/dev/null
        iptables -A DOUGLAS042 -j DROP 2>/dev/null
        iptables -I OUTPUT 1 -j DOUGLAS042 2>/dev/null
        iptables -N DOUGLAS042IN 2>/dev/null
        iptables -F DOUGLAS042IN 2>/dev/null
        iptables -A DOUGLAS042IN -i lo -j ACCEPT 2>/dev/null
        iptables -A DOUGLAS042IN -s "$console_ip" -j ACCEPT 2>/dev/null
        iptables -A DOUGLAS042IN -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
        iptables -A DOUGLAS042IN -j DROP 2>/dev/null
        iptables -I INPUT 1 -j DOUGLAS042IN 2>/dev/null
        echo "Applied with iptables (chains DOUGLAS042 / DOUGLAS042IN)."
    else
        echo "Neither nft nor iptables is available; this host cannot be isolated"
        echo "from here. Contain it at the switch or the hypervisor instead."
        return 1
    fi

    echo
    echo "Proving the console is still reachable:"
    if curl -sSf --max-time 10 -o /dev/null "${SERVER_URL}/health" 2>/dev/null; then
        echo "  OK — the agent can still reach the console, so this can be released from there."
    else
        echo "  WARNING — the console did not answer. Releasing may need local access."
    fi
    echo
    echo "RESULT : isolated. Everything except the console is blocked in both directions."
}

ir_release() {
    local removed=0
    if command -v nft >/dev/null 2>&1 && nft list table inet douglas042 >/dev/null 2>&1; then
        nft delete table inet douglas042 2>/dev/null && { echo "Removed the nftables table."; removed=1; }
    fi
    if command -v iptables >/dev/null 2>&1; then
        if iptables -C OUTPUT -j DOUGLAS042 2>/dev/null; then
            iptables -D OUTPUT -j DOUGLAS042 2>/dev/null
            iptables -F DOUGLAS042 2>/dev/null; iptables -X DOUGLAS042 2>/dev/null
            removed=1
        fi
        if iptables -C INPUT -j DOUGLAS042IN 2>/dev/null; then
            iptables -D INPUT -j DOUGLAS042IN 2>/dev/null
            iptables -F DOUGLAS042IN 2>/dev/null; iptables -X DOUGLAS042IN 2>/dev/null
            removed=1
        fi
        [ "$removed" -eq 1 ] && echo "Removed the iptables chains."
    fi

    if [ "$removed" -eq 0 ]; then
        echo "No isolation rules from this tool were present; nothing to remove."
        echo "Any firewall policy that was here beforehand has been left alone."
        return 0
    fi
    echo
    echo "RESULT : released. Only the rules isolation added were removed."
}

run_ir_action() {
    # run_ir_action ID ACTION TARGET
    local id="$1" action="$2" target="${3:-}"
    local out rc start elapsed
    start="$(date +%s)"

    log OK "Response action: $action${target:+ ($target)}"

    out="$( {
        case "$action" in
            processes)       ir_processes ;;
            connections)     ir_connections ;;
            process_tree)    ir_process_tree "$target" ;;
            file_info)       ir_file_info "$target" ;;
            persistence)     ir_persistence ;;
            kill_process)    ir_kill_process "$target" ;;
            quarantine_file) ir_quarantine_file "$target" ;;
            disable_account) ir_disable_account "$target" ;;
            stop_service)    ir_stop_service "$target" ;;
            isolate)         ir_isolate ;;
            release)         ir_release ;;
            *) echo "Unknown action: $action"; exit 2 ;;
        esac
    } 2>&1 )"
    rc=$?
    elapsed=$(( $(date +%s) - start ))

    local body
    body="$(printf '{"output":"%s","error":"%s","exit_code":%d,"duration_seconds":%d}' \
        "$(json_escape "$out")" \
        "$([ "$rc" -eq 0 ] && printf '' || printf 'the action reported a failure')" \
        "$rc" "$elapsed")"

    api POST "/api/v1/response/agent/$id/result" "$body" >/dev/null
    if [ "$rc" -eq 0 ]; then
        log OK "Response action finished: $action"
    else
        log WARN "Response action failed: $action (exit $rc)"
    fi
}

poll_ir_action() {
    local resp id action target
    resp="$(api GET /api/v1/response/agent/next)"
    [ -n "$resp" ] || return 0
    # json_has adds the quotes itself, so the key is passed bare. Passing
    # "\"id\"" here made the test look for ""id"" and never match, which meant
    # response actions were polled for and silently never run.
    json_has "$resp" "id" || return 0
    id="$(json_get "$resp" id)"
    [ -n "$id" ] && [ "$id" != "null" ] || return 0
    # The outer key is also called "action" and its value is an object, so a
    # flat read returns the object rather than the name. Take the string form.
    action="$(printf '%s' "$resp" | sed -n 's/.*"action"[[:space:]]*:[[:space:]]*"\([a-z_]*\)".*/\1/p' | head -1)"
    target="$(json_get "$resp" target)"
    [ -n "$action" ] || return 0
    run_ir_action "$id" "$action" "$target"
}

# ---------------------------------------------------------------------------
#  Capability detection
#
#  What this host can actually run, checked rather than assumed. Two machines
#  on the same distribution differ on whether auditd is installed, whether it
#  has rules loaded, and whether a YARA binary exists — and each of those
#  decides whether a whole class of detection produces findings or silently
#  produces nothing.
#
#  Silence is the case worth catching. A sweep that could not look returns the
#  same empty result as a sweep that looked and found nothing, and only one of
#  those means the host is clean. Reported to the console so it can say which.
# ---------------------------------------------------------------------------

have() { command -v "$1" >/dev/null 2>&1; }

detect_capabilities() {
    local auditd=false rules=false auditlog=false journal=false
    local py=false yara=false

    # auditd: installed AND actually running. A stopped service records
    # nothing, so "installed" on its own would be a misleading yes.
    if have auditctl || have auditd; then
        if have systemctl && systemctl is-active auditd >/dev/null 2>&1; then
            auditd=true
        elif have service && service auditd status >/dev/null 2>&1; then
            auditd=true
        elif pgrep -x auditd >/dev/null 2>&1; then
            auditd=true
        fi
    fi

    # Rules loaded. auditd with an empty ruleset looks healthy and collects
    # almost nothing, which is the most confusing of the failure modes.
    if [ "$auditd" = true ] && have auditctl; then
        local n
        n="$(auditctl -l 2>/dev/null | grep -cv '^No rules' || echo 0)"
        [ "${n:-0}" -gt 0 ] && rules=true
    fi

    [ -r /var/log/audit/audit.log ] && auditlog=true
    have journalctl && journal=true
    have python3 && py=true
    have yara && yara=true

    printf '{"auditd":%s,"auditd_rules":%s,"audit_log":%s,"journald":%s,"python3":%s,"yara":%s}' \
        "$auditd" "$rules" "$auditlog" "$journal" "$py" "$yara"
}

# A short human summary of the same thing, for the install transcript.
capability_report() {
    local caps="$1"
    printf '\n   Detection capabilities on this host\n'
    case "$caps" in
        *'"auditd":true'*)
            case "$caps" in
                *'"auditd_rules":true'*)
                    printf '     auditd    : running, rules loaded\n' ;;
                *)
                    printf '     auditd    : running, BUT NO RULES LOADED\n'
                    printf '                 It is collecting almost nothing. Load a ruleset:\n'
                    printf '                   auditctl -R /etc/audit/rules.d/audit.rules\n' ;;
            esac ;;
        *)
            printf '     auditd    : NOT RUNNING\n'
            printf '                 Nothing records what executes on this host, so\n'
            printf '                 execution rules cannot fire and a clean result only\n'
            printf '                 means the sweep could not look. Install it:\n'
            printf '                   apt install auditd   # or: dnf install audit\n'
            printf '                   systemctl enable --now auditd\n' ;;
    esac
    case "$caps" in
        *'"python3":true'*) printf '     file rules: available (python3 present)\n' ;;
        *)                  printf '     file rules: UNAVAILABLE - python3 is missing\n'
                            printf '                 Live progress and YARA file matching both need it:\n'
                            printf '                   apt install python3   # or: dnf install python3\n' ;;
    esac
    printf '\n   The console shows this too, so nobody has to remember it.\n'
}

# --- Status -----------------------------------------------------------------
show_status() {
    local line="  ------------------------------------------------------------"
    echo
    echo "  DOUGLAS-042 AGENT STATUS (linux)"
    echo "$line"

    if ! read_config; then
        echo "   Enrolment  : NOT ENROLLED"
        echo "   Run the bootstrap command from the console Deploy tab."
        echo
        return 0
    fi

    printf '   Host       : %s\n' "$(hostname)"
    printf '   Console    : %s\n' "$SERVER_URL"
    printf '   Agent id   : %s\n' "$AGENT_ID"

    if command -v systemctl >/dev/null 2>&1; then
        local state
        state="$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo unknown)"
        printf '   Service    : %s\n' "$state"
    fi

    # The running agent, excluding this status command.
    local pids
    pids="$(pgrep -f 'douglas-agent.sh' 2>/dev/null | grep -v "^$$\$" | tr '\n' ' ')"
    if [ -n "${pids// /}" ]; then
        for p in $pids; do
            local started mem
            started="$(ps -o lstart= -p "$p" 2>/dev/null)"
            mem="$(ps -o rss= -p "$p" 2>/dev/null | awk '{printf "%.1f", $1/1024}')"
            printf '   Process    : RUNNING  pid %s  |  since %s  |  %s MB\n' \
                "$p" "${started:-unknown}" "${mem:-?}"
        done
    else
        echo "   Process    : NOT RUNNING"
        echo "   Start it with:  systemctl start $SERVICE_NAME"
    fi

    [ -r "$LOGF" ] && printf '   Last log   : %s\n' "$(tail -1 "$LOGF" 2>/dev/null)"

    local probe
    probe="$(api POST /api/v1/agents/heartbeat "{\"status\":\"online\",\"capabilities\":$(detect_capabilities)}")"
    if json_has "$probe" "ok"; then
        echo "   Console    : REACHABLE, heartbeat accepted"
        if json_has "$probe" "job_id"; then
            printf '   Work       : hunt %s waiting\n' "$(json_get "$probe" job_id)"
        else
            echo "   Work       : idle, no hunt queued"
        fi
    else
        echo "   Console    : UNREACHABLE"
    fi

    echo "$line"
    printf '   Log        : %s\n' "$LOGF"
    echo
}

# --- Install ----------------------------------------------------------------
# Install narration. The operator is watching a terminal on a production host
# and a command that prints nothing for twenty seconds looks hung — so each
# step announces itself before it runs and confirms after. The step count is
# fixed so "3/6" means something.
IR_STEP=0
IR_STEPS=6

step() {
    IR_STEP=$((IR_STEP + 1))
    printf '\n  [%d/%d] %s\n' "$IR_STEP" "$IR_STEPS" "$1"
}

install_agent() {
    if [ "$(id -u)" -ne 0 ]; then
        log ERROR "Installation needs root."
        return 1
    fi
    [ -n "$SERVER" ] && [ -n "$TOKEN" ] || {
        log ERROR "Installation needs --server and --token."
        return 1
    }

    echo
    echo "  ============================================================"
    echo "   DOUGLAS-042 AGENT INSTALL"
    echo "   host    : $(hostname)"
    echo "   console : ${SERVER%/}"
    echo "  ============================================================"

    step "Staging the agent under $ROOT"
    local self_target="$ROOT/douglas-agent.sh"
    if [ "$(readlink -f "$0")" != "$(readlink -f "$self_target")" ]; then
        cp "$0" "$self_target" && chmod 755 "$self_target"
    fi
    log OK "Agent staged at $self_target"

    step "Enrolling with the console"
    enrol "$SERVER" "$TOKEN" || {
        echo
        echo "  Enrolment failed, so nothing else was installed. Nothing on this"
        echo "  host has been changed."
        return 1
    }

    step "Fetching the collector"
    update_collector

    step "Installing the service"
    if command -v systemctl >/dev/null 2>&1; then
        cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Douglas-042 hunt agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/bin/bash ${self_target}
Restart=always
RestartSec=30
User=root
# The agent reads the whole filesystem by design; it cannot be sandboxed
# without blinding the collection it exists to perform.
NoNewPrivileges=no

[Install]
WantedBy=multi-user.target
EOF
        # Errors are swallowed rather than shown: on a container or a host
        # without a running systemd these print several lines of "Failed to
        # connect to bus", which reads as a broken install when the fallback
        # below is about to handle it correctly.
        systemctl daemon-reload >/dev/null 2>&1
        systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
        if systemctl restart "$SERVICE_NAME" >/dev/null 2>&1; then
            log OK "Service ${SERVICE_NAME} installed and started"
        else
            # systemd is present as a binary but not running as PID 1 — a
            # container, usually. Start the agent directly so the host still
            # joins the fleet, and say which of the two happened.
            rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
            echo "@reboot root /bin/bash $self_target" > /etc/cron.d/douglas042-agent
            chmod 644 /etc/cron.d/douglas042-agent 2>/dev/null
            nohup bash "$self_target" >/dev/null 2>&1 &
            log WARN "systemd is not running here; started directly and registered with cron"
        fi
    else
        # No systemd: fall back to cron, which every Linux has.
        local cron_line="@reboot root /bin/bash $self_target"
        echo "$cron_line" > /etc/cron.d/douglas042-agent
        chmod 644 /etc/cron.d/douglas042-agent
        nohup bash "$self_target" >/dev/null 2>&1 &
        log OK "No systemd found; started directly and registered with cron"
    fi

    # Prove it is running rather than claiming so. An install that prints
    # success and leaves nothing alive is the failure people find three days
    # later when the fleet view is still empty.
    step "Confirming the agent is alive"
    local pid=""
    local i=0
    while [ "$i" -lt 12 ]; do
        sleep 1
        # Exclude this very process: the installer was itself invoked with the
        # agent's path on its command line, so a naive pgrep matches it and
        # then the check either passes for the wrong reason or, once the
        # installer is filtered, misses the child it just started.
        pid="$(pgrep -f "$self_target" 2>/dev/null | grep -vw "$$" | grep -vw "$PPID" | head -1)"
        [ -n "$pid" ] && break
        printf '   .'
        i=$((i + 1))
    done
    echo
    if [ -n "$pid" ]; then
        log OK "Agent process running (pid $pid)"
    else
        log WARN "No agent process yet — check: journalctl -u $SERVICE_NAME -n 40"
    fi

    step "First check-in"
    local caps probe
    caps="$(detect_capabilities)"
    probe="$(api POST /api/v1/agents/heartbeat "{\"status\":\"online\",\"capabilities\":$caps}")"
    if json_has "$probe" "ok"; then
        log OK "Console accepted the heartbeat — this host is now in the fleet"
    else
        log WARN "The console did not answer the heartbeat yet; it will retry."
    fi

    # Said here as well as in the console, because the person who runs the
    # install is the one who can fix a missing package, and they are looking at
    # this terminal right now.
    capability_report "$caps"

    show_status
    printf '   Check on it any time with:\n'
    printf '     %s --status\n' "$self_target"
    printf '   Follow it live with:\n'
    printf '     tail -f %s\n\n' "$LOGF"
}

uninstall_agent() {
    [ "$(id -u)" -eq 0 ] || { log ERROR "Removal needs root."; return 1; }
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop "$SERVICE_NAME" 2>/dev/null
        systemctl disable "$SERVICE_NAME" 2>/dev/null
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        systemctl daemon-reload
    fi
    rm -f /etc/cron.d/douglas042-agent
    pkill -f 'douglas-agent.sh' 2>/dev/null
    rm -rf "$ROOT"
    log OK "Agent removed"
}

# --- Main loop --------------------------------------------------------------
main_loop() {
    read_config || { log ERROR "This host is not enrolled. Run with --server and --token first."; exit 1; }
    log OK "Agent online. Console: $SERVER_URL"

    local backoff=0
    while true; do
        local resp
        resp="$(api POST /api/v1/agents/heartbeat "{\"status\":\"online\",\"capabilities\":$(detect_capabilities)}")"

        if [ -z "$resp" ] || ! json_has "$resp" "ok"; then
            backoff=$(( backoff + 1 ))
            [ "$backoff" -gt 6 ] && backoff=6
            local wait=$(( 2 ** backoff ))
            log WARN "Console unreachable. Retrying in ${wait}s."
            sleep "$wait"
            continue
        fi
        backoff=0

        local hb
        hb="$(json_get "$resp" heartbeat_seconds)"
        [ -n "$hb" ] && [ "$hb" -gt 0 ] 2>/dev/null && HEARTBEAT_SECONDS="$hb"

        if json_has "$resp" "job_id"; then
            update_collector
            run_hunt "$resp"
        fi

        # Response actions are polled far more often than the heartbeat. They
        # are typed by a person who is watching for the answer, and a wait of
        # up to a full heartbeat made every action feel broken — the operator
        # sees a spinner for twenty seconds before anything happens. The
        # heartbeat itself stays slow because it carries real payload; this is
        # one small GET.
        poll_ir_action

        local waited=0
        while [ "$waited" -lt "$HEARTBEAT_SECONDS" ]; do
            sleep "$IR_POLL_SECONDS"
            waited=$((waited + IR_POLL_SECONDS))
            poll_ir_action
        done
    done
}

case "$MODE" in
    install)   install_agent ;;
    uninstall) uninstall_agent ;;
    status)    show_status ;;
    once)
        read_config || { log ERROR "Not enrolled."; exit 1; }
        update_collector
        resp="$(api POST /api/v1/agents/heartbeat "{\"status\":\"online\",\"capabilities\":$(detect_capabilities)}")"
        if json_has "$resp" "job_id"; then run_hunt "$resp"
        else log INFO "No hunt queued."; fi
        ;;
    *)         main_loop ;;
esac
