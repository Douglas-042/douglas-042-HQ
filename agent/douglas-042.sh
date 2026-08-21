#!/usr/bin/env bash
# =============================================================================
#  Douglas-042 Linux Collector
#
#  Incident response collection for Linux hosts. Written in POSIX-leaning bash
#  with no dependencies beyond coreutils, because the machine you are
#  investigating is not the machine to start installing packages on.
#
#  Deliberately not a port of the Windows collector. Linux hides intrusions in
#  different places — cron, systemd units, authorized_keys, LD_PRELOAD, world
#  writable web roots — and the modules below follow those rather than
#  translating registry hunts that have no equivalent.
#
#  Output: a directory of CSV artifacts plus FINDINGS.csv and MANIFEST.json,
#  the same shapes the console already reads.
#
#  Usage:
#    ./douglas-042.sh [--days N] [--output DIR] [--quick] [--profile P]
#                     [--ioc FILE] [--min-severity LEVEL] [--progress FILE]
# =============================================================================

set -uo pipefail

VERSION="2.0.0"
DAYS=14
OUTPUT_ROOT=""
QUICK=0
PROFILE="auto"
IOC_FILE=""
MIN_SEVERITY="INFO"
PROGRESS_FILE=""
NO_RESOLVE=0
# Rules switched off in the console: one id per line. Absent or unreadable
# means run everything, which is the safe direction to fail in — the reverse
# would let a failed fetch quietly disable the detection set and still call
# the host clean.
DISABLED_RULE_FILE=""
DISABLED_RULES=" "
SUPPRESSED_BY_RULE=0
# Findings written one JSON object per line as they are produced, so the agent
# can forward them to the console while the sweep is still running. The CSV
# stays authoritative for the bundle; this is a tap on the same water, not a
# second source of truth. FINDING_SEQ is the position in that stream and is
# what lets the console match a streamed finding to its copy in the bundle.
LIVE_FINDINGS=""
FINDING_SEQ=0
# Parsed YARA rules from the console. Matching runs through a helper rather
# than the real yara binary on purpose: the console already reduced every rule
# to a subset it could represent, so the full engine would find nothing more,
# and evaluating the same structure the Windows collector evaluates is what
# makes a rule behave identically on both platforms.
YARA_BUNDLE=""
# Sigma rules the console compiled for this platform. Evaluated against auditd
# execution records and the auth/cron/syslog text logs — the only two sources
# an ordinary Linux host can be read for without extra configuration.
SIGMA_BUNDLE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --days)          DAYS="$2"; shift 2 ;;
        --output)        OUTPUT_ROOT="$2"; shift 2 ;;
        --quick)         QUICK=1; shift ;;
        --profile)       PROFILE="$2"; shift 2 ;;
        --ioc)           IOC_FILE="$2"; shift 2 ;;
        --min-severity)  MIN_SEVERITY="$2"; shift 2 ;;
        --disabled-rules) DISABLED_RULE_FILE="$2"; shift 2 ;;
        --live-findings)  LIVE_FINDINGS="$2"; shift 2 ;;
        --yara)           YARA_BUNDLE="$2"; shift 2 ;;
        --sigma)          SIGMA_BUNDLE="$2"; shift 2 ;;
        --progress)      PROGRESS_FILE="$2"; shift 2 ;;
        --no-resolve)    NO_RESOLVE=1; shift ;;
        -h|--help)
            sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

# --- Preconditions ----------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "Douglas-042 must run as root: most of what matters is unreadable otherwise." >&2
    exit 1
fi

HOSTNAME_S="$(hostname 2>/dev/null || echo unknown)"
STAMP="$(date -u +%Y%m%d_%H%M%S)"
[ -n "$OUTPUT_ROOT" ] || OUTPUT_ROOT="$(dirname "$0")/Output"
OUTDIR="${OUTPUT_ROOT}/DOUGLAS_${HOSTNAME_S}_${STAMP}"
mkdir -p "$OUTDIR/artifacts" "$OUTDIR/logs" || exit 1

FINDINGS="$OUTDIR/FINDINGS.csv"
TIMELINE="$OUTDIR/TIMELINE.csv"
LOGFILE="$OUTDIR/logs/douglas.log"
MANIFEST_TMP="$OUTDIR/logs/manifest.tmp"
STATS_TMP="$OUTDIR/logs/stats.tmp"

echo '"RuleId","Severity","Title","Evidence","Mitre","Why","Artifact","TimeUtc","Host"' > "$FINDINGS"
echo '"TimeUtc","Source","Severity","Description","Detail"' > "$TIMELINE"
: > "$MANIFEST_TMP"
: > "$STATS_TMP"

CUTOFF_EPOCH=$(( $(date -u +%s) - DAYS * 86400 ))

declare -A RULE_HITS=()
RULE_NAMES=""
CAP_PER_RULE=25
SUPPRESSED_BY_SEVERITY=0

case "$MIN_SEVERITY" in
    INFO) MIN_RANK=0 ;; LOW) MIN_RANK=1 ;; MEDIUM) MIN_RANK=2 ;;
    HIGH) MIN_RANK=3 ;; CRITICAL) MIN_RANK=4 ;; *) MIN_RANK=0 ;;
esac

# --- Helpers ----------------------------------------------------------------

log() {
    local level="$1"; shift
    printf '%s [%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$level" "$*" >> "$LOGFILE"
    case "$level" in
        ERROR|CRIT) printf '  [x] %s\n' "$*" >&2 ;;
        WARN)       printf '  [!] %s\n' "$*" ;;
        OK)         printf '  [+] %s\n' "$*" ;;
        STEP)       printf '[>] %s\n' "$*" ;;
        *)          [ "${DEBUG:-0}" = "1" ] && printf '  [.] %s\n' "$*" ;;
    esac
    return 0
}

# CSV escaping: double the quotes, wrap the field. Every value goes through
# this, because a command line containing a comma would otherwise shift every
# column after it and quietly corrupt the whole row.
csv() {
    printf '"%s"' "$(printf '%s' "${1:-}" | tr -d '\r\n' | sed 's/"/""/g')"
}

severity_rank() {
    case "$1" in
        INFO) echo 0 ;; LOW) echo 1 ;; MEDIUM) echo 2 ;;
        HIGH) echo 3 ;; CRITICAL) echo 4 ;; *) echo 0 ;;
    esac
}

finding() {
    # finding RULE SEVERITY TITLE EVIDENCE [MITRE] [WHY] [ARTIFACT] [TIME]
    local rule="$1" sev="$2" title="$3" evidence="$4"
    local mitre="${5:-}" why="${6:-}" artifact="${7:-}" when="${8:-}"

    # A rule switched off in the console produces nothing at all. Checked
    # before the severity floor and the cap, because a disabled rule should not
    # consume the per-rule budget or move any counter.
    case "$DISABLED_RULES" in
        *" $rule "*)
            SUPPRESSED_BY_RULE=$((SUPPRESSED_BY_RULE + 1))
            return 0 ;;
    esac

    if [ "$MIN_RANK" -gt 0 ] && [ "$(severity_rank "$sev")" -lt "$MIN_RANK" ]; then
        SUPPRESSED_BY_SEVERITY=$((SUPPRESSED_BY_SEVERITY + 1))
        return 0
    fi

    local seen="${RULE_HITS[$rule]:-0}"
    [ "$seen" -eq 0 ] && RULE_NAMES="$RULE_NAMES $rule"
    RULE_HITS[$rule]=$((seen + 1))
    # Same cap as the Windows collector, for the same reason: a rule that fires
    # 300 times makes the report unreadable, and an unreadable finding is the
    # same as no finding.
    if [ "$seen" -ge "$CAP_PER_RULE" ]; then return 0; fi

    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$(csv "$rule")" "$(csv "$sev")" "$(csv "$title")" "$(csv "$evidence")" \
        "$(csv "$mitre")" "$(csv "$why")" "$(csv "$artifact")" \
        "$(csv "${when:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}")" "$(csv "$HOSTNAME_S")" \
        >> "$FINDINGS"

    FINDING_SEQ=$((FINDING_SEQ + 1))
    if [ -n "$LIVE_FINDINGS" ]; then
        # Appended after the CSV row so the two can never disagree about which
        # findings exist: everything filtered out above never reaches either.
        printf '{"seq":%d,"rule_id":"%s","severity":"%s","title":"%s","evidence":"%s","mitre":"%s","why":"%s","artifact":"%s","occurred_at":"%s"}\n' \
            "$FINDING_SEQ" "$(jesc "$rule")" "$(jesc "$sev")" "$(jesc "$title")" \
            "$(jesc "$evidence")" "$(jesc "$mitre")" "$(jesc "$why")" \
            "$(jesc "$artifact")" "$(jesc "${when:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}")" \
            >> "$LIVE_FINDINGS" 2>/dev/null
    fi

    case "$sev" in
        CRITICAL|HIGH) log CRIT "[$sev] $title :: $evidence" ;;
    esac
}

# JSON string escaping. Control characters are dropped rather than encoded:
# they have no meaning in a finding and a raw newline in the middle of a line
# would split one finding into two on the reading side.
jesc() {
    printf '%s' "$1" \
        | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/ /g' \
        | tr -d '\000-\010\013\014\016-\037' \
        | tr '\n\r' '  ' \
        | cut -c1-2000
}

timeline() {
    # timeline TIME SOURCE SEVERITY DESCRIPTION [DETAIL]
    [ -n "${1:-}" ] || return 0
    printf '%s,%s,%s,%s,%s\n' \
        "$(csv "$1")" "$(csv "$2")" "$(csv "$3")" "$(csv "$4")" "$(csv "${5:-}")" \
        >> "$TIMELINE"
}

artifact_start() {
    CURRENT_ARTIFACT="$1"
    CURRENT_PATH="$OUTDIR/artifacts/$1.csv"
    printf '%s\n' "$2" > "$CURRENT_PATH"
}

artifact_row() {
    local out="" first=1
    for field in "$@"; do
        if [ $first -eq 1 ]; then first=0; else out="${out},"; fi
        out="${out}$(csv "$field")"
    done
    printf '%s\n' "$out" >> "$CURRENT_PATH"
}

artifact_end() {
    local rows
    rows=$(( $(wc -l < "$CURRENT_PATH") - 1 ))
    [ "$rows" -lt 0 ] && rows=0
    local sha="-"
    command -v sha256sum >/dev/null 2>&1 && sha="$(sha256sum "$CURRENT_PATH" | cut -d' ' -f1)"
    printf '%s|%s|%s\n' "$CURRENT_ARTIFACT" "$rows" "$sha" >> "$MANIFEST_TMP"
    log DEBUG "  -> $CURRENT_ARTIFACT ($rows rows)"
}

progress() {
    [ -n "$PROGRESS_FILE" ] || return 0
    printf '{"percent":%s,"phase":"%s","detail":"%s","ts":"%s"}\n' \
        "$1" "$2" "${3:-}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$PROGRESS_FILE" 2>/dev/null
    return 0
}

progress_module() {
    # progress_module NAME STATUS MS FINDINGS ROWS ERRORS PERCENT PHASE
    #
    # Emitted as each module finishes, so the console can show what was tried
    # and what it produced while the sweep is still running. A bar that only
    # moves tells an operator nothing about whether the hunt is going well.
    [ -n "$PROGRESS_FILE" ] || return 0
    printf '{"percent":%s,"phase":"%s","detail":"%s","module":"%s","status":"%s","ms":%s,"findings":%s,"rows":%s,"errors":%s,"ts":"%s"}\n' \
        "${7:-0}" "${8:-Running}" "$1" "$1" "$2" \
        "${3:-0}" "${4:-0}" "${5:-0}" "${6:-0}" \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$PROGRESS_FILE" 2>/dev/null
    return 0
}

is_recent() {
    # is_recent PATH — true when modified inside the analysis window
    local mtime
    mtime=$(stat -c %Y "$1" 2>/dev/null) || return 1
    [ "$mtime" -ge "$CUTOFF_EPOCH" ]
}

utc_of() {
    stat -c %y "$1" 2>/dev/null | cut -d'.' -f1 | tr ' ' 'T' | sed 's/$/Z/'
}

# --- Indicators -------------------------------------------------------------
# Declared and seeded so that `set -u` does not trip on an empty associative
# array — bash treats ${#EMPTY[@]} as unbound rather than zero.
declare -A IOCS=()
IOC_COUNT=0

load_iocs() {
    [ -n "$IOC_FILE" ] && [ -r "$IOC_FILE" ] || return 0
    local count=0
    while IFS= read -r line; do
        line="$(printf '%s' "$line" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        case "$line" in ""|\#*) continue ;; esac
        IOCS["$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')"]=1
        count=$((count + 1))
        IOC_COUNT=$((IOC_COUNT + 1))
    done < "$IOC_FILE"
    log OK "Indicator list loaded: $count entries"
}

check_ioc() {
    # check_ioc VALUE CONTEXT ARTIFACT
    [ "$IOC_COUNT" -eq 0 ] && return 0
    [ -n "${1:-}" ] || return 0
    local key
    key="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
    if [ -n "${IOCS[$key]:-}" ]; then
        finding "DGL-IOC" "CRITICAL" "Indicator list match" \
            "$1  |  $2" "" "Direct match against the supplied indicator list" "$3"
    fi
}

# =============================================================================
#  Modules
# =============================================================================

banner() {
    cat <<'EOF'

    ____                    __                 ____  __ __ ___
   / __ \____  __  ______ _/ /___ ______      / __ \/ // /|__ \
  / / / / __ \/ / / / __ `/ / __ `/ ___/_____/ / / / // /___/ /
 / /_/ / /_/ / /_/ / /_/ / / /_/ (__  )_____/ /_/ /__  __/ __/
/_____/\____/\__,_/\__, /_/\__,_/____/      \____/  /_/ /____/
                  /____/
        +---- DEFENSE BY OFFENSE  |  BLUE TEAM ----+
          Incident Response & Threat Hunting  ::  Linux
EOF
    printf '          v%s   OnBT / Behind24\n\n' "$VERSION"
}

# --- 01: host identity ------------------------------------------------------
mod_system() {
    log STEP "System information"
    artifact_start "01_system" '"Key","Value"'

    local os_name kernel uptime_s boot_utc
    os_name="$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}")"
    kernel="$(uname -r 2>/dev/null)"
    uptime_s="$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 0)"
    boot_utc="$(date -u -d "@$(( $(date +%s) - uptime_s ))" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"

    artifact_row "Hostname" "$HOSTNAME_S"
    artifact_row "OS" "$os_name"
    artifact_row "Kernel" "$kernel"
    artifact_row "Architecture" "$(uname -m 2>/dev/null)"
    artifact_row "BootUtc" "$boot_utc"
    artifact_row "UptimeDays" "$(( uptime_s / 86400 ))"
    artifact_row "Timezone" "$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null)"
    artifact_row "Profile" "$PROFILE"
    artifact_row "WindowDays" "$DAYS"
    artifact_end

    timeline "$boot_utc" "System" "INFO" "System started"

    # A host rebuilt inside the window may have been rebuilt to destroy evidence.
    local install_epoch=""
    for marker in /var/log/installer /etc/machine-id /lost+found; do
        [ -e "$marker" ] && install_epoch="$(stat -c %W "$marker" 2>/dev/null)" && break
    done
    if [ -n "$install_epoch" ] && [ "$install_epoch" -gt 0 ] 2>/dev/null; then
        local age=$(( ( $(date +%s) - install_epoch ) / 86400 ))
        if [ "$age" -lt 7 ]; then
            finding "DGL-L000" "MEDIUM" "Operating system installed less than 7 days ago" \
                "install marker age: ${age} days" "" \
                "An unexpected rebuild suggests evidence may have been destroyed" "01_system"
        fi
    fi
}

# --- 02: accounts -----------------------------------------------------------
mod_accounts() {
    log STEP "Users and groups"
    artifact_start "02_users" '"User","Uid","Gid","Home","Shell","PasswordState","LastChangeUtc"'

    local shadow_readable=0
    [ -r /etc/shadow ] && shadow_readable=1

    while IFS=: read -r user _ uid gid _ home shell; do
        local pwstate="unknown" lastchg=""
        if [ "$shadow_readable" -eq 1 ]; then
            local sline
            sline="$(grep "^${user}:" /etc/shadow 2>/dev/null)"
            local hash days
            hash="$(printf '%s' "$sline" | cut -d: -f2)"
            days="$(printf '%s' "$sline" | cut -d: -f3)"
            case "$hash" in
                "")      pwstate="EMPTY" ;;
                "!"|"*"|"!!") pwstate="locked" ;;
                *)       pwstate="set" ;;
            esac
            [ -n "$days" ] && [ "$days" -gt 0 ] 2>/dev/null && \
                lastchg="$(date -u -d "@$(( days * 86400 ))" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"
        fi
        artifact_row "$user" "$uid" "$gid" "$home" "$shell" "$pwstate" "$lastchg"

        # An account with no password is a door with no lock.
        if [ "$pwstate" = "EMPTY" ]; then
            finding "DGL-L021" "CRITICAL" "Account has no password" \
                "$user (uid $uid)" "T1078.003" \
                "Anyone who can reach a login prompt can use this account" "02_users"
        fi
        # uid 0 belongs to root and nothing else.
        if [ "$uid" = "0" ] && [ "$user" != "root" ]; then
            finding "DGL-L022" "CRITICAL" "Non-root account has uid 0" \
                "$user has uid 0, which is full root" "T1136.001" \
                "A second uid-0 account is a common backdoor: it is root without being called root" "02_users"
        fi
        # A service account that can log in interactively is worth questioning.
        case "$shell" in
            */nologin|*/false|"") : ;;
            *)
                if [ "$uid" -lt 1000 ] 2>/dev/null && [ "$user" != "root" ] && [ "$user" != "sync" ]; then
                    finding "DGL-L023" "MEDIUM" "System account has an interactive shell" \
                        "$user (uid $uid) -> $shell" "T1078.003" \
                        "Service accounts normally use nologin. An interactive shell here may have been added" "02_users"
                fi
                ;;
        esac
    done < /etc/passwd
    artifact_end

    # New accounts inside the window
    if [ -r /etc/passwd ] && is_recent /etc/passwd; then
        finding "DGL-L024" "HIGH" "The account database changed inside the analysis window" \
            "/etc/passwd last modified $(utc_of /etc/passwd)" "T1136.001" \
            "Compare against your change record; account creation is common persistence" "02_users" \
            "$(utc_of /etc/passwd)"
        timeline "$(utc_of /etc/passwd)" "Accounts" "HIGH" "/etc/passwd modified"
    fi

    # sudo rights
    artifact_start "02_sudoers" '"Source","Entry"'
    local sudo_files="/etc/sudoers"
    [ -d /etc/sudoers.d ] && sudo_files="$sudo_files $(find /etc/sudoers.d -type f 2>/dev/null)"
    for f in $sudo_files; do
        [ -r "$f" ] || continue
        while IFS= read -r line; do
            case "$line" in ""|\#*|Defaults*) continue ;; esac
            artifact_row "$f" "$line"
            # NOPASSWD grants sudo without proving who is at the keyboard.
            case "$line" in
                *NOPASSWD*)
                    finding "DGL-L025" "HIGH" "Passwordless sudo is configured" \
                        "$f: $line" "T1548.003" \
                        "Sudo without a password means a stolen session is already root" "02_sudoers"
                    ;;
            esac
        done < "$f"
    done
    artifact_end

    # Group membership for the groups that matter
    artifact_start "02_groups" '"Group","Gid","Members"'
    while IFS=: read -r gname _ gid members; do
        [ -n "$members" ] || continue
        artifact_row "$gname" "$gid" "$members"
        case "$gname" in
            root|sudo|wheel|admin|docker|lxd)
                finding "DGL-L026" "MEDIUM" "Membership of a privileged group" \
                    "$gname: $members" "T1078.003" \
                    "docker and lxd membership is root by another route; check every name here" "02_groups"
                ;;
        esac
    done < /etc/group
    artifact_end
}

# --- 03: processes ----------------------------------------------------------
mod_processes() {
    log STEP "Process tree"
    artifact_start "03_processes" \
        '"Pid","Ppid","User","Command","Exe","Cwd","StartUtc","Cpu","MemMB","Deleted","SuspiciousPath"'

    local suspicious_re='^(/tmp/|/var/tmp/|/dev/shm/|/run/shm/|/home/[^/]+/\.|/var/www/|/srv/)'
    local count=0 deleted=0

    for pid_dir in /proc/[0-9]*; do
        local pid="${pid_dir#/proc/}"
        [ -r "$pid_dir/stat" ] || continue

        local cmdline exe cwd ppid user start_utc cpu mem is_deleted=0 is_susp=0
        cmdline="$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null | sed 's/[[:space:]]*$//')"
        [ -n "$cmdline" ] || cmdline="[$(awk '{print $2}' "$pid_dir/stat" 2>/dev/null | tr -d '()')]"
        exe="$(readlink -f "$pid_dir/exe" 2>/dev/null)"
        # A running binary whose file is gone is the classic memory-only payload.
        case "$(readlink "$pid_dir/exe" 2>/dev/null)" in
            *"(deleted)") is_deleted=1 ;;
        esac
        cwd="$(readlink -f "$pid_dir/cwd" 2>/dev/null)"
        ppid="$(awk '/^PPid:/{print $2}' "$pid_dir/status" 2>/dev/null)"
        user="$(stat -c %U "$pid_dir" 2>/dev/null)"
        start_utc="$(date -u -d "@$(stat -c %Y "$pid_dir" 2>/dev/null)" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"
        mem="$(awk '/^VmRSS:/{printf "%.1f", $2/1024}' "$pid_dir/status" 2>/dev/null)"
        cpu="$(awk '{print $14+$15}' "$pid_dir/stat" 2>/dev/null)"

        printf '%s' "$exe" | grep -Eq "$suspicious_re" && is_susp=1

        artifact_row "$pid" "$ppid" "$user" "$cmdline" "$exe" "$cwd" \
            "$start_utc" "$cpu" "$mem" "$is_deleted" "$is_susp"
        count=$((count + 1))

        if [ "$is_deleted" -eq 1 ]; then
            deleted=$((deleted + 1))
            finding "DGL-L040" "CRITICAL" "Running process whose executable was deleted" \
                "pid $pid [$user] $cmdline" "T1070.004" \
                "The binary was removed after launch so nothing remains on disk to examine. Capture /proc/$pid/exe before the process exits" \
                "03_processes" "$start_utc"
            timeline "$start_utc" "Process" "CRITICAL" "Deleted-binary process: $cmdline"
        fi

        if [ "$is_susp" -eq 1 ]; then
            finding "DGL-L041" "HIGH" "Process running from a world-writable or temporary directory" \
                "pid $pid [$user] $exe" "T1036" \
                "/tmp, /dev/shm and web roots are where a dropped payload lands" \
                "03_processes" "$start_utc"
        fi

        # Command line patterns
        case "$cmdline" in
            *"base64 -d"*|*"base64 --decode"*)
                finding "DGL-L042" "HIGH" "Base64 decoding in a command line" \
                    "pid $pid: ${cmdline:0:300}" "T1140" \
                    "Common in droppers to hide the second stage" "03_processes" "$start_utc" ;;
        esac
        case "$cmdline" in
            *"curl "*|*"wget "*)
                case "$cmdline" in
                    *"| sh"*|*"|sh"*|*"| bash"*|*"|bash"*)
                        finding "DGL-L043" "CRITICAL" "Download piped straight into a shell" \
                            "pid $pid: ${cmdline:0:300}" "T1059.004" \
                            "Whatever the server returns is executed without ever touching disk" \
                            "03_processes" "$start_utc" ;;
                esac ;;
        esac
        case "$cmdline" in
            *"nc -e"*|*"ncat -e"*|*"/dev/tcp/"*|*"socat "*)
                finding "DGL-L044" "CRITICAL" "Reverse shell pattern in a command line" \
                    "pid $pid [$user]: ${cmdline:0:300}" "T1059.004" \
                    "This is the shape of an interactive shell handed to a remote address" \
                    "03_processes" "$start_utc" ;;
        esac
        case "$cmdline" in
            *xmrig*|*minerd*|*cpuminer*|*"stratum+tcp"*)
                finding "DGL-L045" "HIGH" "Cryptocurrency miner running" \
                    "pid $pid: ${cmdline:0:200}" "T1496" \
                    "Miners are usually the visible part of a wider compromise" \
                    "03_processes" "$start_utc" ;;
        esac

        [ -n "$exe" ] && check_ioc "$(basename "$exe")" "process $pid" "03_processes"
    done
    artifact_end
    log DEBUG "  $count processes ($deleted with a deleted binary)"
}

# --- 04: network ------------------------------------------------------------
mod_network() {
    log STEP "Network connections"
    artifact_start "04_connections" \
        '"Proto","LocalAddress","LocalPort","RemoteAddress","RemotePort","State","Pid","Process"'

    local have_ss=0
    command -v ss >/dev/null 2>&1 && have_ss=1

    artifact_start "04_external_endpoints" '"Address","Port","Process","Pid","State"'
    local ext_count=0

    if [ "$have_ss" -eq 1 ]; then
        # -H omits the header; parsing our own header back would be a bug.
        ss -tunapH 2>/dev/null | while read -r proto state _ _ local remote rest; do
            local lport rport laddr raddr pid pname
            laddr="${local%:*}"; lport="${local##*:}"
            raddr="${remote%:*}"; rport="${remote##*:}"
            pid="$(printf '%s' "$rest" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')"
            pname="$(printf '%s' "$rest" | sed -n 's/.*users:((\"\([^\"]*\)\".*/\1/p')"
            printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
                "$(csv "$proto")" "$(csv "$laddr")" "$(csv "$lport")" \
                "$(csv "$raddr")" "$(csv "$rport")" "$(csv "$state")" \
                "$(csv "$pid")" "$(csv "$pname")" \
                >> "$OUTDIR/artifacts/04_connections.csv"
        done
    fi
    CURRENT_ARTIFACT="04_connections"
    CURRENT_PATH="$OUTDIR/artifacts/04_connections.csv"
    artifact_end

    # External endpoints, pulled out of the connection table. "What does this
    # box talk to on the internet" is the first question in an incident.
    CURRENT_ARTIFACT="04_external_endpoints"
    CURRENT_PATH="$OUTDIR/artifacts/04_external_endpoints.csv"
    if [ -r "$OUTDIR/artifacts/04_connections.csv" ]; then
        tail -n +2 "$OUTDIR/artifacts/04_connections.csv" | \
        while IFS=, read -r _ _ _ raddr rport state pid pname; do
            raddr="$(printf '%s' "$raddr" | tr -d '"[]')"
            case "$raddr" in
                ""|"*"|0.0.0.0|127.*|10.*|192.168.*|169.254.*|::*|fe80*) continue ;;
                172.1[6-9].*|172.2[0-9].*|172.3[01].*) continue ;;
            esac
            artifact_row "$raddr" "$(printf '%s' "$rport" | tr -d '"')" \
                "$(printf '%s' "$pname" | tr -d '"')" "$(printf '%s' "$pid" | tr -d '"')" \
                "$(printf '%s' "$state" | tr -d '"')"
            check_ioc "$raddr" "external connection" "04_external_endpoints"
        done
    fi
    artifact_end

    # Listeners reachable from anywhere
    artifact_start "04_listening" '"Proto","Address","Port","Process","Pid"'
    if [ "$have_ss" -eq 1 ]; then
        ss -tulnpH 2>/dev/null | while read -r proto _ _ _ local rest; do
            local addr port pname pid
            addr="${local%:*}"; port="${local##*:}"
            pname="$(printf '%s' "$rest" | sed -n 's/.*users:((\"\([^\"]*\)\".*/\1/p')"
            pid="$(printf '%s' "$rest" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')"
            printf '%s,%s,%s,%s,%s\n' "$(csv "$proto")" "$(csv "$addr")" \
                "$(csv "$port")" "$(csv "$pname")" "$(csv "$pid")" \
                >> "$OUTDIR/artifacts/04_listening.csv"
        done
    fi
    CURRENT_ARTIFACT="04_listening"
    CURRENT_PATH="$OUTDIR/artifacts/04_listening.csv"
    artifact_end

    # /etc/hosts changes redirect traffic without touching DNS
    if [ -r /etc/hosts ] && is_recent /etc/hosts; then
        finding "DGL-L052" "HIGH" "The hosts file changed inside the analysis window" \
            "/etc/hosts modified $(utc_of /etc/hosts)" "T1565.001" \
            "Redirecting update or security domains is a way to blind a host" \
            "04_hosts" "$(utc_of /etc/hosts)"
    fi
    artifact_start "04_hosts" '"Entry"'
    grep -vE '^\s*(#|$)' /etc/hosts 2>/dev/null | while IFS= read -r l; do
        printf '%s\n' "$(csv "$l")" >> "$CURRENT_PATH"
    done
    artifact_end
}

# --- 05: persistence --------------------------------------------------------
mod_persistence() {
    log STEP "Persistence"

    # --- cron ---
    artifact_start "05_cron" '"Source","User","Entry","ModifiedUtc"'
    local cron_paths="${TEST_ROOT:-}/etc/crontab ${TEST_ROOT:-}/etc/cron.d ${TEST_ROOT:-}/etc/cron.hourly ${TEST_ROOT:-}/etc/cron.daily ${TEST_ROOT:-}/etc/cron.weekly ${TEST_ROOT:-}/etc/cron.monthly"
    for p in $cron_paths; do
        [ -e "$p" ] || continue
        if [ -d "$p" ]; then
            find "$p" -type f 2>/dev/null | while IFS= read -r f; do
                artifact_row "$f" "system" "$(head -c 400 "$f" 2>/dev/null | tr '\n' ' ')" "$(utc_of "$f")"
            done
        else
            while IFS= read -r line; do
                case "$line" in ""|\#*) continue ;; esac
                artifact_row "$p" "system" "$line" "$(utc_of "$p")"
            done < "$p"
        fi
    done
    # Per-user crontabs
    for spool in /var/spool/cron/crontabs /var/spool/cron; do
        [ -d "$spool" ] || continue
        find "$spool" -type f 2>/dev/null | while IFS= read -r f; do
            local owner
            owner="$(basename "$f")"
            while IFS= read -r line; do
                case "$line" in ""|\#*) continue ;; esac
                artifact_row "$f" "$owner" "$line" "$(utc_of "$f")"
            done < "$f"
        done
    done
    artifact_end

    # Triage cron content separately so the artifact stays complete
    for f in $(find "${TEST_ROOT:-}/etc/cron.d" /var/spool/cron -type f 2>/dev/null) "${TEST_ROOT:-}/etc/crontab"; do
        [ -r "$f" ] || continue
        if is_recent "$f"; then
            finding "DGL-L070" "HIGH" "A cron entry changed inside the analysis window" \
                "$f modified $(utc_of "$f")" "T1053.003" \
                "cron is the most common persistence mechanism on Linux" \
                "05_cron" "$(utc_of "$f")"
            timeline "$(utc_of "$f")" "Cron" "HIGH" "Cron file modified: $f"
        fi
        while IFS= read -r line; do
            case "$line" in ""|\#*) continue ;; esac
            case "$line" in
                *curl*|*wget*|*"base64"*|*"/tmp/"*|*"/dev/shm/"*|*"bash -i"*|*"nc "*)
                    finding "DGL-L071" "CRITICAL" "Suspicious command in a cron entry" \
                        "$f: ${line:0:250}" "T1053.003" \
                        "A scheduled download or shell is persistence, not maintenance" "05_cron" ;;
            esac
        done < "$f"
    done

    # --- systemd units ---
    artifact_start "05_systemd" '"Unit","Path","ExecStart","Enabled","ModifiedUtc"'
    for d in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system \
             /run/systemd/system "$HOME/.config/systemd/user"; do
        [ -d "$d" ] || continue
        find "$d" -maxdepth 2 -name '*.service' -type f 2>/dev/null | while IFS= read -r f; do
            local unit exec_line enabled
            unit="$(basename "$f")"
            exec_line="$(grep -m1 '^ExecStart=' "$f" 2>/dev/null | cut -d= -f2-)"
            enabled="$(systemctl is-enabled "$unit" 2>/dev/null || echo unknown)"
            artifact_row "$unit" "$f" "$exec_line" "$enabled" "$(utc_of "$f")"
        done
    done
    artifact_end

    for f in $(find /etc/systemd/system /run/systemd/system -name '*.service' -type f 2>/dev/null); do
        local unit exec_line
        unit="$(basename "$f")"
        exec_line="$(grep -m1 '^ExecStart=' "$f" 2>/dev/null | cut -d= -f2-)"

        if is_recent "$f"; then
            finding "DGL-L072" "HIGH" "A systemd unit was written inside the analysis window" \
                "$unit -> $exec_line" "T1543.002" \
                "Units under /etc and /run are local additions; distribution units live in /usr/lib" \
                "05_systemd" "$(utc_of "$f")"
            timeline "$(utc_of "$f")" "Systemd" "HIGH" "Unit written: $unit"
        fi
        case "$exec_line" in
            */tmp/*|*/dev/shm/*|*/var/tmp/*)
                finding "DGL-L073" "CRITICAL" "A systemd unit runs a binary from a temporary directory" \
                    "$unit -> $exec_line" "T1543.002" \
                    "Nothing legitimate installs a service that runs out of /tmp" "05_systemd" ;;
        esac
        case "$exec_line" in
            *curl*|*wget*|*"base64"*|*"bash -c"*|*"sh -c"*)
                finding "DGL-L074" "HIGH" "A systemd unit runs a shell command rather than a program" \
                    "$unit -> ${exec_line:0:250}" "T1543.002" \
                    "Read the command. A service whose ExecStart is a one-liner is usually persistence" \
                    "05_systemd" ;;
        esac
    done

    # --- shell profiles and rc files ---
    artifact_start "05_shell_init" '"File","Owner","ModifiedUtc","Lines"'
    local rc_files="/etc/profile /etc/bash.bashrc /etc/environment"
    [ -d /etc/profile.d ] && rc_files="$rc_files $(find /etc/profile.d -type f 2>/dev/null)"
    for home in /root /home/*; do
        [ -d "$home" ] || continue
        for rc in .bashrc .bash_profile .profile .zshrc .bash_login; do
            [ -f "$home/$rc" ] && rc_files="$rc_files $home/$rc"
        done
    done
    for f in $rc_files; do
        [ -r "$f" ] || continue
        artifact_row "$f" "$(stat -c %U "$f" 2>/dev/null)" "$(utc_of "$f")" \
            "$(wc -l < "$f" 2>/dev/null)"
        if is_recent "$f"; then
            finding "DGL-L075" "MEDIUM" "A shell startup file changed inside the analysis window" \
                "$f modified $(utc_of "$f")" "T1546.004" \
                "Code here runs at every login for that user" "05_shell_init" "$(utc_of "$f")"
        fi
        # Anything fetching and running code at login is not a preference
        grep -nE '(curl|wget).*(\||sh|bash)|base64 -d|nc -e|/dev/tcp/' "$f" 2>/dev/null | \
        head -3 | while IFS= read -r hit; do
            finding "DGL-L076" "CRITICAL" "A shell startup file runs a downloader or shell" \
                "$f: ${hit:0:250}" "T1546.004" \
                "This executes every time that user logs in" "05_shell_init"
        done
    done
    artifact_end

    # --- LD_PRELOAD: userland rootkit territory ---
    artifact_start "05_ld_preload" '"Source","Value"'
    if [ -s /etc/ld.so.preload ]; then
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            artifact_row "/etc/ld.so.preload" "$line"
            finding "DGL-L077" "CRITICAL" "/etc/ld.so.preload is populated" \
                "$line" "T1574.006" \
                "A library here loads into every dynamically linked process on the host. This file is empty on a healthy system and is the standard userland rootkit hook" \
                "05_ld_preload"
        done < /etc/ld.so.preload
    fi
    grep -rhE '^\s*LD_PRELOAD=' /etc/environment /etc/profile /etc/profile.d 2>/dev/null | \
    while IFS= read -r line; do
        artifact_row "environment" "$line"
        finding "DGL-L078" "HIGH" "LD_PRELOAD is set in the environment" \
            "$line" "T1574.006" \
            "Injects a library into processes started from that environment" "05_ld_preload"
    done
    artifact_end

    # --- SSH keys ---
    artifact_start "05_ssh_keys" '"User","File","KeyType","Comment","ModifiedUtc"'
    for home in "${TEST_ROOT:-}/root" ${TEST_ROOT:-}/home/*; do
        [ -d "$home" ] || continue
        local owner ak
        owner="$(basename "$home")"
        [ "$home" = "/root" ] && owner="root"
        for ak in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
            [ -r "$ak" ] || continue
            while IFS= read -r line; do
                case "$line" in ""|\#*) continue ;; esac
                local ktype comment
                ktype="$(printf '%s' "$line" | awk '{print $1}')"
                comment="$(printf '%s' "$line" | awk '{print $3}')"
                artifact_row "$owner" "$ak" "$ktype" "$comment" "$(utc_of "$ak")"
            done < "$ak"

            if is_recent "$ak"; then
                finding "DGL-L080" "CRITICAL" "An authorized_keys file changed inside the analysis window" \
                    "$owner: $ak modified $(utc_of "$ak")" "T1098.004" \
                    "An added key is durable remote access that survives password changes" \
                    "05_ssh_keys" "$(utc_of "$ak")"
                timeline "$(utc_of "$ak")" "SSH" "CRITICAL" "authorized_keys changed for $owner"
            fi
            # Options prefixed to a key can force a command or tunnel
            grep -qE '^(command=|no-pty|permitopen)' "$ak" 2>/dev/null && \
                finding "DGL-L081" "HIGH" "An SSH key carries forced options" \
                    "$owner: $ak" "T1098.004" \
                    "Forced commands and permitopen are used to pin a key to a tunnel or backdoor" \
                    "05_ssh_keys"
        done
    done
    artifact_end

    # --- sshd configuration ---
    if [ -r /etc/ssh/sshd_config ]; then
        artifact_start "05_sshd_config" '"Setting","Value"'
        grep -vE '^\s*(#|$)' /etc/ssh/sshd_config 2>/dev/null | while read -r k v; do
            artifact_row "$k" "$v"
        done
        artifact_end

        grep -qiE '^\s*PermitRootLogin\s+(yes|without-password)' /etc/ssh/sshd_config 2>/dev/null && \
            finding "DGL-L082" "HIGH" "sshd permits root login" \
                "PermitRootLogin is enabled" "T1021.004" \
                "Root over SSH removes the audit trail of who escalated and when" "05_sshd_config"
        grep -qiE '^\s*PermitEmptyPasswords\s+yes' /etc/ssh/sshd_config 2>/dev/null && \
            finding "DGL-L083" "CRITICAL" "sshd permits empty passwords" \
                "PermitEmptyPasswords yes" "T1021.004" \
                "Any account with no password is reachable from the network" "05_sshd_config"
        if is_recent /etc/ssh/sshd_config; then
            finding "DGL-L084" "MEDIUM" "The sshd configuration changed inside the analysis window" \
                "modified $(utc_of /etc/ssh/sshd_config)" "T1021.004" \
                "Check what changed against your configuration management" "05_sshd_config" \
                "$(utc_of /etc/ssh/sshd_config)"
        fi
    fi
}

# --- 06: kernel modules -----------------------------------------------------
mod_kernel() {
    log STEP "Kernel modules"
    artifact_start "06_modules" '"Module","Size","UsedBy","Signed"'
    if [ -r /proc/modules ]; then
        while read -r name size used _; do
            local signed="unknown"
            modinfo "$name" 2>/dev/null | grep -q '^sig' && signed="yes" || signed="no"
            artifact_row "$name" "$size" "$used" "$signed"
        done < /proc/modules
    fi
    artifact_end

    # Cross-view: a module hidden from /proc/modules may still be in sysfs.
    # This is the Linux equivalent of the Windows cross-view check, and it
    # catches the same class of hiding.
    if [ -d /sys/module ] && [ -r /proc/modules ]; then
        local proc_mods sys_mods
        proc_mods="$(awk '{print $1}' /proc/modules 2>/dev/null | sort)"
        sys_mods="$(ls /sys/module 2>/dev/null | sort)"
        local only_sys
        only_sys="$(comm -13 <(printf '%s\n' "$proc_mods") <(printf '%s\n' "$sys_mods") 2>/dev/null | head -20)"
        # Built-in modules legitimately appear in sysfs and not in /proc/modules,
        # so this only reports when the gap is unusually wide.
        local gap
        gap="$(printf '%s' "$only_sys" | grep -c . || true)"
        artifact_start "06_module_crossview" '"Module","SeenIn"'
        printf '%s\n' "$only_sys" | while IFS= read -r m; do
            [ -n "$m" ] && artifact_row "$m" "sysfs only"
        done
        artifact_end
    fi

    # Taint tells you an out-of-tree or forced module was loaded
    if [ -r /proc/sys/kernel/tainted ]; then
        local taint
        taint="$(cat /proc/sys/kernel/tainted)"
        if [ "$taint" != "0" ]; then
            finding "DGL-L090" "MEDIUM" "The kernel is tainted" \
                "/proc/sys/kernel/tainted = $taint" "T1014" \
                "Set when an out-of-tree, unsigned or force-loaded module was used. Normal with proprietary drivers, notable otherwise" \
                "06_modules"
        fi
    fi
}

# --- 07: file system --------------------------------------------------------
mod_filesystem() {
    [ "$QUICK" -eq 1 ] && { log DEBUG "File scan skipped in quick mode"; return 0; }
    log STEP "File system"

    artifact_start "07_recent_files" '"Path","SizeKB","ModifiedUtc","Owner","Mode"'
    local scan_dirs="/tmp /var/tmp /dev/shm /root /home /var/www /srv /opt /usr/local/bin"
    local scanned=0
    for d in $scan_dirs; do
        [ -d "$d" ] || continue
        find "$d" -xdev -type f -newermt "@$CUTOFF_EPOCH" 2>/dev/null | head -2000 | \
        while IFS= read -r f; do
            artifact_row "$f" "$(( $(stat -c %s "$f" 2>/dev/null || echo 0) / 1024 ))" \
                "$(utc_of "$f")" "$(stat -c %U "$f" 2>/dev/null)" "$(stat -c %a "$f" 2>/dev/null)"
        done
    done
    artifact_end

    # setuid binaries outside the usual places
    artifact_start "07_setuid" '"Path","Owner","Mode","ModifiedUtc"'
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | head -400 | \
    while IFS= read -r f; do
        artifact_row "$f" "$(stat -c %U "$f" 2>/dev/null)" "$(stat -c %a "$f" 2>/dev/null)" "$(utc_of "$f")"
    done
    artifact_end

    # A setuid binary in a writable or temporary location is privilege
    # escalation waiting to be used.
    find /tmp /var/tmp /dev/shm /home /var/www /srv -xdev -perm -4000 -type f 2>/dev/null | \
    head -20 | while IFS= read -r f; do
        finding "DGL-L100" "CRITICAL" "setuid binary in a writable location" \
            "$f owned by $(stat -c %U "$f" 2>/dev/null)" "T1548.001" \
            "setuid outside system directories is how a shell becomes root" "07_setuid"
    done

    # Recently created setuid binaries anywhere
    find / -xdev -perm -4000 -type f -newermt "@$CUTOFF_EPOCH" 2>/dev/null | head -20 | \
    while IFS= read -r f; do
        finding "DGL-L101" "HIGH" "setuid binary created inside the analysis window" \
            "$f @ $(utc_of "$f")" "T1548.001" \
            "Compare against your package manager; a new setuid file is rarely routine" \
            "07_setuid" "$(utc_of "$f")"
    done

    # Immutable files hide from ordinary deletion
    if command -v lsattr >/dev/null 2>&1; then
        for d in /tmp /var/tmp /dev/shm /etc; do
            [ -d "$d" ] || continue
            lsattr -R "$d" 2>/dev/null | grep -E '^\-{4}i' | head -10 | \
            while IFS= read -r line; do
                finding "DGL-L102" "MEDIUM" "Immutable attribute set on a file" \
                    "$line" "T1564" \
                    "chattr +i stops even root deleting it without clearing the flag first" \
                    "07_recent_files"
            done
        done
    fi
}

# --- 08: web (profile-aware) ------------------------------------------------
mod_sigma() {
    [ -n "$SIGMA_BUNDLE" ] && [ -r "$SIGMA_BUNDLE" ] || return 0
    command -v python3 >/dev/null 2>&1 || {
        log WARN "python3 is missing, so Sigma rules cannot be evaluated here"
        return 0
    }

    local helper="$(dirname "$0")/douglas-sigma.py"
    [ -r "$helper" ] || helper="/var/lib/douglas042/douglas-sigma.py"
    [ -r "$helper" ] || { log WARN "Sigma helper not found; skipping"; return 0; }

    # Say plainly when the main source is absent. A sweep with no auditd
    # returns the same empty result as a clean one, and only the first of those
    # is worth acting on.
    if [ ! -r /var/log/audit/audit.log ]; then
        finding "DGL-L027" "INFO" "Execution records are not available" \
            "auditd is not running or its log cannot be read" "" \
            "Sigma execution rules cannot fire on this host. Install auditd and load a ruleset, or treat a clean result here as unproven." \
            "FINDINGS"
    fi

    python3 "$helper" "$SIGMA_BUNDLE" /var/log/audit/audit.log 2>/dev/null | \
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        local rid title sev mitre ev
        rid="$(printf '%s' "$line" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
        title="$(printf '%s' "$line" | sed -n 's/.*"title"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
        sev="$(printf '%s' "$line" | sed -n 's/.*"severity"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
        mitre="$(printf '%s' "$line" | sed -n 's/.*"mitre"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
        ev="$(printf '%s' "$line" | sed -n 's/.*"evidence"[[:space:]]*:[[:space:]]*"\(.*\)","source".*/\1/p')"
        [ -n "$rid" ] || continue
        finding "SIGMA-$rid" "${sev:-MEDIUM}" "${title:-Sigma rule matched}" \
            "${ev:-matched}" "$mitre" \
            "A community Sigma rule matched an execution record or log line on this host." \
            "16_event_logs"
    done
}

mod_yara() {
    [ -n "$YARA_BUNDLE" ] && [ -r "$YARA_BUNDLE" ] || return 0
    command -v python3 >/dev/null 2>&1 || {
        log WARN "python3 is missing, so file-content rules cannot run on this host"
        return 0
    }

    local helper="$(dirname "$0")/douglas-yara.py"
    [ -r "$helper" ] || helper="/var/lib/douglas042/douglas-yara.py"
    [ -r "$helper" ] || { log WARN "YARA helper not found; skipping file rules"; return 0; }

    # What to scan. Everything on the disk is not a candidate: a full sweep of
    # a fileserver would take longer than the rest of the hunt put together and
    # find the same things. These are where dropped code actually lands.
    local list="$OUTDIR/.yara-targets"
    : > "$list"
    local roots="/tmp /var/tmp /dev/shm /var/www /srv/www /usr/share/nginx /home"
    for root in $roots; do
        [ -d "$root" ] || continue
        find "$root" -xdev -type f -size -16M \
             \( -newermt "-${DAYS:-14} days" -o -perm -u+x \) \
             -not -path '*/node_modules/*' -not -path '*/.git/*' \
             2>/dev/null | head -4000 >> "$list"
    done
    # Anything already flagged as suspicious is worth reading whatever its age.
    [ -s "$list" ] || return 0
    sort -u "$list" -o "$list"

    local n
    n="$(wc -l < "$list" | tr -d ' ')"
    log INFO "File-content rules: scanning $n candidate file(s)"

    python3 "$helper" "$YARA_BUNDLE" "$list" 2>/dev/null | while IFS= read -r line; do
        [ -n "$line" ] || continue
        # The helper reports matches; severity, caps and disabled rules are
        # decided by finding() so both platforms share one set of rules
        # about rules.
        local rule sev path strs desc
        rule="$(printf '%s' "$line" | sed -n 's/.*"rule"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
        sev="$(printf '%s' "$line" | sed -n 's/.*"severity"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
        path="$(printf '%s' "$line" | sed -n 's/.*"path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
        strs="$(printf '%s' "$line" | sed -n 's/.*"strings"[[:space:]]*:[[:space:]]*\[\([^]]*\)\].*/\1/p')"
        desc="$(printf '%s' "$line" | sed -n 's/.*"description"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
        [ -n "$rule" ] && [ -n "$path" ] || continue
        finding "YARA-$rule" "${sev:-HIGH}" "YARA rule matched: $rule" \
            "$path  |  strings: ${strs:-?}" "" \
            "${desc:-A file-content rule from your uploaded set matched this file.}" \
            "13_recent_files"
    done
}

mod_web() {
    local run_web=0
    case "$PROFILE" in
        webserver)
            # Asked for explicitly: run it whether or not a web root is found
            # in the usual places, since the operator knows something we do not.
            run_web=1
            ;;
        *)
            # Every other profile falls through to detection. The Windows roles
            # (workstation, dc) have no Linux meaning, and treating them as
            # "not a web server" silently switched off the webshell hunt on a
            # host that plainly had a web root — losing detection because of a
            # label chosen for a different operating system.
            for d in /var/www /srv/http /srv/www /usr/share/nginx \
                     /opt/lampp/htdocs /var/lib/tomcat*/webapps /home/*/public_html; do
                [ -d "$d" ] && run_web=1 && break
            done
            ;;
    esac
    [ "$run_web" -eq 1 ] || { log DEBUG "No web root found, webshell hunt skipped"; return 0; }
    [ "$QUICK" -eq 1 ] && { log DEBUG "Webshell hunt skipped in quick mode"; return 0; }

    log STEP "Webshell hunt"
    artifact_start "08_web_files" '"Path","SizeKB","ModifiedUtc","Owner","IsNew"'

    # TEST_ROOT lets the webshell hunt be pointed at a fixture tree; unset in
    # normal operation, so behaviour on a real host is unchanged.
    local web_roots="${TEST_ROOT:-}/var/www ${TEST_ROOT:-}/srv/http ${TEST_ROOT:-}/srv/www ${TEST_ROOT:-}/usr/share/nginx ${TEST_ROOT:-}/opt/lampp/htdocs ${TEST_ROOT:-}/home/*/public_html"
    local files_seen=0
    for root in $web_roots; do
        [ -d "$root" ] || continue
        find "$root" -xdev -type f \
            \( -name '*.php' -o -name '*.phtml' -o -name '*.php5' -o -name '*.php7' \
               -o -name '*.jsp' -o -name '*.jspx' -o -name '*.asp' -o -name '*.aspx' \
               -o -name '*.cgi' -o -name '*.pl' -o -name '*.py' \) 2>/dev/null | \
        head -5000 | while IFS= read -r f; do
            local is_new=0
            is_recent "$f" && is_new=1
            artifact_row "$f" "$(( $(stat -c %s "$f" 2>/dev/null || echo 0) / 1024 ))" \
                "$(utc_of "$f")" "$(stat -c %U "$f" 2>/dev/null)" "$is_new"
        done
    done
    artifact_end

    # Content patterns. Same logic as the Windows webshell hunt, with the
    # PHP-heavy patterns that dominate on Linux.
    artifact_start "08_webshell_hits" '"Path","Pattern","Snippet","ModifiedUtc"'
    for root in $web_roots; do
        [ -d "$root" ] || continue
        grep -rlE '(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)' \
            "$root" 2>/dev/null | head -50 | while IFS= read -r f; do
            local snippet
            snippet="$(grep -mE1 '(eval|assert|system|exec|shell_exec|passthru)\s*\(\s*\$_' "$f" 2>/dev/null | head -c 200)"
            artifact_row "$f" "code execution on user input" "$snippet" "$(utc_of "$f")"
            local sev="CRITICAL"
            finding "DGL-L110" "$sev" "Webshell suspected: user input passed to code execution" \
                "$f :: ${snippet:0:200}" "T1505.003" \
                "This is the defining shape of a webshell. Compare against your deployment" \
                "08_webshell_hits" "$(utc_of "$f")"
            timeline "$(utc_of "$f")" "Webshell" "CRITICAL" "Webshell suspected: $(basename "$f")"
        done

        grep -rlE '(base64_decode|gzinflate|str_rot13|eval)\s*\(\s*(base64_decode|gzinflate|\$)' \
            "$root" 2>/dev/null | head -30 | while IFS= read -r f; do
            artifact_row "$f" "obfuscated payload" "" "$(utc_of "$f")"
            finding "DGL-L111" "HIGH" "Obfuscated code in a web file" \
                "$f @ $(utc_of "$f")" "T1027" \
                "Layered decoding is used to hide a shell from both readers and signatures" \
                "08_webshell_hits" "$(utc_of "$f")"
        done
    done
    artifact_end

    # Anything new in a web root outside a deployment is worth a look even
    # without a pattern match.
    for root in $web_roots; do
        [ -d "$root" ] || continue
        find "$root" -xdev -type f -newermt "@$CUTOFF_EPOCH" \
            \( -name '*.php' -o -name '*.jsp' -o -name '*.aspx' \) 2>/dev/null | \
        head -30 | while IFS= read -r f; do
            finding "DGL-L112" "HIGH" "New script written into the web root" \
                "$f @ $(utc_of "$f")" "T1505.003" \
                "If no deployment happened, check the access log around that timestamp" \
                "08_web_files" "$(utc_of "$f")"
        done
    done

    # World-writable files inside a web root are an upload waiting to happen
    for root in $web_roots; do
        [ -d "$root" ] || continue
        find "$root" -xdev -type f -perm -o+w 2>/dev/null | head -20 | while IFS= read -r f; do
            finding "DGL-L113" "MEDIUM" "World-writable file in the web root" \
                "$f mode $(stat -c %a "$f" 2>/dev/null)" "T1505.003" \
                "Anyone on the host, including the web user, can replace this" "08_web_files"
        done
    done

    # WordPress: the most attacked application on Linux, worth naming.
    for root in $web_roots; do
        [ -d "$root" ] || continue
        find "$root" -maxdepth 3 -name 'wp-config.php' 2>/dev/null | head -5 | \
        while IFS= read -r wpconf; do
            local wproot
            wproot="$(dirname "$wpconf")"
            log DEBUG "  WordPress found at $wproot"

            # Files in uploads that are not uploads
            find "$wproot/wp-content/uploads" -type f \
                \( -name '*.php' -o -name '*.phtml' \) 2>/dev/null | head -20 | \
            while IFS= read -r f; do
                finding "DGL-L114" "CRITICAL" "Executable script inside the WordPress uploads directory" \
                    "$f" "T1505.003" \
                    "Nothing legitimate puts PHP in uploads. This is the classic WordPress webshell location" \
                    "08_web_files" "$(utc_of "$f")"
            done

            # Core files changed
            if is_recent "$wproot/wp-config.php"; then
                finding "DGL-L115" "HIGH" "wp-config.php changed inside the analysis window" \
                    "$wpconf @ $(utc_of "$wpconf")" "T1505.003" \
                    "This file holds database credentials and is a common place to hide a loader" \
                    "08_web_files" "$(utc_of "$wpconf")"
            fi

            # Recently modified plugins and themes
            for sub in plugins themes mu-plugins; do
                [ -d "$wproot/wp-content/$sub" ] || continue
                find "$wproot/wp-content/$sub" -name '*.php' -newermt "@$CUTOFF_EPOCH" \
                    2>/dev/null | head -10 | while IFS= read -r f; do
                    finding "DGL-L116" "MEDIUM" "WordPress $sub file changed inside the analysis window" \
                        "$f @ $(utc_of "$f")" "T1505.003" \
                        "Compare against the plugin version; attackers backdoor plugins to survive core updates" \
                        "08_web_files" "$(utc_of "$f")"
                done
            done
        done
    done
}

# --- 09: logs and history ---------------------------------------------------
mod_logs() {
    log STEP "Logs and history"

    # Shell history for every user: what a person actually typed
    artifact_start "09_shell_history" '"User","File","LineNumber","Command"'
    for home in /root /home/*; do
        [ -d "$home" ] || continue
        local owner
        owner="$(basename "$home")"
        [ "$home" = "/root" ] && owner="root"
        for hf in .bash_history .zsh_history .sh_history .history; do
            [ -r "$home/$hf" ] || continue
            local n=0
            while IFS= read -r line; do
                n=$((n + 1))
                [ -n "$line" ] || continue
                artifact_row "$owner" "$home/$hf" "$n" "$line"
                case "$line" in
                    *"curl "*|*"wget "*)
                        case "$line" in
                            *"| sh"*|*"|sh"*|*"| bash"*|*"|bash"*)
                                finding "DGL-L120" "CRITICAL" "Download piped into a shell, from history" \
                                    "[$owner] ${line:0:250}" "T1059.004" \
                                    "Shell history attributes the command to a person, not just a process" \
                                    "09_shell_history" ;;
                        esac ;;
                esac
                case "$line" in
                    *"chattr +i"*|*"history -c"*|*"rm -rf /var/log"*|*"shred "*|*">/var/log/"*)
                        finding "DGL-L121" "CRITICAL" "Anti-forensic command in shell history" \
                            "[$owner] ${line:0:250}" "T1070" \
                            "Someone tried to remove evidence. Whatever is missing was likely removed deliberately" \
                            "09_shell_history" ;;
                esac
                case "$line" in
                    *"useradd"*|*"usermod -aG"*|*"passwd "*|*"visudo"*)
                        finding "DGL-L122" "MEDIUM" "Account management command in shell history" \
                            "[$owner] ${line:0:200}" "T1136.001" \
                            "Match against your change record" "09_shell_history" ;;
                esac
                case "$line" in
                    *"nc -e"*|*"/dev/tcp/"*|*"socat "*|*"bash -i"*)
                        finding "DGL-L123" "CRITICAL" "Reverse shell command in shell history" \
                            "[$owner] ${line:0:250}" "T1059.004" \
                            "Typed by hand, which means someone was at a keyboard" "09_shell_history" ;;
                esac
            done < "$home/$hf"
        done

        # A history file linked to /dev/null is a deliberate blind spot
        for hf in .bash_history .zsh_history; do
            if [ -L "$home/$hf" ]; then
                local target
                target="$(readlink "$home/$hf")"
                case "$target" in
                    /dev/null)
                        finding "DGL-L124" "HIGH" "Shell history is redirected to /dev/null" \
                            "$owner: $home/$hf -> $target" "T1070.003" \
                            "History is being discarded on purpose. Nothing that user typed was recorded" \
                            "09_shell_history" ;;
                esac
            fi
        done
    done
    artifact_end

    # Authentication log: successes, failures and sudo
    artifact_start "09_auth_summary" '"Type","Count","Detail"'
    local auth_log=""
    for candidate in /var/log/auth.log /var/log/secure; do
        [ -r "$candidate" ] && auth_log="$candidate" && break
    done

    if [ -n "$auth_log" ]; then
        local accepted failed sudo_cmds
        accepted="$(grep -c 'Accepted ' "$auth_log" 2>/dev/null || echo 0)"
        failed="$(grep -c 'Failed password' "$auth_log" 2>/dev/null || echo 0)"
        sudo_cmds="$(grep -c 'sudo:.*COMMAND=' "$auth_log" 2>/dev/null || echo 0)"
        artifact_row "AcceptedLogins" "$accepted" "$auth_log"
        artifact_row "FailedPasswords" "$failed" "$auth_log"
        artifact_row "SudoCommands" "$sudo_cmds" "$auth_log"

        # Brute force: many failures from one address
        grep 'Failed password' "$auth_log" 2>/dev/null | \
            grep -oE 'from [0-9]{1,3}(\.[0-9]{1,3}){3}' | awk '{print $2}' | \
            sort | uniq -c | sort -rn | head -5 | while read -r c ip; do
            if [ "$c" -ge 20 ]; then
                artifact_row "BruteForceSource" "$c" "$ip"
                finding "DGL-L130" "HIGH" "Repeated authentication failures from one address" \
                    "$ip: $c failed attempts" "T1110" \
                    "Check whether a success from the same address follows" "09_auth_summary"

                # Success after failure is the one that matters
                if grep -q "Accepted .* from $ip" "$auth_log" 2>/dev/null; then
                    local who
                    who="$(grep "Accepted .* from $ip" "$auth_log" | tail -1 | \
                           grep -oE 'for [^ ]+' | awk '{print $2}')"
                    finding "DGL-L131" "CRITICAL" "Successful login after repeated failures" \
                        "$ip succeeded as ${who:-unknown} after $c failures" "T1110" \
                        "The account may have been taken over. Rotate its credentials and check what the session did" \
                        "09_auth_summary"
                fi
            fi
        done

        # Root logins over SSH
        grep 'Accepted .* for root ' "$auth_log" 2>/dev/null | tail -10 | \
        while IFS= read -r line; do
            local src
            src="$(printf '%s' "$line" | grep -oE 'from [0-9.]+' | awk '{print $2}')"
            finding "DGL-L132" "HIGH" "Direct root login over SSH" \
                "from ${src:-unknown}" "T1021.004" \
                "Root logins remove the record of who escalated" "09_auth_summary"
        done
    else
        finding "DGL-L133" "INFO" "No readable authentication log" \
            "Neither /var/log/auth.log nor /var/log/secure could be read" "" \
            "Login history is unavailable, so absence of evidence here proves nothing" \
            "09_auth_summary"
    fi
    artifact_end

    # Log tampering: a log that is suspiciously short or recently truncated
    artifact_start "09_log_health" '"Log","SizeBytes","ModifiedUtc","OldestLine"'
    for lf in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages \
              /var/log/wtmp /var/log/btmp; do
        [ -e "$lf" ] || continue
        local size
        size="$(stat -c %s "$lf" 2>/dev/null || echo 0)"
        artifact_row "$lf" "$size" "$(utc_of "$lf")" \
            "$(head -1 "$lf" 2>/dev/null | cut -c1-60)"
        if [ "$size" -eq 0 ]; then
            finding "DGL-L134" "CRITICAL" "A log file is empty" \
                "$lf is zero bytes, modified $(utc_of "$lf")" "T1070.002" \
                "Rotation moves a log aside; it does not leave an empty file in place. This is truncation" \
                "09_log_health" "$(utc_of "$lf")"
            timeline "$(utc_of "$lf")" "AntiForensics" "CRITICAL" "Log emptied: $lf"
        fi
    done
    artifact_end
}

# =============================================================================
#  Main
# =============================================================================

banner
log OK "Collection started: $HOSTNAME_S | profile: $PROFILE | window: $DAYS days"
log INFO "Output: $OUTDIR"
if [ -n "$DISABLED_RULE_FILE" ] && [ -r "$DISABLED_RULE_FILE" ]; then
    while IFS= read -r line; do
        line="$(printf '%s' "$line" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        case "$line" in ''|\#*) continue ;; esac
        DISABLED_RULES="$DISABLED_RULES$line "
    done < "$DISABLED_RULE_FILE"
    n="$(printf '%s' "$DISABLED_RULES" | wc -w | tr -d ' ')"
    [ "$n" -gt 0 ] && log INFO "Rules disabled in the console: $n"
fi

[ "$MIN_SEVERITY" != "INFO" ] && log INFO "Severity floor: $MIN_SEVERITY and above"

load_iocs

START_EPOCH=$(date +%s)

run_module() {
    local name="$1" fn="$2" pct="$3"
    progress "$pct" "$4" "$name"
    local t0 t1 rc

    # pipefail is right for catching real failures, but a module ends on
    # whichever pipeline ran last — and `find` over a directory that does not
    # exist, or `grep` that matches nothing, both exit non-zero. Those are
    # ordinary outcomes, not errors, so the module's own exit status is not a
    # useful signal. What matters is that it did not abort the script, which
    # the subshell below guarantees.
    local findings_before rows_before
    findings_before=$(( $(wc -l < "$FINDINGS" 2>/dev/null || echo 1) - 1 ))
    rows_before=$(wc -l < "$MANIFEST_TMP" 2>/dev/null || echo 0)

    t0=$(date +%s%N)
    ( "$fn" )
    rc=$?
    t1=$(date +%s%N)
    [ "$rc" -ge 2 ] && log WARN "$name exited $rc; the collection continued"

    local ms findings_after rows_after status
    ms=$(( (t1 - t0) / 1000000 ))
    findings_after=$(( $(wc -l < "$FINDINGS" 2>/dev/null || echo 1) - 1 ))
    rows_after=$(wc -l < "$MANIFEST_TMP" 2>/dev/null || echo 0)
    status=$([ "$rc" -ge 2 ] && echo PARTIAL || echo OK)

    printf '%s|%s\n' "$name" "$ms" >> "$STATS_TMP"
    progress_module "$name" "$status" "$ms" \
        "$(( findings_after - findings_before ))" \
        "$(( rows_after - rows_before ))" 0 "$pct" "$4"
}

run_module "System information" mod_system      5  "Profiling host"
run_module "Users and groups"   mod_accounts   15  "Profiling host"
run_module "Process tree"       mod_processes  30  "Hunting"
run_module "Network"            mod_network    45  "Hunting"
run_module "Persistence"        mod_persistence 60 "Hunting"
run_module "Kernel modules"     mod_kernel     70  "Hunting"
run_module "File system"        mod_filesystem 80  "Scanning artifacts"
run_module "Web roots"          mod_web        90  "Scanning artifacts"
run_module "File content rules"  mod_yara      93  "Scanning artifacts"
run_module "Sigma rules"         mod_sigma     96  "Correlating events"
run_module "Logs and history"   mod_logs       95  "Sweeping logs"

# --- Overflow and floor reporting -------------------------------------------
for rule in $(printf '%s\n' $RULE_NAMES | sort -u); do
    hits="${RULE_HITS[$rule]:-0}"
    if [ "$hits" -gt "$CAP_PER_RULE" ]; then
        finding "DGL-L028" "INFO" "Rule reported more findings than are shown" \
            "$rule fired $hits times; the first $CAP_PER_RULE are listed" "" \
            "A rule this noisy usually describes how this host is built. Suppress it in the console once reviewed" \
            "FINDINGS"
    fi
done
if [ "$SUPPRESSED_BY_SEVERITY" -gt 0 ]; then
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$(csv "DGL-L024")" "$(csv "$MIN_SEVERITY")" \
        "$(csv "Findings below the severity floor were not reported")" \
        "$(csv "$SUPPRESSED_BY_SEVERITY findings were collected but not listed")" \
        "$(csv "")" "$(csv "Re-run without a floor to see them")" \
        "$(csv "FINDINGS")" "$(csv "$(date -u +%Y-%m-%dT%H:%M:%SZ)")" "$(csv "$HOSTNAME_S")" \
        >> "$FINDINGS"
fi

# Same reasoning as the severity floor above: a quiet result must never be
# mistaken for a clean one. If rules were switched off in the console, say how
# much that hid rather than leaving the gap unexplained.
if [ "$SUPPRESSED_BY_RULE" -gt 0 ]; then
    disabled_n="$(printf '%s' "$DISABLED_RULES" | wc -w | tr -d ' ')"
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$(csv "DGL-025")" "$(csv "INFO")" \
        "$(csv "Some detections are switched off in the console")" \
        "$(csv "$disabled_n rule(s) disabled; $SUPPRESSED_BY_RULE finding(s) were not produced")" \
        "$(csv "")" \
        "$(csv "Switched off means the check did not run, so there is nothing to review for those rules.")" \
        "$(csv "FINDINGS")" "$(csv "$(date -u +%Y-%m-%dT%H:%M:%SZ)")" "$(csv "$HOSTNAME_S")" \
        >> "$FINDINGS"
fi

# --- Score ------------------------------------------------------------------
# `grep -c` exits non-zero when it counts nothing, so `|| echo 0` appends a
# second line and the arithmetic below sees "0\n0". Count with a pipeline that
# always succeeds instead.
count_sev() {
    grep -E "^\"[^\"]*\",\"$1\"" "$FINDINGS" 2>/dev/null | wc -l | tr -d ' '
}
CRIT=$(count_sev CRITICAL)
HIGH=$(count_sev HIGH)
MED=$(count_sev MEDIUM)
LOW=$(count_sev LOW)
SCORE=$(( CRIT * 10 + HIGH * 5 + MED * 2 + LOW ))
if   [ "$SCORE" -ge 50 ]; then RISK="CRITICAL"
elif [ "$SCORE" -ge 25 ]; then RISK="HIGH"
elif [ "$SCORE" -ge 10 ]; then RISK="MEDIUM"
elif [ "$SCORE" -gt 0 ];  then RISK="LOW"
else RISK="CLEAN"; fi

DURATION=$(( $(date +%s) - START_EPOCH ))

# --- Module statistics ------------------------------------------------------
{
    echo '"Module","Status","DurationMs"'
    while IFS='|' read -r m ms; do
        printf '"%s","OK","%s"\n' "$m" "$ms"
    done < "$STATS_TMP"
} > "$OUTDIR/logs/module_stats.csv"

# --- Manifest ---------------------------------------------------------------
{
    printf '{\n'
    printf '  "Tool": {"Name": "Douglas-042", "Version": "%s", "Platform": "linux"},\n' "$VERSION"
    printf '  "Collection": {"StartUtc": "%s", "EndUtc": "%s", "DurationSeconds": %s,\n' \
        "$(date -u -d "@$START_EPOCH" +%Y-%m-%dT%H:%M:%SZ)" \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$DURATION"
    printf '    "Parameters": {"Days": %s, "Quick": %s, "Profile": "%s", "MinSeverity": "%s"}},\n' \
        "$DAYS" "$QUICK" "$PROFILE" "$MIN_SEVERITY"
    printf '  "Host": {"ComputerName": "%s", "OS": "%s", "Kernel": "%s", "Platform": "linux"},\n' \
        "$HOSTNAME_S" \
        "$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}")" \
        "$(uname -r)"
    printf '  "Result": {"RiskScore": %s, "RiskLevel": "%s",\n' "$SCORE" "$RISK"
    printf '    "FindingCount": {"CRITICAL": %s, "HIGH": %s, "MEDIUM": %s, "LOW": %s}},\n' \
        "$CRIT" "$HIGH" "$MED" "$LOW"
    printf '  "Scope": {"NotCollected": ['
    printf '"Memory image", "Disk image", "Full packet capture", '
    printf '"Container internals", "Kernel-level rootkit detection"]}\n'
    printf '}\n'
} > "$OUTDIR/MANIFEST.json"

# --- Console summary --------------------------------------------------------
echo
printf '  %s\n' "$(printf '=%.0s' $(seq 1 68))"
printf '   HOST      : %s\n' "$HOSTNAME_S"
printf '   PROFILE   : %s\n' "$PROFILE"
printf '   ELAPSED   : %ss   |   WINDOW: last %s days\n' "$DURATION" "$DAYS"
printf '  %s\n' "$(printf -- '-%.0s' $(seq 1 68))"
printf '   RISK      : %s   (score %s)\n' "$RISK" "$SCORE"
printf '   FINDINGS  : CRITICAL %s  |  HIGH %s  |  MEDIUM %s  |  LOW %s\n' \
    "$CRIT" "$HIGH" "$MED" "$LOW"
printf '  %s\n' "$(printf '=%.0s' $(seq 1 68))"
echo

if [ "$CRIT" -gt 0 ]; then
    echo "   PRIORITY FINDINGS:"
    grep '^"[^"]*","CRITICAL"' "$FINDINGS" | head -10 | \
    while IFS= read -r line; do
        rule="$(printf '%s' "$line" | cut -d, -f1 | tr -d '"')"
        title="$(printf '%s' "$line" | cut -d, -f3 | tr -d '"')"
        printf '     [%s] %s\n' "$rule" "$title"
    done
    echo
fi

printf '   FOLDER : %s\n' "$OUTDIR"
echo

progress 100 "Complete" "done"
rm -f "$MANIFEST_TMP" "$STATS_TMP"
log OK "Collection finished in ${DURATION}s: risk $RISK (score $SCORE)"
exit 0
