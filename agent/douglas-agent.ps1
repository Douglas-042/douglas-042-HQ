<#
.SYNOPSIS
    Douglas-042 Agent - enrolls a host with the hunt console and runs hunts on demand.

.DESCRIPTION
    Lifecycle:  enroll once -> heartbeat -> claim job -> scan -> report progress -> upload

    The agent stores its credentials under ProgramData and can install itself as a
    scheduled task running as SYSTEM so it survives reboots.

.PARAMETER Server
    Console base URL, e.g. https://ir.corp.local:8000

.PARAMETER Token
    Enrollment token issued by the console.

.PARAMETER Install
    Register a scheduled task (SYSTEM, at startup) and exit.

.PARAMETER Uninstall
    Remove the scheduled task and stored credentials.

.PARAMETER Once
    Check in a single time, run any pending hunt, then exit. Useful for GPO
    startup scripts and one-shot sweeps.

.EXAMPLE
    .\douglas-agent.ps1 -Server https://ir.corp.local:8000 -Token abc123 -Install
#>

[CmdletBinding()]
param(
    [string]$Server,
    [string]$Token,
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Once,
    [switch]$Status,
    [switch]$SkipCertCheck,
    [int]$HeartbeatSeconds = 20
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$Script:AgentVersion = '2.0.0'

# NOT: 'Root', 'Home' degil. $HOME PowerShell'in salt-okunur otomatik
# degiskenidir; $Script:Home ona cozulur ve atama sessizce basarisiz olur.
# Sonuc: ajan yanlis dizine yazar, SYSTEM olarak calisan gorev config'i
# bulamaz ve host kayittan hemen sonra offline gorunur.
# ProgramData is always set on Windows, but a stripped service environment can
# leave it empty — and then every path below becomes null, which surfaces much
# later as "Cannot bind argument to parameter 'Path'" from whichever cmdlet
# happens to touch one first. Resolve it here so the failure is named.
$Script:DataRoot = $env:ProgramData
if ([string]::IsNullOrWhiteSpace($Script:DataRoot) -and
    -not [string]::IsNullOrWhiteSpace($env:SystemDrive)) {
    $Script:DataRoot = [IO.Path]::Combine($env:SystemDrive, 'ProgramData')
}
if ([string]::IsNullOrWhiteSpace($Script:DataRoot)) {
    $Script:DataRoot = 'C:\ProgramData'
}

# [IO.Path]::Combine rather than Join-Path: Join-Path validates that the drive
# exists, so building a path for a directory that has not been created yet — or
# on a host where the drive is not mounted — fails before anything is written.
$Script:Root    = [IO.Path]::Combine($Script:DataRoot, 'Douglas042')
$Script:CfgPath = [IO.Path]::Combine($Script:Root, 'agent.json')
$Script:LogPath = [IO.Path]::Combine($Script:Root, 'agent.log')
$Script:Scanner = [IO.Path]::Combine($Script:Root, 'Douglas-042.ps1')
$Script:WorkDir = [IO.Path]::Combine($Script:Root, 'work')
$Script:TaskName = 'Douglas042-Agent'

# TLS 1.2 for older Windows builds that still default to TLS 1.0.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.SecurityProtocolType]::Tls12 -bor [Net.ServicePointManager]::SecurityProtocol
} catch { }

if ($SkipCertCheck) {
    try {
        Add-Type @'
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class DouglasCertPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate c, WebRequest r, int p) { return true; }
}
'@ -ErrorAction SilentlyContinue
        [Net.ServicePointManager]::CertificatePolicy = New-Object DouglasCertPolicy
    } catch { }
}

# Fail loudly rather than limping along with a half-initialised state. Without
# this, a bad path silently sends the agent's config somewhere the scheduled
# task cannot read, and the only symptom is a host that enrols then never
# checks in again.
if ([string]::IsNullOrWhiteSpace($Script:Root) -or
    $Script:Root -notlike ([IO.Path]::Combine($Script:DataRoot, '*'))) {
    Write-Host "Agent paths did not initialise correctly (root: $Script:Root)." -ForegroundColor Red
    Write-Host 'Refusing to continue; report this with the line above.' -ForegroundColor Red
    exit 1
}

# ============================================================================
#  Helpers
# ============================================================================

function Write-Log {
    param([string]$Message, [ValidateSet('INFO', 'OK', 'WARN', 'ERROR')][string]$Level = 'INFO')
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    $color = switch ($Level) { 'OK' { 'Green' } 'WARN' { 'Yellow' } 'ERROR' { 'Red' } default { 'Gray' } }
    Write-Host $line -ForegroundColor $color
    try {
        if (-not (Test-Path $Script:Root)) { $null = New-Item $Script:Root -ItemType Directory -Force }
        Add-Content -Path $Script:LogPath -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch { }
}

function Test-Admin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object Security.Principal.WindowsPrincipal($id)
        $sid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
        return ($pr.IsInRole($sid) -or $id.User.Value -eq 'S-1-5-18')
    } catch { return $false }
}

function Get-Config {
    if (-not (Test-Path $Script:CfgPath)) { return $null }
    try { return Get-Content $Script:CfgPath -Raw | ConvertFrom-Json } catch { return $null }
}

function Save-Config {
    param([hashtable]$Config)
    if (-not (Test-Path $Script:Root)) { $null = New-Item $Script:Root -ItemType Directory -Force }
    $Config | ConvertTo-Json -Depth 5 | Out-File $Script:CfgPath -Encoding UTF8 -Force
    # Credentials live here; keep them off non-admin eyes.
    try {
        $acl = Get-Acl $Script:CfgPath
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($who in 'SYSTEM', 'Administrators') {
            $rule = New-Object Security.AccessControl.FileSystemAccessRule(
                $who, 'FullControl', 'Allow')
            $acl.AddAccessRule($rule)
        }
        Set-Acl $Script:CfgPath $acl
    } catch { }
}

function Invoke-Api {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Method = 'POST',
        $Body,
        [hashtable]$Headers = @{},
        [int]$TimeoutSec = 60
    )
    $cfg = Get-Config
    $base = if ($cfg -and $cfg.server) { $cfg.server } else { $Server }
    $uri = "$($base.TrimEnd('/'))$Path"

    $h = @{ 'Accept' = 'application/json' }
    foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] }
    if ($cfg -and $cfg.agent_id) {
        $h['X-Agent-Id'] = $cfg.agent_id
        $h['X-Agent-Key'] = $cfg.agent_key
    }

    $params = @{
        Uri = $uri; Method = $Method; Headers = $h
        TimeoutSec = $TimeoutSec; UseBasicParsing = $true
    }
    if ($null -ne $Body) {
        $params['Body'] = ($Body | ConvertTo-Json -Depth 8 -Compress)
        $params['ContentType'] = 'application/json; charset=utf-8'
    }
    return Invoke-RestMethod @params
}

function Get-HostFacts {
    $facts = @{
        hostname      = $env:COMPUTERNAME
        agent_version = $Script:AgentVersion
        ps_version    = $PSVersionTable.PSVersion.ToString()
    }
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $facts.domain = $cs.Domain
        $facts.domain_role = switch ([int]$cs.DomainRole) {
            0 { 'Standalone Workstation' } 1 { 'Member Workstation' }
            2 { 'Standalone Server' }      3 { 'Member Server' }
            4 { 'Backup Domain Controller' } 5 { 'Primary Domain Controller' }
            default { 'Unknown' }
        }
    } catch { }
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $facts.os_caption = $os.Caption
        $facts.os_build = $os.BuildNumber
        $facts.architecture = $os.OSArchitecture
    } catch { }
    try {
        # Locale-independent: never parse ipconfig output.
        $ip = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
              Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
              Select-Object -First 1 -ExpandProperty IPAddress
        $facts.ip_address = $ip
    } catch { }
    return $facts
}

# ============================================================================
#  Enrollment
# ============================================================================

function Register-Agent {
    param([string]$ServerUrl, [string]$EnrollToken)

    Write-Log "Enrolling with $ServerUrl" -Level INFO
    $facts = Get-HostFacts
    $facts.token = $EnrollToken

    $uri = "$($ServerUrl.TrimEnd('/'))/api/v1/agents/enroll"
    $resp = Invoke-RestMethod -Uri $uri -Method POST -UseBasicParsing -TimeoutSec 30 `
        -ContentType 'application/json; charset=utf-8' `
        -Body ($facts | ConvertTo-Json -Depth 5 -Compress)

    Save-Config @{
        server    = $ServerUrl.TrimEnd('/')
        agent_id  = $resp.agent_id
        agent_key = $resp.agent_key
        enrolled  = (Get-Date).ToUniversalTime().ToString('o')
    }
    Write-Log "Enrolled as $($resp.agent_id)" -Level OK
    return $resp
}

function Get-Scanner {
    param([string]$ServerUrl)
    $uri = "$($ServerUrl.TrimEnd('/'))/api/v1/reports/deploy/scanner"
    try {
        Invoke-WebRequest -Uri $uri -OutFile $Script:Scanner -UseBasicParsing -TimeoutSec 120
        Write-Log "Collector downloaded ($([math]::Round((Get-Item $Script:Scanner).Length/1KB)) KB)" -Level OK
        return $true
    } catch {
        Write-Log "Could not download the collector: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Update-Self {
    <#
        Refresh the agent script itself when the console serves a newer one.

        The collector already does this. The agent did not, which meant fixes to
        the agent stopped at whatever version a host enrolled with — the same
        bug, in the half nobody noticed.

        The running script cannot overwrite itself while executing, so the new
        copy is staged beside it and swapped in on the next start. The scheduled
        task restarts the agent anyway, so the change lands within one cycle
        rather than needing anyone to touch the host.
    #>
    param([string]$ServerUrl)

    $selfPath = Join-Path $Script:Root 'douglas-agent.ps1'
    $staged   = Join-Path $Script:Root 'douglas-agent.pending.ps1'

    # A staged copy from last time gets promoted before anything else, so an
    # update is never left half-applied.
    if (Test-Path $staged) {
        try {
            Move-Item $staged $selfPath -Force -ErrorAction Stop
            Write-Log 'Agent script updated; restarting to pick it up' -Level OK
            Start-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
            return $true   # caller should exit; the task is starting a new copy
        } catch {
            Write-Log "Could not apply the staged agent update: $($_.Exception.Message)" -Level WARN
            Remove-Item $staged -Force -ErrorAction SilentlyContinue
        }
    }

    if (-not (Test-Path $selfPath)) { return $false }

    $remote = $null
    try {
        $remote = Invoke-RestMethod -Uri "$($ServerUrl.TrimEnd('/'))/api/v1/reports/deploy/agent/version" `
                  -UseBasicParsing -TimeoutSec 30
    } catch {
        return $false   # cannot check: keep running what we have
    }
    if (-not $remote -or -not $remote.sha256) { return $false }

    $localHash = $null
    try { $localHash = (Get-FileHash -Path $selfPath -Algorithm SHA256).Hash } catch { }
    if ($localHash -and $localHash -ieq $remote.sha256) { return $false }

    Write-Log 'Console is serving a newer agent, staging it' -Level INFO
    try {
        Invoke-WebRequest -Uri "$($ServerUrl.TrimEnd('/'))/api/v1/reports/deploy/agent" `
            -OutFile $staged -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop

        # Verify before trusting it. A truncated download that replaced a
        # working agent would take the host off the fleet silently.
        $newHash = (Get-FileHash -Path $staged -Algorithm SHA256).Hash
        if ($newHash -ine $remote.sha256) {
            Write-Log 'Downloaded agent does not match the published hash; discarded' -Level WARN
            Remove-Item $staged -Force -ErrorAction SilentlyContinue
            return $false
        }
        $parseErrors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile(
                    $staged, [ref]$null, [ref]$parseErrors)
        if ($parseErrors -and $parseErrors.Count -gt 0) {
            Write-Log 'Downloaded agent does not parse; discarded' -Level WARN
            Remove-Item $staged -Force -ErrorAction SilentlyContinue
            return $false
        }
        Write-Log 'New agent staged; it takes effect at the next start' -Level OK
    } catch {
        Write-Log "Could not stage the agent update: $($_.Exception.Message)" -Level WARN
        Remove-Item $staged -Force -ErrorAction SilentlyContinue
    }
    return $false
}

function Update-Scanner {
    <#
        Refresh the collector when the console is serving a different one.

        The agent used to fetch it once at install and never again, so rule
        changes, translations and fixes stopped at whatever version a host
        happened to enrol with. Checked before every hunt: the cost is one
        small request, the cost of not checking is a fleet running stale
        detections nobody can see from the console.
    #>
    param([string]$ServerUrl)

    if (-not (Test-Path $Script:Scanner)) {
        return (Get-Scanner -ServerUrl $ServerUrl)
    }

    $remote = $null
    try {
        $remote = Invoke-RestMethod -Uri "$($ServerUrl.TrimEnd('/'))/api/v1/reports/deploy/scanner/version" `
                  -UseBasicParsing -TimeoutSec 30
    } catch {
        # Cannot check: keep the collector we have rather than failing the hunt.
        Write-Log "Collector version check failed, using the local copy" -Level WARN
        return $true
    }
    if (-not $remote -or -not $remote.sha256) { return $true }

    $localHash = $null
    try {
        $localHash = (Get-FileHash -Path $Script:Scanner -Algorithm SHA256).Hash
    } catch { }

    if ($localHash -and $localHash -ieq $remote.sha256) { return $true }

    Write-Log 'Console is serving a newer collector, updating' -Level INFO
    return (Get-Scanner -ServerUrl $ServerUrl)
}

# ============================================================================
#  Hunt execution
# ============================================================================

function Send-Progress {
    param([string]$JobId, [double]$Percent, [string]$Phase, [string]$Detail,
          [int]$Done = 0, [int]$Total = 0, $Events = @())
    try {
        # Clamped here as well. An older collector on a host that has not
        # updated yet can still report a percentage outside the range, and a
        # rejected progress post makes a running hunt look dead in the console.
        $pct = [math]::Round($Percent, 1)
        if ($pct -lt 0)   { $pct = 0 }
        if ($pct -gt 100) { $pct = 100 }

        $body = @{
            progress = $pct
            phase = $Phase; detail = $Detail
            modules_done = $Done; modules_total = $Total
        }
        if ($Events -and @($Events).Count -gt 0) { $body['events'] = @($Events) }
        $null = Invoke-Api -Path "/api/v1/jobs/$JobId/progress" -Body $body -TimeoutSec 15
    } catch { }
}

function Invoke-Hunt {
    param($Job)

    $jobId = $Job.job_id
    Write-Log "Hunt $jobId starting (days=$($Job.days) quick=$($Job.quick))" -Level OK

    $cfg = Get-Config
    if (-not (Update-Scanner -ServerUrl $cfg.server)) {
        Invoke-Api -Path "/api/v1/jobs/$jobId/fail" -Body @{
            error = 'Collector not available on this host.' } | Out-Null
        return
    }

    if (Test-Path $Script:WorkDir) { Remove-Item $Script:WorkDir -Recurse -Force -ErrorAction SilentlyContinue }
    $null = New-Item $Script:WorkDir -ItemType Directory -Force

    $progressFile = Join-Path $Script:WorkDir 'progress.jsonl'
    $iocFile = $null
    if ($Job.ioc_list) {
        $iocFile = Join-Path $Script:WorkDir 'ioc.txt'
        $Job.ioc_list | Out-File $iocFile -Encoding UTF8 -Force
    }

    # Fetch the Sigma ruleset for this hunt. Pulled per hunt rather than cached
    # so a rule enabled in the console applies to the very next collection.
    # Each rule set is fetched only when the hunt asked for it. Pulling 2400
    # Sigma rules for a run that will not evaluate them wastes the operator's
    # time on a triage sweep, which is exactly when they turned it off.
    $sigmaFile = $null
    if ($Job.use_sigma -ne $false) {
    try {
        $bundle = Invoke-Api -Path '/api/v1/sigma/bundle' -Method GET -TimeoutSec 120
        if ($bundle -and $bundle.count -gt 0) {
            $sigmaFile = Join-Path $Script:WorkDir 'sigma.json'
            ($bundle | ConvertTo-Json -Depth 12 -Compress) |
                Out-File $sigmaFile -Encoding UTF8 -Force
            Write-Log "Sigma rules fetched: $($bundle.count)" -Level OK
        }
    } catch {
        # Not fatal: the built-in rules still run. Say so rather than pretending.
        Write-Log "Could not fetch Sigma rules: $($_.Exception.Message)" -Level WARN
    }
    } else { Write-Log 'Sigma disabled for this hunt' -Level DEBUG }

    $yaraFile = $null
    if ($Job.use_yara -ne $false) {
    try {
        $yb = Invoke-Api -Path '/api/v1/yara/bundle' -Method GET -TimeoutSec 120
        if ($yb -and $yb.count -gt 0) {
            $yaraFile = Join-Path $Script:WorkDir 'yara.json'
            ($yb | ConvertTo-Json -Depth 12 -Compress) | Out-File $yaraFile -Encoding UTF8 -Force
            Write-Log "YARA rules fetched: $($yb.count)" -Level OK
        }
    } catch {
        Write-Log "Could not fetch YARA rules: $($_.Exception.Message)" -Level WARN
    }
    } else { Write-Log 'YARA disabled for this hunt' -Level DEBUG }

    $customFile = $null
    if ($Job.use_custom -ne $false) {
    try {
        $cb = Invoke-Api -Path '/api/v1/custom-rules/bundle' -Method GET -TimeoutSec 60
        if ($cb -and $cb.count -gt 0) {
            $customFile = Join-Path $Script:WorkDir 'custom.json'
            ($cb | ConvertTo-Json -Depth 10 -Compress) | Out-File $customFile -Encoding UTF8 -Force
            Write-Log "Custom rules fetched: $($cb.count)" -Level OK
        }
    } catch {
        Write-Log "Could not fetch custom rules: $($_.Exception.Message)" -Level WARN
    }
    } else { Write-Log 'Custom rules disabled for this hunt' -Level DEBUG }

    # Rules switched off in the console. Fetched every hunt so a change takes
    # effect on the next sweep with nothing to redeploy. A failure here is
    # logged and ignored: no list means the collector runs every rule, which is
    # the safe direction — the alternative would let one failed request turn a
    # host's whole detection set off and still report it clean.
    $disabledFile = $null
    try {
        $rb = Invoke-Api -Path '/api/v1/findings/rules/bundle' -Method GET -TimeoutSec 30
        if ($rb -and $rb.count -gt 0) {
            $disabledFile = Join-Path $Script:WorkDir 'disabled-rules.txt'
            ($rb.disabled -join "`r`n") | Out-File $disabledFile -Encoding UTF8 -Force
            Write-Log "Rules switched off in the console: $($rb.count)" -Level INFO
        }
    } catch {
        Write-Log "Could not fetch the disabled rule list; running every rule." -Level WARN
    }

    $argList = @(
        '-ExecutionPolicy', 'Bypass', '-NoProfile', '-NonInteractive',
        '-File', "`"$Script:Scanner`"",
        '-Days', $Job.days,
        '-OutputPath', "`"$Script:WorkDir`"",
        '-MaxEventsPerChannel', $Job.max_events,
        '-ProgressFile', "`"$progressFile`""
    )
    if ($Job.min_severity -and $Job.min_severity -ne 'INFO') {
        $argList += @('-MinSeverity', $Job.min_severity)
    }
    if ($Job.profile -and $Job.profile -ne 'auto') {
        $argList += @('-Profile', $Job.profile)
    }
    if ($Job.quick)       { $argList += '-Quick' }
    if ($Job.collect_raw) { $argList += '-CollectRaw' }
    if ($Job.no_resolve)  { $argList += '-NoResolve' }
    if ($iocFile)         { $argList += @('-IocFile', "`"$iocFile`"") }
    if ($sigmaFile)       { $argList += @('-SigmaFile', "`"$sigmaFile`"") }
    if ($yaraFile)        { $argList += @('-YaraFile', "`"$yaraFile`"") }
    if ($customFile)      { $argList += @('-CustomRuleFile', "`"$customFile`"") }
    if ($disabledFile)    { $argList += @('-DisabledRuleFile', "`"$disabledFile`"") }

    Send-Progress -JobId $jobId -Percent 1 -Phase 'Starting' -Detail 'Launching the collector'

    $started = Get-Date
    $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList $argList `
            -PassThru -WindowStyle Hidden -WorkingDirectory $Script:Root

    # Follow the collector's progress file while it runs.
    $lastLine = 0
    $lastPost = Get-Date
    while (-not $proc.HasExited) {
        Start-Sleep -Milliseconds 800
        if (Test-Path $progressFile) {
            try {
                $lines = @(Get-Content $progressFile -ErrorAction Stop)
                if ($lines.Count -gt $lastLine) {
                    # Every new line, not just the last one: several modules can
                    # finish inside one poll interval, and the console's log
                    # should not lose the ones in between.
                    $fresh = @($lines[$lastLine..($lines.Count - 1)])
                    $lastLine = $lines.Count

                    $events = New-Object System.Collections.ArrayList
                    $latest = $null
                    foreach ($raw in $fresh) {
                        if (-not $raw) { continue }
                        try { $obj = $raw | ConvertFrom-Json } catch { continue }
                        $latest = $obj
                        if ($obj.module) {
                            $null = $events.Add(@{
                                module   = [string]$obj.module
                                status   = [string]$obj.status
                                ms       = [int]$obj.ms
                                findings = [int]$obj.findings
                                rows     = [int]$obj.rows
                                errors   = [int]$obj.errors
                                ts       = [string]$obj.ts
                            })
                        }
                    }

                    if ($latest) {
                        Send-Progress -JobId $jobId -Percent $latest.percent `
                            -Phase $latest.phase -Detail $latest.detail `
                            -Done $latest.done -Total $latest.total `
                            -Events $events
                        $lastPost = Get-Date
                    }
                }
            } catch { }
        }
        # Keep the console from thinking we died during a long module.
        if (((Get-Date) - $lastPost).TotalSeconds -gt 25) {
            Send-Progress -JobId $jobId -Percent 0 -Phase 'Working' -Detail 'Collector still running'
            $lastPost = Get-Date
        }
    }

    $duration = ((Get-Date) - $started).TotalSeconds
    Write-Log "Collector exited with code $($proc.ExitCode) after $([math]::Round($duration))s" -Level INFO

    # Locate the output folder the collector produced.
    $outFolder = Get-ChildItem $Script:WorkDir -Directory -Filter 'DOUGLAS_*' -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $outFolder) {
        Invoke-Api -Path "/api/v1/jobs/$jobId/fail" -Body @{
            error = "Collector produced no output (exit code $($proc.ExitCode))." } | Out-Null
        Write-Log 'No collector output found' -Level ERROR
        return
    }

    Send-Progress -JobId $jobId -Percent 96 -Phase 'Uploading' -Detail 'Sending results to the console'

    # --- Assemble the payload ---
    function Read-Csv {
        param([string]$Path)
        if (-not (Test-Path $Path)) { return '[]' }
        try {
            $rows = @(Import-Csv $Path -ErrorAction Stop)
            if ($rows.Count -eq 0) { return '[]' }
            return ($rows | ConvertTo-Json -Depth 4 -Compress)
        } catch { return '[]' }
    }
    function Read-Json {
        param([string]$Path, [string]$Fallback = '{}')
        if (-not (Test-Path $Path)) { return $Fallback }
        try { return (Get-Content $Path -Raw -ErrorAction Stop) } catch { return $Fallback }
    }

    # Compact snapshot for the console graph: external endpoints and the
    # heaviest processes. Only what gets drawn, not the raw tables — a full
    # connection dump from a busy server is megabytes nobody reads.
    function Read-GraphData {
        param([string]$Folder)

        $art = Join-Path $Folder 'artifacts'
        $out = [ordered]@{ endpoints = @(); processes = @(); dns = @() }

        try {
            $tcpPath = Join-Path $art '04_tcp_connections.csv'
            if (Test-Path $tcpPath) {
                $tcp = @(Import-Csv $tcpPath -ErrorAction Stop)
                $ext = @($tcp | Where-Object {
                    $_.RemoteIsPrivate -ne 'True' -and $_.RemoteAddress -and
                    $_.RemoteAddress -notmatch '^(0\.0\.0\.0|::|127\.)' })

                # Grouped by address so one chatty process is one node, not 400.
                $out.endpoints = @($ext | Group-Object RemoteAddress | ForEach-Object {
                    $g = $_.Group
                    [ordered]@{
                        address     = $_.Name
                        rdns        = (@($g | Where-Object RemoteRDNS)[0]).RemoteRDNS
                        connections = $_.Count
                        ports       = ((@($g | Select-Object -ExpandProperty RemotePort -Unique) |
                                        Select-Object -First 6) -join ',')
                        processes   = ((@($g | Where-Object ProcessName |
                                         Select-Object -ExpandProperty ProcessName -Unique) |
                                        Select-Object -First 4) -join ',')
                        paths       = ((@($g | Where-Object ProcessPath |
                                         Select-Object -ExpandProperty ProcessPath -Unique) |
                                        Select-Object -First 3) -join ' | ')
                        suspicious  = [bool](@($g | Where-Object { $_.SuspiciousPath -eq 'True' }).Count)
                        unsigned    = [bool](@($g | Where-Object { $_.Signed -eq 'False' }).Count)
                        established = [bool](@($g | Where-Object { $_.State -eq 'Established' }).Count)
                    }
                } | Sort-Object -Property @{E={$_.suspicious};D=$true},
                                          @{E={$_.connections};D=$true} |
                    Select-Object -First 80)
            }
        } catch { Write-Log "Graph: connections unreadable ($($_.Exception.Message))" -Level DEBUG }

        try {
            $procPath = Join-Path $art '03_processes.csv'
            if (Test-Path $procPath) {
                $out.processes = @(Import-Csv $procPath -ErrorAction Stop |
                    Where-Object { $_.WorkingSetMB } | ForEach-Object {
                        [ordered]@{
                            pid = $_.PID; name = $_.Name; path = $_.Path; user = $_.User
                            cpu = $_.CPU; memoryMB = $_.WorkingSetMB
                            threads = $_.Threads; handles = $_.Handles
                            signed = ($_.Signed -eq 'True')
                            suspicious = ($_.SuspiciousPath -eq 'True')
                            parent = $_.ParentName
                        }
                    } | Sort-Object { [double]($_.memoryMB) } -Descending |
                    Select-Object -First 40)
            }
        } catch { Write-Log "Graph: processes unreadable ($($_.Exception.Message))" -Level DEBUG }

        try {
            $dnsPath = Join-Path $art '04_dns_cache.csv'
            if (Test-Path $dnsPath) {
                $out.dns = @(Import-Csv $dnsPath -ErrorAction Stop |
                    Where-Object { $_.Name -and $_.Data } | Select-Object -First 200 |
                    ForEach-Object { [ordered]@{ name = $_.Name; data = $_.Data; type = $_.Type } })
            }
        } catch { }

        return $out
    }

    $graph = Read-GraphData -Folder $outFolder.FullName
    Write-Log ("Graph data: {0} endpoints, {1} processes" -f `
               @($graph.endpoints).Count, @($graph.processes).Count) -Level DEBUG

    $findings = Read-Csv (Join-Path $outFolder.FullName 'FINDINGS.csv')
    $timeline = Read-Csv (Join-Path $outFolder.FullName 'TIMELINE.csv')
    $manifest = Read-Json (Join-Path $outFolder.FullName 'MANIFEST.json')
    $stats    = Read-Csv (Join-Path $outFolder.FullName 'logs\module_stats.csv')
    $errors   = Read-Json (Join-Path $outFolder.FullName 'logs\errors.json') '[]'

    $zipPath = Get-ChildItem $Script:WorkDir -Filter '*.zip' -ErrorAction SilentlyContinue |
               Sort-Object LastWriteTime -Descending | Select-Object -First 1

    $cfg = Get-Config
    $uploadUri = "$($cfg.server)/api/v1/jobs/$jobId/results"

    try {
        Send-MultipartUpload -Uri $uploadUri -AgentId $cfg.agent_id -AgentKey $cfg.agent_key `
            -Fields @{
                findings = $findings; timeline = $timeline; manifest = $manifest
                module_stats = $stats; errors = $errors
                graph = ($graph | ConvertTo-Json -Depth 5 -Compress)
                duration_seconds = [string][math]::Round($duration, 1)
            } -FilePath $(if ($zipPath) { $zipPath.FullName } else { $null })
        Write-Log "Results uploaded for hunt $jobId" -Level OK
    } catch {
        Write-Log "Upload failed: $($_.Exception.Message)" -Level ERROR
        try {
            Invoke-Api -Path "/api/v1/jobs/$jobId/fail" -Body @{
                error = "Upload failed: $($_.Exception.Message)" } | Out-Null
        } catch { }
    }

    Remove-Item $Script:WorkDir -Recurse -Force -ErrorAction SilentlyContinue
}

function Send-MultipartUpload {
    <#
        Hand-rolled multipart because Invoke-RestMethod -Form needs PS7 and we
        support 5.1. Streams the zip so a 400 MB bundle does not blow up memory.
    #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$AgentId,
        [Parameter(Mandatory)][string]$AgentKey,
        [hashtable]$Fields,
        [string]$FilePath
    )

    $boundary = "----Douglas$([guid]::NewGuid().ToString('N'))"
    $req = [Net.HttpWebRequest]::Create($Uri)
    $req.Method = 'POST'
    $req.ContentType = "multipart/form-data; boundary=$boundary"
    $req.Headers.Add('X-Agent-Id', $AgentId)
    $req.Headers.Add('X-Agent-Key', $AgentKey)
    $req.Timeout = 1800000
    $req.ReadWriteTimeout = 1800000
    $req.AllowWriteStreamBuffering = $false
    $req.SendChunked = $true

    $enc = [Text.Encoding]::UTF8
    $stream = $req.GetRequestStream()
    try {
        foreach ($name in $Fields.Keys) {
            $head = "--$boundary`r`nContent-Disposition: form-data; name=`"$name`"`r`n" +
                    "Content-Type: text/plain; charset=utf-8`r`n`r`n"
            $bytes = $enc.GetBytes($head + $Fields[$name] + "`r`n")
            $stream.Write($bytes, 0, $bytes.Length)
        }

        if ($FilePath -and (Test-Path $FilePath)) {
            $fname = Split-Path $FilePath -Leaf
            $head = "--$boundary`r`nContent-Disposition: form-data; name=`"bundle`"; " +
                    "filename=`"$fname`"`r`nContent-Type: application/zip`r`n`r`n"
            $bytes = $enc.GetBytes($head)
            $stream.Write($bytes, 0, $bytes.Length)

            $fs = [IO.File]::OpenRead($FilePath)
            try {
                $buf = New-Object byte[] 262144
                while (($read = $fs.Read($buf, 0, $buf.Length)) -gt 0) {
                    $stream.Write($buf, 0, $read)
                }
            } finally { $fs.Dispose() }

            $bytes = $enc.GetBytes("`r`n")
            $stream.Write($bytes, 0, $bytes.Length)
        }

        $tail = $enc.GetBytes("--$boundary--`r`n")
        $stream.Write($tail, 0, $tail.Length)
    } finally {
        $stream.Close()
    }

    $resp = $req.GetResponse()
    try {
        $reader = New-Object IO.StreamReader($resp.GetResponseStream())
        return $reader.ReadToEnd()
    } finally { $resp.Close() }
}

# ============================================================================
#  Install / uninstall
# ============================================================================

# Install narration. The operator is watching a terminal on a production host,
# and a command that prints nothing for twenty seconds looks hung — so each
# step announces itself before it runs and confirms after. The count is fixed
# so "3/6" means something.
# How often to ask for a queued response action, in seconds. Deliberately much
# shorter than the heartbeat: containment is typed by somebody watching.
$Script:IrPollSeconds = 5

$Script:InstallStep = 0
$Script:InstallSteps = 6

function Write-InstallStep {
    param([string]$Text)
    $Script:InstallStep++
    Write-Host ''
    Write-Host ("  [{0}/{1}] {2}" -f $Script:InstallStep, $Script:InstallSteps, $Text) -ForegroundColor Cyan
}

function Install-Agent {
    param([string]$ServerUrl, [string]$EnrollToken)

    if (-not (Test-Admin)) {
        Write-Log 'Installation needs an elevated PowerShell session.' -Level ERROR
        return $false
    }

    Write-Host ''
    Write-Host '  ============================================================' -ForegroundColor DarkGray
    Write-Host '   DOUGLAS-042 AGENT INSTALL' -ForegroundColor White
    Write-Host ("   host    : {0}" -f $env:COMPUTERNAME) -ForegroundColor DarkGray
    Write-Host ("   console : {0}" -f $ServerUrl.TrimEnd('/')) -ForegroundColor DarkGray
    Write-Host '  ============================================================' -ForegroundColor DarkGray

    Write-InstallStep "Staging the agent under $Script:Root"
    if (-not (Test-Path $Script:Root)) { $null = New-Item $Script:Root -ItemType Directory -Force }
    $selfTarget = Join-Path $Script:Root 'douglas-agent.ps1'
    if ($PSCommandPath -and $PSCommandPath -ne $selfTarget) {
        Copy-Item $PSCommandPath $selfTarget -Force
    } elseif (-not (Test-Path $selfTarget)) {
        try {
            Invoke-WebRequest -Uri "$($ServerUrl.TrimEnd('/'))/api/v1/reports/deploy/agent" `
                -OutFile $selfTarget -UseBasicParsing -TimeoutSec 60
        } catch {
            Write-Log "Could not stage the agent script: $($_.Exception.Message)" -Level ERROR
            return $false
        }
    }

    Write-Log "Agent staged at $selfTarget" -Level OK

    Write-InstallStep 'Enrolling with the console'
    try {
        $null = Register-Agent -ServerUrl $ServerUrl -EnrollToken $EnrollToken
    } catch {
        Write-Log "Enrolment refused: $($_.Exception.Message)" -Level ERROR
        Write-Host ''
        Write-Host '  Enrolment failed, so nothing else was installed. Nothing on this' -ForegroundColor Red
        Write-Host '  host has been changed.' -ForegroundColor Red
        return $false
    }

    Write-InstallStep 'Fetching the collector'
    Get-Scanner -ServerUrl $ServerUrl | Out-Null

    Write-InstallStep 'Registering the scheduled task'
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$selfTarget`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 999 `
        -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 0)

    Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName $Script:TaskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $taskSettings `
        -Description 'Douglas-042 hunt agent' | Out-Null

    Start-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue

    Write-Log "Scheduled task '$Script:TaskName' registered and started" -Level OK

    # Prove it is actually running rather than claiming so. An install that
    # prints success and leaves nothing alive is the failure people discover
    # three days later when the fleet view is still empty.
    Write-InstallStep 'Confirming the agent is alive'
    $proc = @()
    for ($i = 0; $i -lt 15; $i++) {
        Start-Sleep -Milliseconds 700
        Write-Host '.' -NoNewline -ForegroundColor DarkGray
        $proc = Get-AgentProcess
        if ($proc.Count -gt 0) { break }
    }
    Write-Host ''

    if ($proc.Count -gt 0) {
        Write-Log ("Agent process is running (pid {0})" -f $proc[0].ProcessId) -Level OK

        Write-InstallStep 'First check-in'
        try {
            $probe = Invoke-Api -Path '/api/v1/agents/heartbeat' -Body @{ status = 'online' } -TimeoutSec 20
            if ($probe) {
                Write-Log 'Console accepted the heartbeat — this host is now in the fleet' -Level OK
            }
        } catch {
            Write-Log 'The console did not answer the heartbeat yet; the agent will retry.' -Level WARN
        }
    } else {
        Write-Log 'Agent process did not appear. Check the task and the log below.' -Level WARN
    }

    # And confirm the console saw it, which is what the operator came for.
    $seen = $false
    for ($i = 0; $i -lt 10; $i++) {
        try {
            $r = Invoke-Api -Path '/api/v1/agents/heartbeat' -Body @{ status = 'online' } -TimeoutSec 20
            if ($r) { $seen = $true; break }
        } catch { }
        Start-Sleep -Seconds 2
    }
    if ($seen) {
        Write-Log 'Console acknowledged the first heartbeat.' -Level OK
    } else {
        Write-Log 'Console has not acknowledged a heartbeat yet; it may take a minute.' -Level WARN
    }

    Show-AgentStatus
    Write-Host '   Check on it any time with:' -ForegroundColor DarkGray
    Write-Host ("     & '{0}' -Status" -f $selfTarget) -ForegroundColor Cyan
    Write-Host ''
    return $true
}

function Get-AgentProcess {
    <#
        Find the process actually running the agent.

        The scheduled task runs powershell.exe, so the task name alone does not
        tell you whether anything is alive. Matching on the command line finds
        the real process, which is what an operator wants to see.
    #>
    try {
        return @(Get-CimInstance Win32_Process -EA Stop |
                 Where-Object {
                     $_.CommandLine -and
                     $_.CommandLine -like '*douglas-agent.ps1*' -and
                     # Not this process. Running -Status from a console would
                     # otherwise report the status command as a live agent.
                     [int]$_.ProcessId -ne $PID -and
                     # Not a one-shot invocation either: the long-running agent
                     # is the one with no mode switch on its command line.
                     $_.CommandLine -notmatch '(?i)-(Status|Install|Uninstall|Once)\b'
                 })
    } catch { return @() }
}

function Show-AgentStatus {
    <# What an operator needs to see to believe the agent is working. #>
    $cfg = Get-Config
    $line = '  ' + ('-' * 62)

    Write-Host ''
    Write-Host '  DOUGLAS-042 AGENT STATUS' -ForegroundColor Cyan
    Write-Host $line -ForegroundColor DarkGray

    if (-not $cfg) {
        Write-Host '   Enrolment  : NOT ENROLLED' -ForegroundColor Red
        Write-Host '   Run the bootstrap command from the console Deploy tab.' -ForegroundColor DarkGray
        Write-Host ''
        return
    }

    Write-Host ("   Host       : {0}" -f $env:COMPUTERNAME)
    Write-Host ("   Console    : {0}" -f $cfg.server)
    Write-Host ("   Agent id   : {0}" -f $cfg.agent_id)

    # --- Scheduled task ---
    $task = $null
    try { $task = Get-ScheduledTask -TaskName $Script:TaskName -EA Stop } catch { }
    if ($task) {
        $state = [string]$task.State
        $col = if ($state -eq 'Running') { 'Green' } elseif ($state -eq 'Ready') { 'Yellow' } else { 'Red' }
        Write-Host ("   Task       : {0}" -f $state) -ForegroundColor $col
    } else {
        Write-Host '   Task       : NOT REGISTERED' -ForegroundColor Red
    }

    # --- Live process ---
    $procs = Get-AgentProcess
    if ($procs.Count -gt 1) {
        Write-Host ("   Warning    : {0} agent processes are running. One is expected." -f `
                    $procs.Count) -ForegroundColor Yellow
        Write-Host '   Stop the extras with: Stop-ScheduledTask -TaskName Douglas042-Agent' -ForegroundColor DarkGray
    }
    if ($procs.Count -gt 0) {
        foreach ($pr in $procs) {
            # Get-CimInstance already hands back a DateTime; the WMI converter
            # only applies to the Get-WmiObject fallback, and calling it on a
            # DateTime is what produced "up unknown".
            $started = $null
            if ($pr.CreationDate -is [DateTime]) {
                $started = $pr.CreationDate
            } else {
                try { $started = [Management.ManagementDateTimeConverter]::ToDateTime($pr.CreationDate) }
                catch { try { $started = [DateTime]$pr.CreationDate } catch { } }
            }
            $upFor = if ($started) { '{0:N1} h' -f ((Get-Date) - $started).TotalHours } else { 'unknown' }
            $memMB = [math]::Round($pr.WorkingSetSize / 1MB, 1)
            Write-Host ("   Process    : RUNNING  pid {0}  |  up {1}  |  {2} MB" -f `
                        $pr.ProcessId, $upFor, $memMB) -ForegroundColor Green
        }
    } else {
        Write-Host '   Process    : NOT RUNNING' -ForegroundColor Red
        Write-Host '   Start it with:  Start-ScheduledTask -TaskName Douglas042-Agent' -ForegroundColor DarkGray
    }

    # --- Last heartbeat, from our own log ---
    $lastBeat = $null
    if (Test-Path $Script:LogPath) {
        try {
            $lastBeat = Get-Content $Script:LogPath -Tail 400 -EA Stop |
                        Where-Object { $_ -match 'heartbeat|Agent online|hunt' } |
                        Select-Object -Last 1
        } catch { }
    }
    if ($lastBeat) { Write-Host ("   Last log   : {0}" -f $lastBeat.Trim()) -ForegroundColor DarkGray }

    # --- Does the console agree? The only answer that really matters. ---
    try {
        $probe = Invoke-Api -Path '/api/v1/agents/heartbeat' -Body @{ status = 'online' } -TimeoutSec 20
        if ($probe) {
            Write-Host '   Console    : REACHABLE, heartbeat accepted' -ForegroundColor Green
            if ($probe.job) {
                Write-Host ("   Work       : hunt {0} waiting" -f $probe.job.job_id) -ForegroundColor Cyan
            } else {
                Write-Host '   Work       : idle, no hunt queued' -ForegroundColor DarkGray
            }
        }
    } catch {
        Write-Host ("   Console    : UNREACHABLE - {0}" -f $_.Exception.Message) -ForegroundColor Red
    }

    Write-Host $line -ForegroundColor DarkGray
    Write-Host ("   Log        : {0}" -f $Script:LogPath) -ForegroundColor DarkGray
    Write-Host ''
}

function Uninstall-Agent {
    if (-not (Test-Admin)) {
        Write-Log 'Removal needs an elevated PowerShell session.' -Level ERROR
        return
    }
    Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $Script:Root -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log 'Agent removed.' -Level OK
}

# ============================================================================
#  Main loop
# ============================================================================

# ============================================================================
#  Incident response actions
#
#  Short commands run from the console, kept apart from the hunt queue because
#  they are a different kind of work: quick, sometimes destructive, and read
#  line by line by whoever asked for them.
#
#  Each one returns a transcript rather than a status code. Mid-incident "it
#  worked" is not useful; what the host actually said is.
# ============================================================================

$Script:IrQuarantine = Join-Path $env:ProgramData 'Douglas042\quarantine'

function Get-IrProcesses {
    $rows = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Sort-Object -Property WorkingSetSize -Descending | Select-Object -First 200
    $out = New-Object Text.StringBuilder
    [void]$out.AppendLine(('{0,-7} {1,-7} {2,-24} {3}' -f 'PID','PPID','NAME','PATH'))
    foreach ($p in $rows) {
        [void]$out.AppendLine(('{0,-7} {1,-7} {2,-24} {3}' -f `
            $p.ProcessId, $p.ParentProcessId, $p.Name, ($p.ExecutablePath)))
    }
    $out.ToString()
}

function Get-IrConnections {
    $out = New-Object Text.StringBuilder
    [void]$out.AppendLine('== Established and listening ==')
    try {
        $names = @{}
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $names[$_.Id] = $_.ProcessName }
        $conns = Get-NetTCPConnection -ErrorAction Stop |
            Where-Object { $_.State -in 'Established','Listen' } | Select-Object -First 200
        [void]$out.AppendLine(('{0,-22} {1,-22} {2,-12} {3,-7} {4}' -f `
            'LOCAL','REMOTE','STATE','PID','PROCESS'))
        foreach ($c in $conns) {
            [void]$out.AppendLine(('{0,-22} {1,-22} {2,-12} {3,-7} {4}' -f `
                "$($c.LocalAddress):$($c.LocalPort)",
                "$($c.RemoteAddress):$($c.RemotePort)",
                $c.State, $c.OwningProcess, $names[[int]$c.OwningProcess]))
        }
    } catch {
        # Server 2012 R2 has no Get-NetTCPConnection in every configuration.
        [void]$out.AppendLine((netstat -ano | Select-Object -First 200 | Out-String))
    }
    $out.ToString()
}

function Get-IrProcessTree {
    # Not $PID: that is a read-only automatic variable in PowerShell and
    # binding a parameter to it fails at runtime.
    param([int]$TargetPid)
    $p = Get-CimInstance Win32_Process -Filter "ProcessId=$TargetPid" -ErrorAction SilentlyContinue
    if (-not $p) { throw "No process with pid $TargetPid is running." }

    $out = New-Object Text.StringBuilder
    [void]$out.AppendLine("== Process $TargetPid ==")
    [void]$out.AppendLine("Name    : $($p.Name)")
    [void]$out.AppendLine("Path    : $($p.ExecutablePath)")
    [void]$out.AppendLine("Started : $($p.CreationDate)")
    [void]$out.AppendLine("Command : $($p.CommandLine)")
    try {
        $owner = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue
        if ($owner) { [void]$out.AppendLine("User    : $($owner.Domain)\$($owner.User)") }
    } catch { }
    if ($p.ExecutablePath -and (Test-Path $p.ExecutablePath)) {
        try {
            $sig = Get-AuthenticodeSignature $p.ExecutablePath -ErrorAction SilentlyContinue
            [void]$out.AppendLine("Signed  : $($sig.Status) $($sig.SignerCertificate.Subject)")
        } catch { }
        try {
            $h = Get-FileHash $p.ExecutablePath -Algorithm SHA256 -ErrorAction SilentlyContinue
            [void]$out.AppendLine("SHA256  : $($h.Hash)")
        } catch { }
    }

    [void]$out.AppendLine('')
    [void]$out.AppendLine('== Ancestry ==')
    $cur = $p; $depth = 0
    while ($cur -and $depth -lt 12) {
        [void]$out.AppendLine(('{0}{1} ({2})  {3}' -f (' ' * $depth), $cur.ProcessId, $cur.Name,
            ($cur.CommandLine -replace '\s+', ' ')))
        if (-not $cur.ParentProcessId -or $cur.ParentProcessId -eq 0) { break }
        $cur = Get-CimInstance Win32_Process -Filter "ProcessId=$($cur.ParentProcessId)" -ErrorAction SilentlyContinue
        $depth += 2
    }

    [void]$out.AppendLine('')
    [void]$out.AppendLine('== Network connections ==')
    try {
        $c = Get-NetTCPConnection -OwningProcess $TargetPid -ErrorAction SilentlyContinue
        if ($c) {
            foreach ($x in $c) {
                [void]$out.AppendLine("  $($x.LocalAddress):$($x.LocalPort) -> $($x.RemoteAddress):$($x.RemotePort) $($x.State)")
            }
        } else { [void]$out.AppendLine('  none') }
    } catch { [void]$out.AppendLine('  (could not read)') }
    $out.ToString()
}

function Get-IrFileInfo {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "No such file: $Path" }
    $f = Get-Item -LiteralPath $Path -Force -ErrorAction Stop

    $out = New-Object Text.StringBuilder
    [void]$out.AppendLine("== $Path ==")
    [void]$out.AppendLine("Size    : $($f.Length) bytes")
    [void]$out.AppendLine("Created : $($f.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC")
    [void]$out.AppendLine("Modified: $($f.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC")
    [void]$out.AppendLine("Accessed: $($f.LastAccessTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC")
    [void]$out.AppendLine("Attribs : $($f.Attributes)")
    try {
        $h = Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction SilentlyContinue
        [void]$out.AppendLine("SHA256  : $($h.Hash)")
    } catch { }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction SilentlyContinue
        [void]$out.AppendLine("Signed  : $($sig.Status)")
        if ($sig.SignerCertificate) {
            [void]$out.AppendLine("Signer  : $($sig.SignerCertificate.Subject)")
        }
    } catch { }
    # Mark of the web: where it came from, if the browser recorded it.
    try {
        $zone = Get-Content -LiteralPath "$Path`:Zone.Identifier" -ErrorAction SilentlyContinue
        if ($zone) {
            [void]$out.AppendLine('')
            [void]$out.AppendLine('== Downloaded from (mark of the web) ==')
            $zone | ForEach-Object { [void]$out.AppendLine("  $_") }
        }
    } catch { }
    $out.ToString()
}

function Get-IrPersistence {
    $out = New-Object Text.StringBuilder

    [void]$out.AppendLine('== Run keys ==')
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($k in $keys) {
        if (-not (Test-Path $k)) { continue }
        $props = Get-ItemProperty $k -ErrorAction SilentlyContinue
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            [void]$out.AppendLine("  [$k] $($p.Name) = $($p.Value)")
        }
    }

    [void]$out.AppendLine('')
    [void]$out.AppendLine('== Non-Microsoft services ==')
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.PathName -and $_.PathName -notmatch 'system32|SysWOW64' } |
        Select-Object -First 60 | ForEach-Object {
            [void]$out.AppendLine("  $($_.Name) [$($_.State)/$($_.StartMode)] $($_.PathName)")
        }

    [void]$out.AppendLine('')
    [void]$out.AppendLine('== Scheduled tasks (non-Microsoft) ==')
    try {
        Get-ScheduledTask -ErrorAction Stop |
            Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
            Select-Object -First 60 | ForEach-Object {
                $act = ($_.Actions | ForEach-Object { $_.Execute }) -join '; '
                [void]$out.AppendLine("  $($_.TaskPath)$($_.TaskName) [$($_.State)] $act")
            }
    } catch {
        [void]$out.AppendLine('  (Get-ScheduledTask unavailable on this host)')
    }

    [void]$out.AppendLine('')
    [void]$out.AppendLine('== WMI event subscriptions ==')
    try {
        $f = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
        if ($f) { $f | ForEach-Object { [void]$out.AppendLine("  filter: $($_.Name) :: $($_.Query)") } }
        else { [void]$out.AppendLine('  none') }
    } catch { [void]$out.AppendLine('  (could not read)') }

    $out.ToString()
}

function Invoke-IrKill {
    param([int]$TargetPid)
    $p = Get-CimInstance Win32_Process -Filter "ProcessId=$TargetPid" -ErrorAction SilentlyContinue
    if (-not $p) { throw "No process with pid $TargetPid is running." }

    # Killing a core Windows process takes the host down rather than the
    # intrusion. Refused rather than warned about: nobody reads a warning at
    # the moment this gets used.
    $protected = @('system','smss.exe','csrss.exe','wininit.exe','winlogon.exe',
                   'services.exe','lsass.exe')
    if ($protected -contains $p.Name.ToLower()) {
        throw "Refusing to kill $($p.Name) (pid $TargetPid): stopping it takes the host down."
    }

    $out = New-Object Text.StringBuilder
    [void]$out.AppendLine("Target : pid $TargetPid  ($($p.Name))")
    [void]$out.AppendLine("Path   : $($p.ExecutablePath)")
    [void]$out.AppendLine("Command: $($p.CommandLine)")
    [void]$out.AppendLine('')

    Stop-Process -Id $TargetPid -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $still = Get-Process -Id $TargetPid -ErrorAction SilentlyContinue
    if ($still) {
        [void]$out.AppendLine('RESULT : still running. It may be protected or unresponsive.')
        throw $out.ToString()
    }
    [void]$out.AppendLine('RESULT : stopped.')
    [void]$out.AppendLine('')
    [void]$out.AppendLine('If it had persistence it will come back — check persistence next.')
    $out.ToString()
}

function Invoke-IrQuarantine {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "No such file: $Path" }
    if (-not (Test-Path $Script:IrQuarantine)) {
        $null = New-Item $Script:IrQuarantine -ItemType Directory -Force
    }

    $out = New-Object Text.StringBuilder
    [void]$out.AppendLine("Source : $Path")
    try {
        $h = Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction SilentlyContinue
        [void]$out.AppendLine("SHA256 : $($h.Hash)")
    } catch { }

    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $dest = Join-Path $Script:IrQuarantine ("{0}_{1}" -f $stamp, (Split-Path $Path -Leaf))

    # Moved rather than deleted: the call may have been wrong, and whoever does
    # the analysis needs the sample.
    Move-Item -LiteralPath $Path -Destination $dest -Force -ErrorAction Stop
    Set-Content -LiteralPath "$dest.origin" -Value $Path -ErrorAction SilentlyContinue
    try {
        # Deny execution to everyone; the file stays readable to an admin who
        # wants to analyse it.
        $acl = Get-Acl $dest
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            'BUILTIN\Administrators', 'FullControl', 'Allow')
        $acl.SetAccessRule($rule)
        Set-Acl -Path $dest -AclObject $acl
    } catch { }

    [void]$out.AppendLine("Moved  : $dest")
    [void]$out.AppendLine('RESULT : quarantined, access restricted to administrators, original path recorded.')
    $out.ToString()
}

function Invoke-IrDisableAccount {
    param([string]$User)
    $name = ($User -split '\\')[-1]
    $acct = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND Name='$name'" -ErrorAction SilentlyContinue
    if (-not $acct) { throw "No local account named $name." }

    $out = New-Object Text.StringBuilder
    [void]$out.AppendLine("Account: $name")
    [void]$out.AppendLine("SID    : $($acct.SID)")

    try {
        Disable-LocalUser -Name $name -ErrorAction Stop
        [void]$out.AppendLine('  disabled')
    } catch {
        $r = net user "$name" /active:no 2>&1
        [void]$out.AppendLine("  $r")
    }

    [void]$out.AppendLine('')
    [void]$out.AppendLine('Existing sessions are not closed by this. Current logons:')
    try {
        $sessions = quser 2>$null
        if ($sessions) { $sessions | ForEach-Object { [void]$out.AppendLine("  $_") } }
        else { [void]$out.AppendLine('  none visible') }
    } catch { [void]$out.AppendLine('  (quser unavailable)') }

    [void]$out.AppendLine('')
    [void]$out.AppendLine('RESULT : disabled, not deleted — the account and its history stay for the investigation.')
    $out.ToString()
}

function Invoke-IrStopService {
    param([string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { throw "No service named $Name." }

    $out = New-Object Text.StringBuilder
    [void]$out.AppendLine("Service: $Name ($($svc.DisplayName))")
    [void]$out.AppendLine("Before : $($svc.Status)")

    Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    # Disabled as well as stopped: stopping an auto-start service buys you
    # until the next reboot and no longer.
    Set-Service -Name $Name -StartupType Disabled -ErrorAction SilentlyContinue

    Start-Sleep -Seconds 2
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    [void]$out.AppendLine("After  : $($svc.Status)")
    [void]$out.AppendLine('')
    [void]$out.AppendLine('RESULT : stopped and set to disabled.')
    $out.ToString()
}

function Get-IrConsoleHost {
    $cfg = Get-Config
    if (-not $cfg -or -not $cfg.server) { return $null }
    try { return ([Uri]$cfg.server).Host } catch { return $null }
}

function Invoke-IrIsolate {
    $consoleHost = Get-IrConsoleHost
    if (-not $consoleHost) {
        throw 'Refusing to isolate: the console address is unknown, so this host would have no way back.'
    }
    $ip = $consoleHost
    try {
        $resolved = [Net.Dns]::GetHostAddresses($consoleHost) |
            Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
        if ($resolved) { $ip = $resolved.IPAddressToString }
    } catch { }

    $out = New-Object Text.StringBuilder
    [void]$out.AppendLine("Console: $consoleHost ($ip) — this stays reachable.")
    [void]$out.AppendLine('')

    # Allow rules first, then the block: applied the other way round, the agent
    # loses the console before it can add the exception.
    netsh advfirewall firewall delete rule name="Douglas042-Console-Out" 2>&1 | Out-Null
    netsh advfirewall firewall delete rule name="Douglas042-Console-In" 2>&1 | Out-Null
    netsh advfirewall firewall add rule name="Douglas042-Console-Out" dir=out action=allow remoteip=$ip 2>&1 | Out-Null
    netsh advfirewall firewall add rule name="Douglas042-Console-In" dir=in action=allow remoteip=$ip 2>&1 | Out-Null
    [void]$out.AppendLine('Console exception added.')

    $r = netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound 2>&1
    [void]$out.AppendLine("Firewall: $r")

    [void]$out.AppendLine('')
    [void]$out.AppendLine('Proving the console is still reachable:')
    try {
        $cfg = Get-Config
        $null = Invoke-WebRequest -Uri "$($cfg.server)/health" -UseBasicParsing -TimeoutSec 10
        [void]$out.AppendLine('  OK — the agent can still reach the console, so this can be released from there.')
    } catch {
        [void]$out.AppendLine('  WARNING — the console did not answer. Releasing may need local access.')
    }
    [void]$out.AppendLine('')
    [void]$out.AppendLine('RESULT : isolated. Everything except the console is blocked in both directions.')
    $out.ToString()
}

function Invoke-IrRelease {
    $out = New-Object Text.StringBuilder
    $r = netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound 2>&1
    [void]$out.AppendLine("Firewall: $r")
    netsh advfirewall firewall delete rule name="Douglas042-Console-Out" 2>&1 | Out-Null
    netsh advfirewall firewall delete rule name="Douglas042-Console-In" 2>&1 | Out-Null
    [void]$out.AppendLine('Console exception rules removed.')
    [void]$out.AppendLine('')
    [void]$out.AppendLine('RESULT : released. The firewall policy is back to the Windows default')
    [void]$out.AppendLine('         (inbound blocked, outbound allowed). If this host had a custom')
    [void]$out.AppendLine('         policy before isolation, re-apply it — that is not recorded here.')
    $out.ToString()
}

function Invoke-IrAction {
    param([string]$Id, [string]$Action, [string]$Target)

    Write-Log "Response action: $Action$(if ($Target) { " ($Target)" })" -Level OK
    $started = Get-Date
    $output = ''
    $err = ''
    $code = 0

    try {
        switch ($Action) {
            'processes'       { $output = Get-IrProcesses }
            'connections'     { $output = Get-IrConnections }
            'process_tree'    { $output = Get-IrProcessTree -TargetPid ([int]$Target) }
            'file_info'       { $output = Get-IrFileInfo -Path $Target }
            'persistence'     { $output = Get-IrPersistence }
            'kill_process'    { $output = Invoke-IrKill -TargetPid ([int]$Target) }
            'quarantine_file' { $output = Invoke-IrQuarantine -Path $Target }
            'disable_account' { $output = Invoke-IrDisableAccount -User $Target }
            'stop_service'    { $output = Invoke-IrStopService -Name $Target }
            'isolate'         { $output = Invoke-IrIsolate }
            'release'         { $output = Invoke-IrRelease }
            default           { throw "Unknown action: $Action" }
        }
    } catch {
        # The transcript is kept either way: a failed containment attempt is
        # exactly the thing somebody needs to read.
        $err = $_.Exception.Message
        if (-not $output) { $output = $err }
        $code = 1
    }

    $elapsed = [int]((Get-Date) - $started).TotalSeconds
    try {
        $null = Invoke-Api -Path "/api/v1/response/agent/$Id/result" -Body @{
            output           = [string]$output
            error            = [string]$err
            exit_code        = $code
            duration_seconds = $elapsed
        } -TimeoutSec 60
    } catch {
        Write-Log "Could not report the action result: $($_.Exception.Message)" -Level WARN
    }

    if ($code -eq 0) { Write-Log "Response action finished: $Action" -Level OK }
    else { Write-Log "Response action failed: $Action — $err" -Level WARN }
}

function Invoke-IrPoll {
    try {
        $resp = Invoke-Api -Path '/api/v1/response/agent/next' -Method GET -TimeoutSec 20
        if ($resp -and $resp.action -and $resp.action.id) {
            Invoke-IrAction -Id $resp.action.id -Action $resp.action.action -Target $resp.action.target
        }
    } catch {
        # An older console has no such endpoint; that is not an error worth
        # logging every heartbeat.
    }
}

function Start-AgentLoop {
    $cfg = Get-Config
    if (-not $cfg) {
        Write-Log 'This host is not enrolled. Run with -Server and -Token first.' -Level ERROR
        return
    }
    Write-Log "Agent online. Console: $($cfg.server)" -Level OK

    $interval = $HeartbeatSeconds
    $backoff = 0
    $beats = 0

    # Apply anything staged by a previous run before settling into the loop.
    if (Update-Self -ServerUrl $cfg.server) { return }

    while ($true) {
        try {
            $resp = Invoke-Api -Path '/api/v1/agents/heartbeat' -Body @{
                status = 'online'
            } -TimeoutSec 30

            $backoff = 0
            if ($resp.heartbeat_seconds) { $interval = [int]$resp.heartbeat_seconds }

            if ($resp.job) {
                Invoke-Hunt -Job $resp.job
            }

            # Response actions ride the same interval as the heartbeat. Checked
            # after the hunt branch so a queued action does not wait behind a
            # sweep, and before the sleep so containment is not delayed by a
            # full heartbeat.
            Invoke-IrPoll

            # Check for a newer agent occasionally rather than every beat: the
            # request is small but so is the value of asking twice a minute.
            $beats++
            if ($beats % 30 -eq 0) {
                if (Update-Self -ServerUrl $cfg.server) { return }
            }
        } catch {
            $backoff = [Math]::Min($backoff + 1, 6)
            $wait = [Math]::Pow(2, $backoff)
            Write-Log "Console unreachable ($($_.Exception.Message)). Retrying in ${wait}s." -Level WARN
            Start-Sleep -Seconds $wait
            continue
        }

        if ($Once) { break }

        # Response actions are polled far more often than the heartbeat. They
        # are typed by a person watching for the answer, and waiting a full
        # heartbeat made every action feel broken — a spinner for twenty
        # seconds before anything happens. The heartbeat stays slow because it
        # carries real payload; this is one small GET.
        $waited = 0
        while ($waited -lt $interval) {
            Start-Sleep -Seconds $Script:IrPollSeconds
            $waited += $Script:IrPollSeconds
            Invoke-IrPoll
        }
    }
}

# ============================================================================
#  Entry point
# ============================================================================

if ($Status)    { Show-AgentStatus; return }
if ($Uninstall) { Uninstall-Agent; return }

if ($Install) {
    if (-not $Server -or -not $Token) {
        Write-Log 'Installation needs both -Server and -Token.' -Level ERROR
        return
    }
    if (Install-Agent -ServerUrl $Server -EnrollToken $Token) { return }
    return
}

if ($Server -and $Token -and -not (Get-Config)) {
    Register-Agent -ServerUrl $Server -EnrollToken $Token | Out-Null
    Get-Scanner -ServerUrl $Server | Out-Null
}

Start-AgentLoop
