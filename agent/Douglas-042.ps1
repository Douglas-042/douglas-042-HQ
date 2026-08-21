<#
.SYNOPSIS
    Douglas-042 v2 - Incident Response & Threat Hunting Collector

.DESCRIPTION
    Tek script, tek calistirma, otomatik toplama. Domain ortaminda
    Client / Member Server / Domain Controller uzerinde rol tespiti yapip
    ilgili modulleri calistirir.

    Cikti: klasor + artefakt basina CSV/JSON + FINDINGS.csv + REPORT.html

.PARAMETER Days
    Event log ve dosya sistemi icin geriye donuk gun sayisi. Varsayilan 14.

.PARAMETER OutputPath
    Cikti kok dizini. Varsayilan: script dizini altinda .\Output

.PARAMETER Quick
    Hizli triage modu. Faz 3 (dosya tarama/hash) atlanir. ~1-2 dakika.

.PARAMETER CollectRaw
    Ham adli artefakt kopyalama (MFT, registry hive, evtx, SRUM, Amcache).
    VSS snapshot uzerinden calisir. Birkac GB olabilir.

.PARAMETER NoResolve
    Reverse DNS ve dis ag sorgularini kapatir. (OPSEC / izole ortam)

.PARAMETER MaxEventsPerChannel
    Kanal basina maksimum event sayisi. Varsayilan 100000.

.PARAMETER IocFile
    Satir basina bir IOC iceren dosya (hash / IP / domain / dosya adi).
    Toplanan tum veriyle eslestirilir.

.EXAMPLE
    .\Douglas-042.ps1
    .\Douglas-042.ps1 -Days 30 -CollectRaw
    .\Douglas-042.ps1 -Quick

.NOTES
    Version : 2.0.0-alpha (iskelet)
    Author  : OnBT / Behind24 Blue Team
    Requires: Administrator. PS 5.1+ onerilir, PS 4.0 fallback destegi var.

    UYARI: Bu script calistigi anda dosya erisim zamanlarini ve Prefetch'i
    etkiler. Bellek/disk imaji alinacaksa ONCE onu alin.
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 365)]
    [int]$Days = 14,

    [string]$OutputPath,

    [switch]$Quick,

    [switch]$CollectRaw,

    [switch]$NoResolve,

    [ValidateRange(1000, 2000000)]
    [int]$MaxEventsPerChannel = 100000,

    [string]$IocFile,

    [string[]]$ComputerName,

    [System.Management.Automation.PSCredential]$Credential,

    [ValidateRange(1, 100)]
    [int]$ThrottleLimit = 16,

    [string]$ProgressFile,

    [string]$SigmaFile,

    [string]$YaraFile,

    [string]$CustomRuleFile,

    # Findings below this are still collected but not reported. Useful on a
    # triage sweep where INFO and LOW would bury what matters.
    [ValidateSet('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')]
    [string]$MinSeverity = 'INFO',

    # Overrides the role detected from the machine. A standalone web server
    # still needs the webshell hunt.
    [ValidateSet('auto', 'server', 'workstation', 'webserver', 'dc')]
    [string]$Profile = 'auto',

    # Rule ids an operator switched off in the console. A file of one id per
    # line, fetched by the agent before the hunt starts. The disabled set is
    # passed rather than the enabled one on purpose: if this file is missing or
    # unreadable the collector runs everything, which is the safe direction to
    # fail in. The reverse would let a network problem quietly switch off the
    # entire detection set and still report a clean host.
    [string]$DisabledRuleFile,

    # Findings are written here one JSON object per line as they are produced,
    # so the agent can forward them while the sweep is still running. The
    # bundle written at the end stays authoritative; this is a tap on the same
    # water, not a second source of truth.
    [string]$LiveFindingFile
)

# ============================================================================
#  GLOBAL DURUM
# ============================================================================

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'   # Write-Progress cok yavaslatiyor
$WarningPreference     = 'SilentlyContinue'

# --- KULTUR SABITLEME ---
# TR locale'de ondalik ayraci virguldur: 12.5 -> "12,5". Export-Csv degerleri
# gecerli kulturle string'e cevirir, bu da virgul-ayracli CSV'yi ve sayisal
# analizi bozar. Ayrica tarih formati da degisir. Invariant'a sabitliyoruz.
$Script:OriginalCulture = [Threading.Thread]::CurrentThread.CurrentCulture
try {
    [Threading.Thread]::CurrentThread.CurrentCulture   = [Globalization.CultureInfo]::InvariantCulture
    [Threading.Thread]::CurrentThread.CurrentUICulture = [Globalization.CultureInfo]::InvariantCulture
} catch { }

$Script:Version   = '2.0.0-alpha'
$Script:StartTime = Get-Date
$Script:Ctx       = @{}            # host / calisma baglami
$Script:Caps      = @{}            # yetenek matrisi
$Script:Findings  = New-Object System.Collections.ArrayList
$Script:Errors    = New-Object System.Collections.ArrayList
$Script:Manifest  = New-Object System.Collections.ArrayList
$Script:Timeline  = New-Object System.Collections.ArrayList
$Script:HashCache = @{}
$Script:SigCache  = @{}
$Script:Iocs      = @{}

# Suspicious path regex - malware'in %95'i bu dizinlerden calisir
$Script:SuspiciousPathRegex = '(?i)\\(Temp|Tmp|AppData|ProgramData|Users\\Public|' +
                              'Public|PerfLogs|\$Recycle\.Bin|Windows\\Tasks|' +
                              'Windows\\Debug|Windows\\Fonts|Windows\\addins|' +
                              'Windows\\Media|Recycler|Intel|AMD|Downloads)\\'

# Hedefli dosya tarama dizinleri - C:\ recurse ASLA
# Directories worth walking on the system drive. Deliberately targeted:
# a full C:\ -Recurse takes hours on a file server, wakes up EDR, and disturbs
# the access times of everything it touches. These paths hold the large
# majority of real findings.
$Script:SystemScanPaths = @(
    "$env:SystemRoot\Temp"
    "$env:SystemRoot\Tasks"
    "$env:SystemRoot\Debug"
    "$env:SystemRoot\System32\Tasks"
    "$env:ProgramData"
    'C:\Users'
    'C:\PerfLogs'
    'C:\inetpub'
    'C:\Temp'
    'C:\Tmp'
)

# Applied to every additional fixed drive. A second volume usually carries data,
# web roots or shares rather than a Windows install, so the same shape of
# hiding place appears under different names.
$Script:ScanPaths = @()
$Script:ScannedVolumes = @()
$Script:ExtraVolumePaths = 0

$Script:VolumeScanPatterns = @(
    'Temp', 'Tmp', 'Users', 'inetpub', 'wwwroot', 'www', 'web', 'sites',
    'Shares', 'Share', 'Public', 'Data', 'Backup', 'Backups', 'Apps',
    'Scripts', 'Tools', 'Upload', 'Uploads', 'FTP', 'Transfer', 'Exchange'
)

function Get-DScanPaths {
    <#
        Build the scan list: the targeted system-drive directories plus the
        same shapes on every other fixed volume.

        Data lives on D: far more often than people remember, and a webshell
        under D:\wwwroot is invisible to a C:-only sweep. Removable and network
        drives are skipped: a USB stick is not this host's story, and walking a
        mapped share turns one host's collection into a file server scan.
    #>
    $paths = New-Object System.Collections.ArrayList
    foreach ($p in $Script:SystemScanPaths) {
        if (Test-Path $p) { $null = $paths.Add($p) }
    }

    $sysDrive = ($env:SystemDrive).TrimEnd('\')
    $volumes = @()
    try {
        # DriveType 3 is a fixed local disk.
        $volumes = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop |
                     Select-Object -ExpandProperty DeviceID)
    } catch {
        try {
            $volumes = @(Get-WmiObject Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop |
                         Select-Object -ExpandProperty DeviceID)
        } catch { $volumes = @() }
    }

    $extra = 0
    foreach ($vol in $volumes) {
        if ($vol -eq $sysDrive) { continue }
        foreach ($name in $Script:VolumeScanPatterns) {
            $candidate = Join-Path "$vol\" $name
            if (Test-Path $candidate) {
                $null = $paths.Add($candidate)
                $extra++
            }
        }
        # A second volume's root often holds loose files; include it shallowly
        # by adding the root itself only when it has few top-level entries.
        try {
            $topLevel = @(Get-ChildItem "$vol\" -File -Force -ErrorAction Stop)
            if ($topLevel.Count -gt 0 -and $topLevel.Count -le 200) {
                $null = $paths.Add("$vol\")
                $extra++
            }
        } catch { }
    }

    $Script:ExtraVolumePaths = $extra
    $Script:ScannedVolumes = @($volumes)
    return @($paths | Select-Object -Unique)
}

$Script:InterestingExt = @('.exe', '.dll', '.ps1', '.psm1', '.bat', '.cmd',
                           '.vbs', '.js', '.jse', '.vbe', '.wsf', '.hta',
                           '.scr', '.jar', '.aspx', '.ashx', '.asmx', '.php',
                           '.jsp', '.sys', '.msi', '.lnk')

# ============================================================================
#  BANNER
# ============================================================================

function Show-Banner {
    $b = @'

    ____                    __                 ____  __ __ ___
   / __ \____  __  ______ _/ /___ ______      / __ \/ // /|__ \
  / / / / __ \/ / / / __ `/ / __ `/ ___/_____/ / / / // /___/ /
 / /_/ / /_/ / /_/ / /_/ / / /_/ (__  )_____/ /_/ /__  __/ __/
/_____/\____/\__,_/\__, /_/\__,_/____/      \____/  /_/ /____/
                  /____/

        +---- DEFENSE BY OFFENSE  |  BLUE TEAM ----+
          Incident Response & Threat Hunting
'@
    Write-Host $b -ForegroundColor Cyan
    Write-Host ("          v{0}   OnBT / Behind24" -f $Script:Version) -ForegroundColor DarkCyan
    Write-Host ''
}

# ============================================================================
#  LOGLAMA
# ============================================================================

function Write-DLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR', 'CRIT', 'STEP', 'DEBUG')]
        [string]$Level = 'INFO',
        [switch]$NoConsole
    )

    $ts  = (Get-Date).ToString('HH:mm:ss')
    $utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

    if (-not $NoConsole) {
        $color = switch ($Level) {
            'OK'    { 'Green' }
            'WARN'  { 'Yellow' }
            'ERROR' { 'Red' }
            'CRIT'  { 'Magenta' }
            'STEP'  { 'Cyan' }
            'DEBUG' { 'DarkGray' }
            default { 'Gray' }
        }
        $tag = switch ($Level) {
            'OK'    { '[+]' }
            'WARN'  { '[!]' }
            'ERROR' { '[x]' }
            'CRIT'  { '[!!]' }
            'STEP'  { '[>]' }
            'DEBUG' { '[.]' }
            default { '[*]' }
        }
        Write-Host ("{0} {1} {2}" -f $ts, $tag, $Message) -ForegroundColor $color
    }

    if ($Script:Ctx.LogFile) {
        try {
            "$utc [$Level] $Message" |
                Out-File -FilePath $Script:Ctx.LogFile -Append -Encoding UTF8
        } catch { }
    }
}

# ============================================================================
#  ILERLEME BILDIRIMI  (-ProgressFile)
# ============================================================================

# Modul basina agirlik degil, tamamlanan modul orani kullaniliyor. Fazlarin
# gorece maliyeti farkli oldugu icin faz bazinda bir taban yuzde veriyoruz;
# boylece Faz 2 uzun surse bile cubuk geri gitmiyor.
$Script:PhaseFloor = @{ 0 = 0; 1 = 8; 2 = 35; 3 = 75; 4 = 92 }
$Script:PhaseCeil  = @{ 0 = 8; 1 = 35; 2 = 75; 3 = 92; 4 = 99 }
$Script:PhaseLabel = @{
    0 = 'Profiling host'
    1 = 'Hunting'
    2 = 'Sweeping event logs'
    3 = 'Scanning artifacts'
    4 = 'Collecting evidence'
}
$Script:CurrentPhase = 0
$Script:PhaseModuleTotal = 0
$Script:PhaseModuleDone = 0

function Write-DProgress {
    param(
        [string]$Detail = '', [switch]$Final,
        [string]$Module = '', [string]$Status = '',
        [int]$DurationMs = 0, [int]$Findings = -1, [int]$Rows = -1, [int]$Errors = 0
    )

    if (-not $Script:ProgressPath) { return }

    $ph = $Script:CurrentPhase
    $floor = $Script:PhaseFloor[$ph]
    $ceil  = $Script:PhaseCeil[$ph]
    if ($null -eq $floor) { $floor = 0 }
    if ($null -eq $ceil)  { $ceil = 99 }

    $frac = 0.0
    if ($Script:PhaseModuleTotal -gt 0) {
        $frac = $Script:PhaseModuleDone / $Script:PhaseModuleTotal
    }
    $pct = if ($Final) { 100 } else { $floor + (($ceil - $floor) * $frac) }
    # The eligible count and the loop can disagree — a module filtered out by
    # scope still runs the counter — so done can exceed total and push this
    # past 100. The console rejects anything outside 0..100, which turned a
    # cosmetic miscount into progress reporting failing for the whole hunt.
    if ($pct -lt 0)   { $pct = 0 }
    if ($pct -gt 100) { $pct = 100 }

    $payload = [ordered]@{
        percent = [math]::Round($pct, 1)
        phase   = $Script:PhaseLabel[$ph]
        detail  = $Detail
        done    = $Script:PhaseModuleDone
        total   = $Script:PhaseModuleTotal
        ts      = (Get-Date).ToUniversalTime().ToString('o')
    }
    if ($Module) {
        $payload['module']   = $Module
        $payload['status']   = $Status
        $payload['ms']       = $DurationMs
        $payload['findings'] = $Findings
        $payload['rows']     = $Rows
        $payload['errors']   = $Errors
    }
    try {
        ($payload | ConvertTo-Json -Compress) |
            Out-File -FilePath $Script:ProgressPath -Append -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch { }
}

# ============================================================================
#  ONKOSUL KONTROLLERI
# ============================================================================

function Test-DAdmin {
    try {
        $id        = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($id)
        # SID tabanli kontrol - locale bagimsiz (TR Windows'ta "Yoneticiler")
        $adminSid  = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')

        $isAdmin  = $principal.IsInRole($adminSid)
        $isSystem = ($id.User.Value -eq 'S-1-5-18')

        return [PSCustomObject]@{
            IsAdmin   = ($isAdmin -or $isSystem)
            IsSystem  = $isSystem
            User      = $id.Name
            UserSid   = $id.User.Value
        }
    } catch {
        return [PSCustomObject]@{
            IsAdmin = $false; IsSystem = $false; User = 'UNKNOWN'; UserSid = $null
        }
    }
}

function Get-DCapabilities {
    <#
        Yetenek matrisi. Moduller "if (Get-Command X)" serpistirmek yerine
        buna bakar. 2012 R2 / PS4 fallback kararlari burada verilir.
    #>
    $c = @{}

    $c.PSVersion      = $PSVersionTable.PSVersion
    $c.PSMajor        = $PSVersionTable.PSVersion.Major
    $c.IsPS5Plus      = ($PSVersionTable.PSVersion.Major -ge 5)
    $c.IsPS7Plus      = ($PSVersionTable.PSVersion.Major -ge 7)
    $c.IsCoreEdition  = ($PSVersionTable.PSEdition -eq 'Core')

    # Cmdlet varligi
    $cmds = @{
        LocalAccounts  = 'Get-LocalUser'
        ScheduledTasks = 'Get-ScheduledTask'
        Defender       = 'Get-MpComputerStatus'
        NetTCP         = 'Get-NetTCPConnection'
        NetAdapter     = 'Get-NetAdapter'
        SmbShare       = 'Get-SmbShare'
        Firewall       = 'Get-NetFirewallProfile'
        DnsCache       = 'Get-DnsClientCache'
        Cim            = 'Get-CimInstance'
        Wmi            = 'Get-WmiObject'
        WinEvent       = 'Get-WinEvent'
        BitsTransfer   = 'Get-BitsTransfer'
        FileHash       = 'Get-FileHash'
        ADModule       = 'Get-ADDomain'
        AppxPackage    = 'Get-AppxPackage'
    }
    foreach ($k in $cmds.Keys) {
        $c[$k] = [bool](Get-Command $cmds[$k] -ErrorAction SilentlyContinue)
    }

    # Paralel isleme yetenegi
    $c.ParallelForEach = $c.IsPS7Plus
    $c.Runspaces       = $true   # PS3+ her yerde var

    return $c
}

function Get-DHostContext {
    param([object]$AdminInfo)

    $ctx = @{}

    $ctx.ComputerName = $env:COMPUTERNAME
    $ctx.UserDomain   = $env:USERDOMAIN
    $ctx.Operator     = $AdminInfo.User
    $ctx.OperatorSid  = $AdminInfo.UserSid
    $ctx.RunAsSystem  = $AdminInfo.IsSystem

    # --- Bilgisayar sistemi / rol ---
    $cs = $null
    try {
        if ($Script:Caps.Cim) { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop }
        else                  { $cs = Get-WmiObject  Win32_ComputerSystem -ErrorAction Stop }
    } catch { }

    $roleId = if ($cs) { [int]$cs.DomainRole } else { -1 }
    $ctx.DomainRoleId = $roleId
    $ctx.DomainRole   = switch ($roleId) {
        0 { 'Standalone Workstation' }
        1 { 'Member Workstation' }
        2 { 'Standalone Server' }
        3 { 'Member Server' }
        4 { 'Backup Domain Controller' }
        5 { 'Primary Domain Controller' }
        default { 'Unknown' }
    }
    $ctx.IsDomainController = ($roleId -in 4, 5)
    $ctx.IsServer           = ($roleId -in 2, 3, 4, 5)
    $ctx.IsWorkstation      = ($roleId -in 0, 1)

    # An explicit profile wins over what the machine reports. A standalone web
    # server reads as "Standalone Server"; the operator asking for the web
    # profile wants the webshell hunt run whatever the domain role says.
    switch ($Profile) {
        'dc'          { $ctx.IsDomainController = $true; $ctx.IsServer = $true
                        $ctx.IsWorkstation = $false }
        'server'      { $ctx.IsServer = $true; $ctx.IsWorkstation = $false }
        'webserver'   { $ctx.IsServer = $true; $ctx.IsWorkstation = $false }
        'workstation' { $ctx.IsWorkstation = $true; $ctx.IsServer = $false
                        $ctx.IsDomainController = $false }
    }
    $ctx.Profile = $Profile
    $ctx.IsDomainJoined     = ($cs -and $cs.PartOfDomain)
    $ctx.Domain             = if ($cs) { $cs.Domain } else { $null }
    $ctx.Manufacturer       = if ($cs) { $cs.Manufacturer } else { $null }
    $ctx.Model              = if ($cs) { $cs.Model } else { $null }
    $ctx.TotalRAMGB         = if ($cs -and $cs.TotalPhysicalMemory) {
                                  [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
                              } else { $null }

    # --- Isletim sistemi ---
    $os = $null
    try {
        if ($Script:Caps.Cim) { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop }
        else                  { $os = Get-WmiObject  Win32_OperatingSystem -ErrorAction Stop }
    } catch { }

    if ($os) {
        $ctx.OSCaption      = $os.Caption
        $ctx.OSVersion      = $os.Version
        $ctx.OSBuild        = $os.BuildNumber
        $ctx.OSArchitecture = $os.OSArchitecture
        $ctx.InstallDate    = ConvertTo-DDateTime $os.InstallDate
        $ctx.LastBootUtc    = (ConvertTo-DDateTime $os.LastBootUpTime)
        if ($ctx.LastBootUtc) {
            $ctx.UptimeDays = [math]::Round(((Get-Date) - $ctx.LastBootUtc).TotalDays, 2)
        }
    }

    # --- Zaman dilimi (timeline korelasyonu icin sart) ---
    try {
        $tz = Get-CimInstance Win32_TimeZone -ErrorAction SilentlyContinue
        $ctx.TimeZone       = if ($tz) { $tz.Caption } else { [TimeZoneInfo]::Local.DisplayName }
        $ctx.UtcOffsetHours = [math]::Round(
            [TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalHours, 2)
    } catch { }

    # --- IP adresleri (locale bagimsiz - ipconfig parse ETME) ---
    $ips = @()
    try {
        if ($Script:Caps.NetAdapter) {
            $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
                   Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
                   Select-Object -ExpandProperty IPAddress
        } else {
            $ips = ([System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME) |
                    Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                    ForEach-Object { $_.IPAddressToString }) |
                   Where-Object { $_ -notmatch '^(127\.|169\.254\.)' }
        }
    } catch { }
    $ctx.IPAddresses = @($ips)
    $ctx.PrimaryIP   = if ($ips) { $ips[0] } else { 'N/A' }

    # --- Zaman penceresi ---
    $ctx.WindowDays     = $Days
    $ctx.WindowStart    = (Get-Date).AddDays(-$Days)
    $ctx.WindowStartUtc = $ctx.WindowStart.ToUniversalTime()

    return $ctx
}

function ConvertTo-DDateTime {
    <# WMI/CIM tarih alanlarini guvenle DateTime'a cevirir #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [DateTime]) { return $Value }

    # CIM_DATETIME formati: yyyyMMddHHmmss.ffffff+UUU
    # NOT: Get-CimInstance zaten DateTime dondurur; bu yol sadece
    # Get-WmiObject fallback'inde devreye girer.
    # System.Management assembly'si PS7 Core'da yuklu olmayabilir.
    try {
        return [Management.ManagementDateTimeConverter]::ToDateTime($Value)
    } catch {
        try {
            if ($Value -match '^(\d{14})') {
                return [DateTime]::ParseExact($Matches[1], 'yyyyMMddHHmmss',
                       [Globalization.CultureInfo]::InvariantCulture)
            }
            return [DateTime]::Parse($Value, [Globalization.CultureInfo]::InvariantCulture)
        } catch { return $null }
    }
}

function ConvertTo-DUtcString {
    param($DateTime)
    if ($null -eq $DateTime) { return $null }
    try { return ([DateTime]$DateTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    catch { return $null }
}

# ============================================================================
#  CIKTI ALTYAPISI
# ============================================================================

function Initialize-DOutput {
    param([string]$Root)

    if (-not $Root) {
        $base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
        $Root = Join-Path $base 'Output'
    }

    $stamp  = $Script:StartTime.ToString('yyyyMMdd_HHmmss')
    $folder = 'DOUGLAS_{0}_{1}' -f $env:COMPUTERNAME, $stamp
    $full   = Join-Path $Root $folder

    $null = New-Item -Path $full -ItemType Directory -Force -ErrorAction Stop
    foreach ($sub in 'artifacts', 'events', 'raw', 'logs') {
        $null = New-Item -Path (Join-Path $full $sub) -ItemType Directory -Force -ErrorAction SilentlyContinue
    }

    return $full
}

function Export-DArtifact {
    <#
        Tek cikis noktasi. CSV her zaman, JSON istege bagli.
        Manifest'e satir sayisi + SHA256 kaydeder.
        DIKKAT: Format-Table/Format-List ASLA kullanilmaz - obje kaybolur.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter()][AllowNull()]$Data,
        [ValidateSet('artifacts', 'events', 'raw', 'logs')]
        [string]$SubDir = 'artifacts',
        [switch]$AsJson,
        [switch]$JsonOnly,
        [int]$JsonDepth = 6
    )

    $rows = @($Data | Where-Object { $null -ne $_ })
    $dir  = Join-Path $Script:Ctx.OutputDir $SubDir

    $csvPath  = Join-Path $dir "$Name.csv"
    $jsonPath = Join-Path $dir "$Name.json"
    $written  = @()

    try {
        if (-not $JsonOnly) {
            if ($rows.Count -gt 0) {
                $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
            } else {
                # Bos artefakt da kayit birakmali: "toplanmadi" ile "bos" ayri seyler
                '# NO DATA' | Out-File -FilePath $csvPath -Encoding UTF8 -Force
            }
            $written += $csvPath
        }

        if ($AsJson -or $JsonOnly) {
            $json = if ($rows.Count -gt 0) {
                $rows | ConvertTo-Json -Depth $JsonDepth
            } else { '[]' }
            $json | Out-File -FilePath $jsonPath -Encoding UTF8 -Force
            $written += $jsonPath
        }
    } catch {
        Write-DLog "Export-DArtifact '$Name' basarisiz: $($_.Exception.Message)" -Level ERROR
        return
    }

    foreach ($f in $written) {
        $null = $Script:Manifest.Add([PSCustomObject]@{
            Artifact = $Name
            File     = (Split-Path $f -Leaf)
            SubDir   = $SubDir
            Rows     = $rows.Count
            SizeKB   = if (Test-Path $f) { [math]::Round((Get-Item $f).Length / 1KB, 2) } else { 0 }
            SHA256   = Get-DFileHashSafe -Path $f
        })
    }

    Write-DLog "  -> $Name ($($rows.Count) rows)" -Level DEBUG
}

function Add-DTimelineEvent {
    <# Birlesik timeline besleyicisi. Her modul zaman damgali kaydini buraya atar. #>
    param(
        [Parameter(Mandatory)]$Timestamp,
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Description,
        [string]$Detail,
        [ValidateSet('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')]
        [string]$Severity = 'INFO'
    )
    $utc = ConvertTo-DUtcString $Timestamp
    if (-not $utc) { return }

    $null = $Script:Timeline.Add([PSCustomObject]@{
        TimeUtc     = $utc
        Source      = $Source
        Severity    = $Severity
        Description = $Description
        Detail      = $Detail
    })
}

# How many times one rule may report before it is capped.
#
# Measured in the field: a single rule fired 324 times on one server and the
# report became unreadable. A finding you cannot get through is the same as no
# finding. The overflow is counted and reported once, so the number is never
# quietly wrong.
$Script:FindingCapPerRule = 25
$Script:RuleHitCount = @{}

# Held in script scope rather than read from the parameter inside the function.
# A parameter resolved through dynamic scope silently becomes empty when the
# function is called from a nested scope, and an empty floor filters nothing —
# which is worse than no floor, because it looks like it is working.
# Held in script scope rather than read from the parameter inside the function.
# A parameter reached through dynamic scope resolves to empty when the function
# is called from a nested one, and an empty path silently disables progress
# reporting — the hunt then looks dead in the console while it is running.
$Script:ProgressPath = $null

$Script:SeverityRank = @{ INFO = 0; LOW = 1; MEDIUM = 2; HIGH = 3; CRITICAL = 4 }
$Script:MinSeverityRank = 0
$Script:SuppressedBySeverity = 0

# Rules switched off in the console. Held in script scope for the same reason
# the severity floor is: a parameter reached through dynamic scope resolves to
# empty inside a nested call, and an empty set filters nothing while looking
# like it works.
$Script:DisabledRules = @{}
$Script:SuppressedByRule = 0

# Position of each finding in the live stream. The console uses it to match a
# streamed finding against its copy in the bundle, so nothing arrives twice.
$Script:FindingSeq = 0
$Script:LiveFindingPath = ''

function Add-DFinding {
    <# A triage finding. Goes to the top of the HTML report and to FINDINGS.csv. #>
    param(
        [Parameter(Mandatory)][string]$RuleId,
        [Parameter(Mandatory)]
        [ValidateSet('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')]
        [string]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Evidence,
        [string]$Mitre,
        [string]$Why,
        [string]$Artifact,
        $Timestamp,
        # Set on findings that must always be reported, however many there are.
        [switch]$NoCap
    )

    # A rule switched off in the console produces nothing at all. Checked
    # first: a disabled rule should not consume the per-rule budget or move any
    # counter, because as far as this hunt is concerned it does not exist.
    if ($Script:DisabledRules.Count -gt 0 -and $Script:DisabledRules.ContainsKey($RuleId)) {
        $Script:SuppressedByRule++
        return
    }

    # Severity floor, applied before the cap so a floor does not spend the
    # per-rule budget on findings nobody asked for.
    if ($Script:MinSeverityRank -gt 0) {
        $thisRank = $Script:SeverityRank[$Severity]
        if ($null -eq $thisRank) { $thisRank = 0 }
        if ($thisRank -lt $Script:MinSeverityRank) {
            $Script:SuppressedBySeverity++
            return
        }
    }

    if (-not $Script:RuleHitCount.ContainsKey($RuleId)) { $Script:RuleHitCount[$RuleId] = 0 }
    $Script:RuleHitCount[$RuleId]++

    if (-not $NoCap -and $Script:RuleHitCount[$RuleId] -gt $Script:FindingCapPerRule) {
        return
    }

    $when = ConvertTo-DUtcString $Timestamp
    $null = $Script:Findings.Add([PSCustomObject]@{
        RuleId    = $RuleId
        Severity  = $Severity
        Title     = $Title
        Evidence  = $Evidence
        Mitre     = $Mitre
        Why       = $Why
        Artifact  = $Artifact
        TimeUtc   = $when
        Host      = $Script:Ctx.ComputerName
    })

    $Script:FindingSeq++
    if ($Script:LiveFindingPath) {
        # Wrapped because a sweep must not fail over a stream nobody is
        # obliged to be reading. If this file cannot be written the hunt still
        # completes and the bundle still carries every finding.
        try {
            $line = [PSCustomObject]@{
                seq         = $Script:FindingSeq
                rule_id     = [string]$RuleId
                severity    = [string]$Severity
                title       = [string]$Title
                evidence    = [string]$Evidence
                mitre       = [string]$Mitre
                why         = [string]$Why
                artifact    = [string]$Artifact
                occurred_at = [string]$when
            } | ConvertTo-Json -Depth 3 -Compress
            Add-Content -LiteralPath $Script:LiveFindingPath -Value $line -Encoding UTF8 -ErrorAction Stop
        } catch { }
    }

    $lvl = switch ($Severity) {
        'CRITICAL' { 'CRIT' }
        'HIGH'     { 'WARN' }
        default    { 'INFO' }
    }
    if ($Severity -in 'CRITICAL', 'HIGH') {
        Write-DLog "  [$Severity] $Title :: $Evidence" -Level $lvl
    }
}

# ============================================================================
#  YARDIMCILAR - HASH / IMZA (cache'li)
# ============================================================================

function Get-DFileHashSafe {
    <#
        SHA256. Cache'li - ayni exe 40 process'te calisiyorsa 1 kez hesaplanir.
        200 MB ustu dosya atlanir.
    #>
    param([string]$Path, [int]$MaxSizeMB = 200)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $key = $Path.ToLowerInvariant()
    if ($Script:HashCache.ContainsKey($key)) { return $Script:HashCache[$key] }

    $result = $null
    try {
        $fi = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($fi.PSIsContainer) { $result = $null }
        elseif ($fi.Length -gt ($MaxSizeMB * 1MB)) { $result = 'SKIPPED_LARGE' }
        else {
            if ($Script:Caps.FileHash) {
                $result = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
            } else {
                # PS4 fallback
                $sha = [Security.Cryptography.SHA256]::Create()
                $fs  = [IO.File]::OpenRead($Path)
                try {
                    $result = ([BitConverter]::ToString($sha.ComputeHash($fs))) -replace '-', ''
                } finally { $fs.Dispose(); $sha.Dispose() }
            }
        }
    } catch {
        $result = 'ERROR_LOCKED'
    }

    $Script:HashCache[$key] = $result
    return $result
}

function Get-DSignature {
    <#
        Authenticode imza durumu. Cache'li.
        Donen: Status, Signer, IsMicrosoft, IsValid
    #>
    param([string]$Path)

    $unknown = [PSCustomObject]@{
        Status = 'NoPath'; Signer = $null; IsMicrosoft = $false; IsValid = $false
    }
    if ([string]::IsNullOrWhiteSpace($Path)) { return $unknown }

    $key = $Path.ToLowerInvariant()
    if ($Script:SigCache.ContainsKey($key)) { return $Script:SigCache[$key] }

    $res = $unknown
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf -ErrorAction SilentlyContinue) {
            $sig    = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
            $cn     = $null
            if ($signer -and $signer -match 'CN=([^,]+)') { $cn = $Matches[1].Trim('" ') }

            $res = [PSCustomObject]@{
                Status      = [string]$sig.Status
                Signer      = $cn
                IsMicrosoft = ($cn -like '*Microsoft*')
                IsValid     = ($sig.Status -eq 'Valid')
            }
        } else {
            $res = [PSCustomObject]@{
                Status = 'FileNotFound'; Signer = $null; IsMicrosoft = $false; IsValid = $false
            }
        }
    } catch {
        $res = [PSCustomObject]@{
            Status = 'Error'; Signer = $null; IsMicrosoft = $false; IsValid = $false
        }
    }

    $Script:SigCache[$key] = $res
    return $res
}

function Test-DSuspiciousPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    return [bool]($Path -match $Script:SuspiciousPathRegex)
}

function Get-DCleanPath {
    <# Servis/task komut satirindan gercek binary yolunu ayiklar #>
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }

    $cl = $CommandLine.Trim()
    if ($cl.StartsWith('"')) {
        $end = $cl.IndexOf('"', 1)
        if ($end -gt 0) { return $cl.Substring(1, $end - 1) }
    }
    # Tirnaksiz: ilk .exe/.dll/.sys uzantisina kadar al
    if ($cl -match '^(.*?\.(exe|dll|sys|com|bat|cmd|scr))(\s|$)') {
        return $Matches[1]
    }
    return ($cl -split '\s+')[0]
}

# ============================================================================
#  IOC YUKLEME
# ============================================================================

function Import-DIocs {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path $Path)) { return }

    $count = 0
    try {
        Get-Content -Path $Path -ErrorAction Stop | ForEach-Object {
            $line = $_.Trim()
            if ($line -and -not $line.StartsWith('#')) {
                $type = switch -Regex ($line) {
                    '^[a-fA-F0-9]{64}$'                  { 'SHA256'; break }
                    '^[a-fA-F0-9]{40}$'                  { 'SHA1';   break }
                    '^[a-fA-F0-9]{32}$'                  { 'MD5';    break }
                    '^\d{1,3}(\.\d{1,3}){3}$'            { 'IP';     break }
                    '^[\w\-\.]+\.[a-zA-Z]{2,}$'          { 'DOMAIN'; break }
                    default                              { 'STRING' }
                }
                $Script:Iocs[$line.ToLowerInvariant()] = $type
                $count++
            }
        }
        Write-DLog "Indicator list loaded: $count entries" -Level OK
    } catch {
        Write-DLog "IOC dosyasi okunamadi: $($_.Exception.Message)" -Level WARN
    }
}

function Test-DIoc {
    <# Toplanan her deger bundan gecer. Hit varsa otomatik CRITICAL finding. #>
    param([string]$Value, [string]$Context, [string]$Artifact)
    if (-not $Value -or $Script:Iocs.Count -eq 0) { return $false }

    $k = $Value.ToLowerInvariant()
    if ($Script:Iocs.ContainsKey($k)) {
        Add-DFinding -RuleId 'DGL-IOC' -Severity CRITICAL `
                     -Title "IOC match ($($Script:Iocs[$k]))" `
                     -Evidence "$Value  |  $Context" `
                     -Why 'Direct match against the supplied indicator list' `
                     -Artifact $Artifact
        return $true
    }
    return $false
}

# ============================================================================
#  MODUL MOTORU
# ============================================================================

$Script:ModuleRegistry = New-Object System.Collections.ArrayList

function Register-DModule {
    <#
        Modul kaydi. Calisma sirasi Phase + kayit sirasi.
        Scope: All / Client / Server / DC  (rol filtresi)
        RequiresCap: yetenek matrisinde true olmasi gereken anahtarlar
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateRange(0, 4)][int]$Phase,
        [Parameter(Mandatory)][scriptblock]$Body,
        [ValidateSet('All', 'Client', 'Server', 'DC')]
        [string[]]$Scope = @('All'),
        [string[]]$RequiresCap = @(),
        [string]$Description,
        [switch]$SkipOnQuick
    )

    $null = $Script:ModuleRegistry.Add([PSCustomObject]@{
        Name        = $Name
        Phase       = $Phase
        Scope       = $Scope
        RequiresCap = $RequiresCap
        Description = $Description
        SkipOnQuick = [bool]$SkipOnQuick
        Body        = $Body
    })
}

function Test-DModuleScope {
    param([string[]]$Scope)
    if ($Scope -contains 'All') { return $true }
    if ($Scope -contains 'DC'     -and $Script:Ctx.IsDomainController) { return $true }
    if ($Scope -contains 'Server' -and $Script:Ctx.IsServer)           { return $true }
    if ($Scope -contains 'Client' -and $Script:Ctx.IsWorkstation)      { return $true }
    return $false
}

function Invoke-DModule {
    <#
        Modul izolasyonu. Bir modul patlarsa script DEVAM EDER.
        Hata errors.json'a duser, sure manifest'e yazilir.
    #>
    param([Parameter(Mandatory)][object]$Module)

    # Kapsam filtresi
    if (-not (Test-DModuleScope -Scope $Module.Scope)) {
        Write-DLog "$($Module.Name) - out of scope (role: $($Script:Ctx.DomainRole))" -Level DEBUG
        return
    }

    # Quick mod filtresi
    if ($Quick -and $Module.SkipOnQuick) {
        Write-DLog "$($Module.Name) - Quick modda atlandi" -Level DEBUG
        return
    }

    # Yetenek filtresi
    foreach ($cap in $Module.RequiresCap) {
        if (-not $Script:Caps[$cap]) {
            Write-DLog "$($Module.Name) - yetenek yok ($cap), atlandi" -Level WARN
            $null = $Script:Errors.Add([PSCustomObject]@{
                Module    = $Module.Name
                Type      = 'SkippedCapability'
                Message   = "Gerekli yetenek mevcut degil: $cap"
                TimeUtc   = (Get-Date).ToUniversalTime().ToString('o')
            })
            return
        }
    }

    Write-DLog "$($Module.Name)" -Level STEP
    Write-DProgress -Detail $Module.Name
    $sw           = [Diagnostics.Stopwatch]::StartNew()
    $errCountPre  = $Global:Error.Count
    $findCountPre = $Script:Findings.Count
    $status       = 'OK'

    try {
        & $Module.Body
    } catch {
        $status = 'FAILED'
        Write-DLog "$($Module.Name) FAILED: $($_.Exception.Message)" -Level ERROR
        $null = $Script:Errors.Add([PSCustomObject]@{
            Module     = $Module.Name
            Type       = 'Terminating'
            Message    = $_.Exception.Message
            Category   = $_.CategoryInfo.Category
            ScriptLine = $_.InvocationInfo.ScriptLineNumber
            TimeUtc    = (Get-Date).ToUniversalTime().ToString('o')
        })
    } finally {
        $sw.Stop()
    }

    # Non-terminating hatalari da yakala (SilentlyContinue ile yutulanlar)
    $newErrors = $Global:Error.Count - $errCountPre
    if ($newErrors -gt 0) {
        $take = [Math]::Min($newErrors, 5)
        for ($i = 0; $i -lt $take; $i++) {
            $e = $Global:Error[$i]
            $null = $Script:Errors.Add([PSCustomObject]@{
                Module     = $Module.Name
                Type       = 'NonTerminating'
                Message    = "$e"
                Category   = $e.CategoryInfo.Category
                ScriptLine = $e.InvocationInfo.ScriptLineNumber
                TimeUtc    = (Get-Date).ToUniversalTime().ToString('o')
            })
        }
        if ($newErrors -gt 5) {
            $null = $Script:Errors.Add([PSCustomObject]@{
                Module  = $Module.Name
                Type    = 'NonTerminating'
                Message = "... and $($newErrors - 5) more errors (truncated)"
                TimeUtc = (Get-Date).ToUniversalTime().ToString('o')
            })
        }
    }

    $null = $Script:ModuleStats.Add([PSCustomObject]@{
        Module     = $Module.Name
        Phase      = $Module.Phase
        Status     = $status
        DurationMs = [int]$sw.ElapsedMilliseconds
        ErrorCount = $newErrors
    })

    $Script:PhaseModuleDone++

    # A module-level event, not just a percentage. The console can then show
    # what was tried, what it produced and what failed while the hunt is still
    # running — a bar that only moves tells an operator nothing about whether
    # the sweep is going well.
    $modFindings = $Script:Findings.Count - $findCountPre
    $modRows = 0
    foreach ($mf in @($Script:Manifest | Where-Object { $_.Module -eq $Module.Name })) {
        $modRows += [int]$mf.Rows
    }
    Write-DProgress -Detail $Module.Name -Module $Module.Name -Status $status `
        -DurationMs ([int]$sw.ElapsedMilliseconds) -Findings $modFindings `
        -Rows $modRows -Errors $newErrors

    $secs = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    if ($secs -gt 10) {
        Write-DLog "  tamamlandi ($secs sn)" -Level WARN
    } else {
        Write-DLog "  tamamlandi ($secs sn)" -Level DEBUG
    }
}

$Script:ModuleStats = New-Object System.Collections.ArrayList

function Invoke-DPhase {
    param([Parameter(Mandatory)][int]$Phase, [string]$Title)

    $mods = @($Script:ModuleRegistry | Where-Object { $_.Phase -eq $Phase })
    if ($mods.Count -eq 0) { return }

    # Bu fazda gercekten calisacak modul sayisi (kapsam/yetenek filtresi sonrasi)
    $eligible = @($mods | Where-Object {
        (Test-DModuleScope -Scope $_.Scope) -and -not ($Quick -and $_.SkipOnQuick)
    })
    $Script:CurrentPhase = $Phase
    # Counted from what the loop below actually iterates, not from the eligible
    # subset: Invoke-DModule increments the counter for every module it is
    # handed, including the ones it then skips.
    $Script:PhaseModuleTotal = [Math]::Max(1, @($mods).Count)
    $Script:PhaseModuleDone  = 0
    Write-DProgress -Detail $Title

    Write-Host ''
    Write-Host ("  === FAZ {0}: {1} ===" -f $Phase, $Title) -ForegroundColor White `
               -BackgroundColor DarkBlue
    Write-DLog "FAZ $Phase basladi: $Title" -Level INFO -NoConsole

    foreach ($m in $mods) { Invoke-DModule -Module $m }

    # Her faz sonunda ara kayit - script 8. dakikada patlarsa veri kaybolmasin
    Save-DInterimState
}

function Save-DInterimState {
    try {
        if ($Script:Findings.Count -gt 0) {
            $Script:Findings |
                Sort-Object @{E = {
                    switch ($_.Severity) {
                        'CRITICAL' { 0 } 'HIGH' { 1 } 'MEDIUM' { 2 } 'LOW' { 3 } default { 4 }
                    }}} |
                Export-Csv -Path (Join-Path $Script:Ctx.OutputDir 'FINDINGS.csv') `
                           -NoTypeInformation -Encoding UTF8 -Force
        }
        if ($Script:Errors.Count -gt 0) {
            $Script:Errors | ConvertTo-Json -Depth 4 |
                Out-File -FilePath (Join-Path $Script:Ctx.OutputDir 'logs\errors.json') `
                         -Encoding UTF8 -Force
        }
    } catch { }
}

# ============================================================================
#  FINALIZE
# ============================================================================

function Complete-DCollection {
    Write-Host ''
    Write-Host '  === FINALIZE ===' -ForegroundColor White -BackgroundColor DarkBlue

    # Timeline
    if ($Script:Timeline.Count -gt 0) {
        $Script:Timeline | Sort-Object TimeUtc |
            Export-Csv -Path (Join-Path $Script:Ctx.OutputDir 'TIMELINE.csv') `
                       -NoTypeInformation -Encoding UTF8 -Force
        Write-DLog "Timeline: $($Script:Timeline.Count) rows" -Level OK
    }

    # Findings
    Save-DInterimState

    # Skor
    $crit = @($Script:Findings | Where-Object Severity -eq 'CRITICAL').Count
    $high = @($Script:Findings | Where-Object Severity -eq 'HIGH').Count
    $med  = @($Script:Findings | Where-Object Severity -eq 'MEDIUM').Count
    $low  = @($Script:Findings | Where-Object Severity -eq 'LOW').Count
    $score = ($crit * 10) + ($high * 5) + ($med * 2) + ($low * 1)
    $risk  = if ($score -ge 50) { 'CRITICAL' }
             elseif ($score -ge 25) { 'HIGH' }
             elseif ($score -ge 10) { 'MEDIUM' }
             elseif ($score -gt 0)  { 'LOW' }
             else { 'CLEAN' }

    $Script:Ctx.RiskScore = $score
    $Script:Ctx.RiskLevel = $risk

    # Modul istatistikleri
    $Script:ModuleStats | Export-Csv `
        -Path (Join-Path $Script:Ctx.OutputDir 'logs\module_stats.csv') `
        -NoTypeInformation -Encoding UTF8 -Force

    # Manifest
    $elapsed = (Get-Date) - $Script:StartTime
    $manifest = [ordered]@{
        Tool = [ordered]@{
            Name        = 'Douglas-042'
            Version     = $Script:Version
            ScriptPath  = $PSCommandPath
            ScriptSHA256 = if ($PSCommandPath) { Get-DFileHashSafe -Path $PSCommandPath } else { $null }
        }
        Collection = [ordered]@{
            StartUtc        = $Script:StartTime.ToUniversalTime().ToString('o')
            EndUtc          = (Get-Date).ToUniversalTime().ToString('o')
            StartLocal      = $Script:StartTime.ToString('o')
            DurationSeconds = [math]::Round($elapsed.TotalSeconds, 1)
            Operator        = $Script:Ctx.Operator
            OperatorSid     = $Script:Ctx.OperatorSid
            RunAsSystem     = $Script:Ctx.RunAsSystem
            Parameters      = [ordered]@{
                Days               = $Days
                Quick              = [bool]$Quick
                CollectRaw         = [bool]$CollectRaw
                NoResolve          = [bool]$NoResolve
                MaxEventsPerChannel = $MaxEventsPerChannel
                IocFile            = $IocFile
            }
        }
        Host = [ordered]@{
            ComputerName   = $Script:Ctx.ComputerName
            IPAddresses    = $Script:Ctx.IPAddresses
            Domain         = $Script:Ctx.Domain
            DomainRole     = $Script:Ctx.DomainRole
            IsDC           = $Script:Ctx.IsDomainController
            OS             = $Script:Ctx.OSCaption
            OSVersion      = $Script:Ctx.OSVersion
            OSBuild        = $Script:Ctx.OSBuild
            Architecture   = $Script:Ctx.OSArchitecture
            TimeZone       = $Script:Ctx.TimeZone
            UtcOffsetHours = $Script:Ctx.UtcOffsetHours
            LastBootUtc    = ConvertTo-DUtcString $Script:Ctx.LastBootUtc
            UptimeDays     = $Script:Ctx.UptimeDays
        }
        Capabilities = $Script:Caps
        Result = [ordered]@{
            RiskScore     = $score
            RiskLevel     = $risk
            FindingCount  = [ordered]@{
                CRITICAL = $crit; HIGH = $high; MEDIUM = $med; LOW = $low
                TOTAL    = $Script:Findings.Count
            }
            TimelineRows  = $Script:Timeline.Count
            ArtifactCount = $Script:Manifest.Count
            ErrorCount    = $Script:Errors.Count
        }
        Artifacts = @($Script:Manifest)
        Scope     = [ordered]@{
            NotCollected = @(
                'RAM imaji (WinPmem / DumpIt / Magnet RAM Capture)'
                'Disk imaji (FTK Imager / dd)'
                'Tarayici gecmisi tam parse (Hindsight / BrowsingHistoryView)'
                'Tam ShellBag / Jumplist rekonstruksiyonu (Eric Zimmerman araclari)'
                'Ag trafigi yakalama (PCAP)'
            )
            Note = 'This collection ran on a live system; file access times and Prefetch may have been altered.'
        }
    }

    $manifest | ConvertTo-Json -Depth 8 |
        Out-File -FilePath (Join-Path $Script:Ctx.OutputDir 'MANIFEST.json') -Encoding UTF8 -Force

    # Report every rule that hit the cap, once, so a truncated count is visible
    # rather than a silently short list.
    foreach ($rid in @($Script:RuleHitCount.Keys)) {
        $hits = $Script:RuleHitCount[$rid]
        if ($hits -le $Script:FindingCapPerRule) { continue }
        $sample = $Script:Findings | Where-Object { $_.RuleId -eq $rid } | Select-Object -First 1
        Add-DFinding -RuleId 'DGL-023' -Severity INFO -NoCap `
            -Title 'Rule reported more findings than are shown' `
            -Evidence "$rid fired $hits times; the first $($Script:FindingCapPerRule) are listed. $($sample.Title)" `
            -Artifact 'FINDINGS' `
            -Why 'A rule this noisy is usually how the environment is built rather than an intrusion. Suppress it in the console once reviewed.'
    }

    if ($Script:SuppressedBySeverity -gt 0) {
        Add-DFinding -RuleId 'DGL-024' -Severity $MinSeverity -NoCap `
            -Title 'Findings below the severity floor were not reported' `
            -Evidence "$($Script:SuppressedBySeverity) findings at or below $MinSeverity were collected but not listed" `
            -Artifact 'FINDINGS' `
            -Why 'Re-run without a floor, or with a lower one, to see them.'
    }

    # Same reasoning as the severity floor above: a quiet result must never be
    # mistaken for a clean one. If rules were switched off in the console, say
    # how much that hid rather than letting the gap go unexplained.
    if ($Script:SuppressedByRule -gt 0) {
        Add-DFinding -RuleId 'DGL-025' -Severity 'INFO' -NoCap `
            -Title 'Some detections are switched off in the console' `
            -Evidence "$($Script:DisabledRules.Count) rule(s) disabled; $($Script:SuppressedByRule) finding(s) were not produced" `
            -Artifact 'FINDINGS' `
            -Why 'Switched off means the check did not run, so there is nothing to review for those rules. Re-enable them in DGL rules to see what they would have found.'
    }

    Write-DProgress -Detail 'Building report' -Final

    # --- HTML rapor ---
    $htmlPath = $null
    try { $htmlPath = New-DHtmlReport } catch {
        Write-DLog "HTML rapor hatasi: $($_.Exception.Message)" -Level ERROR
    }

    # --- Paketleme ---
    $zipPath = $null
    try {
        $zipPath = "$($Script:Ctx.OutputDir).zip"
        if (Get-Command Compress-Archive -ErrorAction SilentlyContinue) {
            Compress-Archive -Path "$($Script:Ctx.OutputDir)\*" -DestinationPath $zipPath `
                             -CompressionLevel Optimal -Force -ErrorAction Stop
            $zipMB = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
            Write-DLog "Archive created ($zipMB MB)" -Level OK
        }
    } catch {
        Write-DLog "Archiving failed: $($_.Exception.Message)" -Level WARN
        $zipPath = $null
    }

    # --- Konsol ozeti ---
    Write-Host ''
    Write-Host ('  ' + ('=' * 68)) -ForegroundColor DarkGray
    Write-Host ('   HOST      : {0}  ({1})' -f $Script:Ctx.ComputerName, $Script:Ctx.PrimaryIP)
    Write-Host ('   ROLE      : {0}' -f $Script:Ctx.DomainRole)
    Write-Host ('   ELAPSED   : {0} s   |   WINDOW: last {1} days' -f `
                [math]::Round($elapsed.TotalSeconds, 1), $Days)
    Write-Host ('   ARTIFACTS : {0} files   |   TIMELINE: {1} rows   |   ERRORS: {2}' -f `
                $Script:Manifest.Count, $Script:Timeline.Count, $Script:Errors.Count)
    Write-Host ('  ' + ('-' * 68)) -ForegroundColor DarkGray

    $riskColor = switch ($risk) {
        'CRITICAL' { 'Red' } 'HIGH' { 'Red' } 'MEDIUM' { 'Yellow' }
        'LOW' { 'Cyan' } default { 'Green' }
    }
    Write-Host ('   RISK      : {0}   (score {1})' -f $risk, $score) -ForegroundColor $riskColor
    Write-Host ('   FINDINGS  : CRITICAL {0}  |  HIGH {1}  |  MEDIUM {2}  |  LOW {3}' -f `
                $crit, $high, $med, $low) -ForegroundColor $riskColor
    Write-Host ('  ' + ('=' * 68)) -ForegroundColor DarkGray
    Write-Host ''

    if ($crit -gt 0) {
        Write-Host '   PRIORITY FINDINGS:' -ForegroundColor Red
        $Script:Findings | Where-Object Severity -eq 'CRITICAL' |
            Select-Object -First 10 | ForEach-Object {
                Write-Host ('     [{0}] {1}' -f $_.RuleId, $_.Title) -ForegroundColor Red
                $ev = if ($_.Evidence.Length -gt 110) {
                          $_.Evidence.Substring(0, 110) + '...' } else { $_.Evidence }
                Write-Host ('            {0}' -f $ev) -ForegroundColor DarkGray
            }
        if ($crit -gt 10) { Write-Host "     ... and $($crit - 10) more critical findings" -ForegroundColor DarkGray }
        Write-Host ''
    }

    Write-Host ('   FOLDER : {0}' -f $Script:Ctx.OutputDir) -ForegroundColor Green
    if ($htmlPath) { Write-Host ('   REPORT : {0}' -f $htmlPath) -ForegroundColor Green }
    if ($zipPath)  { Write-Host ('   ARCHIVE: {0}' -f $zipPath) -ForegroundColor Green }
    Write-Host ''

    # Etkilesimli oturumda raporu ac
    if ($htmlPath -and -not $Script:Ctx.RunAsSystem) {
        try { Start-Process $htmlPath -ErrorAction SilentlyContinue } catch { }
    }
}

# ============================================================================
#  ORNEK MODULLER  (dikey kesit dogrulamasi - Adim 2'de genisleyecek)
# ============================================================================

Register-DModule -Name 'Scan scope' -Phase 0 `
    -Description 'Fixed volumes and the directories that will be walked' -Body {

    # Resolved once and reused: probing every volume inside each file module
    # would repeat the same disk I/O three times.
    $Script:ScanPaths = Get-DScanPaths

    $rows = foreach ($p in $Script:ScanPaths) {
        [PSCustomObject]@{
            Path   = $p
            Volume = ($p -replace '^([A-Za-z]:).*$', '$1')
            OnSystemDrive = $p.StartsWith($env:SystemDrive, [StringComparison]::OrdinalIgnoreCase)
        }
    }
    Export-DArtifact -Name '00_scan_scope' -Data @($rows)

    $vols = ($Script:ScannedVolumes -join ', ')
    Write-DLog "  Fixed volumes: $vols" -Level DEBUG
    Write-DLog "  $($Script:ScanPaths.Count) directories in scope ($($Script:ExtraVolumePaths) off the system drive)" -Level DEBUG

    if ($Script:ScannedVolumes.Count -gt 1 -and $Script:ExtraVolumePaths -eq 0) {
        Add-DFinding -RuleId 'DGL-020' -Severity INFO `
            -Title 'Additional volumes present but no known directories matched' `
            -Evidence "Volumes: $vols" -Artifact '00_scan_scope' `
            -Why 'Data on these volumes was not walked. If a web root or share lives there, scan it separately.'
    }
}

Register-DModule -Name 'System information' -Phase 0 -Description 'OS, hardware, time' -Body {
    $sys = [PSCustomObject]@{
        ComputerName   = $Script:Ctx.ComputerName
        Domain         = $Script:Ctx.Domain
        DomainRole     = $Script:Ctx.DomainRole
        OS             = $Script:Ctx.OSCaption
        Version        = $Script:Ctx.OSVersion
        Build          = $Script:Ctx.OSBuild
        Architecture   = $Script:Ctx.OSArchitecture
        InstallDateUtc = ConvertTo-DUtcString $Script:Ctx.InstallDate
        LastBootUtc    = ConvertTo-DUtcString $Script:Ctx.LastBootUtc
        UptimeDays     = $Script:Ctx.UptimeDays
        TimeZone       = $Script:Ctx.TimeZone
        UtcOffsetHours = $Script:Ctx.UtcOffsetHours
        IPAddresses    = ($Script:Ctx.IPAddresses -join '; ')
        Manufacturer   = $Script:Ctx.Manufacturer
        Model          = $Script:Ctx.Model
        TotalRAMGB     = $Script:Ctx.TotalRAMGB
        PSVersion      = $Script:Caps.PSVersion.ToString()
    }
    Export-DArtifact -Name '01_system' -Data $sys -AsJson

    # Yeni kurulmus sistem = muhtemelen yeniden kurulmus / sahte
    if ($Script:Ctx.InstallDate -and
        ((Get-Date) - $Script:Ctx.InstallDate).TotalDays -lt 7) {
        Add-DFinding -RuleId 'DGL-000' -Severity MEDIUM `
                     -Title 'Operating system installed less than 7 days ago' `
                     -Evidence "InstallDate: $($Script:Ctx.InstallDate)" `
                     -Why 'An unexpected rebuild suggests evidence may have been destroyed' `
                     -Artifact '01_system'
    }

    Add-DTimelineEvent -Timestamp $Script:Ctx.LastBootUtc -Source 'System' `
                       -Description 'System started' -Severity INFO
}

Register-DModule -Name 'Hotfixes and patch status' -Phase 0 -Body {
    $hf = @()
    try {
        $hf = Get-HotFix -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                HotFixID    = $_.HotFixID
                Description = $_.Description
                InstalledBy = $_.InstalledBy
                InstalledOn = ConvertTo-DUtcString $_.InstalledOn
            }
        }
    } catch { }

    Export-DArtifact -Name '01_hotfixes' -Data $hf

    $last = $hf | Where-Object InstalledOn | Sort-Object InstalledOn -Descending |
            Select-Object -First 1
    if ($last) {
        $age = ((Get-Date) - [DateTime]$last.InstalledOn).TotalDays
        if ($age -gt 90) {
            Add-DFinding -RuleId 'DGL-002' -Severity MEDIUM `
                         -Title 'System unpatched for 90+ days' `
                         -Evidence "Son yama: $($last.HotFixID) @ $($last.InstalledOn)" `
                         -Mitre 'T1190' `
                         -Why 'An unpatched system is open to known exploits and is an initial access vector' `
                         -Artifact '01_hotfixes'
        }
    }
}

Register-DModule -Name 'Event log health' -Phase 1 -RequiresCap 'WinEvent' `
    -Description 'Anti-forensics: has the log been cleared?' -Body {

    # Her kanala -Oldest sorgusu atmak pahali (Win11/2022'de 1100+ kanal var).
    # Sadece hunting acisindan onemli kanallari probe ediyoruz.
    $probe = @(
        'Security', 'System', 'Application', 'Setup'
        'Windows PowerShell'
        'Microsoft-Windows-PowerShell/Operational'
        'Microsoft-Windows-Sysmon/Operational'
        'Microsoft-Windows-WinRM/Operational'
        'Microsoft-Windows-TaskScheduler/Operational'
        'Microsoft-Windows-Windows Defender/Operational'
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
        'Microsoft-Windows-TerminalServices-RDPClient/Operational'
        'Microsoft-Windows-WMI-Activity/Operational'
        'Microsoft-Windows-Bits-Client/Operational'
        'Microsoft-Windows-CodeIntegrity/Operational'
        'Microsoft-Windows-SMBServer/Security'
        'Microsoft-Windows-SMBClient/Security'
        'Microsoft-Windows-NTLM/Operational'
        'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
        'Directory Service'
        'DNS Server'
    )

    $logs = @()
    try {
        $logs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
                Where-Object { $_.RecordCount -gt 0 } |
                ForEach-Object {
                    $oldest    = $null
                    $oldestAge = $null
                    if ($probe -contains $_.LogName) {
                        try {
                            $first = Get-WinEvent -LogName $_.LogName -Oldest -MaxEvents 1 -ErrorAction Stop
                            if ($first) {
                                $oldest    = $first.TimeCreated
                                $oldestAge = [math]::Round(((Get-Date) - $first.TimeCreated).TotalDays, 2)
                            }
                        } catch { }
                    }

                    [PSCustomObject]@{
                        LogName         = $_.LogName
                        IsEnabled       = $_.IsEnabled
                        RecordCount     = $_.RecordCount
                        MaxSizeMB       = [math]::Round($_.MaximumSizeInBytes / 1MB, 1)
                        CurrentSizeMB   = [math]::Round($_.FileSize / 1MB, 1)
                        PctFull         = if ($_.MaximumSizeInBytes -gt 0) {
                                              [math]::Round(($_.FileSize / $_.MaximumSizeInBytes) * 100, 1)
                                          } else { 0 }
                        OldestRecordUtc = ConvertTo-DUtcString $oldest
                        OldestAgeDays   = $oldestAge
                        LogMode         = [string]$_.LogMode
                        LastWriteUtc    = ConvertTo-DUtcString $_.LastWriteTime
                    }
                }
    } catch {
        Write-DLog "Could not enumerate event logs: $($_.Exception.Message)" -Level ERROR
    }

    Export-DArtifact -Name '11_log_health' -Data $logs

    # --- Triage: log temizlenmis mi? ---
    # Mantik: log kapasitesi buyuk + doluluk dusuk + gecmis kisa = temizlenmis
    foreach ($l in $logs) {
        if ($l.LogName -in 'Security', 'System', 'Application' -or
            $l.LogName -like '*PowerShell*' -or $l.LogName -like '*Sysmon*') {

            if ($null -ne $l.OldestAgeDays -and $l.OldestAgeDays -lt 3 -and
                $l.MaxSizeMB -gt 50 -and $l.PctFull -lt 70) {

                Add-DFinding -RuleId 'DGL-014' -Severity CRITICAL `
                    -Title 'Event log may have been cleared' `
                    -Evidence ("{0}: oldest record {1} days old, capacity {2} MB, {3}% full" -f `
                               $l.LogName, $l.OldestAgeDays, $l.MaxSizeMB, $l.PctFull) `
                    -Mitre 'T1070.001' `
                    -Why 'The log is large and not full, yet holds no history. That is clearing, not rollover.' `
                    -Artifact '11_log_health'
            }

            if (-not $l.IsEnabled) {
                Add-DFinding -RuleId 'DGL-015' -Severity HIGH `
                    -Title 'Critical event log channel is disabled' `
                    -Evidence "$($l.LogName) kapali" `
                    -Mitre 'T1562.002' `
                    -Why 'An attacker may have disabled visibility' `
                    -Artifact '11_log_health'
            }
        }

        # Istenen pencere gercekten mevcut mu?
        if ($l.LogName -eq 'Security' -and $null -ne $l.OldestAgeDays -and
            $l.OldestAgeDays -lt $Days) {
            Add-DFinding -RuleId 'DGL-016' -Severity INFO `
                -Title 'Requested window exceeds log retention' `
                -Evidence ("-Days {0} istendi, Security logunda {1} gunluk veri var" -f `
                           $Days, $l.OldestAgeDays) `
                -Why 'The effective window is shorter than requested; weigh this when scoping' `
                -Artifact '11_log_health'
        }
    }

    # Sysmon var mi?
    $sysmon = $logs | Where-Object LogName -like '*Sysmon*'
    if (-not $sysmon) {
        Add-DFinding -RuleId 'DGL-017' -Severity MEDIUM `
            -Title 'Sysmon is not installed' `
            -Evidence 'Microsoft-Windows-Sysmon/Operational kanali bulunamadi' `
            -Why 'Process, network and pipe visibility is badly limited, reducing hunting depth' `
            -Artifact '11_log_health'
    }
    $Script:Caps.Sysmon = [bool]$sysmon
    $Script:Caps.AvailableLogs = @($logs.LogName)
}

# ============================================================================
#  TESPIT SOZLUKLERI
# ============================================================================

# LOLBAS - mesru ama saldirganin execution proxy olarak kullandigi binary'ler
$Script:LolBasExec = @(
    'certutil.exe', 'bitsadmin.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe',
    'installutil.exe', 'cmstp.exe', 'odbcconf.exe', 'msbuild.exe', 'msiexec.exe',
    'regasm.exe', 'regsvcs.exe', 'ieexec.exe', 'presentationhost.exe', 'dfsvc.exe',
    'msdt.exe', 'pcalua.exe', 'xwizard.exe', 'mavinject.exe', 'wsreset.exe',
    'forfiles.exe', 'scriptrunner.exe', 'wmic.exe', 'hh.exe', 'extrac32.exe',
    'esentutl.exe', 'expand.exe', 'makecab.exe', 'print.exe', 'replace.exe',
    'ftp.exe', 'curl.exe', 'wget.exe', 'finger.exe', 'diskshadow.exe'
)

# Kesif komutlari - tek basina zararsiz, kumelenirse hands-on-keyboard gostergesi
$Script:DiscoveryBins = @(
    'whoami.exe', 'systeminfo.exe', 'nltest.exe', 'net.exe', 'net1.exe',
    'tasklist.exe', 'ipconfig.exe', 'arp.exe', 'route.exe', 'netstat.exe',
    'quser.exe', 'qwinsta.exe', 'klist.exe', 'dsquery.exe', 'nbtstat.exe'
)

# Sikistirma / exfil / tunel araclari
$Script:ExfilBins = @(
    'rar.exe', 'winrar.exe', '7z.exe', '7za.exe', 'rclone.exe', 'megacmd.exe',
    'megasync.exe', 'azcopy.exe', 'winscp.exe', 'psftp.exe', 'pscp.exe', 'ncat.exe',
    'nc.exe', 'plink.exe', 'chisel.exe', 'frpc.exe', 'ngrok.exe'
)

# Komut satiri tehlike pattern'leri
$Script:CmdLinePatterns = @(
    @{ P = '(?i)-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}'; N = 'Base64 encoded PowerShell'; S = 'CRITICAL'; M = 'T1027' }
    @{ P = '(?i)frombase64string';                           N = 'Base64 decode';            S = 'HIGH';     M = 'T1140' }
    @{ P = '(?i)(iex|invoke-expression)\s';                  N = 'Invoke-Expression';        S = 'HIGH';     M = 'T1059.001' }
    @{ P = '(?i)downloadstring|downloadfile|net\.webclient'; N = 'PowerShell indirici';      S = 'CRITICAL'; M = 'T1105' }
    @{ P = '(?i)invoke-webrequest|iwr\s|curl\s+http';        N = 'HTTP indirme';             S = 'MEDIUM';   M = 'T1105' }
    @{ P = '(?i)-w(indowstyle)?\s+hidden|-nop\b|-noni\b';    N = 'Gizli PowerShell';         S = 'HIGH';     M = 'T1564.003' }
    @{ P = '(?i)-ex(ecutionpolicy)?\s+bypass';               N = 'ExecutionPolicy bypass';   S = 'HIGH';     M = 'T1059.001' }
    @{ P = '(?i)vssadmin.*delete\s+shadows';                 N = 'Shadow copy deletion';        S = 'CRITICAL'; M = 'T1490' }
    @{ P = '(?i)wbadmin.*delete\s+(catalog|backup)';         N = 'Backup deletion';              S = 'CRITICAL'; M = 'T1490' }
    @{ P = '(?i)bcdedit.*(recoveryenabled\s+no|bootstatuspolicy)'; N = 'Recovery disabled'; S = 'CRITICAL'; M = 'T1490' }
    @{ P = '(?i)wevtutil\s+cl|clear-eventlog';               N = 'Event log clearing';      S = 'CRITICAL'; M = 'T1070.001' }
    @{ P = '(?i)comsvcs\.dll.*minidump';                     N = 'LSASS dump (comsvcs)';     S = 'CRITICAL'; M = 'T1003.001' }
    @{ P = '(?i)(procdump|rundll32).*lsass';                 N = 'LSASS dump girisimi';      S = 'CRITICAL'; M = 'T1003.001' }
    @{ P = '(?i)ntdsutil|ntds\.dit';                         N = 'NTDS.dit access';         S = 'CRITICAL'; M = 'T1003.003' }
    @{ P = '(?i)reg\s+save.*(hklm\\sam|hklm\\system|hklm\\security)'; N = 'SAM/SYSTEM hive dump'; S = 'CRITICAL'; M = 'T1003.002' }
    @{ P = '(?i)certutil.*(-urlcache|-decode|-encode|-decodehex)'; N = 'Certutil abuse'; S = 'HIGH'; M = 'T1105' }
    @{ P = '(?i)add-mppreference.*exclusionpath|set-mppreference.*-disable'; N = 'Defender exclusion or shutdown'; S = 'CRITICAL'; M = 'T1562.001' }
    @{ P = '(?i)netsh.*(firewall|advfirewall).*(disable|off)'; N = 'Firewall shutdown';       S = 'HIGH';     M = 'T1562.004' }
    @{ P = '(?i)netsh\s+interface\s+portproxy';              N = 'Port proxy (tunelleme)';   S = 'CRITICAL'; M = 'T1090' }
    @{ P = '(?i)\\\\[\w\.\-]+\\(admin|c|ipc)\$';             N = 'Admin share access';      S = 'HIGH';     M = 'T1021.002' }
    @{ P = '(?i)(psexec|paexec|smbexec|wmiexec|atexec)';      N = 'Remote execution tool'; S = 'HIGH';     M = 'T1569.002' }
    @{ P = '(?i)mimikatz|sekurlsa|lsadump|kerberos::';        N = 'Mimikatz';                 S = 'CRITICAL'; M = 'T1003' }
    @{ P = '(?i)rubeus|sharphound|seatbelt|bloodhound|certify\.exe'; N = 'Offensive toolkit'; S = 'CRITICAL'; M = 'T1587' }
    @{ P = '(?i)(rar|7z)(\.exe)?\s+a\s+.*-hp';               N = 'Password-protected archiving (exfil)'; S = 'HIGH';   M = 'T1560.001' }
    @{ P = '(?i)schtasks.*/create.*/ru\s+system';            N = 'Task creation as SYSTEM'; S = 'HIGH'; M = 'T1053.005' }
    @{ P = '(?i)sc\s+(create|config).*binpath';              N = 'Service creation or modification'; S = 'HIGH';  M = 'T1543.003' }
    @{ P = '(?i)net\s+(user|localgroup).*\/add';             N = 'Account or group creation';        S = 'HIGH';     M = 'T1136' }
    @{ P = '(?i)nltest.*(/dclist|/domain_trusts)';           N = 'Domain kesfi';             S = 'MEDIUM';   M = 'T1482' }
)

# Ust process -> alt process anomalileri
$Script:BadParentChild = @(
    @{ Parent = 'winword|excel|powerpnt|outlook|msaccess|onenote'
       Child  = 'cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil'
       Name   = 'Office application spawned a shell'; S = 'CRITICAL'; M = 'T1566.001' }
    @{ Parent = 'w3wp|httpd|nginx|tomcat|java|php-cgi|node'
       Child  = 'cmd|powershell|pwsh|wscript|cscript|net|net1|whoami'
       Name   = 'Web server spawned a shell (WEBSHELL)'; S = 'CRITICAL'; M = 'T1505.003' }
    @{ Parent = 'sqlservr|mysqld|postgres'
       Child  = 'cmd|powershell|pwsh'
       Name   = 'Database service spawned a shell'; S = 'CRITICAL'; M = 'T1190' }
    @{ Parent = 'wmiprvse'
       Child  = 'cmd|powershell|pwsh|mshta|rundll32'
       Name   = 'Execution via WMI (lateral movement)'; S = 'HIGH'; M = 'T1047' }
    @{ Parent = 'mmc|taskeng|schtasks'
       Child  = 'cmd|powershell|pwsh'
       Name   = 'Scheduled task or MMC spawned a shell'; S = 'MEDIUM'; M = 'T1053.005' }
    @{ Parent = 'services'
       Child  = 'cmd|powershell|pwsh|rundll32'
       Name   = 'services.exe spawned a shell directly'; S = 'HIGH'; M = 'T1543.003' }
    @{ Parent = 'winlogon|lsass|csrss|smss'
       Child  = 'cmd|powershell|pwsh|net|whoami'
       Name   = 'Critical system process abused'; S = 'CRITICAL'; M = 'T1055' }
    @{ Parent = 'explorer'
       Child  = 'mshta|regsvr32|certutil|bitsadmin'
       Name   = 'User launched a LOLBAS binary'; S = 'MEDIUM'; M = 'T1218' }
)

# Bilinen C2 named pipe pattern'leri (Cobalt Strike varsayilanlari dahil)
$Script:BadPipePatterns = @(
    'msagent_', 'MSSE-', 'postex_', 'status_', 'srvsvc_', 'ntsvcs_', 'scerpc_',
    'wkssvc_', 'lsarpc_', 'atsvc_', 'spoolss_', 'netlogon_', 'f4c3',
    'demoagent', 'gruntsvc', 'psexesvc', 'paexec', 'remcom', 'csexec', '^\d{4}$'
)

# Windows'un mesru kisa servis adlari - rastgele-isim kuralinda haric tutulur
$Script:KnownServiceNames = @(
    'Spooler','Winmgmt','Dnscache','EventLog','Themes','Schedule','LanmanServer',
    'LanmanWorkstation','TermService','RpcSs','RpcEptMapper','DcomLaunch','BITS','wuauserv',
    'W32Time','WinRM','WinDefend','MpsSvc','SessionEnv','UmRdpService','ProfSvc','Netlogon',
    'NlaSvc','Dhcp','Audiosrv','AudioEndpointBuilder','CryptSvc','TrustedInstaller','MSDTC',
    'SamSs','KeyIso','Power','SysMain','Wcmsvc','WlanSvc','WSearch','WdiServiceHost',
    'WdiSystemHost','Wecsvc','WEPHOSTSVC','WPDBusEnum','wscsvc','WerSvc','TrkWks','swprv',
    'StorSvc','ShellHWDetection','seclogon','SENS','SharedAccess','RemoteRegistry','PolicyAgent',
    'PlugPlay','pla','p2pimsvc','netprofm','MSiSCSI','msiserver','LSM','KtmRm','iphlpsvc',
    'IKEEXT','gpsvc','FontCache','EFS','DsmSvc','DPS','DoSvc','DiagTrack','Dfs','DFSR',
    'defragsvc','CertPropSvc','CDPSvc','camsvc','BrokerInfrastructure','BFE','Browser',
    'AppMgmt','Appinfo','AJRouter','ALG','aspnet_state','NTDS','DNS','kdc','IsmServ',
    'ADWS','Eaphost','hidserv','hkmsvc','lltdsvc','MMCSS','napagent','NcaSvc','Netman',
    'NcbService','nsi','PcaSvc','PerfHost','PNRPsvc','QWAVE','RasAuto','RasMan','RmSvc',
    'RpcLocator','RSoPProv','sacsvr','SCardSvr','ScDeviceEnum','SCPolicySvc','SDRSVC',
    'SNMPTRAP','sppsvc','SSDPSRV','SstpSvc','svsvc','TabletInputService','TapiSrv',
    'TieringEngineService','TimeBrokerSvc','TokenBroker','UALSVC','UI0Detect','UevAgentService',
    'upnphost','UserManager','usosvc','VaultSvc','vds','VSS','W3SVC','WAS','WalletService',
    'WbioSrvc','wbengine','WcsPlugInService','webthreatdefsvc','wercplsupport','WFDSConMgrSvc',
    'WiaRpc','WinHttpAutoProxySvc','wisvc','wlidsvc','wmiApSrv','WMPNetworkSvc','workfolderssvc',
    'WpnService','WwanSvc','XblAuthManager','XboxNetApiSvc','WMSvc','AppHostSvc','SQLBrowser',
    'MSSQLSERVER','SQLSERVERAGENT','SQLTELEMETRY','SQLWriter','ClusSvc','Netlogon','IaStorDataMgrSvc'
)

function Test-DRandomName {
    <#
        Rastgele uretilmis servis/gorev adi tespiti (Cobalt Strike, Impacket, Metasploit
        varsayilan davranisi). Basit "buyuk+kucuk harf" kontrolu 'Spooler', 'Winmgmt'
        gibi mesru servislerde false positive uretir; entropi gostergeleri kullaniyoruz.
    #>
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Name -notmatch '^[a-zA-Z0-9]{6,14}$') { return $false }
    if ($Script:KnownServiceNames -contains $Name) { return $false }
    # Bilinen urun onekleri
    if ($Name -match '(?i)^(Microsoft|Windows|Intel|NVIDIA|AMD|Realtek|Adobe|Google|Mozilla|VMware|Citrix|Dell|HP|Lenovo|Sophos|Symantec|McAfee|Trend|Kaspersky|ESET|CrowdStrike|SentinelOne|Splunk|Nessus|Qualys|Rapid7|Tanium|Zabbix|Nagios|Veeam|Acronis|Sql|MSSql|Oracle|IBM|SAP)') { return $false }
    # Urun adlandirma sonekleri - rastgele ureticiler bunlari kullanmaz
    if ($Name -match '(?i)(Svc|Service|Srv|Server|Host|Agent|Mgr|Manager|Sys|Daemon|Broker|Helper|Monitor|Update|Client|Sync|Launcher|Worker|Handler|Provider|Listener)$') { return $false }

    $signals = 0

    # 1. Harf ve rakam ic ice (a9d3f1c2, xY9kLm2p) - urun adlarinda rakam genelde sonda olur
    if ($Name -match '[a-zA-Z]' -and $Name -match '\d' -and $Name -notmatch '^\D+\d+$') { $signals++ }

    # 2. Cok dusuk sesli harf orani - rastgele diziler telaffuz edilemez
    $vowels = ([regex]::Matches($Name, '(?i)[aeiou]')).Count
    if (($vowels / $Name.Length) -lt 0.20) { $signals++ }

    # 3. Coklu buyuk/kucuk gecisi (aBcDeF) - CamelCase'de 1-2 gecis olur, 3+ anormal
    $trans = 0
    for ($i = 1; $i -lt $Name.Length; $i++) {
        $p = $Name[$i - 1]; $c = $Name[$i]
        if ([char]::IsLetter($p) -and [char]::IsLetter($c)) {
            if ([char]::IsUpper($p) -ne [char]::IsUpper($c)) { $trans++ }
        }
    }
    if ($trans -ge 3) { $signals++ }

    # 4. Ustuste 6+ sessiz harf (kisaltmalar 5'e kadar cikabilir: SQLBr, NPSMS)
    if ($Name -match '(?i)[bcdfghjklmnpqrstvwxyz]{6,}') { $signals++ }

    return ($signals -ge 2)
}
$Script:SystemBinNames = @(
    'svchost.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe', 'services.exe',
    'smss.exe', 'wininit.exe', 'taskhostw.exe', 'spoolsv.exe', 'dllhost.exe',
    'conhost.exe', 'RuntimeBroker.exe', 'SearchIndexer.exe', 'lsm.exe', 'ctfmon.exe'
)

# ============================================================================
#  REGISTRY YARDIMCILARI
# ============================================================================

function Get-DRegValues {
    <# Bir registry anahtarindaki degerleri PS meta-property'leri haric dondurur #>
    param([string]$Path)

    $out = @()
    try { $item = Get-ItemProperty -Path $Path -ErrorAction Stop } catch { return $out }
    if (-not $item) { return $out }

    foreach ($p in $item.PSObject.Properties) {
        if ($p.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }
        $val = $p.Value
        if ($val -is [array]) { $val = ($val -join ' | ') }
        $out += [PSCustomObject]@{ Name = $p.Name; Value = [string]$val }
    }
    return $out
}

function Get-DUserHives {
    <#
        Yuklu kullanici hive'lari (HKU). Eski script sadece HKCU'ya bakiyordu,
        yani IR operatorunun kendi profiline - kurbanin degil.
    #>
    $hives = @()
    try {
        Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction Stop |
            Where-Object { $_.PSChildName -match '^S-1-5-21-' -and
                           $_.PSChildName -notmatch '_Classes$' } |
            ForEach-Object {
                $sid  = $_.PSChildName
                $name = $sid
                try {
                    $sidObj = New-Object Security.Principal.SecurityIdentifier($sid)
                    $name   = $sidObj.Translate([Security.Principal.NTAccount]).Value
                } catch { }
                $hives += [PSCustomObject]@{
                    Sid = $sid; User = $name; RegRoot = "Registry::HKEY_USERS\$sid"
                }
            }
    } catch { }
    return $hives
}

function New-DAutorunEntry {
    <# Tum ASEP'ler icin normalize kayit uretici - hash/imza/suspicious otomatik #>
    param(
        [string]$Category, [string]$Location, [string]$Name,
        [string]$Value, [string]$User = 'MACHINE'
    )

    $bin  = Get-DCleanPath -CommandLine $Value
    $sig  = Get-DSignature -Path $bin
    $exists = $false
    $hash = $null
    $ft   = $null

    if ($bin) {
        try {
            if (Test-Path -LiteralPath $bin -PathType Leaf -ErrorAction SilentlyContinue) {
                $exists = $true
                $hash   = Get-DFileHashSafe -Path $bin
                $ft     = (Get-Item -LiteralPath $bin -Force -ErrorAction Stop).LastWriteTime
            }
        } catch { }
    }

    return [PSCustomObject]@{
        Category       = $Category
        Location       = $Location
        User           = $User
        Name           = $Name
        Value          = $Value
        BinaryPath     = $bin
        BinaryExists   = $exists
        BinaryWriteUtc = ConvertTo-DUtcString $ft
        Signed         = $sig.IsValid
        Signer         = $sig.Signer
        SigStatus      = $sig.Status
        IsMicrosoft    = $sig.IsMicrosoft
        SHA256         = $hash
        SuspiciousPath = Test-DSuspiciousPath -Path $bin
    }
}

function Invoke-DAutorunTriage {
    <# Autoruns tablosundaki her satir icin ortak kural seti #>
    param([object]$Entry, [string]$Artifact)

    $ev = "[$($Entry.Category)] $($Entry.Name) = $($Entry.Value)"

    if ($Entry.SuspiciousPath) {
        Add-DFinding -RuleId 'DGL-030' -Severity CRITICAL `
            -Title 'Autorun runs from a suspicious directory' -Evidence $ev `
            -Mitre 'T1547' -Artifact $Artifact `
            -Why 'Legitimate autorun entries live under System32 or Program Files'
    }
    elseif ($Entry.BinaryExists -and -not $Entry.Signed -and -not $Entry.IsMicrosoft) {
        Add-DFinding -RuleId 'DGL-031' -Severity HIGH `
            -Title 'Unsigned autorun binary' -Evidence "$ev  (imza: $($Entry.SigStatus))" `
            -Mitre 'T1547' -Artifact $Artifact -Why 'Unsigned persistent startup entry'
    }

    if ($Entry.BinaryPath -and -not $Entry.BinaryExists -and
        $Entry.Category -notmatch 'Winlogon|LSA|Netsh') {
        Add-DFinding -RuleId 'DGL-032' -Severity MEDIUM `
            -Title 'Autorun target is missing' -Evidence $ev -Artifact $Artifact `
            -Why 'Either the remnant of removed malware or an opportunity for path hijacking'
    }

    foreach ($pat in $Script:CmdLinePatterns) {
        if ($Entry.Value -match $pat.P) {
            Add-DFinding -RuleId 'DGL-033' -Severity $pat.S `
                -Title "Suspicious autorun command: $($pat.N)" -Evidence $ev `
                -Mitre $pat.M -Artifact $Artifact `
                -Why 'A persistence entry matches an attacker behaviour pattern'
            break
        }
    }

    if ($Entry.SHA256) { $null = Test-DIoc -Value $Entry.SHA256 -Context $ev -Artifact $Artifact }
}

# ============================================================================
#  MODUL: HESAPLAR VE GRUPLAR
# ============================================================================

Register-DModule -Name 'Users and groups' -Phase 1 `
    -Description 'Local accounts, group membership, profiles, sessions' -Body {

    # --- Lokal kullanicilar ---
    $users = @()
    if ($Script:Caps.LocalAccounts) {
        try {
            $users = Get-LocalUser -ErrorAction Stop | ForEach-Object {
                [PSCustomObject]@{
                    Name                  = $_.Name
                    SID                   = $_.SID.Value
                    Enabled               = $_.Enabled
                    Description           = $_.Description
                    LastLogonUtc          = ConvertTo-DUtcString $_.LastLogon
                    PasswordLastSetUtc    = ConvertTo-DUtcString $_.PasswordLastSet
                    PasswordRequired      = $_.PasswordRequired
                    UserMayChangePassword = $_.UserMayChangePassword
                    PrincipalSource       = [string]$_.PrincipalSource
                }
            }
        } catch { }
    } else {
        # PS4 / 2012 R2 fallback - ADSI
        try {
            $adsi  = [ADSI]"WinNT://$env:COMPUTERNAME"
            $users = $adsi.Children | Where-Object { $_.SchemaClassName -eq 'user' } |
                ForEach-Object {
                    $u = $_
                    [PSCustomObject]@{
                        Name        = [string]$u.Name
                        SID         = (New-Object Security.Principal.SecurityIdentifier(
                                        $u.objectSid.Value, 0)).Value
                        Enabled     = -not (($u.UserFlags.Value -band 2) -eq 2)
                        Description = [string]$u.Description
                        LastLogonUtc = ConvertTo-DUtcString $u.LastLogin.Value
                        PasswordLastSetUtc = $null
                        PasswordRequired = -not (($u.UserFlags.Value -band 32) -eq 32)
                        UserMayChangePassword = $null
                        PrincipalSource = 'Local(ADSI)'
                    }
                }
        } catch { }
    }
    Export-DArtifact -Name '02_local_users' -Data $users

    # --- Kritik grup uyelikleri ---
    # ESKI SCRIPT BUGU: Get-LocalGroup Administrators grubun KENDISINI donuyordu,
    # uyelerini degil. Get-LocalGroupMember olmasi gerekiyordu.
    $members = @()
    $criticalGroups = @('Administrators', 'Remote Desktop Users', 'Backup Operators',
                        'Power Users', 'Remote Management Users', 'Distributed COM Users',
                        'Print Operators', 'Server Operators', 'Account Operators')

    foreach ($g in $criticalGroups) {
        try {
            foreach ($m in (Get-LocalGroupMember -Group $g -ErrorAction Stop)) {
                $members += [PSCustomObject]@{
                    Group           = $g
                    Member          = $m.Name
                    SID             = $m.SID.Value
                    ObjectClass     = $m.ObjectClass
                    PrincipalSource = [string]$m.PrincipalSource
                }
            }
        } catch { continue }
    }

    # SID tabanli yedek (lokalize Windows: "Yoneticiler" vb.)
    if ($members.Count -eq 0) {
        $sidMap = @{ 'S-1-5-32-544' = 'Administrators'
                     'S-1-5-32-555' = 'Remote Desktop Users'
                     'S-1-5-32-551' = 'Backup Operators' }
        foreach ($sid in $sidMap.Keys) {
            try {
                $grp = Get-CimInstance Win32_Group -Filter "SID='$sid'" -ErrorAction Stop
                if (-not $grp) { continue }
                $adsiGrp = [ADSI]"WinNT://$env:COMPUTERNAME/$($grp.Name),group"
                foreach ($mem in @($adsiGrp.Invoke('Members'))) {
                    $mname = $mem.GetType().InvokeMember('Name', 'GetProperty', $null, $mem, $null)
                    $members += [PSCustomObject]@{
                        Group = $sidMap[$sid]; Member = $mname
                        SID = $null; ObjectClass = 'Unknown'; PrincipalSource = 'ADSI'
                    }
                }
            } catch { }
        }
    }
    Export-DArtifact -Name '02_group_members' -Data $members

    # --- Kullanici profilleri (yeni hesap = persistence gostergesi) ---
    $profiles = @()
    try {
        $profiles = Get-CimInstance Win32_UserProfile -ErrorAction Stop |
            Where-Object { $_.SID -match '^S-1-5-21-' } |
            ForEach-Object {
                $created = $null
                try {
                    if ($_.LocalPath -and (Test-Path $_.LocalPath)) {
                        $created = (Get-Item $_.LocalPath -Force -ErrorAction Stop).CreationTime
                    }
                } catch { }
                $uname = $_.SID
                try {
                    $sidObj = New-Object Security.Principal.SecurityIdentifier($_.SID)
                    $uname  = $sidObj.Translate([Security.Principal.NTAccount]).Value
                } catch { }
                [PSCustomObject]@{
                    User           = $uname
                    SID            = $_.SID
                    LocalPath      = $_.LocalPath
                    ProfileCreated = ConvertTo-DUtcString $created
                    LastUseUtc     = ConvertTo-DUtcString $_.LastUseTime
                    Loaded         = $_.Loaded
                    Special        = $_.Special
                }
            }
    } catch { }
    Export-DArtifact -Name '02_user_profiles' -Data $profiles

    # --- Aktif oturumlar ---
    $sessions = @()
    try {
        $logonSessions = Get-CimInstance Win32_LogonSession -ErrorAction Stop
        $loggedOn      = Get-CimInstance Win32_LoggedOnUser -ErrorAction Stop
        $userBySession = @{}
        foreach ($lo in $loggedOn) {
            if ($lo.Dependent.LogonId) {
                $userBySession[[string]$lo.Dependent.LogonId] =
                    "$($lo.Antecedent.Domain)\$($lo.Antecedent.Name)"
            }
        }
        $sessions = $logonSessions | ForEach-Object {
            $lt = [int]$_.LogonType
            [PSCustomObject]@{
                LogonId       = $_.LogonId
                User          = $userBySession[[string]$_.LogonId]
                LogonType     = $lt
                LogonTypeName = switch ($lt) {
                    2 { 'Interactive' } 3 { 'Network' } 4 { 'Batch' } 5 { 'Service' }
                    7 { 'Unlock' } 8 { 'NetworkCleartext' } 9 { 'NewCredentials(RunAs)' }
                    10 { 'RemoteInteractive(RDP)' } 11 { 'CachedInteractive' }
                    default { "Type$lt" }
                }
                AuthPackage = $_.AuthenticationPackage
                StartUtc    = ConvertTo-DUtcString $_.StartTime
            }
        }
    } catch { }
    Export-DArtifact -Name '02_logon_sessions' -Data $sessions

    # --- TRIAGE ---
    $now = Get-Date

    foreach ($u in $users) {
        if ($u.PasswordLastSetUtc) {
            try {
                $age = ($now - [DateTime]$u.PasswordLastSetUtc).TotalDays
                if ($age -lt $Days -and $u.Enabled) {
                    Add-DFinding -RuleId 'DGL-020' -Severity MEDIUM `
                        -Title 'Account password changed inside the analysis window' `
                        -Evidence "$($u.Name) - $($u.PasswordLastSetUtc)" `
                        -Mitre 'T1098' -Artifact '02_local_users' `
                        -Timestamp $u.PasswordLastSetUtc `
                        -Why 'If the account was taken over, the attacker may have changed the password'
                }
            } catch { }
        }
        if ($u.Enabled -and $false -eq $u.PasswordRequired) {
            Add-DFinding -RuleId 'DGL-021' -Severity HIGH `
                -Title 'Active account requires no password' -Evidence $u.Name `
                -Mitre 'T1078.003' -Artifact '02_local_users' `
                -Why 'An enabled account with no password grants direct access'
        }
        if ($u.Enabled -and $u.SID -match '-(500|501)$') {
            $sev = if ($u.SID -match '-501$') { 'HIGH' } else { 'MEDIUM' }
            Add-DFinding -RuleId 'DGL-022' -Severity $sev `
                -Title 'Built-in account is enabled' `
                -Evidence "$($u.Name) (RID: $($u.SID.Split('-')[-1]))" `
                -Mitre 'T1078.001' -Artifact '02_local_users' `
                -Why 'Guest and the built-in Administrator should normally be disabled'
        }
    }

    foreach ($p in $profiles) {
        if (-not $p.ProfileCreated) { continue }
        try {
            $age = ($now - [DateTime]$p.ProfileCreated).TotalDays
            if ($age -lt $Days) {
                Add-DFinding -RuleId 'DGL-023' -Severity HIGH `
                    -Title 'User profile created inside the analysis window' `
                    -Evidence "$($p.User) - $($p.LocalPath) @ $($p.ProfileCreated)" `
                    -Mitre 'T1136.001' -Artifact '02_user_profiles' `
                    -Timestamp $p.ProfileCreated `
                    -Why 'Creating a new account is a common persistence technique'
                Add-DTimelineEvent -Timestamp $p.ProfileCreated -Source 'Accounts' `
                    -Description "New profile: $($p.User)" -Detail $p.LocalPath -Severity HIGH
            }
        } catch { }
    }

    $adminCount = @($members | Where-Object Group -eq 'Administrators').Count
    if ($adminCount -gt 5) {
        Add-DFinding -RuleId 'DGL-024' -Severity MEDIUM `
            -Title 'Unusually large local Administrators group' `
            -Evidence "$adminCount uye" -Mitre 'T1078' -Artifact '02_group_members' `
            -Why 'Broad administrator membership enlarges the lateral movement surface'
    }

    Write-DLog "  $($users.Count) users, $($members.Count) group memberships, $($sessions.Count) sessions" -Level DEBUG
}

# ============================================================================
#  MODUL: PROCESS AGACI
# ============================================================================

Register-DModule -Name 'Process tree' -Phase 1 `
    -Description 'All processes with command lines, signatures, hashes and parent-child analysis' -Body {

    # NOT: Get-Process DEGIL Win32_Process - CommandLine alani sadece CIM/WMI'de var
    $raw = @()
    try { $raw = Get-CimInstance Win32_Process -ErrorAction Stop }
    catch { try { $raw = Get-WmiObject Win32_Process -ErrorAction Stop } catch { } }

    if (@($raw).Count -eq 0) {
        Write-DLog '  Could not enumerate processes' -Level ERROR
        return
    }

    # Kullanici eslemesi - process basina GetOwner cagirmak yavas
    $ownerMap = @{}
    try {
        Get-Process -IncludeUserName -ErrorAction Stop | ForEach-Object {
            if ($_.UserName) { $ownerMap[[int]$_.Id] = $_.UserName }
        }
    } catch {
        foreach ($p in $raw) {
            try {
                $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
                if ($o.ReturnValue -eq 0) {
                    $ownerMap[[int]$p.ProcessId] = "$($o.Domain)\$($o.User)"
                }
            } catch { }
        }
    }

    # PID -> isim haritasi (parent cozumlemesi icin)
    $nameMap = @{}
    foreach ($p in $raw) { $nameMap[[int]$p.ProcessId] = $p.Name }

    # CPU / bellek icin tek cagri
    $perfMap = @{}
    try {
        Get-Process -ErrorAction Stop | ForEach-Object {
            $perfMap[[int]$_.Id] = [PSCustomObject]@{
                CPU = $_.CPU; WS = $_.WorkingSet64
                Threads = $_.Threads.Count; Handles = $_.HandleCount
            }
        }
    } catch { }

    $procs = foreach ($p in $raw) {
        $procId   = [int]$p.ProcessId
        $parentId = [int]$p.ParentProcessId
        $path     = $p.ExecutablePath
        $sig      = Get-DSignature -Path $path
        $perf     = $perfMap[$procId]
        $baseName = if ($p.Name) { $p.Name.ToLowerInvariant() } else { '' }

        [PSCustomObject]@{
            PID            = $procId
            PPID           = $parentId
            ParentName     = $nameMap[$parentId]
            Name           = $p.Name
            Path           = $path
            CommandLine    = $p.CommandLine
            User           = $ownerMap[$procId]
            StartTimeUtc   = ConvertTo-DUtcString (ConvertTo-DDateTime $p.CreationDate)
            SessionId      = $p.SessionId
            Signed         = $sig.IsValid
            Signer         = $sig.Signer
            SigStatus      = $sig.Status
            IsMicrosoft    = $sig.IsMicrosoft
            SHA256         = if ($path) { Get-DFileHashSafe -Path $path } else { $null }
            SuspiciousPath = Test-DSuspiciousPath -Path $path
            IsLolBas       = ($Script:LolBasExec -contains $baseName)
            IsDiscovery    = ($Script:DiscoveryBins -contains $baseName)
            IsExfilTool    = ($Script:ExfilBins -contains $baseName)
            CPU            = if ($perf) { [math]::Round($perf.CPU, 2) } else { $null }
            WorkingSetMB   = if ($perf) { [math]::Round($perf.WS / 1MB, 2) } else { $null }
            Threads        = if ($perf) { $perf.Threads } else { $null }
            Handles        = if ($perf) { $perf.Handles } else { $null }
        }
    }

    $procs = @($procs)
    Export-DArtifact -Name '03_processes' -Data $procs -AsJson

    # Process index - ag modulu bunu kullanacak, tekrar sorgu yok (O(1) lookup)
    $Script:ProcIndex = @{}
    foreach ($pr in $procs) { $Script:ProcIndex[$pr.PID] = $pr }

    # --- TRIAGE ---
    foreach ($pr in $procs) {
        $ev = "PID $($pr.PID) $($pr.Name) -> $($pr.Path)"

        if ($pr.SuspiciousPath) {
            Add-DFinding -RuleId 'DGL-040' -Severity HIGH `
                -Title 'Process running from a suspicious directory' `
                -Evidence "$ev  [user: $($pr.User)]" `
                -Mitre 'T1036' -Artifact '03_processes' -Timestamp $pr.StartTimeUtc `
                -Why 'Temp, AppData and ProgramData are the most common malware working directories'
        }

        if ($pr.Path -and $false -eq $pr.Signed -and -not $pr.IsMicrosoft -and
            $pr.Path -match '(?i)\\Users\\') {
            Add-DFinding -RuleId 'DGL-041' -Severity HIGH `
                -Title 'Unsigned process running from a user profile' `
                -Evidence "$ev  (imza: $($pr.SigStatus))" `
                -Mitre 'T1204' -Artifact '03_processes' -Timestamp $pr.StartTimeUtc `
                -Why 'Legitimate software is normally signed and under Program Files'
        }

        # Dogru isim, yanlis yer = masquerading
        if ($Script:SystemBinNames -contains $pr.Name -and $pr.Path -and
            $pr.Path -notmatch '(?i)\\Windows\\(System32|SysWOW64|WinSxS)\\') {
            Add-DFinding -RuleId 'DGL-042' -Severity CRITICAL `
                -Title 'System binary in an unexpected location (masquerading)' -Evidence $ev `
                -Mitre 'T1036.005' -Artifact '03_processes' -Timestamp $pr.StartTimeUtc `
                -Why "$($pr.Name) normally runs from System32"
        }

        if ($pr.CommandLine) {
            foreach ($pat in $Script:CmdLinePatterns) {
                if ($pr.CommandLine -match $pat.P) {
                    $len = [Math]::Min(300, $pr.CommandLine.Length)
                    $cl  = $pr.CommandLine.Substring(0, $len)
                    Add-DFinding -RuleId 'DGL-043' -Severity $pat.S `
                        -Title "Suspicious command line: $($pat.N)" `
                        -Evidence "PID $($pr.PID) [$($pr.User)] $cl" `
                        -Mitre $pat.M -Artifact '03_processes' -Timestamp $pr.StartTimeUtc `
                        -Why 'Command line matching known attacker behaviour'
                }
            }
        }

        if ($pr.ParentName) {
            $pn = $pr.ParentName -replace '\.exe$', ''
            $cn = $pr.Name -replace '\.exe$', ''
            foreach ($rule in $Script:BadParentChild) {
                if ($pn -match "^($($rule.Parent))$" -and $cn -match "^($($rule.Child))$") {
                    Add-DFinding -RuleId 'DGL-044' -Severity $rule.S -Title $rule.Name `
                        -Evidence "$($pr.ParentName) (PID $($pr.PPID)) -> $($pr.Name) (PID $($pr.PID))" `
                        -Mitre $rule.M -Artifact '03_processes' -Timestamp $pr.StartTimeUtc `
                        -Why 'This parent-child relationship does not occur during normal operation'
                    break
                }
            }
        }

        if ($pr.IsExfilTool) {
            Add-DFinding -RuleId 'DGL-045' -Severity HIGH `
                -Title 'Archiving, exfiltration or tunnelling tool running' -Evidence $ev `
                -Mitre 'T1560' -Artifact '03_processes' -Timestamp $pr.StartTimeUtc `
                -Why 'Indicates the collection and exfiltration stage'
        }

        if (-not $pr.Path -and $pr.PID -gt 4 -and
            $pr.Name -notmatch '^(System|Registry|Secure System|Memory Compression)$') {
            Add-DFinding -RuleId 'DGL-046' -Severity MEDIUM `
                -Title 'Process path could not be read' -Evidence "PID $($pr.PID) $($pr.Name)" `
                -Artifact '03_processes' `
                -Why 'May be a protected process, or the image was deleted from disk'
        }

        if ($pr.SHA256) { $null = Test-DIoc -Value $pr.SHA256 -Context $ev -Artifact '03_processes' }

        if ($pr.StartTimeUtc) {
            $sev = if ($pr.SuspiciousPath -or $pr.IsLolBas) { 'MEDIUM' } else { 'INFO' }
            Add-DTimelineEvent -Timestamp $pr.StartTimeUtc -Source 'Process' `
                -Description "$($pr.Name) started (PID $($pr.PID))" `
                -Detail $pr.CommandLine -Severity $sev
        }
    }

    # Kesif komutu kumelenmesi = hands-on-keyboard
    $disc = @($procs | Where-Object IsDiscovery)
    if ($disc.Count -ge 4) {
        $names = ($disc | Select-Object -First 8 |
                  ForEach-Object { "$($_.Name)(PID $($_.PID))" }) -join ', '
        Add-DFinding -RuleId 'DGL-047' -Severity HIGH `
            -Title 'Multiple discovery commands running together' -Evidence $names `
            -Mitre 'T1082' -Artifact '03_processes' `
            -Why 'Indicates hands-on-keyboard discovery activity'
    }

    $unsigned = @($procs | Where-Object { $_.Path -and $false -eq $_.Signed }).Count
    Write-DLog "  $($procs.Count) processes ($unsigned unsigned)" -Level DEBUG
}

# ============================================================================
#  MODUL: AG BAGLANTILARI
# ============================================================================

Register-DModule -Name 'Network connections' -Phase 1 -RequiresCap 'NetTCP' `
    -Description 'TCP/UDP joined to processes, portproxy, proxy settings, DNS' -Body {

    if (-not $Script:ProcIndex) { $Script:ProcIndex = @{} }

    $privateRegex = '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|0\.0\.0\.0$|::1$|::$|fe80:)'

    # --- TCP (process'e JOIN edilmis - eski scriptte sadece IP listesi vardi) ---
    $tcp = @()
    try {
        $tcp = Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
            $op = [int]$_.OwningProcess
            $pi = $Script:ProcIndex[$op]
            $rdns = $null
            if (-not $NoResolve -and $_.RemoteAddress -notmatch $privateRegex) {
                try { $rdns = [Net.Dns]::GetHostEntry($_.RemoteAddress).HostName } catch { }
            }
            [PSCustomObject]@{
                Protocol        = 'TCP'
                LocalAddress    = $_.LocalAddress
                LocalPort       = $_.LocalPort
                RemoteAddress   = $_.RemoteAddress
                RemotePort      = $_.RemotePort
                State           = [string]$_.State
                PID             = $op
                ProcessName     = if ($pi) { $pi.Name } else { $null }
                ProcessPath     = if ($pi) { $pi.Path } else { $null }
                ProcessUser     = if ($pi) { $pi.User } else { $null }
                Signed          = if ($pi) { $pi.Signed } else { $null }
                SHA256          = if ($pi) { $pi.SHA256 } else { $null }
                SuspiciousPath  = if ($pi) { $pi.SuspiciousPath } else { $false }
                CreationTimeUtc = ConvertTo-DUtcString $_.CreationTime
                RemoteIsPrivate = [bool]($_.RemoteAddress -match $privateRegex)
                RemoteRDNS      = $rdns
            }
        }
    } catch {
        Write-DLog "  TCP baglantilari alinamadi: $($_.Exception.Message)" -Level WARN
    }
    Export-DArtifact -Name '04_tcp_connections' -Data $tcp

    # --- UDP ---
    $udp = @()
    try {
        $udp = Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
            $op = [int]$_.OwningProcess
            $pi = $Script:ProcIndex[$op]
            [PSCustomObject]@{
                Protocol = 'UDP'; LocalAddress = $_.LocalAddress; LocalPort = $_.LocalPort
                PID = $op
                ProcessName = if ($pi) { $pi.Name } else { $null }
                ProcessPath = if ($pi) { $pi.Path } else { $null }
                Signed = if ($pi) { $pi.Signed } else { $null }
                SuspiciousPath = if ($pi) { $pi.SuspiciousPath } else { $false }
                CreationTimeUtc = ConvertTo-DUtcString $_.CreationTime
            }
        }
    } catch { }
    Export-DArtifact -Name '04_udp_endpoints' -Data $udp

    # --- Dinleyen portlar (backdoor dinleyicisi burada cikar) ---
    $listen = @($tcp | Where-Object { $_.State -eq 'Listen' })
    Export-DArtifact -Name '04_listening_ports' -Data $listen

    # --- Port proxy (tunelleme - eski scriptte hic yoktu, cok kritik) ---
    $portproxy = @()
    try {
        $pp = netsh interface portproxy show all 2>$null
        if ($pp) {
            $portproxy = @($pp | Where-Object { $_ -match '^\s*[\d\*]' } | ForEach-Object {
                $f = (($_ -replace '\s+', ' ').Trim() -split ' ')
                if ($f.Count -ge 4) {
                    [PSCustomObject]@{
                        ListenAddress = $f[0]; ListenPort = $f[1]
                        ConnectAddress = $f[2]; ConnectPort = $f[3]
                    }
                }
            })
        }
    } catch { }
    Export-DArtifact -Name '04_portproxy' -Data $portproxy

    foreach ($p in $portproxy) {
        Add-DFinding -RuleId 'DGL-050' -Severity CRITICAL `
            -Title 'netsh portproxy rule present (tunnelling)' `
            -Evidence "$($p.ListenAddress):$($p.ListenPort) -> $($p.ConnectAddress):$($p.ConnectPort)" `
            -Mitre 'T1090.001' -Artifact '04_portproxy' `
            -Why 'Port forwarding is almost always for pivoting or tunnelling'
    }

    # --- Proxy yapilandirmasi ---
    $proxyCfg = New-Object System.Collections.ArrayList
    try {
        $wh = netsh winhttp show proxy 2>$null
        $null = $proxyCfg.Add([PSCustomObject]@{
            Scope = 'WinHTTP'; Setting = (($wh -join ' ') -replace '\s+', ' ').Trim()
        })
    } catch { }

    foreach ($h in (Get-DUserHives)) {
        $isKey = "$($h.RegRoot)\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        foreach ($x in (Get-DRegValues -Path $isKey |
                        Where-Object Name -in 'ProxyEnable', 'ProxyServer', 'AutoConfigURL')) {
            $null = $proxyCfg.Add([PSCustomObject]@{
                Scope = "WinINET:$($h.User)"; Setting = "$($x.Name)=$($x.Value)"
            })
            if ($x.Name -eq 'AutoConfigURL' -and $x.Value) {
                Add-DFinding -RuleId 'DGL-051' -Severity HIGH `
                    -Title 'User proxy AutoConfigURL is set' `
                    -Evidence "$($h.User): $($x.Value)" `
                    -Mitre 'T1090' -Artifact '04_proxy_config' `
                    -Why 'A malicious PAC file can route traffic through attacker infrastructure'
            }
        }
    }
    Export-DArtifact -Name '04_proxy_config' -Data @($proxyCfg)

    # --- ARP + route (lateral movement haritasi) ---
    $arp = @()
    try {
        $arp = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop |
               Where-Object { $_.State -notin 'Unreachable', 'Permanent' } |
               Select-Object IPAddress, LinkLayerAddress,
                             @{N = 'State'; E = { [string]$_.State } }, InterfaceAlias
    } catch { }
    Export-DArtifact -Name '04_arp_cache' -Data $arp

    $routes = @()
    try {
        $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop |
                  Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias,
                                @{N = 'Store'; E = { [string]$_.Store } }
    } catch { }
    Export-DArtifact -Name '04_routes' -Data $routes

    # --- DNS cache ---
    $dns = @()
    if ($Script:Caps.DnsCache) {
        try {
            $dns = Get-DnsClientCache -ErrorAction Stop |
                   Select-Object Entry, Name,
                                 @{N = 'Type'; E = { [string]$_.Type } },
                                 @{N = 'Status'; E = { [string]$_.Status } },
                                 Data, TimeToLive
        } catch { }
    }
    Export-DArtifact -Name '04_dns_cache' -Data $dns

    foreach ($d in $dns) {
        if ($d.Name) { $null = Test-DIoc -Value $d.Name -Context 'DNS cache' -Artifact '04_dns_cache' }
        if ($d.Data) { $null = Test-DIoc -Value $d.Data -Context "DNS: $($d.Name)" -Artifact '04_dns_cache' }
    }

    # --- Hosts dosyasi ---
    $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
    $hostsData = @()
    try {
        $hi = Get-Item $hostsFile -Force -ErrorAction Stop
        $hostsData = @(Get-Content $hostsFile -ErrorAction Stop |
            Where-Object { $_ -match '^\s*[^#\s]' } |
            ForEach-Object { [PSCustomObject]@{ Entry = $_.Trim() } })

        if (((Get-Date) - $hi.LastWriteTime).TotalDays -lt $Days -and $hostsData.Count -gt 0) {
            Add-DFinding -RuleId 'DGL-052' -Severity HIGH `
                -Title 'Hosts file modified inside the analysis window' `
                -Evidence "Last write: $($hi.LastWriteTime) - $($hostsData.Count) active entries" `
                -Mitre 'T1565.001' -Artifact '04_hosts' -Timestamp $hi.LastWriteTime `
                -Why 'Security vendor domains may be blocked or traffic redirected'
            Add-DTimelineEvent -Timestamp $hi.LastWriteTime -Source 'Network' `
                -Description 'Hosts file modified' -Severity HIGH
        }
    } catch { }
    Export-DArtifact -Name '04_hosts' -Data $hostsData

    # --- Firewall ---
    $fwProfiles = @()
    if ($Script:Caps.Firewall) {
        try {
            $fwProfiles = Get-NetFirewallProfile -ErrorAction Stop |
                Select-Object Name, Enabled,
                              @{N = 'DefaultInbound'; E = { [string]$_.DefaultInboundAction } },
                              @{N = 'DefaultOutbound'; E = { [string]$_.DefaultOutboundAction } },
                              @{N = 'LogBlocked'; E = { [string]$_.LogBlocked } }
        } catch { }
    }
    Export-DArtifact -Name '04_firewall_profiles' -Data $fwProfiles

    foreach ($f in $fwProfiles) {
        if ($false -eq $f.Enabled) {
            Add-DFinding -RuleId 'DGL-056' -Severity HIGH `
                -Title 'Firewall profile disabled' -Evidence "$($f.Name) profili kapali" `
                -Mitre 'T1562.004' -Artifact '04_firewall_profiles' `
                -Why 'Attackers disable the firewall for C2 and lateral movement'
        }
    }

    # Izin veren gelen kurallar (backdoor icin acilan portlar)
    $fwRules = @()
    if ($Script:Caps.Firewall) {
        try {
            $fwRules = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -EA Stop |
                ForEach-Object {
                    $pf = $null; $ap = $null
                    try { $pf = ($_ | Get-NetFirewallPortFilter -EA Stop) } catch { }
                    try { $ap = ($_ | Get-NetFirewallApplicationFilter -EA Stop) } catch { }
                    [PSCustomObject]@{
                        Name        = $_.DisplayName
                        Group       = $_.DisplayGroup
                        Profile     = [string]$_.Profile
                        Protocol    = if ($pf) { $pf.Protocol } else { $null }
                        LocalPort   = if ($pf) { ($pf.LocalPort -join ',') } else { $null }
                        Program     = if ($ap) { $ap.Program } else { $null }
                    }
                }
        } catch { }
    }
    Export-DArtifact -Name '04_firewall_inbound_allow' -Data $fwRules

    foreach ($r in $fwRules) {
        if ($r.Program -and (Test-DSuspiciousPath -Path $r.Program)) {
            Add-DFinding -RuleId 'DGL-057' -Severity CRITICAL `
                -Title 'Firewall rule allows inbound traffic to a suspicious binary' `
                -Evidence "$($r.Name) -> $($r.Program) : $($r.LocalPort)" `
                -Mitre 'T1562.004' -Artifact '04_firewall_inbound_allow'
        }
    }

    # --- TRIAGE: baglanti bazli ---
    foreach ($c in $tcp) {
        if ($c.State -ne 'Established') { continue }

        if (-not $c.RemoteIsPrivate -and $c.SuspiciousPath) {
            Add-DFinding -RuleId 'DGL-053' -Severity CRITICAL `
                -Title 'Suspicious process talking to an external address (possible C2)' `
                -Evidence "$($c.ProcessName) (PID $($c.PID)) -> $($c.RemoteAddress):$($c.RemotePort)  [$($c.ProcessPath)]" `
                -Mitre 'T1071' -Artifact '04_tcp_connections' -Timestamp $c.CreationTimeUtc `
                -Why 'An external connection from a process in a temporary directory indicates C2'
        }
        elseif (-not $c.RemoteIsPrivate -and $false -eq $c.Signed -and $c.ProcessPath) {
            Add-DFinding -RuleId 'DGL-054' -Severity HIGH `
                -Title 'Unsigned process communicating with an external address' `
                -Evidence "$($c.ProcessName) -> $($c.RemoteAddress):$($c.RemotePort)" `
                -Mitre 'T1071' -Artifact '04_tcp_connections' -Timestamp $c.CreationTimeUtc
        }

        if ($c.RemoteAddress) {
            $null = Test-DIoc -Value $c.RemoteAddress `
                -Context "$($c.ProcessName) -> $($c.RemoteAddress):$($c.RemotePort)" `
                -Artifact '04_tcp_connections'
        }
    }

    foreach ($l in $listen) {
        if ($l.LocalAddress -in '0.0.0.0', '::' -and $l.ProcessPath -and
            ($l.SuspiciousPath -or $false -eq $l.Signed)) {
            Add-DFinding -RuleId 'DGL-055' -Severity CRITICAL `
                -Title 'Suspicious process listening on all interfaces (backdoor)' `
                -Evidence "$($l.ProcessName) :$($l.LocalPort) - $($l.ProcessPath)" `
                -Mitre 'T1571' -Artifact '04_listening_ports' `
                -Why 'A listener that is unsigned or runs from a temporary directory indicates a backdoor'
        }
    }

    Write-DLog "  $($tcp.Count) TCP, $($udp.Count) UDP, $($listen.Count) dinleyen, $(@($portproxy).Count) portproxy" -Level DEBUG
}

# ============================================================================
#  MODUL: SERVISLER
# ============================================================================

Register-DModule -Name 'Services' -Phase 1 `
    -Description 'Service binaries, signatures, unquoted paths and ServiceDll' -Body {

    $svcRaw = @()
    try { $svcRaw = Get-CimInstance Win32_Service -ErrorAction Stop }
    catch { try { $svcRaw = Get-WmiObject Win32_Service -ErrorAction Stop } catch { } }

    $svcs = foreach ($s in $svcRaw) {
        $bin = Get-DCleanPath -CommandLine $s.PathName
        $sig = Get-DSignature -Path $bin

        $binWrite = $null
        try {
            if ($bin -and (Test-Path -LiteralPath $bin -PathType Leaf -EA SilentlyContinue)) {
                $binWrite = (Get-Item -LiteralPath $bin -Force -EA Stop).LastWriteTime
            }
        } catch { }

        # svchost servisleri icin gercek DLL
        $svcDll = $null
        try {
            $sp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)\Parameters" `
                                  -Name ServiceDll -ErrorAction Stop
            $svcDll = [Environment]::ExpandEnvironmentVariables($sp.ServiceDll)
        } catch { }

        # Tirnaksiz path + bosluk = binary hijack firsati
        $unquoted = $false
        if ($s.PathName -and -not $s.PathName.Trim().StartsWith('"') -and
            $s.PathName -match '^[A-Za-z]:\\[^"]*\s+[^"]*\.(exe|bat|cmd)') {
            $unquoted = $true
        }

        [PSCustomObject]@{
            Name           = $s.Name
            DisplayName    = $s.DisplayName
            State          = $s.State
            StartMode      = $s.StartMode
            StartName      = $s.StartName
            PathName       = $s.PathName
            BinaryPath     = $bin
            ServiceDll     = $svcDll
            ProcessId      = $s.ProcessId
            Signed         = $sig.IsValid
            Signer         = $sig.Signer
            SigStatus      = $sig.Status
            IsMicrosoft    = $sig.IsMicrosoft
            SHA256         = if ($bin) { Get-DFileHashSafe -Path $bin } else { $null }
            BinaryWriteUtc = ConvertTo-DUtcString $binWrite
            SuspiciousPath = Test-DSuspiciousPath -Path $bin
            UnquotedPath   = $unquoted
            Description    = $s.Description
        }
    }

    $svcs = @($svcs)
    Export-DArtifact -Name '05_services' -Data $svcs -AsJson

    # --- TRIAGE ---
    foreach ($s in $svcs) {
        $ev = "$($s.Name) -> $($s.PathName)"

        if ($s.SuspiciousPath) {
            Add-DFinding -RuleId 'DGL-001' -Severity CRITICAL `
                -Title 'Service binary sits in a suspicious directory' -Evidence $ev `
                -Mitre 'T1543.003' -Artifact '05_services' -Timestamp $s.BinaryWriteUtc `
                -Why 'Legitimate services run from System32 or Program Files'
        }

        if ($s.BinaryPath -and $false -eq $s.Signed -and -not $s.IsMicrosoft -and
            $s.SigStatus -notin 'FileNotFound', 'NoPath') {
            Add-DFinding -RuleId 'DGL-060' -Severity HIGH `
                -Title 'Service binary is unsigned' -Evidence "$ev  (imza: $($s.SigStatus))" `
                -Mitre 'T1543.003' -Artifact '05_services' -Timestamp $s.BinaryWriteUtc
        }

        if ($s.UnquotedPath) {
            Add-DFinding -RuleId 'DGL-061' -Severity MEDIUM `
                -Title 'Unquoted service path (binary hijack risk)' -Evidence $ev `
                -Mitre 'T1574.009' -Artifact '05_services' `
                -Why 'An unquoted path containing spaces can be hijacked by dropping a binary in a parent directory'
        }

        if ($s.BinaryWriteUtc) {
            try {
                $age = ((Get-Date) - [DateTime]$s.BinaryWriteUtc).TotalDays
                if ($age -lt $Days -and -not $s.IsMicrosoft) {
                    Add-DFinding -RuleId 'DGL-062' -Severity HIGH `
                        -Title 'Service binary changed inside the analysis window' `
                        -Evidence "$ev @ $($s.BinaryWriteUtc)" `
                        -Mitre 'T1543.003' -Artifact '05_services' -Timestamp $s.BinaryWriteUtc
                    Add-DTimelineEvent -Timestamp $s.BinaryWriteUtc -Source 'Service' `
                        -Description "Service binary written: $($s.Name)" `
                        -Detail $s.BinaryPath -Severity HIGH
                }
            } catch { }
        }

        # Rastgele isimli servis (PsExec / CS beacon imzasi)
        if ((Test-DRandomName -Name $s.Name) -and -not $s.IsMicrosoft) {
            Add-DFinding -RuleId 'DGL-063' -Severity HIGH `
                -Title 'Service name looks randomly generated' -Evidence $ev `
                -Mitre 'T1569.002' -Artifact '05_services' `
                -Why 'Cobalt Strike and similar tooling generates random service names'
        }

        if ($s.Name -match '(?i)(psexesvc|paexec|remcom|csexec|winexesvc)') {
            Add-DFinding -RuleId 'DGL-064' -Severity CRITICAL `
                -Title 'Remote execution service detected' -Evidence $ev `
                -Mitre 'T1569.002' -Artifact '05_services' `
                -Why 'PsExec and its derivatives are used for lateral movement'
        }

        if ($s.PathName) {
            foreach ($pat in $Script:CmdLinePatterns) {
                if ($s.PathName -match $pat.P) {
                    Add-DFinding -RuleId 'DGL-065' -Severity $pat.S `
                        -Title "Suspicious command in service path: $($pat.N)" -Evidence $ev `
                        -Mitre $pat.M -Artifact '05_services'
                    break
                }
            }
        }

        if ($s.SHA256) { $null = Test-DIoc -Value $s.SHA256 -Context $ev -Artifact '05_services' }
    }

    $running = @($svcs | Where-Object State -eq 'Running').Count
    Write-DLog "  $($svcs.Count) services ($running running)" -Level DEBUG
}

# ============================================================================
#  MODUL: ZAMANLANMIS GOREVLER
# ============================================================================

Register-DModule -Name 'Scheduled tasks' -Phase 1 -RequiresCap 'ScheduledTasks' `
    -Description 'Task Execute and Arguments fields, which the original script never captured' -Body {

    $tasks = @()
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
            $t = $_
            $info = $null
            try {
                $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -EA Stop
            } catch { }

            $actions = @()
            foreach ($a in $t.Actions) {
                if ($a.Execute)      { $actions += (($a.Execute + ' ' + $a.Arguments).Trim()) }
                elseif ($a.ClassId)  { $actions += "COM:$($a.ClassId)" }
            }
            $actionStr = ($actions -join ' ;; ')
            $bin = Get-DCleanPath -CommandLine $actionStr
            $sig = Get-DSignature -Path $bin

            $triggers = @()
            foreach ($tr in $t.Triggers) {
                try { $triggers += ($tr.CimClass.CimClassName -replace '^MSFT_Task', '') } catch { }
            }

            [PSCustomObject]@{
                TaskName       = $t.TaskName
                TaskPath       = $t.TaskPath
                State          = [string]$t.State
                Author         = $t.Author
                Description    = $t.Description
                RunAsUser      = $t.Principal.UserId
                RunLevel       = [string]$t.Principal.RunLevel
                Actions        = $actionStr
                BinaryPath     = $bin
                Triggers       = ($triggers -join ',')
                Signed         = $sig.IsValid
                Signer         = $sig.Signer
                SigStatus      = $sig.Status
                IsMicrosoft    = $sig.IsMicrosoft
                SHA256         = if ($bin) { Get-DFileHashSafe -Path $bin } else { $null }
                LastRunUtc     = if ($info) { ConvertTo-DUtcString $info.LastRunTime } else { $null }
                NextRunUtc     = if ($info) { ConvertTo-DUtcString $info.NextRunTime } else { $null }
                SuspiciousPath = Test-DSuspiciousPath -Path $bin
            }
        }
    } catch {
        Write-DLog "  Could not enumerate scheduled tasks: $($_.Exception.Message)" -Level WARN
    }
    Export-DArtifact -Name '06_scheduled_tasks' -Data $tasks -AsJson

    # Task XML dosya zaman damgalari (gorev NE ZAMAN kaydedildi)
    $taskFiles = @()
    try {
        $tRoot = "$env:SystemRoot\System32\Tasks"
        $taskFiles = @(Get-ChildItem $tRoot -Recurse -File -EA SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{
                TaskFile    = $_.FullName.Replace($tRoot, '')
                CreatedUtc  = ConvertTo-DUtcString $_.CreationTime
                ModifiedUtc = ConvertTo-DUtcString $_.LastWriteTime
                SizeBytes   = $_.Length
            }
        })
    } catch { }
    Export-DArtifact -Name '06_task_files' -Data $taskFiles

    # --- TRIAGE ---
    foreach ($t in $tasks) {
        if ($t.State -eq 'Disabled') { continue }
        $ev = "$($t.TaskPath)$($t.TaskName) -> $($t.Actions)"

        if ($t.SuspiciousPath) {
            Add-DFinding -RuleId 'DGL-070' -Severity CRITICAL `
                -Title 'Scheduled task runs from a suspicious directory' -Evidence $ev `
                -Mitre 'T1053.005' -Artifact '06_scheduled_tasks'
        }

        if ($t.TaskPath -eq '\' -and -not $t.IsMicrosoft -and $t.BinaryPath) {
            Add-DFinding -RuleId 'DGL-071' -Severity MEDIUM `
                -Title 'Task defined at the root of the task library' -Evidence $ev `
                -Mitre 'T1053.005' -Artifact '06_scheduled_tasks' `
                -Why 'Attacker-created tasks are usually left at the root of the library'
        }

        if ($t.BinaryPath -and $false -eq $t.Signed -and -not $t.IsMicrosoft -and
            $t.SigStatus -notin 'FileNotFound', 'NoPath') {
            Add-DFinding -RuleId 'DGL-072' -Severity HIGH `
                -Title 'Scheduled task runs an unsigned binary' -Evidence $ev `
                -Mitre 'T1053.005' -Artifact '06_scheduled_tasks'
        }

        if ($t.RunAsUser -match '(?i)(SYSTEM|S-1-5-18)' -and -not $t.IsMicrosoft -and $t.BinaryPath) {
            Add-DFinding -RuleId 'DGL-073' -Severity HIGH `
                -Title 'Non-Microsoft task runs as SYSTEM' -Evidence $ev `
                -Mitre 'T1053.005' -Artifact '06_scheduled_tasks'
        }

        if ($t.Actions) {
            foreach ($pat in $Script:CmdLinePatterns) {
                if ($t.Actions -match $pat.P) {
                    Add-DFinding -RuleId 'DGL-074' -Severity $pat.S `
                        -Title "Suspicious pattern in task command: $($pat.N)" -Evidence $ev `
                        -Mitre $pat.M -Artifact '06_scheduled_tasks'
                    break
                }
            }
        }
    }

    foreach ($tf in $taskFiles) {
        if (-not $tf.CreatedUtc) { continue }
        try {
            $age = ((Get-Date) - [DateTime]$tf.CreatedUtc).TotalDays
            if ($age -lt $Days) {
                Add-DFinding -RuleId 'DGL-075' -Severity HIGH `
                    -Title 'Scheduled task created inside the analysis window' `
                    -Evidence "$($tf.TaskFile) @ $($tf.CreatedUtc)" `
                    -Mitre 'T1053.005' -Artifact '06_task_files' -Timestamp $tf.CreatedUtc
                Add-DTimelineEvent -Timestamp $tf.CreatedUtc -Source 'ScheduledTask' `
                    -Description "Task created: $($tf.TaskFile)" -Severity HIGH
            }
        } catch { }
    }

    Write-DLog "  $(@($tasks).Count) tasks, $(@($taskFiles).Count) task files" -Level DEBUG
}

# ============================================================================
#  MODUL: AUTORUNS (NORMALIZE ASEP TABLOSU)
# ============================================================================

Register-DModule -Name 'Autoruns / ASEP' -Phase 1 `
    -Description 'Every persistence point in one normalised table' -Body {

    $entries = New-Object System.Collections.ArrayList
    $hives   = Get-DUserHives

    # --- 1. Run / RunOnce (makine) ---
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )
    foreach ($k in $runKeys) {
        foreach ($v in (Get-DRegValues -Path $k)) {
            $null = $entries.Add((New-DAutorunEntry -Category 'Run' -Location $k `
                                  -Name $v.Name -Value $v.Value))
        }
    }

    # --- 2. Run / RunOnce (TUM kullanicilar - eski script sadece HKCU'ya bakiyordu) ---
    foreach ($h in $hives) {
        foreach ($sub in 'Run', 'RunOnce', 'RunServices', 'Policies\Explorer\Run') {
            $k = "$($h.RegRoot)\Software\Microsoft\Windows\CurrentVersion\$sub"
            foreach ($v in (Get-DRegValues -Path $k)) {
                $null = $entries.Add((New-DAutorunEntry -Category 'Run(User)' -Location $k `
                                      -Name $v.Name -Value $v.Value -User $h.User))
            }
        }
    }

    # --- 3. Startup klasorleri (tum kullanicilar) ---
    $startupDirs = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
    try {
        Get-ChildItem 'C:\Users' -Directory -EA SilentlyContinue | ForEach-Object {
            $startupDirs += "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
        }
    } catch { }

    foreach ($d in $startupDirs) {
        if (-not (Test-Path $d)) { continue }
        $whose = 'ALLUSERS'
        if ($d -match '\\Users\\([^\\]+)\\') { $whose = $Matches[1] }
        try {
            Get-ChildItem $d -File -Force -EA Stop |
                Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object {
                    $null = $entries.Add((New-DAutorunEntry -Category 'StartupFolder' `
                            -Location $d -Name $_.Name -Value $_.FullName -User $whose))
                }
        } catch { }
    }

    # --- 4. Winlogon (Shell / Userinit / Taskman / GinaDLL) ---
    $wlKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $wlExpected = @{ 'Shell' = 'explorer.exe'; 'Userinit' = 'userinit.exe' }
    foreach ($v in (Get-DRegValues -Path $wlKey)) {
        if ($v.Name -notin 'Shell', 'Userinit', 'Taskman', 'AppSetup', 'VmApplet', 'GinaDLL') { continue }
        $null = $entries.Add((New-DAutorunEntry -Category 'Winlogon' -Location $wlKey `
                              -Name $v.Name -Value $v.Value))

        if ($wlExpected.ContainsKey($v.Name)) {
            $exp = $wlExpected[$v.Name]
            if ($v.Value -notmatch "^(?i)(C:\\Windows\\system32\\)?$([regex]::Escape($exp)),?\s*$") {
                Add-DFinding -RuleId 'DGL-080' -Severity CRITICAL `
                    -Title "Winlogon $($v.Name) value was modified" `
                    -Evidence "$($v.Name) = $($v.Value)" `
                    -Mitre 'T1547.004' -Artifact '07_autoruns' `
                    -Why "Expected value: $exp"
            }
        }
        if ($v.Name -in 'Taskman', 'GinaDLL', 'AppSetup', 'VmApplet') {
            Add-DFinding -RuleId 'DGL-089' -Severity HIGH `
                -Title "Winlogon $($v.Name) is set" -Evidence "$($v.Name) = $($v.Value)" `
                -Mitre 'T1547.004' -Artifact '07_autoruns' `
                -Why 'This value is not present by default'
        }
    }

    # --- 5. AppInit_DLLs ---
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
        $v = Get-DRegValues -Path $k | Where-Object Name -eq 'AppInit_DLLs'
        if ($v -and $v.Value -and $v.Value.Trim()) {
            $null = $entries.Add((New-DAutorunEntry -Category 'AppInit_DLLs' -Location $k `
                                  -Name 'AppInit_DLLs' -Value $v.Value))
            Add-DFinding -RuleId 'DGL-081' -Severity CRITICAL `
                -Title 'AppInit_DLLs is set' -Evidence $v.Value `
                -Mitre 'T1546.010' -Artifact '07_autoruns' `
                -Why 'AppInit_DLLs injects a DLL into every process that loads user32.dll'
        }
    }

    # --- 6. IFEO Debugger (accessibility backdoor dahil) ---
    foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
                        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
        try {
            Get-ChildItem $base -EA Stop | ForEach-Object {
                $dbg = Get-DRegValues -Path $_.PSPath | Where-Object Name -eq 'Debugger'
                if ($dbg -and $dbg.Value) {
                    $target = $_.PSChildName
                    $null = $entries.Add((New-DAutorunEntry -Category 'IFEO-Debugger' `
                            -Location $_.PSPath -Name $target -Value $dbg.Value))
                    $sev = if ($target -match '(?i)^(sethc|utilman|osk|magnify|narrator|displayswitch|atbroker)\.exe$') {
                               'CRITICAL' } else { 'HIGH' }
                    Add-DFinding -RuleId 'DGL-082' -Severity $sev -Title 'IFEO Debugger is set' `
                        -Evidence "$target -> $($dbg.Value)" `
                        -Mitre 'T1546.012' -Artifact '07_autoruns' `
                        -Why 'The debugger runs instead of the target binary (accessibility backdoor)'
                }
            }
        } catch { }
    }

    # --- 6b. SilentProcessExit ---
    try {
        Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' -EA Stop |
            ForEach-Object {
                $mon = Get-DRegValues -Path $_.PSPath | Where-Object Name -eq 'MonitorProcess'
                if ($mon -and $mon.Value) {
                    $null = $entries.Add((New-DAutorunEntry -Category 'SilentProcessExit' `
                            -Location $_.PSPath -Name $_.PSChildName -Value $mon.Value))
                    Add-DFinding -RuleId 'DGL-083' -Severity CRITICAL `
                        -Title 'SilentProcessExit MonitorProcess is set' `
                        -Evidence "$($_.PSChildName) -> $($mon.Value)" `
                        -Mitre 'T1546.012' -Artifact '07_autoruns' `
                        -Why 'The named binary runs when the target process exits'
                }
            }
    } catch { }

    # --- 7. LSA paketleri (SSP backdoor / mimilib) ---
    $lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $knownLsa = 'kerberos|msv1_0|schannel|wdigest|tspkg|pku2u|cloudap|negoexts|rassfm|scecli'
    foreach ($v in (Get-DRegValues -Path $lsaKey)) {
        if ($v.Name -notin 'Security Packages', 'Authentication Packages', 'Notification Packages') { continue }
        $null = $entries.Add((New-DAutorunEntry -Category 'LSA-Package' -Location $lsaKey `
                              -Name $v.Name -Value $v.Value))
        $unknown = @($v.Value -split '\s*\|\s*' |
                     Where-Object { $_ -and $_ -ne '""' -and $_ -notmatch "(?i)^($knownLsa)$" })
        if ($unknown.Count -gt 0) {
            Add-DFinding -RuleId 'DGL-084' -Severity CRITICAL `
                -Title 'Unknown entry in the LSA package list' `
                -Evidence "$($v.Name): $($unknown -join ', ')" `
                -Mitre 'T1547.002' -Artifact '07_autoruns' `
                -Why 'A custom DLL loaded into LSA can steal credentials'
        }
    }

    # --- 8. Netsh helper DLL ---
    foreach ($v in (Get-DRegValues -Path 'HKLM:\SOFTWARE\Microsoft\Netsh')) {
        $null = $entries.Add((New-DAutorunEntry -Category 'NetshHelper' `
                -Location 'HKLM:\SOFTWARE\Microsoft\Netsh' -Name $v.Name -Value $v.Value))
    }

    # --- 9. AppCertDlls (varsayilan olarak BOS olmali) ---
    $acKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
    foreach ($v in (Get-DRegValues -Path $acKey)) {
        $null = $entries.Add((New-DAutorunEntry -Category 'AppCertDlls' -Location $acKey `
                              -Name $v.Name -Value $v.Value))
        Add-DFinding -RuleId 'DGL-085' -Severity CRITICAL `
            -Title 'AppCertDlls entry present' -Evidence "$($v.Name) = $($v.Value)" `
            -Mitre 'T1546.009' -Artifact '07_autoruns' `
            -Why 'This key is empty by default; a DLL here loads on every CreateProcess call'
    }

    # --- 10. Print Monitors / Providers ---
    foreach ($k in @('HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors',
                     'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers')) {
        try {
            Get-ChildItem $k -EA Stop | ForEach-Object {
                foreach ($d in (Get-DRegValues -Path $_.PSPath |
                                Where-Object { $_.Name -match '^(Driver|Name)$' -and $_.Value })) {
                    $null = $entries.Add((New-DAutorunEntry -Category 'PrintMonitor' `
                            -Location $_.PSPath -Name $_.PSChildName -Value $d.Value))
                }
            }
        } catch { }
    }

    # --- 11. Time Providers ---
    try {
        Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders' -EA Stop |
            ForEach-Object {
                $dll = Get-DRegValues -Path $_.PSPath | Where-Object Name -eq 'DllName'
                if ($dll -and $dll.Value -notmatch '(?i)w32time\.dll') {
                    $null = $entries.Add((New-DAutorunEntry -Category 'TimeProvider' `
                            -Location $_.PSPath -Name $_.PSChildName -Value $dll.Value))
                    Add-DFinding -RuleId 'DGL-086' -Severity HIGH `
                        -Title 'Non-standard Time Provider DLL' `
                        -Evidence "$($_.PSChildName) -> $($dll.Value)" `
                        -Mitre 'T1547.003' -Artifact '07_autoruns'
                }
            }
    } catch { }

    # --- 12. Active Setup ---
    foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components',
                        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components')) {
        try {
            Get-ChildItem $base -EA Stop | ForEach-Object {
                $sc = Get-DRegValues -Path $_.PSPath | Where-Object Name -eq 'StubPath'
                if ($sc -and $sc.Value) {
                    $null = $entries.Add((New-DAutorunEntry -Category 'ActiveSetup' `
                            -Location $_.PSPath -Name $_.PSChildName -Value $sc.Value))
                }
            }
        } catch { }
    }

    # --- 13. UserInitMprLogonScript (logon script persistence) ---
    foreach ($h in $hives) {
        $v = Get-DRegValues -Path "$($h.RegRoot)\Environment" |
             Where-Object Name -eq 'UserInitMprLogonScript'
        if ($v -and $v.Value) {
            $null = $entries.Add((New-DAutorunEntry -Category 'LogonScript' `
                    -Location "$($h.RegRoot)\Environment" `
                    -Name 'UserInitMprLogonScript' -Value $v.Value -User $h.User))
            Add-DFinding -RuleId 'DGL-087' -Severity CRITICAL `
                -Title 'UserInitMprLogonScript is set' -Evidence "$($h.User): $($v.Value)" `
                -Mitre 'T1037.001' -Artifact '07_autoruns' `
                -Why 'This value is absent by default and runs at every logon'
        }
    }

    # --- 14. Screensaver ---
    foreach ($h in $hives) {
        $v = Get-DRegValues -Path "$($h.RegRoot)\Control Panel\Desktop" |
             Where-Object Name -eq 'SCRNSAVE.EXE'
        if ($v -and $v.Value -and $v.Value -notmatch '(?i)\\System32\\[\w\.]+\.scr$') {
            $null = $entries.Add((New-DAutorunEntry -Category 'Screensaver' `
                    -Location "$($h.RegRoot)\Control Panel\Desktop" `
                    -Name 'SCRNSAVE.EXE' -Value $v.Value -User $h.User))
        }
    }

    # --- 15. BITS transfer jobs (indirme + kalicilik) ---
    $bits = @()
    if ($Script:Caps.BitsTransfer) {
        try {
            $bits = @(Get-BitsTransfer -AllUsers -EA Stop | ForEach-Object {
                [PSCustomObject]@{
                    JobId       = $_.JobId
                    DisplayName = $_.DisplayName
                    Owner       = $_.OwnerAccount
                    State       = [string]$_.JobState
                    CreatedUtc  = ConvertTo-DUtcString $_.CreationTime
                    RemoteUrls  = (($_.FileList | ForEach-Object { $_.RemoteName }) -join ' ; ')
                    LocalFiles  = (($_.FileList | ForEach-Object { $_.LocalName }) -join ' ; ')
                }
            })
        } catch { }
    }
    Export-DArtifact -Name '07_bits_jobs' -Data $bits
    foreach ($b in $bits) {
        Add-DFinding -RuleId 'DGL-088' -Severity HIGH `
            -Title 'BITS transfer job present' `
            -Evidence "$($b.DisplayName) [$($b.Owner)] -> $($b.RemoteUrls)" `
            -Mitre 'T1197' -Artifact '07_bits_jobs' -Timestamp $b.CreatedUtc `
            -Why 'BITS is used both to download and to persist'
    }

    # --- Kaydet ve toplu triage ---
    $arr = @($entries)
    Export-DArtifact -Name '07_autoruns' -Data $arr -AsJson
    foreach ($e in $arr) { Invoke-DAutorunTriage -Entry $e -Artifact '07_autoruns' }

    Write-DLog "  $($arr.Count) autorun girdisi, $(@($bits).Count) BITS isi" -Level DEBUG
}

# ============================================================================
#  MODUL: WMI KALICILIGI
# ============================================================================

Register-DModule -Name 'WMI persistence' -Phase 1 `
    -Description 'Event filter, consumer and binding - fileless persistence' -Body {

    $wmi = New-Object System.Collections.ArrayList

    foreach ($ns in 'root\subscription', 'root\default') {
        try {
            Get-CimInstance -Namespace $ns -ClassName __EventFilter -EA Stop | ForEach-Object {
                $null = $wmi.Add([PSCustomObject]@{
                    Namespace = $ns; Type = 'EventFilter'; Name = $_.Name
                    Detail = $_.Query; Extra = $_.QueryLanguage
                })
            }
        } catch { }

        foreach ($cls in 'CommandLineEventConsumer', 'ActiveScriptEventConsumer',
                         'LogFileEventConsumer', 'SMTPEventConsumer', 'NTEventLogEventConsumer') {
            try {
                Get-CimInstance -Namespace $ns -ClassName $cls -EA Stop | ForEach-Object {
                    $detail = if ($_.CommandLineTemplate) { $_.CommandLineTemplate }
                              elseif ($_.ScriptText)      { $_.ScriptText }
                              elseif ($_.ScriptFileName)  { $_.ScriptFileName }
                              elseif ($_.Filename)        { $_.Filename }
                              else { '(detay yok)' }
                    $null = $wmi.Add([PSCustomObject]@{
                        Namespace = $ns; Type = "Consumer:$cls"; Name = $_.Name
                        Detail = $detail; Extra = $_.ExecutablePath
                    })
                }
            } catch { }
        }

        try {
            Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -EA Stop |
                ForEach-Object {
                    $null = $wmi.Add([PSCustomObject]@{
                        Namespace = $ns; Type = 'Binding'
                        Name = "$($_.Filter) => $($_.Consumer)"
                        Detail = [string]$_.Consumer; Extra = [string]$_.Filter
                    })
                }
        } catch { }
    }

    $arr = @($wmi)
    Export-DArtifact -Name '08_wmi_persistence' -Data $arr -AsJson

    # Binding varsa bu neredeyse her zaman kalicilik demektir
    $bindings = @($arr | Where-Object Type -eq 'Binding')
    foreach ($b in $bindings) {
        if ($b.Name -match '(?i)(SCM Event Log|BVTFilter|TSlogonEvents|RmAssistEventFilter)') { continue }
        Add-DFinding -RuleId 'DGL-090' -Severity CRITICAL `
            -Title 'WMI permanent event subscription present' -Evidence $b.Name `
            -Mitre 'T1546.003' -Artifact '08_wmi_persistence' `
            -Why 'Filter-to-consumer binding is the most common form of fileless persistence'
    }

    foreach ($c in @($arr | Where-Object { $_.Type -match 'Consumer:(CommandLine|ActiveScript)' })) {
        if (-not $c.Detail) { continue }
        foreach ($pat in $Script:CmdLinePatterns) {
            if ($c.Detail -match $pat.P) {
                $len = [Math]::Min(200, $c.Detail.Length)
                Add-DFinding -RuleId 'DGL-091' -Severity CRITICAL `
                    -Title "Suspicious command in WMI consumer: $($pat.N)" `
                    -Evidence "$($c.Name): $($c.Detail.Substring(0, $len))" `
                    -Mitre $pat.M -Artifact '08_wmi_persistence'
                break
            }
        }
    }

    Write-DLog "  $($arr.Count) WMI nesnesi ($($bindings.Count) binding)" -Level DEBUG
}

# ============================================================================
#  MODUL: NAMED PIPES
# ============================================================================

Register-DModule -Name 'Named pipes' -Phase 1 -Description 'C2 beacon pipe detection' -Body {

    $pipes = @()
    try {
        $pipes = @([IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object {
            $n = $_ -replace '^\\\\\.\\pipe\\', ''
            [PSCustomObject]@{ Name = $n; FullPath = $_; Length = $n.Length }
        })
    } catch {
        try {
            $pipes = @(Get-ChildItem '\\.\pipe\' -EA Stop | ForEach-Object {
                [PSCustomObject]@{ Name = $_.Name; FullPath = $_.FullName; Length = $_.Name.Length }
            })
        } catch { }
    }
    Export-DArtifact -Name '09_named_pipes' -Data $pipes

    foreach ($p in $pipes) {
        foreach ($pat in $Script:BadPipePatterns) {
            if ($p.Name -match $pat) {
                Add-DFinding -RuleId 'DGL-100' -Severity HIGH `
                    -Title 'Named pipe matches a known C2 pattern' -Evidence $p.Name `
                    -Mitre 'T1071' -Artifact '09_named_pipes' `
                    -Why 'Cobalt Strike and similar C2 frameworks use characteristic pipe names'
                break
            }
        }
    }

    Write-DLog "  $($pipes.Count) named pipe" -Level DEBUG
}

# ============================================================================
#  MODUL: GUVENLIK DURUMU / TAMPER TESPITI
# ============================================================================

Register-DModule -Name 'Security posture' -Phase 1 `
    -Description 'Defender, exclusions, AMSI, LSA, PowerShell logging, audit policy, VSS' -Body {

    # --- Defender durumu ---
    $mpStatus = $null
    if ($Script:Caps.Defender) {
        try {
            $s = Get-MpComputerStatus -EA Stop
            $mpStatus = [PSCustomObject]@{
                AMServiceEnabled          = $s.AMServiceEnabled
                AntivirusEnabled          = $s.AntivirusEnabled
                AntispywareEnabled        = $s.AntispywareEnabled
                RealTimeProtectionEnabled = $s.RealTimeProtectionEnabled
                BehaviorMonitorEnabled    = $s.BehaviorMonitorEnabled
                IoavProtectionEnabled     = $s.IoavProtectionEnabled
                OnAccessProtectionEnabled = $s.OnAccessProtectionEnabled
                IsTamperProtected         = $s.IsTamperProtected
                AntivirusSignatureAge     = $s.AntivirusSignatureAge
                SignatureLastUpdatedUtc   = ConvertTo-DUtcString $s.AntivirusSignatureLastUpdated
                QuickScanAge              = $s.QuickScanAge
                FullScanAge               = $s.FullScanAge
            }
        } catch { }
    }
    Export-DArtifact -Name '12_defender_status' -Data $mpStatus -AsJson

    if ($mpStatus) {
        foreach ($prop in 'RealTimeProtectionEnabled', 'BehaviorMonitorEnabled',
                          'AntivirusEnabled', 'OnAccessProtectionEnabled') {
            if ($false -eq $mpStatus.$prop) {
                Add-DFinding -RuleId 'DGL-110' -Severity CRITICAL `
                    -Title 'Defender protection component disabled' -Evidence "$prop = False" `
                    -Mitre 'T1562.001' -Artifact '12_defender_status' `
                    -Why "Disabling AV protection is usually an attacker's first move"
            }
        }
        if ($mpStatus.AntivirusSignatureAge -gt 14) {
            Add-DFinding -RuleId 'DGL-111' -Severity MEDIUM `
                -Title 'Defender signatures are out of date' `
                -Evidence "$($mpStatus.AntivirusSignatureAge) gun" `
                -Mitre 'T1562.001' -Artifact '12_defender_status'
        }
    }

    # --- Exclusion'lar: cmdlet + registry + GPO (biri yoksa digeri calissin) ---
    $excl = New-Object System.Collections.ArrayList
    if ($Script:Caps.Defender) {
        try {
            $pref = Get-MpPreference -EA Stop
            foreach ($t in 'ExclusionPath', 'ExclusionProcess', 'ExclusionExtension', 'ExclusionIpAddress') {
                foreach ($x in @($pref.$t)) {
                    if ($x) { $null = $excl.Add([PSCustomObject]@{ Type = $t; Value = $x; Source = 'Cmdlet' }) }
                }
            }
            Export-DArtifact -Name '12_defender_prefs' -AsJson -Data ([PSCustomObject]@{
                DisableRealtimeMonitoring    = $pref.DisableRealtimeMonitoring
                DisableBehaviorMonitoring    = $pref.DisableBehaviorMonitoring
                DisableScriptScanning        = $pref.DisableScriptScanning
                DisableIOAVProtection        = $pref.DisableIOAVProtection
                DisableArchiveScanning       = $pref.DisableArchiveScanning
                MAPSReporting                = [string]$pref.MAPSReporting
                SubmitSamplesConsent         = [string]$pref.SubmitSamplesConsent
                EnableControlledFolderAccess = [string]$pref.EnableControlledFolderAccess
            })
        } catch { }
    }
    foreach ($t in 'Paths', 'Processes', 'Extensions', 'IpAddresses') {
        foreach ($v in (Get-DRegValues -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\$t")) {
            $null = $excl.Add([PSCustomObject]@{ Type = "Exclusion$t"; Value = $v.Name; Source = 'Registry' })
        }
        foreach ($v in (Get-DRegValues -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\$t")) {
            $null = $excl.Add([PSCustomObject]@{ Type = "Policy$t"; Value = $v.Name; Source = 'GPO' })
        }
    }
    $exclArr = @($excl)
    Export-DArtifact -Name '12_defender_exclusions' -Data $exclArr

    foreach ($e in $exclArr) {
        $sev = if ($e.Value -match '(?i)^[a-z]:\\?$|\\(Users|Temp|ProgramData|Windows)\\?$') {
                   'CRITICAL' } else { 'HIGH' }
        Add-DFinding -RuleId 'DGL-112' -Severity $sev -Title 'Defender exclusion configured' `
            -Evidence "$($e.Type) [$($e.Source)]: $($e.Value)" `
            -Mitre 'T1562.001' -Artifact '12_defender_exclusions' `
            -Why 'Attackers add their payload directory to the exclusion list'
    }

    # --- Tespit gecmisi ---
    $threats = @()
    if ($Script:Caps.Defender) {
        try {
            $threats = @(Get-MpThreatDetection -EA Stop | ForEach-Object {
                [PSCustomObject]@{
                    ThreatID         = $_.ThreatID
                    DetectionTimeUtc = ConvertTo-DUtcString $_.InitialDetectionTime
                    Resources        = ($_.Resources -join ' ; ')
                    ProcessName      = $_.ProcessName
                    DomainUser       = $_.DomainUser
                    ActionSuccess    = $_.ActionSuccess
                    CleaningAction   = [string]$_.CleaningActionID
                    ThreatStatus     = [string]$_.ThreatStatusID
                }
            })
        } catch { }
    }
    Export-DArtifact -Name '12_defender_threats' -Data $threats

    foreach ($t in $threats) {
        $failed = ($false -eq $t.ActionSuccess)
        $sev    = if ($failed) { 'CRITICAL' } else { 'HIGH' }
        $title  = if ($failed) { 'Defender detection NOT remediated' } else { 'Defender threat detection' }
        Add-DFinding -RuleId 'DGL-113' -Severity $sev -Title $title `
            -Evidence "$($t.Resources)  [$($t.DetectionTimeUtc)]" `
            -Artifact '12_defender_threats' -Timestamp $t.DetectionTimeUtc
        Add-DTimelineEvent -Timestamp $t.DetectionTimeUtc -Source 'Defender' `
            -Description 'Malware detected' -Detail $t.Resources -Severity HIGH
    }

    # --- Guvenlik yapilandirmasi (tamper gostergeleri) ---
    $cfg = New-Object System.Collections.ArrayList

    $checks = @(
        @{ N = 'WDigest cleartext password storage'
           P = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
           K = 'UseLogonCredential'; E = '0'; S = 'CRITICAL'; M = 'T1003.001'
           W = 'UseLogonCredential=1 parolalari bellekte duz metin tutar' }
        @{ N = 'LSA Protection (RunAsPPL)'
           P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
           K = 'RunAsPPL'; E = '1'; S = 'MEDIUM'; M = 'T1003.001'
           W = 'Kapali ise LSASS bellegi kolayca dump edilir' }
        @{ N = 'PowerShell Script Block Logging'
           P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
           K = 'EnableScriptBlockLogging'; E = '1'; S = 'MEDIUM'; M = 'T1562.002'
           W = 'Kapali ise PowerShell tabanli saldirilar gorunmez kalir (4104 uretilmez)' }
        @{ N = 'PowerShell Module Logging'
           P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
           K = 'EnableModuleLogging'; E = '1'; S = 'LOW'; M = 'T1562.002'; W = '' }
        @{ N = 'Komut satiri denetimi (4688)'
           P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
           K = 'ProcessCreationIncludeCmdLine_Enabled'; E = '1'; S = 'MEDIUM'; M = 'T1562.002'
           W = 'Kapali ise 4688 eventleri komut satiri icermez - hunting degeri buyuk olcude duser' }
        @{ N = 'SMBv1 protokolu'
           P = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
           K = 'SMB1'; E = '0'; S = 'MEDIUM'; M = 'T1210'
           W = 'SMBv1 EternalBlue ve benzeri exploitlere aciktir' }
        @{ N = 'RestrictedAdmin RDP modu'
           P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
           K = 'DisableRestrictedAdmin'; E = $null; S = 'INFO'; M = ''; W = '' }
        @{ N = 'RDP durumu (fDenyTSConnections)'
           P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
           K = 'fDenyTSConnections'; E = $null; S = 'INFO'; M = ''; W = '' }
    )

    foreach ($c in $checks) {
        $v   = (Get-DRegValues -Path $c.P | Where-Object Name -eq $c.K)
        $val = if ($v) { $v.Value } else { '(tanimsiz)' }
        $null = $cfg.Add([PSCustomObject]@{
            Setting = $c.N; Path = $c.P; Key = $c.K; Value = $val
        })
        if ($v -and $c.E -and $v.Value -ne $c.E) {
            Add-DFinding -RuleId 'DGL-114' -Severity $c.S -Title $c.N `
                -Evidence "$($c.K) = $($v.Value) (beklenen: $($c.E))" `
                -Mitre $c.M -Artifact '12_security_config' -Why $c.W
        }
    }

    # AMSI provider'lari silinmis mi?
    $amsiCount = 0
    try {
        $amsiCount = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -EA Stop).Count
    } catch { }
    $null = $cfg.Add([PSCustomObject]@{
        Setting = 'AMSI Providers'; Path = 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'
        Key = 'Count'; Value = $amsiCount
    })
    if ($amsiCount -eq 0) {
        Add-DFinding -RuleId 'DGL-115' -Severity HIGH -Title 'No AMSI provider registered' `
            -Evidence 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers bos' `
            -Mitre 'T1562.001' -Artifact '12_security_config' `
            -Why 'The AMSI provider registration may have been removed, disabling script scanning'
    }
    Export-DArtifact -Name '12_security_config' -Data @($cfg)

    # --- Audit policy ---
    $audit = @()
    try {
        $ap = auditpol /get /category:* /r 2>$null
        if ($ap) {
            $audit = @($ap | ConvertFrom-Csv | ForEach-Object {
                [PSCustomObject]@{
                    Category = $_.'Subcategory'
                    GUID     = $_.'Subcategory GUID'
                    Setting  = $_.'Inclusion Setting'
                }
            })
        }
    } catch { }
    Export-DArtifact -Name '12_audit_policy' -Data $audit

    foreach ($ca in @('Process Creation', 'Logon', 'Special Logon', 'Security Group Management',
                      'User Account Management', 'Audit Policy Change', 'Security System Extension')) {
        $a = $audit | Where-Object Category -eq $ca
        if ($a -and $a.Setting -match '(?i)No Auditing') {
            Add-DFinding -RuleId 'DGL-116' -Severity MEDIUM `
                -Title 'Critical audit category is disabled' -Evidence "$ca : $($a.Setting)" `
                -Mitre 'T1562.002' -Artifact '12_audit_policy' `
                -Why 'While this category is off the related events are never produced'
        }
    }

    # --- Shadow copy (ransomware / anti-forensics) ---
    $vss = @()
    try {
        $vss = @(Get-CimInstance Win32_ShadowCopy -EA Stop | ForEach-Object {
            [PSCustomObject]@{
                ID = $_.ID; VolumeName = $_.VolumeName
                InstallDateUtc = ConvertTo-DUtcString $_.InstallDate
            }
        })
    } catch { }
    Export-DArtifact -Name '12_shadow_copies' -Data $vss

    if ($vss.Count -eq 0 -and $Script:Ctx.IsServer) {
        Add-DFinding -RuleId 'DGL-117' -Severity MEDIUM `
            -Title 'No shadow copies found' -Evidence 'Win32_ShadowCopy bos' `
            -Mitre 'T1490' -Artifact '12_shadow_copies' `
            -Why 'Servers normally hold shadow copies; these may have been deleted'
    }

    Write-DLog "  $($exclArr.Count) exclusion, $(@($threats).Count) tehdit, $($vss.Count) shadow copy" -Level DEBUG
}

# ============================================================================
#  MODUL: SMB VE PAYLASIMLAR
# ============================================================================

Register-DModule -Name 'SMB and shares' -Phase 1 -RequiresCap 'SmbShare' -Body {

    $shares = @()
    try {
        $shares = @(Get-SmbShare -EA Stop | ForEach-Object {
            $acl = $null
            try {
                $acl = ((Get-SmbShareAccess -Name $_.Name -EA Stop |
                         ForEach-Object { "$($_.AccountName):$($_.AccessRight)" }) -join ' ; ')
            } catch { }
            [PSCustomObject]@{
                Name = $_.Name; Path = $_.Path; Description = $_.Description
                ShareType = [string]$_.ShareType; Special = $_.Special; Access = $acl
            }
        })
    } catch { }
    Export-DArtifact -Name '10_smb_shares' -Data $shares

    foreach ($s in $shares) {
        if ($s.Special) { continue }
        if ($s.Access -match '(?i)Everyone:Full') {
            Add-DFinding -RuleId 'DGL-120' -Severity HIGH `
                -Title 'Share grants Everyone full control' `
                -Evidence "$($s.Name) -> $($s.Path)" -Mitre 'T1135' -Artifact '10_smb_shares'
        }
        if ($s.Path -match '(?i)^[A-Z]:\\?$') {
            Add-DFinding -RuleId 'DGL-121' -Severity HIGH `
                -Title 'Drive root is shared' `
                -Evidence "$($s.Name) -> $($s.Path)" -Mitre 'T1135' -Artifact '10_smb_shares'
        }
    }

    $sessions = @()
    try {
        $sessions = @(Get-SmbSession -EA Stop | Select-Object ClientComputerName,
                      ClientUserName, NumOpens, SessionId,
                      @{N = 'Dialect'; E = { [string]$_.Dialect } })
    } catch { }
    Export-DArtifact -Name '10_smb_sessions' -Data $sessions

    $conns = @()
    try {
        $conns = @(Get-SmbConnection -EA Stop | Select-Object ServerName, ShareName, UserName,
                   @{N = 'Dialect'; E = { [string]$_.Dialect } })
    } catch { }
    Export-DArtifact -Name '10_smb_connections' -Data $conns

    $mappings = @()
    try {
        $mappings = @(Get-SmbMapping -EA Stop | Select-Object LocalPath, RemotePath,
                      @{N = 'Status'; E = { [string]$_.Status } })
    } catch { }
    Export-DArtifact -Name '10_smb_mappings' -Data $mappings

    Write-DLog "  $($shares.Count) shares, $($sessions.Count) sessions, $($conns.Count) connections" -Level DEBUG
}

# ============================================================================
#  MODUL: SURUCULER (BYOVD)
# ============================================================================

Register-DModule -Name 'Drivers' -Phase 1 `
    -Description 'Unsigned and suspicious driver detection (BYOVD)' -Body {

    $drivers = @()
    try {
        $drivers = @(Get-CimInstance Win32_SystemDriver -EA Stop | ForEach-Object {
            $p = $_.PathName
            if ($p) {
                $p = [Environment]::ExpandEnvironmentVariables(($p -replace '^\\\?\?\\', ''))
            }
            $sig = Get-DSignature -Path $p
            $wr = $null
            try {
                if ($p -and (Test-Path -LiteralPath $p -PathType Leaf -EA SilentlyContinue)) {
                    $wr = (Get-Item -LiteralPath $p -Force -EA Stop).LastWriteTime
                }
            } catch { }
            [PSCustomObject]@{
                Name = $_.Name; DisplayName = $_.DisplayName
                State = $_.State; StartMode = $_.StartMode; PathName = $p
                Signed = $sig.IsValid; Signer = $sig.Signer; SigStatus = $sig.Status
                IsMicrosoft = $sig.IsMicrosoft
                SHA256 = if ($p) { Get-DFileHashSafe -Path $p } else { $null }
                WriteUtc = ConvertTo-DUtcString $wr
                SuspiciousPath = Test-DSuspiciousPath -Path $p
            }
        })
    } catch { }
    Export-DArtifact -Name '09_drivers' -Data $drivers

    foreach ($d in $drivers) {
        if ($d.State -ne 'Running') { continue }

        if ($d.SuspiciousPath) {
            Add-DFinding -RuleId 'DGL-130' -Severity CRITICAL `
                -Title 'Driver loaded from a suspicious directory' `
                -Evidence "$($d.Name) -> $($d.PathName)" `
                -Mitre 'T1068' -Artifact '09_drivers' -Timestamp $d.WriteUtc `
                -Why 'In BYOVD attacks the driver is loaded from a temporary directory'
        }
        elseif ($d.PathName -and $false -eq $d.Signed -and -not $d.IsMicrosoft) {
            Add-DFinding -RuleId 'DGL-131' -Severity HIGH `
                -Title 'Unsigned driver loaded' `
                -Evidence "$($d.Name) -> $($d.PathName) ($($d.SigStatus))" `
                -Mitre 'T1068' -Artifact '09_drivers' -Timestamp $d.WriteUtc
        }

        if ($d.WriteUtc) {
            try {
                $age = ((Get-Date) - [DateTime]$d.WriteUtc).TotalDays
                if ($age -lt $Days -and -not $d.IsMicrosoft) {
                    Add-DFinding -RuleId 'DGL-132' -Severity HIGH `
                        -Title 'Driver written inside the analysis window' `
                        -Evidence "$($d.Name) @ $($d.WriteUtc)" `
                        -Mitre 'T1068' -Artifact '09_drivers' -Timestamp $d.WriteUtc
                }
            } catch { }
        }

        if ($d.SHA256) { $null = Test-DIoc -Value $d.SHA256 -Context $d.Name -Artifact '09_drivers' }
    }

    Write-DLog "  $($drivers.Count) drivers" -Level DEBUG
}

# ============================================================================
#  EVENT LOG MOTORU
# ============================================================================

$Script:EventStats = New-Object System.Collections.ArrayList

function Get-DWinEvents {
    <#
        Tek cikis noktasi. Kanal basina TEK cagri, ID'ler dizi olarak.
        Cap'e takilirsa rapora uyari duser - sessizce kesmez.
    #>
    param(
        [Parameter(Mandatory)][string]$LogName,
        [int[]]$Id,
        [int]$Max = 0
    )

    if ($Max -le 0) { $Max = $MaxEventsPerChannel }

    # Kanal yoksa bosuna sorgulama
    if ($Script:Caps.AvailableLogs -and ($Script:Caps.AvailableLogs -notcontains $LogName)) {
        $null = $Script:EventStats.Add([PSCustomObject]@{
            LogName = $LogName; RequestedIds = ($Id -join ','); Returned = 0
            Capped = $false; Status = 'CHANNEL_NOT_FOUND'
        })
        return @()
    }

    $filter = @{ LogName = $LogName; StartTime = $Script:Ctx.WindowStart }
    if ($Id) { $filter['ID'] = $Id }

    $events = @()
    $status = 'OK'
    try {
        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $Max -ErrorAction Stop)
    } catch {
        if ($_.Exception.Message -match 'No events were found|Belirtilen secim') {
            $status = 'NO_EVENTS'
        } else {
            $status = 'ERROR'
            Write-DLog "  Query failed for $LogName : $($_.Exception.Message)" -Level WARN
        }
    }

    $capped = ($events.Count -ge $Max)
    if ($capped) {
        $status = 'CAPPED'
        Write-DLog "  UYARI: $LogName cap'e takildi ($Max) - pencereyi daralt" -Level WARN
        Add-DFinding -RuleId 'DGL-018' -Severity INFO `
            -Title 'Event collection cap reached - data is incomplete' `
            -Evidence "$LogName : stopped at $Max records (-Days $Days)" `
            -Artifact '11_event_stats' `
            -Why 'Narrow the window or raise -MaxEventsPerChannel'
    }

    $null = $Script:EventStats.Add([PSCustomObject]@{
        LogName = $LogName; RequestedIds = ($Id -join ','); Returned = $events.Count
        Capped = $capped; Status = $status
    })

    return $events
}

function Get-DProp {
    <#
        Event property'sine indeksle guvenli erisim.
        NOT: .Message KULLANILMIYOR - her event icin mesaj formatlamasi yapar,
        50k eventte 4 dakikayi 40 dakikaya cikarir. Properties[] 10-20x hizli.
    #>
    param($Event, [int]$Index)
    try {
        if ($Event.Properties.Count -gt $Index) {
            return [string]$Event.Properties[$Index].Value
        }
    } catch { }
    return $null
}

function ConvertFrom-DEncodedCommand {
    <# -EncodedCommand payload'ini cozer. Raporda okunabilir hale getirir. #>
    param([string]$Text)
    if (-not $Text) { return $null }
    if ($Text -notmatch '(?i)\s-e(nc|ncod|ncoded|ncodedcommand)?\s+([A-Za-z0-9+/=]{24,})') {
        return $null
    }
    $b64 = $Matches[2]
    try {
        $bytes = [Convert]::FromBase64String($b64)
        $dec   = [Text.Encoding]::Unicode.GetString($bytes)
        # UTF-16LE degilse ASCII dene
        if ($dec -match '\x00') { $dec = [Text.Encoding]::UTF8.GetString($bytes) }
        return ($dec -replace '\s+', ' ').Trim()
    } catch { return $null }
}

function Get-DLogonTypeName {
    param($Type)
    switch ([string]$Type) {
        '2'  { 'Interactive' }
        '3'  { 'Network' }
        '4'  { 'Batch' }
        '5'  { 'Service' }
        '7'  { 'Unlock' }
        '8'  { 'NetworkCleartext' }
        '9'  { 'NewCredentials(RunAs)' }
        '10' { 'RemoteInteractive(RDP)' }
        '11' { 'CachedInteractive' }
        default { "Type$Type" }
    }
}

function Test-DEventCmdLine {
    <# Bir event komut satirini pattern setinden gecirir #>
    param([string]$CommandLine, [string]$Context, [string]$Artifact, $Timestamp, [string]$RuleId)

    if (-not $CommandLine) { return }
    foreach ($pat in $Script:CmdLinePatterns) {
        if ($CommandLine -match $pat.P) {
            $len = [Math]::Min(400, $CommandLine.Length)
            Add-DFinding -RuleId $RuleId -Severity $pat.S `
                -Title "Suspicious command in event record: $($pat.N)" `
                -Evidence "$Context :: $($CommandLine.Substring(0, $len))" `
                -Mitre $pat.M -Artifact $Artifact -Timestamp $Timestamp `
                -Why 'A historical event record matches an attacker behaviour pattern'
            return
        }
    }
}

# ============================================================================
#  MODUL: EVENT - PROCESS OLUSTURMA (4688) + POWERSHELL (4104)
# ============================================================================

Register-DModule -Name 'Events: process creation (4688)' -Phase 2 -RequiresCap 'WinEvent' `
    -Description 'Historical process execution with command lines' -Body {

    $evts = Get-DWinEvents -LogName 'Security' -Id 4688
    if ($evts.Count -eq 0) {
        Add-DFinding -RuleId 'DGL-140' -Severity MEDIUM `
            -Title 'No process creation auditing (4688) recorded' `
            -Evidence "No 4688 events found in the last $Days days" `
            -Mitre 'T1562.002' -Artifact '11_evt_4688' `
            -Why 'With this auditing off, past execution activity is invisible'
        return
    }

    $rows = foreach ($e in $evts) {
        $newProc = Get-DProp $e 5
        $cmdLine = Get-DProp $e 8
        $parent  = Get-DProp $e 13
        $baseName = if ($newProc) { (Split-Path $newProc -Leaf).ToLowerInvariant() } else { '' }

        [PSCustomObject]@{
            TimeUtc      = ConvertTo-DUtcString $e.TimeCreated
            SubjectUser  = "$(Get-DProp $e 2)\$(Get-DProp $e 1)"
            NewProcessId = Get-DProp $e 4
            NewProcess   = $newProc
            ParentProcess = $parent
            ParentPid    = Get-DProp $e 7
            CommandLine  = $cmdLine
            TokenElevation = Get-DProp $e 6
            TargetUser   = Get-DProp $e 10
            DecodedB64   = ConvertFrom-DEncodedCommand -Text $cmdLine
            IsLolBas     = ($Script:LolBasExec -contains $baseName)
            IsDiscovery  = ($Script:DiscoveryBins -contains $baseName)
            IsExfilTool  = ($Script:ExfilBins -contains $baseName)
            SuspiciousPath = Test-DSuspiciousPath -Path $newProc
        }
    }
    $rows = @($rows)
    Export-DArtifact -Name '11_evt_4688' -Data $rows -SubDir events

    # Komut satiri denetimi acik mi?
    $withCmd = @($rows | Where-Object { $_.CommandLine }).Count
    if ($withCmd -eq 0 -and $rows.Count -gt 0) {
        Add-DFinding -RuleId 'DGL-141' -Severity MEDIUM `
            -Title '4688 events carry no command line' `
            -Evidence "$($rows.Count) events present but the CommandLine field is empty" `
            -Mitre 'T1562.002' -Artifact '11_evt_4688' `
            -Why 'ProcessCreationIncludeCmdLine_Enabled is off, which removes most of the hunting value'
    }

    # --- TRIAGE ---
    $lolCount = @{}
    foreach ($r in $rows) {
        if ($r.SuspiciousPath) {
            Add-DFinding -RuleId 'DGL-142' -Severity HIGH `
                -Title 'Process previously executed from a suspicious directory' `
                -Evidence "$($r.TimeUtc) [$($r.SubjectUser)] $($r.NewProcess)" `
                -Mitre 'T1036' -Artifact '11_evt_4688' -Timestamp $r.TimeUtc
            Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'Evt4688' `
                -Description "Suspicious execution: $($r.NewProcess)" `
                -Detail $r.CommandLine -Severity HIGH
        }

        Test-DEventCmdLine -CommandLine $r.CommandLine -RuleId 'DGL-143' `
            -Context "4688 $($r.TimeUtc) [$($r.SubjectUser)]" `
            -Artifact '11_evt_4688' -Timestamp $r.TimeUtc

        # Cozulmus base64 payload da taransin
        if ($r.DecodedB64) {
            Add-DFinding -RuleId 'DGL-144' -Severity HIGH `
                -Title 'Encoded PowerShell command decoded' `
                -Evidence "$($r.TimeUtc) :: $($r.DecodedB64.Substring(0, [Math]::Min(400, $r.DecodedB64.Length)))" `
                -Mitre 'T1027' -Artifact '11_evt_4688' -Timestamp $r.TimeUtc `
                -Why 'The decoded form of a base64-obfuscated command'
            Test-DEventCmdLine -CommandLine $r.DecodedB64 -RuleId 'DGL-145' `
                -Context "4688-decoded $($r.TimeUtc)" `
                -Artifact '11_evt_4688' -Timestamp $r.TimeUtc
        }

        # Parent-child anomalisi (gecmis)
        if ($r.ParentProcess -and $r.NewProcess) {
            $pn = (Split-Path $r.ParentProcess -Leaf) -replace '\.exe$', ''
            $cn = (Split-Path $r.NewProcess -Leaf) -replace '\.exe$', ''
            foreach ($rule in $Script:BadParentChild) {
                if ($pn -match "^($($rule.Parent))$" -and $cn -match "^($($rule.Child))$") {
                    Add-DFinding -RuleId 'DGL-146' -Severity $rule.S `
                        -Title "$($rule.Name) [historical]" `
                        -Evidence "$($r.TimeUtc) $($r.ParentProcess) -> $($r.NewProcess) :: $($r.CommandLine)" `
                        -Mitre $rule.M -Artifact '11_evt_4688' -Timestamp $r.TimeUtc
                    Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'Evt4688' `
                        -Description $rule.Name -Detail "$($r.ParentProcess) -> $($r.NewProcess)" `
                        -Severity CRITICAL
                    break
                }
            }
        }

        if ($r.IsLolBas) {
            $key = (Split-Path $r.NewProcess -Leaf)
            if (-not $lolCount.ContainsKey($key)) { $lolCount[$key] = 0 }
            $lolCount[$key]++
        }
    }

    # LOLBAS ozeti
    $lolSummary = @($lolCount.GetEnumerator() | Sort-Object Value -Descending |
                    ForEach-Object { [PSCustomObject]@{ Binary = $_.Key; Count = $_.Value } })
    Export-DArtifact -Name '11_evt_4688_lolbas' -Data $lolSummary -SubDir events

    # Parent-child frekans tablosu (nadir kombinasyon = supheli)
    $pcPairs = @($rows | Where-Object { $_.ParentProcess -and $_.NewProcess } |
        Group-Object { "$(Split-Path $_.ParentProcess -Leaf) -> $(Split-Path $_.NewProcess -Leaf)" } |
        Sort-Object Count |
        ForEach-Object { [PSCustomObject]@{ Pair = $_.Name; Count = $_.Count } })
    Export-DArtifact -Name '11_evt_4688_parentchild' -Data $pcPairs -SubDir events

    Write-DLog "  $($rows.Count) adet 4688 ($($lolSummary.Count) farkli LOLBAS)" -Level DEBUG
}

Register-DModule -Name 'Events: PowerShell (4104/4103/400)' -Phase 2 -RequiresCap 'WinEvent' `
    -Description 'Script block logging and remoting traces' -Body {

    # --- 4104 Script Block Logging ---
    $sb = Get-DWinEvents -LogName 'Microsoft-Windows-PowerShell/Operational' -Id 4104
    $sbRows = foreach ($e in $sb) {
        $text = Get-DProp $e 2
        if ($text -and $text.Length -gt 4000) { $text = $text.Substring(0, 4000) + '...[KIRPILDI]' }
        [PSCustomObject]@{
            TimeUtc       = ConvertTo-DUtcString $e.TimeCreated
            Level         = [string]$e.LevelDisplayName
            MessageNumber = Get-DProp $e 0
            MessageTotal  = Get-DProp $e 1
            ScriptBlockId = Get-DProp $e 3
            Path          = Get-DProp $e 4
            ScriptBlock   = $text
        }
    }
    $sbRows = @($sbRows)
    Export-DArtifact -Name '11_evt_ps_4104' -Data $sbRows -SubDir events

    foreach ($r in $sbRows) {
        # Warning seviyesi = PowerShell'in kendi supheli-blok tespiti
        if ($r.Level -match '(?i)warning') {
            Add-DFinding -RuleId 'DGL-150' -Severity HIGH `
                -Title 'PowerShell flagged the script block as suspicious' `
                -Evidence "$($r.TimeUtc) :: $($r.ScriptBlock.Substring(0, [Math]::Min(300, $r.ScriptBlock.Length)))" `
                -Mitre 'T1059.001' -Artifact '11_evt_ps_4104' -Timestamp $r.TimeUtc `
                -Why 'Warning-level blocks are recorded even when script block logging is off'
        }
        Test-DEventCmdLine -CommandLine $r.ScriptBlock -RuleId 'DGL-151' `
            -Context "4104 $($r.TimeUtc)" -Artifact '11_evt_ps_4104' -Timestamp $r.TimeUtc
    }

    # --- 400 klasik: PS Remoting girisi ---
    $classic = Get-DWinEvents -LogName 'Windows PowerShell' -Id 400, 403, 600
    $clRows = foreach ($e in $classic) {
        $detail = Get-DProp $e 2
        [PSCustomObject]@{
            TimeUtc = ConvertTo-DUtcString $e.TimeCreated
            EventId = $e.Id
            EngineState = Get-DProp $e 0
            Detail  = if ($detail -and $detail.Length -gt 1000) {
                          $detail.Substring(0, 1000) } else { $detail }
            IsRemoting = [bool]($detail -match '(?i)ServerRemoteHost')
        }
    }
    $clRows = @($clRows)
    Export-DArtifact -Name '11_evt_ps_classic' -Data $clRows -SubDir events

    $remoting = @($clRows | Where-Object IsRemoting)
    foreach ($r in ($remoting | Select-Object -First 20)) {
        Add-DFinding -RuleId 'DGL-152' -Severity MEDIUM `
            -Title 'PowerShell Remoting session detected' `
            -Evidence "$($r.TimeUtc) EventID $($r.EventId) HostName=ServerRemoteHost" `
            -Mitre 'T1021.006' -Artifact '11_evt_ps_classic' -Timestamp $r.TimeUtc `
            -Why 'Remote PowerShell access can indicate lateral movement'
        Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'PSRemoting' `
            -Description 'PowerShell Remoting session' -Severity MEDIUM
    }

    Write-DLog "  $($sbRows.Count) adet 4104, $($clRows.Count) klasik PS ($($remoting.Count) remoting)" -Level DEBUG
}

# ============================================================================
#  MODUL: EVENT - OTURUM ACMA / KIMLIK DOGRULAMA
# ============================================================================

Register-DModule -Name 'Events: logon activity' -Phase 2 -RequiresCap 'WinEvent' `
    -Description '4624/4625/4648/4672/4776 - who, from where, how' -Body {

    # --- 4624 basarili logon ---
    $ok = Get-DWinEvents -LogName 'Security' -Id 4624
    $okRows = foreach ($e in $ok) {
        $lt = Get-DProp $e 8
        [PSCustomObject]@{
            TimeUtc       = ConvertTo-DUtcString $e.TimeCreated
            TargetUser    = "$(Get-DProp $e 6)\$(Get-DProp $e 5)"
            TargetSid     = Get-DProp $e 4
            LogonType     = $lt
            LogonTypeName = Get-DLogonTypeName $lt
            LogonProcess  = Get-DProp $e 9
            AuthPackage   = Get-DProp $e 10
            Workstation   = Get-DProp $e 11
            ProcessName   = Get-DProp $e 17
            IpAddress     = Get-DProp $e 18
            IpPort        = Get-DProp $e 19
            LogonId       = Get-DProp $e 7
        }
    }
    # Makine hesaplarini ve ANONYMOUS'u ele - gurultu
    $okRows = @($okRows | Where-Object {
        $_.TargetUser -notmatch '\$$' -and $_.TargetUser -notmatch 'ANONYMOUS LOGON' -and
        $_.TargetSid -notin 'S-1-5-18', 'S-1-5-19', 'S-1-5-20'
    })
    Export-DArtifact -Name '11_evt_4624_logon' -Data $okRows -SubDir events

    # --- 4625 basarisiz logon ---
    $fail = Get-DWinEvents -LogName 'Security' -Id 4625
    $failRows = @(foreach ($e in $fail) {
        $lt = Get-DProp $e 10
        [PSCustomObject]@{
            TimeUtc       = ConvertTo-DUtcString $e.TimeCreated
            TargetUser    = "$(Get-DProp $e 6)\$(Get-DProp $e 5)"
            LogonType     = $lt
            LogonTypeName = Get-DLogonTypeName $lt
            Status        = Get-DProp $e 7
            SubStatus     = Get-DProp $e 9
            Workstation   = Get-DProp $e 13
            IpAddress     = Get-DProp $e 19
            ProcessName   = Get-DProp $e 18
        }
    })
    Export-DArtifact -Name '11_evt_4625_failed' -Data $failRows -SubDir events

    # --- 4648 explicit credential (lateral movement altin sinyali) ---
    $expl = Get-DWinEvents -LogName 'Security' -Id 4648
    $explRows = @(foreach ($e in $expl) {
        [PSCustomObject]@{
            TimeUtc      = ConvertTo-DUtcString $e.TimeCreated
            SubjectUser  = "$(Get-DProp $e 2)\$(Get-DProp $e 1)"
            TargetUser   = "$(Get-DProp $e 6)\$(Get-DProp $e 5)"
            TargetServer = Get-DProp $e 8
            ProcessName  = Get-DProp $e 11
            IpAddress    = Get-DProp $e 12
        }
    })
    Export-DArtifact -Name '11_evt_4648_explicit' -Data $explRows -SubDir events

    # --- 4672 ozel yetkiler ---
    $priv = Get-DWinEvents -LogName 'Security' -Id 4672
    $privAll = @(foreach ($e in $priv) {
        [PSCustomObject]@{
            TimeUtc    = ConvertTo-DUtcString $e.TimeCreated
            User       = "$(Get-DProp $e 2)\$(Get-DProp $e 1)"
            Sid        = Get-DProp $e 0
            LogonId    = Get-DProp $e 3
        }
    })
    $privRows = @($privAll | Where-Object {
        $_.User -notmatch '\$$' -and $_.Sid -notin 'S-1-5-18', 'S-1-5-19', 'S-1-5-20'
    })
    Export-DArtifact -Name '11_evt_4672_privileged' -Data $privRows -SubDir events

    # --- TRIAGE ---

    # Type 9 = RunAs/NetOnly - pass-the-hash / overpass-the-hash klasigi
    foreach ($r in @($okRows | Where-Object LogonType -eq '9')) {
        Add-DFinding -RuleId 'DGL-160' -Severity HIGH `
            -Title 'Logon Type 9 (NewCredentials/RunAs) detected' `
            -Evidence "$($r.TimeUtc) $($r.TargetUser) via $($r.ProcessName)" `
            -Mitre 'T1550.002' -Artifact '11_evt_4624_logon' -Timestamp $r.TimeUtc `
            -Why 'Type 9 is the typical trace of pass-the-hash and overpass-the-hash'
        Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'Logon' `
            -Description "Type9 RunAs logon: $($r.TargetUser)" -Severity HIGH
    }

    # Type 8 = NetworkCleartext - duz metin parola agdan gecti
    foreach ($r in @($okRows | Where-Object LogonType -eq '8' | Select-Object -First 20)) {
        Add-DFinding -RuleId 'DGL-161' -Severity MEDIUM `
            -Title 'Logon Type 8 (NetworkCleartext)' `
            -Evidence "$($r.TimeUtc) $($r.TargetUser) from $($r.IpAddress)" `
            -Mitre 'T1078' -Artifact '11_evt_4624_logon' -Timestamp $r.TimeUtc `
            -Why 'The password may have crossed the network in clear text'
    }

    # RDP oturumlari (Type 10) - dis kaynakli olanlar
    foreach ($r in @($okRows | Where-Object { $_.LogonType -eq '10' -and $_.IpAddress -and
                     $_.IpAddress -notmatch '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|-|::1)' })) {
        Add-DFinding -RuleId 'DGL-162' -Severity HIGH `
            -Title 'RDP session from outside private address space' `
            -Evidence "$($r.TimeUtc) $($r.TargetUser) <- $($r.IpAddress)" `
            -Mitre 'T1021.001' -Artifact '11_evt_4624_logon' -Timestamp $r.TimeUtc `
            -Why 'Internet-exposed RDP is a common initial access vector'
        Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'RDP' `
            -Description "External RDP: $($r.TargetUser) from $($r.IpAddress)" -Severity HIGH
    }

    # Brute force / password spray tespiti
    $byIp = $failRows | Where-Object { $_.IpAddress -and $_.IpAddress -notin '-', '::1', '127.0.0.1' } |
            Group-Object IpAddress | Sort-Object Count -Descending
    foreach ($g in ($byIp | Select-Object -First 10)) {
        if ($g.Count -ge 20) {
            $uniqUsers = @($g.Group | Select-Object -ExpandProperty TargetUser -Unique).Count
            $kind = if ($uniqUsers -ge 5) { 'Password spray' } else { 'Brute force' }
            Add-DFinding -RuleId 'DGL-163' -Severity HIGH `
                -Title "$kind suspected (4625 volume)" `
                -Evidence "$($g.Count) failed attempts from $($g.Name) against $uniqUsers distinct accounts" `
                -Mitre 'T1110' -Artifact '11_evt_4625_failed' `
                -Why 'A high volume of authentication failures from a single source'
        }
    }

    # Basarisiz denemelerin ardindan BASARILI logon = ele gecirme
    foreach ($g in ($byIp | Select-Object -First 20)) {
        if ($g.Count -lt 10) { continue }
        $succ = @($okRows | Where-Object { $_.IpAddress -eq $g.Name })
        if ($succ.Count -gt 0) {
            Add-DFinding -RuleId 'DGL-164' -Severity CRITICAL `
                -Title 'SUCCESSFUL logon after repeated failures' `
                -Evidence "$($g.Name): $($g.Count) failures followed by $($succ.Count) success ($($succ[0].TargetUser))" `
                -Mitre 'T1110' -Artifact '11_evt_4624_logon' `
                -Why 'The account may have been taken over after brute force or password spraying'
        }
    }

    # 4648 - admin share hedefleri
    foreach ($r in @($explRows | Where-Object { $_.TargetServer -and
                     $_.TargetServer -notmatch '(?i)^(localhost|-)$' } | Select-Object -First 30)) {
        Add-DFinding -RuleId 'DGL-165' -Severity MEDIUM `
            -Title 'Remote access using explicit credentials' `
            -Evidence "$($r.TimeUtc) $($r.SubjectUser) -> $($r.TargetUser)@$($r.TargetServer) via $($r.ProcessName)" `
            -Mitre 'T1021' -Artifact '11_evt_4648_explicit' -Timestamp $r.TimeUtc `
            -Why '4648 is among the most reliable indicators of lateral movement'
        Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'Lateral' `
            -Description "Explicit cred: $($r.SubjectUser) -> $($r.TargetServer)" -Severity MEDIUM
    }

    # Mesai disi interaktif logon
    foreach ($r in @($okRows | Where-Object { $_.LogonType -in '2', '10' })) {
        try {
            $h = ([DateTime]$r.TimeUtc).Hour
            if ($h -ge 0 -and $h -le 5) {
                Add-DFinding -RuleId 'DGL-166' -Severity MEDIUM `
                    -Title 'Out-of-hours interactive logon (00:00-05:00 UTC)' `
                    -Evidence "$($r.TimeUtc) $($r.TargetUser) [$($r.LogonTypeName)] from $($r.IpAddress)" `
                    -Artifact '11_evt_4624_logon' -Timestamp $r.TimeUtc `
                    -Why 'Attacker activity typically falls outside normal working hours'
            }
        } catch { }
    }

    Write-DLog "  4624:$($okRows.Count)  4625:$($failRows.Count)  4648:$($explRows.Count)  4672:$($privRows.Count)" -Level DEBUG
}

# ============================================================================
#  MODUL: EVENT - HESAP YONETIMI VE POLITIKA
# ============================================================================

Register-DModule -Name 'Events: account and policy changes' -Phase 2 -RequiresCap 'WinEvent' `
    -Description '4720-4756 account operations plus 1102/4719 anti-forensics' -Body {

    # --- Hesap islemleri ---
    $acct = Get-DWinEvents -LogName 'Security' `
            -Id 4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4767, 4781
    $acctRows = @(foreach ($e in $acct) {
        [PSCustomObject]@{
            TimeUtc    = ConvertTo-DUtcString $e.TimeCreated
            EventId    = $e.Id
            Action     = switch ($e.Id) {
                4720 { 'User account created' }    4722 { 'Account enabled' }
                4723 { 'Password changed' }      4724 { 'Password reset' }
                4725 { 'Account disabled' }         4726 { 'User account deleted' }
                4738 { 'Account modified' }       4740 { 'Account locked out' }
                4767 { 'Account unlocked' }      4781 { 'Account renamed' }
                default { "ID$($e.Id)" }
            }
            TargetUser = Get-DProp $e 0
            TargetSid  = Get-DProp $e 2
            ByUser     = "$(Get-DProp $e 5)\$(Get-DProp $e 4)"
        }
    })
    Export-DArtifact -Name '11_evt_account_mgmt' -Data $acctRows -SubDir events

    foreach ($r in $acctRows) {
        $sev = switch ($r.EventId) {
            4720 { 'HIGH' }  4726 { 'HIGH' }  4724 { 'HIGH' }
            4722 { 'MEDIUM' } 4781 { 'MEDIUM' } default { 'LOW' }
        }
        if ($sev -in 'HIGH', 'MEDIUM') {
            Add-DFinding -RuleId 'DGL-170' -Severity $sev -Title $r.Action `
                -Evidence "$($r.TimeUtc) target: $($r.TargetUser) | by: $($r.ByUser)" `
                -Mitre 'T1136.001' -Artifact '11_evt_account_mgmt' -Timestamp $r.TimeUtc
            Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'AccountMgmt' `
                -Description "$($r.Action): $($r.TargetUser)" -Detail "by $($r.ByUser)" -Severity $sev
        }
    }

    # --- Grup uyelik degisimleri ---
    $grp = Get-DWinEvents -LogName 'Security' -Id 4728, 4732, 4756, 4729, 4733, 4757
    $grpRows = @(foreach ($e in $grp) {
        [PSCustomObject]@{
            TimeUtc   = ConvertTo-DUtcString $e.TimeCreated
            EventId   = $e.Id
            Action    = if ($e.Id -in 4728, 4732, 4756) { 'ADDED to group' } else { 'Removed from group' }
            Member    = Get-DProp $e 0
            MemberSid = Get-DProp $e 1
            Group     = Get-DProp $e 2
            ByUser    = "$(Get-DProp $e 7)\$(Get-DProp $e 6)"
        }
    })
    Export-DArtifact -Name '11_evt_group_mgmt' -Data $grpRows -SubDir events

    $privGroups = 'Domain Admins|Enterprise Admins|Schema Admins|Administrators|Yoneticiler|' +
                  'Account Operators|Backup Operators|Server Operators|Print Operators|' +
                  'DnsAdmins|Group Policy Creator Owners|Remote Desktop Users'
    foreach ($r in $grpRows) {
        if ($r.EventId -in 4728, 4732, 4756) {
            $sev = if ($r.Group -match "(?i)($privGroups)") { 'CRITICAL' } else { 'MEDIUM' }
            Add-DFinding -RuleId 'DGL-171' -Severity $sev `
                -Title 'Member added to a privileged group' `
                -Evidence "$($r.TimeUtc) $($r.Member) -> $($r.Group) | ekleyen: $($r.ByUser)" `
                -Mitre 'T1098' -Artifact '11_evt_group_mgmt' -Timestamp $r.TimeUtc `
                -Why 'Group membership changes indicate privilege escalation and persistence'
            Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'GroupMgmt' `
                -Description "Added to group: $($r.Member) -> $($r.Group)" -Severity $sev
        }
    }

    # --- ANTI-FORENSICS: log temizleme ve denetim politikasi degisimi ---
    $af = Get-DWinEvents -LogName 'Security' -Id 1102, 4719, 4616
    $afRows = @(foreach ($e in $af) {
        [PSCustomObject]@{
            TimeUtc = ConvertTo-DUtcString $e.TimeCreated
            EventId = $e.Id
            Action  = switch ($e.Id) {
                1102 { 'SECURITY LOG CLEARED' }
                4719 { 'Audit policy changed' }
                4616 { 'System clock changed' }
            }
            User    = "$(Get-DProp $e 2)\$(Get-DProp $e 1)"
        }
    })
    Export-DArtifact -Name '11_evt_antiforensics' -Data $afRows -SubDir events

    foreach ($r in $afRows) {
        $sev = if ($r.EventId -eq 1102) { 'CRITICAL' } else { 'HIGH' }
        Add-DFinding -RuleId 'DGL-172' -Severity $sev -Title $r.Action `
            -Evidence "$($r.TimeUtc) | $($r.User)" `
            -Mitre 'T1070.001' -Artifact '11_evt_antiforensics' -Timestamp $r.TimeUtc `
            -Why 'Anti-forensic activity, a sign the intrusion is active'
        Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'AntiForensics' `
            -Description $r.Action -Detail $r.User -Severity CRITICAL
    }

    # --- Servis kurulumu (Security tarafi) + gorev islemleri ---
    $svcEvt = Get-DWinEvents -LogName 'Security' -Id 4697
    $svcRows = @(foreach ($e in $svcEvt) {
        [PSCustomObject]@{
            TimeUtc     = ConvertTo-DUtcString $e.TimeCreated
            ServiceName = Get-DProp $e 4
            ServiceFile = Get-DProp $e 5
            StartType   = Get-DProp $e 7
            Account     = Get-DProp $e 8
            ByUser      = "$(Get-DProp $e 2)\$(Get-DProp $e 1)"
        }
    })
    Export-DArtifact -Name '11_evt_4697_service' -Data $svcRows -SubDir events

    foreach ($r in $svcRows) {
        Add-DFinding -RuleId 'DGL-173' -Severity HIGH `
            -Title 'Service installation recorded (4697)' `
            -Evidence "$($r.TimeUtc) $($r.ServiceName) -> $($r.ServiceFile) [$($r.ByUser)]" `
            -Mitre 'T1543.003' -Artifact '11_evt_4697_service' -Timestamp $r.TimeUtc
        Test-DEventCmdLine -CommandLine $r.ServiceFile -RuleId 'DGL-174' `
            -Context "4697 $($r.ServiceName)" -Artifact '11_evt_4697_service' -Timestamp $r.TimeUtc
    }

    $taskEvt = Get-DWinEvents -LogName 'Security' -Id 4698, 4699, 4700, 4702
    $taskRows = @(foreach ($e in $taskEvt) {
        [PSCustomObject]@{
            TimeUtc = ConvertTo-DUtcString $e.TimeCreated
            EventId = $e.Id
            Action  = switch ($e.Id) {
                4698 { 'Task created' } 4699 { 'Task deleted' }
                4700 { 'Task enabled' } 4702 { 'Task updated' }
            }
            ByUser  = "$(Get-DProp $e 2)\$(Get-DProp $e 1)"
            TaskName = Get-DProp $e 4
        }
    })
    Export-DArtifact -Name '11_evt_task_mgmt' -Data $taskRows -SubDir events

    foreach ($r in $taskRows) {
        if ($r.EventId -in 4698, 4702) {
            Add-DFinding -RuleId 'DGL-175' -Severity HIGH -Title $r.Action `
                -Evidence "$($r.TimeUtc) $($r.TaskName) [$($r.ByUser)]" `
                -Mitre 'T1053.005' -Artifact '11_evt_task_mgmt' -Timestamp $r.TimeUtc
            Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'TaskMgmt' `
                -Description "$($r.Action): $($r.TaskName)" -Severity HIGH
        }
    }

    Write-DLog "  accounts:$($acctRows.Count) groups:$($grpRows.Count) antiforensics:$($afRows.Count) services:$($svcRows.Count)" -Level DEBUG
}

# ============================================================================
#  MODUL: EVENT - SYSTEM (SERVIS / SURUCU / LOG)
# ============================================================================

Register-DModule -Name 'Events: system (7045/7040/104)' -Phase 2 -RequiresCap 'WinEvent' `
    -Description 'Service installation, start type changes, log clearing' -Body {

    $sys = Get-DWinEvents -LogName 'System' -Id 7045, 7034, 7040, 104, 6008, 1074, 20001

    $rows = @(foreach ($e in $sys) {
        $o = [PSCustomObject]@{
            TimeUtc  = ConvertTo-DUtcString $e.TimeCreated
            EventId  = $e.Id
            Provider = $e.ProviderName
            F0 = Get-DProp $e 0; F1 = Get-DProp $e 1
            F2 = Get-DProp $e 2; F3 = Get-DProp $e 3; F4 = Get-DProp $e 4
        }
        $o
    })

    # 7045: [0]ServiceName [1]ImagePath [2]ServiceType [3]StartType [4]AccountName
    $newSvc = @($rows | Where-Object EventId -eq 7045 | ForEach-Object {
        [PSCustomObject]@{
            TimeUtc     = $_.TimeUtc
            ServiceName = $_.F0
            ImagePath   = $_.F1
            ServiceType = $_.F2
            StartType   = $_.F3
            Account     = $_.F4
            SuspiciousPath = Test-DSuspiciousPath -Path (Get-DCleanPath -CommandLine $_.F1)
        }
    })
    Export-DArtifact -Name '11_evt_7045_newservice' -Data $newSvc -SubDir events

    foreach ($s in $newSvc) {
        $sev = if ($s.SuspiciousPath) { 'CRITICAL' } else { 'HIGH' }
        Add-DFinding -RuleId 'DGL-180' -Severity $sev `
            -Title 'New service installed (7045)' `
            -Evidence "$($s.TimeUtc) $($s.ServiceName) -> $($s.ImagePath) [$($s.Account)]" `
            -Mitre 'T1543.003' -Artifact '11_evt_7045_newservice' -Timestamp $s.TimeUtc `
            -Why 'PsExec, Impacket and the Cobalt Strike SMB beacon install as services'
        Add-DTimelineEvent -Timestamp $s.TimeUtc -Source 'Service' `
            -Description "New service: $($s.ServiceName)" -Detail $s.ImagePath -Severity $sev

        # Rastgele servis adi (CS beacon imzasi)
        if (Test-DRandomName -Name $s.ServiceName) {
            Add-DFinding -RuleId 'DGL-181' -Severity CRITICAL `
                -Title 'Service installed with a random name' `
                -Evidence "$($s.TimeUtc) $($s.ServiceName) -> $($s.ImagePath)" `
                -Mitre 'T1569.002' -Artifact '11_evt_7045_newservice' -Timestamp $s.TimeUtc
        }
        Test-DEventCmdLine -CommandLine $s.ImagePath -RuleId 'DGL-182' `
            -Context "7045 $($s.ServiceName)" `
            -Artifact '11_evt_7045_newservice' -Timestamp $s.TimeUtc
    }

    # 7040: baslangic tipi degisimi (savunma kapatma)
    $startChg = @($rows | Where-Object EventId -eq 7040)
    Export-DArtifact -Name '11_evt_7040_starttype' -Data $startChg -SubDir events
    foreach ($c in $startChg) {
        if ($c.F0 -match '(?i)(defender|windefend|wuauserv|eventlog|mpssvc|sense|wscsvc|sppsvc|bits)') {
            Add-DFinding -RuleId 'DGL-183' -Severity CRITICAL `
                -Title 'Security service start type was changed' `
                -Evidence "$($c.TimeUtc) $($c.F0) : $($c.F1) -> $($c.F2)" `
                -Mitre 'T1562.001' -Artifact '11_evt_7040_starttype' -Timestamp $c.TimeUtc `
                -Why 'A defensive mechanism may have been disabled'
        }
    }

    # 7034: beklenmedik sonlanma (EDR kill)
    $crashed = @($rows | Where-Object EventId -eq 7034)
    foreach ($c in $crashed) {
        if ($c.F0 -match '(?i)(defender|windefend|eventlog|mpssvc|sense|sysmon|wscsvc)') {
            Add-DFinding -RuleId 'DGL-184' -Severity CRITICAL `
                -Title 'Security service stopped unexpectedly' `
                -Evidence "$($c.TimeUtc) $($c.F0)" `
                -Mitre 'T1562.001' -Artifact '11_evt_system' -Timestamp $c.TimeUtc
        }
    }

    # 104: log temizleme
    foreach ($c in @($rows | Where-Object EventId -eq 104)) {
        Add-DFinding -RuleId 'DGL-185' -Severity CRITICAL `
            -Title 'Event log cleared (System 104)' `
            -Evidence "$($c.TimeUtc) channel: $($c.F2) | user: $($c.F1)" `
            -Mitre 'T1070.001' -Artifact '11_evt_system' -Timestamp $c.TimeUtc `
            -Why 'Anti-forensic activity'
        Add-DTimelineEvent -Timestamp $c.TimeUtc -Source 'AntiForensics' `
            -Description "Log cleared: $($c.F2)" -Severity CRITICAL
    }

    Export-DArtifact -Name '11_evt_system' -Data $rows -SubDir events
    Write-DLog "  $($rows.Count) System events ($($newSvc.Count) new services)" -Level DEBUG
}

# ============================================================================
#  MODUL: EVENT - RDP VE WINRM
# ============================================================================

Register-DModule -Name 'Events: RDP and WinRM' -Phase 2 -RequiresCap 'WinEvent' `
    -Description 'Inbound and OUTBOUND RDP plus remote management' -Body {

    # --- 1149: basarili RDP ag baglantisi (kullanici + kaynak IP) ---
    $rcm = Get-DWinEvents -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -Id 1149
    $rcmRows = @(foreach ($e in $rcm) {
        [PSCustomObject]@{
            TimeUtc   = ConvertTo-DUtcString $e.TimeCreated
            User      = Get-DProp $e 0
            Domain    = Get-DProp $e 1
            SourceIP  = Get-DProp $e 2
        }
    })
    Export-DArtifact -Name '11_evt_rdp_inbound' -Data $rcmRows -SubDir events

    foreach ($r in $rcmRows) {
        if ($r.SourceIP -and $r.SourceIP -notmatch '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1)') {
            Add-DFinding -RuleId 'DGL-190' -Severity HIGH `
                -Title 'RDP connection from outside private address space (1149)' `
                -Evidence "$($r.TimeUtc) $($r.Domain)\$($r.User) <- $($r.SourceIP)" `
                -Mitre 'T1021.001' -Artifact '11_evt_rdp_inbound' -Timestamp $r.TimeUtc
        }
        Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'RDP-In' `
            -Description "RDP giris: $($r.User)" -Detail $r.SourceIP -Severity MEDIUM
    }

    # --- 21/22/23/24/25: yerel oturum yonetimi ---
    $lsm = Get-DWinEvents -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' `
           -Id 21, 22, 23, 24, 25
    $lsmRows = @(foreach ($e in $lsm) {
        [PSCustomObject]@{
            TimeUtc = ConvertTo-DUtcString $e.TimeCreated
            EventId = $e.Id
            Action  = switch ($e.Id) {
                21 { 'Session logged on' }   22 { 'Shell baslatildi' }  23 { 'Session logged off' }
                24 { 'Session disconnected' } 25 { 'Session reconnected' }
            }
            User      = Get-DProp $e 0
            SessionId = Get-DProp $e 1
            SourceIP  = Get-DProp $e 2
        }
    })
    Export-DArtifact -Name '11_evt_rdp_sessions' -Data $lsmRows -SubDir events

    # --- 1024/1102: BU HOSTTAN DISARI RDP - lateral movement kaynagi ---
    $rdpc = Get-DWinEvents -LogName 'Microsoft-Windows-TerminalServices-RDPClient/Operational' -Id 1024, 1102
    $rdpcRows = @(foreach ($e in $rdpc) {
        [PSCustomObject]@{
            TimeUtc = ConvertTo-DUtcString $e.TimeCreated
            EventId = $e.Id
            Target  = Get-DProp $e 0
        }
    })
    Export-DArtifact -Name '11_evt_rdp_outbound' -Data $rdpcRows -SubDir events

    $targets = @($rdpcRows | Where-Object Target | Group-Object Target)
    foreach ($t in $targets) {
        Add-DFinding -RuleId 'DGL-191' -Severity HIGH `
            -Title 'OUTBOUND RDP connection from this host' `
            -Evidence "Destination: $($t.Name) ($($t.Count) times)" `
            -Mitre 'T1021.001' -Artifact '11_evt_rdp_outbound' `
            -Why 'Outbound RDP shows this host was a source of lateral movement'
        Add-DTimelineEvent -Timestamp $t.Group[0].TimeUtc -Source 'RDP-Out' `
            -Description "Outbound RDP: $($t.Name)" -Severity HIGH
    }

    # --- WinRM ---
    $wrm = Get-DWinEvents -LogName 'Microsoft-Windows-WinRM/Operational' -Id 6, 91, 168, 169
    $wrmRows = @(foreach ($e in $wrm) {
        [PSCustomObject]@{
            TimeUtc = ConvertTo-DUtcString $e.TimeCreated
            EventId = $e.Id
            Detail  = (Get-DProp $e 0)
            Extra   = (Get-DProp $e 1)
        }
    })
    Export-DArtifact -Name '11_evt_winrm' -Data $wrmRows -SubDir events

    $auth = @($wrmRows | Where-Object EventId -eq 169)
    foreach ($a in ($auth | Select-Object -First 20)) {
        Add-DFinding -RuleId 'DGL-192' -Severity MEDIUM `
            -Title 'WinRM authentication' `
            -Evidence "$($a.TimeUtc) $($a.Detail) $($a.Extra)" `
            -Mitre 'T1021.006' -Artifact '11_evt_winrm' -Timestamp $a.TimeUtc `
            -Why 'Remote management access can be used for lateral movement'
    }

    Write-DLog "  RDP-in:$($rcmRows.Count) sessions:$($lsmRows.Count) RDP-out:$($rdpcRows.Count) WinRM:$($wrmRows.Count)" -Level DEBUG
}

# ============================================================================
#  MODUL: EVENT - GOREV / WMI / DEFENDER / BITS / CODEINTEGRITY / FIREWALL
# ============================================================================

Register-DModule -Name 'Events: persistence and defence channels' -Phase 2 -RequiresCap 'WinEvent' `
    -Description 'TaskScheduler, WMI-Activity, Defender, BITS, CodeIntegrity, Firewall' -Body {

    # --- Task Scheduler ---
    $ts = Get-DWinEvents -LogName 'Microsoft-Windows-TaskScheduler/Operational' -Id 106, 140, 141, 200
    $tsRows = @(foreach ($e in $ts) {
        [PSCustomObject]@{
            TimeUtc  = ConvertTo-DUtcString $e.TimeCreated
            EventId  = $e.Id
            Action   = switch ($e.Id) {
                106 { 'Task registered' } 140 { 'Task updated' }
                141 { 'Task deleted' }    200 { 'Task action started' }
            }
            TaskName = Get-DProp $e 0
            User     = Get-DProp $e 1
        }
    })
    Export-DArtifact -Name '11_evt_taskscheduler' -Data $tsRows -SubDir events

    foreach ($r in @($tsRows | Where-Object EventId -in 106, 140)) {
        Add-DFinding -RuleId 'DGL-200' -Severity HIGH -Title $r.Action `
            -Evidence "$($r.TimeUtc) $($r.TaskName) [$($r.User)]" `
            -Mitre 'T1053.005' -Artifact '11_evt_taskscheduler' -Timestamp $r.TimeUtc
        Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'TaskScheduler' `
            -Description "$($r.Action): $($r.TaskName)" -Severity HIGH
    }

    # --- WMI Activity: 5861 = kalici event aboneligi ---
    $wmiEvt = Get-DWinEvents -LogName 'Microsoft-Windows-WMI-Activity/Operational' -Id 5857, 5858, 5860, 5861
    $wmiRows = @(foreach ($e in $wmiEvt) {
        $msg = $null
        # Dusuk hacimli kanal - burada Message kullanmak guvenli
        if ($e.Id -in 5860, 5861) {
            try { $msg = $e.Message } catch { }
            if ($msg -and $msg.Length -gt 2000) { $msg = $msg.Substring(0, 2000) }
        }
        [PSCustomObject]@{
            TimeUtc = ConvertTo-DUtcString $e.TimeCreated
            EventId = $e.Id
            Detail  = $msg
        }
    })
    Export-DArtifact -Name '11_evt_wmi_activity' -Data $wmiRows -SubDir events

    foreach ($r in @($wmiRows | Where-Object EventId -eq 5861)) {
        Add-DFinding -RuleId 'DGL-201' -Severity CRITICAL `
            -Title 'WMI permanent event subscription recorded (5861)' `
            -Evidence "$($r.TimeUtc) :: $($r.Detail)" `
            -Mitre 'T1546.003' -Artifact '11_evt_wmi_activity' -Timestamp $r.TimeUtc `
            -Why '5861 is direct evidence of WMI persistence'
        Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'WMI' `
            -Description 'WMI permanent subscription created' -Severity CRITICAL
    }

    # --- Defender ---
    $def = Get-DWinEvents -LogName 'Microsoft-Windows-Windows Defender/Operational' `
           -Id 1006, 1007, 1008, 1009, 1116, 1117, 1118, 1119, 5001, 5007, 5010, 5012
    $defRows = @(foreach ($e in $def) {
        $msg = $null
        try { $msg = $e.Message } catch { }
        if ($msg) { $msg = ($msg -replace '\s+', ' ').Trim() }
        if ($msg -and $msg.Length -gt 1500) { $msg = $msg.Substring(0, 1500) }
        [PSCustomObject]@{
            TimeUtc = ConvertTo-DUtcString $e.TimeCreated
            EventId = $e.Id
            Detail  = $msg
        }
    })
    Export-DArtifact -Name '11_evt_defender' -Data $defRows -SubDir events

    foreach ($r in $defRows) {
        $info = switch ($r.EventId) {
            1116 { @{ S = 'HIGH';     T = 'Defender detected malware' } }
            1117 { @{ S = 'HIGH';     T = 'Defender aksiyon aldi' } }
            1118 { @{ S = 'CRITICAL'; T = 'Defender remediation FAILED' } }
            1119 { @{ S = 'CRITICAL'; T = 'Defender remediation failed critically' } }
            5001 { @{ S = 'CRITICAL'; T = 'Real-time protection DISABLED' } }
            5007 { @{ S = 'HIGH';     T = 'Defender configuration changed (exclusion?)' } }
            5010 { @{ S = 'CRITICAL'; T = 'Malware scanning disabled' } }
            5012 { @{ S = 'CRITICAL'; T = 'Virus scanning disabled' } }
            default { $null }
        }
        if ($info) {
            Add-DFinding -RuleId 'DGL-202' -Severity $info.S -Title $info.T `
                -Evidence "$($r.TimeUtc) :: $($r.Detail)" `
                -Mitre 'T1562.001' -Artifact '11_evt_defender' -Timestamp $r.TimeUtc
            Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'Defender' `
                -Description $info.T -Detail $r.Detail -Severity $info.S
        }
    }

    # --- BITS: URL iceren indirme kayitlari ---
    $bitsEvt = Get-DWinEvents -LogName 'Microsoft-Windows-Bits-Client/Operational' -Id 3, 59, 60, 61
    $bitsRows = @(foreach ($e in $bitsEvt) {
        $msg = $null
        try { $msg = ($e.Message -replace '\s+', ' ').Trim() } catch { }
        if ($msg -and $msg.Length -gt 1000) { $msg = $msg.Substring(0, 1000) }
        [PSCustomObject]@{
            TimeUtc = ConvertTo-DUtcString $e.TimeCreated
            EventId = $e.Id
            Detail  = $msg
            Url     = if ($msg -match '(https?://[^\s,;]+)') { $Matches[1] } else { $null }
        }
    })
    Export-DArtifact -Name '11_evt_bits' -Data $bitsRows -SubDir events

    foreach ($r in @($bitsRows | Where-Object Url)) {
        $null = Test-DIoc -Value $r.Url -Context 'BITS transfer' -Artifact '11_evt_bits'
        Add-DFinding -RuleId 'DGL-203' -Severity MEDIUM `
            -Title 'File transferred over BITS' `
            -Evidence "$($r.TimeUtc) $($r.Url)" `
            -Mitre 'T1197' -Artifact '11_evt_bits' -Timestamp $r.TimeUtc `
            -Why 'BITS is a common download channel that evades AV and EDR inspection'
    }

    # --- CodeIntegrity: imzasiz surucu bloklandi (BYOVD denemesi) ---
    $ci = Get-DWinEvents -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -Id 3033, 3077, 3001, 3002
    $ciRows = @(foreach ($e in $ci) {
        $msg = $null
        try { $msg = ($e.Message -replace '\s+', ' ').Trim() } catch { }
        [PSCustomObject]@{
            TimeUtc = ConvertTo-DUtcString $e.TimeCreated
            EventId = $e.Id
            Detail  = if ($msg -and $msg.Length -gt 800) { $msg.Substring(0, 800) } else { $msg }
        }
    })
    Export-DArtifact -Name '11_evt_codeintegrity' -Data $ciRows -SubDir events

    foreach ($r in $ciRows) {
        Add-DFinding -RuleId 'DGL-204' -Severity HIGH `
            -Title 'Code integrity violation (unsigned driver or image)' `
            -Evidence "$($r.TimeUtc) ID$($r.EventId) :: $($r.Detail)" `
            -Mitre 'T1068' -Artifact '11_evt_codeintegrity' -Timestamp $r.TimeUtc `
            -Why 'May be the trace of a bring-your-own-vulnerable-driver attempt'
    }

    # --- Firewall kural degisimleri ---
    $fw = Get-DWinEvents -LogName 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' `
          -Id 2004, 2005, 2006, 2033
    $fwRows = @(foreach ($e in $fw) {
        [PSCustomObject]@{
            TimeUtc  = ConvertTo-DUtcString $e.TimeCreated
            EventId  = $e.Id
            Action   = switch ($e.Id) {
                2004 { 'Rule added' } 2005 { 'Rule modified' }
                2006 { 'Rule deleted' } 2033 { 'TUM KURALLAR SILINDI' }
            }
            RuleName = Get-DProp $e 1
            AppPath  = Get-DProp $e 3
            Port     = Get-DProp $e 8
        }
    })
    Export-DArtifact -Name '11_evt_firewall' -Data $fwRows -SubDir events

    foreach ($r in $fwRows) {
        $sev = if ($r.EventId -eq 2033) { 'CRITICAL' }
               elseif ($r.EventId -eq 2004) { 'MEDIUM' } else { 'LOW' }
        if ($sev -in 'CRITICAL', 'MEDIUM') {
            Add-DFinding -RuleId 'DGL-205' -Severity $sev -Title "Firewall: $($r.Action)" `
                -Evidence "$($r.TimeUtc) $($r.RuleName) | $($r.AppPath) | port $($r.Port)" `
                -Mitre 'T1562.004' -Artifact '11_evt_firewall' -Timestamp $r.TimeUtc
        }
    }

    Write-DLog "  task:$($tsRows.Count) wmi:$($wmiRows.Count) defender:$($defRows.Count) bits:$($bitsRows.Count) fw:$($fwRows.Count)" -Level DEBUG
}

# ============================================================================
#  MODUL: EVENT - SYSMON (kuruluysa)
# ============================================================================

Register-DModule -Name 'Events: Sysmon' -Phase 2 -RequiresCap 'WinEvent' `
    -Description 'Process, network, pipe, LSASS access, WMI - the richest telemetry' -Body {

    if (-not $Script:Caps.Sysmon) {
        Write-DLog '  Sysmon kanali yok, atlandi' -Level DEBUG
        return
    }

    $ch = 'Microsoft-Windows-Sysmon/Operational'

    # --- Event 10: LSASS'a handle acma = credential dump ---
    $pa = Get-DWinEvents -LogName $ch -Id 10 -Max 20000
    $paRows = @(foreach ($e in $pa) {
        # Sysmon 13+ RuleName ile basliyor, eski surumler baslamiyor
        $off = if ($e.Properties.Count -ge 11) { 1 } else { 0 }
        [PSCustomObject]@{
            TimeUtc       = ConvertTo-DUtcString $e.TimeCreated
            SourceImage   = Get-DProp $e (4 + $off)
            TargetImage   = Get-DProp $e (7 + $off)
            GrantedAccess = Get-DProp $e (8 + $off)
            CallTrace     = Get-DProp $e (9 + $off)
        }
    })
    $lsassAccess = @($paRows | Where-Object { $_.TargetImage -match '(?i)lsass\.exe' })
    Export-DArtifact -Name '11_sysmon_10_lsass' -Data $lsassAccess -SubDir events

    foreach ($r in $lsassAccess) {
        # 0x1010 / 0x1410 / 0x143a = bellek okuma haklari
        if ($r.GrantedAccess -match '(?i)0x(1010|1410|143a|1438|1fffff)') {
            Add-DFinding -RuleId 'DGL-210' -Severity CRITICAL `
                -Title 'Access to LSASS memory (credential dump)' `
                -Evidence "$($r.TimeUtc) $($r.SourceImage) -> lsass.exe [$($r.GrantedAccess)]" `
                -Mitre 'T1003.001' -Artifact '11_sysmon_10_lsass' -Timestamp $r.TimeUtc `
                -Why 'This access mask is used to read LSASS memory'
            Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'Sysmon10' `
                -Description 'LSASS access' -Detail $r.SourceImage -Severity CRITICAL
        }
    }

    # --- Event 8: CreateRemoteThread = injection ---
    $crt = Get-DWinEvents -LogName $ch -Id 8 -Max 10000
    $crtRows = @(foreach ($e in $crt) {
        $off = if ($e.Properties.Count -ge 12) { 1 } else { 0 }
        [PSCustomObject]@{
            TimeUtc     = ConvertTo-DUtcString $e.TimeCreated
            SourceImage = Get-DProp $e (3 + $off)
            TargetImage = Get-DProp $e (6 + $off)
            StartModule = Get-DProp $e (8 + $off)
            StartFunction = Get-DProp $e (9 + $off)
        }
    })
    Export-DArtifact -Name '11_sysmon_08_injection' -Data $crtRows -SubDir events
    foreach ($r in ($crtRows | Select-Object -First 50)) {
        Add-DFinding -RuleId 'DGL-211' -Severity HIGH `
            -Title 'CreateRemoteThread (process injection)' `
            -Evidence "$($r.TimeUtc) $($r.SourceImage) -> $($r.TargetImage)" `
            -Mitre 'T1055' -Artifact '11_sysmon_08_injection' -Timestamp $r.TimeUtc
    }

    # --- Event 17/18: named pipe ---
    $pipes = Get-DWinEvents -LogName $ch -Id 17, 18 -Max 20000
    $pipeRows = @(foreach ($e in $pipes) {
        $off = if ($e.Properties.Count -ge 8) { 1 } else { 0 }
        [PSCustomObject]@{
            TimeUtc   = ConvertTo-DUtcString $e.TimeCreated
            EventId   = $e.Id
            PipeName  = Get-DProp $e (4 + $off)
            Image     = Get-DProp $e (5 + $off)
        }
    })
    Export-DArtifact -Name '11_sysmon_17_pipes' -Data $pipeRows -SubDir events
    foreach ($r in $pipeRows) {
        if (-not $r.PipeName) { continue }
        foreach ($pat in $Script:BadPipePatterns) {
            if ($r.PipeName -match $pat) {
                Add-DFinding -RuleId 'DGL-212' -Severity HIGH `
                    -Title 'Named pipe matching a C2 pattern was created' `
                    -Evidence "$($r.TimeUtc) $($r.PipeName) <- $($r.Image)" `
                    -Mitre 'T1071' -Artifact '11_sysmon_17_pipes' -Timestamp $r.TimeUtc
                break
            }
        }
    }

    # --- Event 22: DNS sorgulari ---
    $dnsq = Get-DWinEvents -LogName $ch -Id 22 -Max 20000
    $dnsRows = @(foreach ($e in $dnsq) {
        $off = if ($e.Properties.Count -ge 8) { 1 } else { 0 }
        [PSCustomObject]@{
            TimeUtc     = ConvertTo-DUtcString $e.TimeCreated
            QueryName   = Get-DProp $e (3 + $off)
            QueryResults = Get-DProp $e (5 + $off)
            Image       = Get-DProp $e (6 + $off)
        }
    })
    Export-DArtifact -Name '11_sysmon_22_dns' -Data $dnsRows -SubDir events
    foreach ($r in $dnsRows) {
        if ($r.QueryName) {
            $null = Test-DIoc -Value $r.QueryName -Context "DNS by $($r.Image)" `
                    -Artifact '11_sysmon_22_dns'
        }
    }

    # --- Event 25: process tampering (hollowing / herpaderping) ---
    $tamper = Get-DWinEvents -LogName $ch -Id 25 -Max 5000
    $tamperRows = @(foreach ($e in $tamper) {
        [PSCustomObject]@{
            TimeUtc = ConvertTo-DUtcString $e.TimeCreated
            Detail  = try { ($e.Message -replace '\s+', ' ').Trim() } catch { $null }
        }
    })
    Export-DArtifact -Name '11_sysmon_25_tampering' -Data $tamperRows -SubDir events
    foreach ($r in $tamperRows) {
        Add-DFinding -RuleId 'DGL-213' -Severity CRITICAL `
            -Title 'Process tampering (hollowing / herpaderping)' `
            -Evidence "$($r.TimeUtc) :: $($r.Detail)" `
            -Mitre 'T1055.012' -Artifact '11_sysmon_25_tampering' -Timestamp $r.TimeUtc
    }

    # --- Event 19/20/21: WMI ---
    $wmiSys = Get-DWinEvents -LogName $ch -Id 19, 20, 21 -Max 5000
    $wmiSysRows = @(foreach ($e in $wmiSys) {
        [PSCustomObject]@{
            TimeUtc = ConvertTo-DUtcString $e.TimeCreated
            EventId = $e.Id
            Detail  = try { ($e.Message -replace '\s+', ' ').Trim() } catch { $null }
        }
    })
    Export-DArtifact -Name '11_sysmon_19_wmi' -Data $wmiSysRows -SubDir events
    foreach ($r in $wmiSysRows) {
        Add-DFinding -RuleId 'DGL-214' -Severity CRITICAL `
            -Title 'Sysmon WMI event record (persistence)' `
            -Evidence "$($r.TimeUtc) ID$($r.EventId) :: $($r.Detail)" `
            -Mitre 'T1546.003' -Artifact '11_sysmon_19_wmi' -Timestamp $r.TimeUtc
    }

    Write-DLog "  Sysmon - lsass:$($lsassAccess.Count) inject:$($crtRows.Count) pipe:$($pipeRows.Count) dns:$($dnsRows.Count)" -Level DEBUG
}

# ============================================================================
#  MODUL: EVENT - KERBEROS (SADECE DC)
# ============================================================================

Register-DModule -Name 'Events: Kerberos (DC)' -Phase 2 -Scope 'DC' -RequiresCap 'WinEvent' `
    -Description '4768/4769/4771 - Kerberoasting, AS-REP, downgrade' -Body {

    # --- 4769: service ticket - RC4 + hacim = Kerberoasting ---
    $tgs = Get-DWinEvents -LogName 'Security' -Id 4769
    $tgsRows = @(foreach ($e in $tgs) {
        [PSCustomObject]@{
            TimeUtc     = ConvertTo-DUtcString $e.TimeCreated
            AccountName = Get-DProp $e 0
            Domain      = Get-DProp $e 1
            ServiceName = Get-DProp $e 2
            TicketEnc   = Get-DProp $e 5
            IpAddress   = Get-DProp $e 6
            Status      = Get-DProp $e 8
        }
    })
    Export-DArtifact -Name '11_evt_4769_kerberos' -Data $tgsRows -SubDir events

    # 0x17 = RC4-HMAC (Kerberoasting icin tercih edilir, kirilabilir)
    $rc4 = @($tgsRows | Where-Object { $_.TicketEnc -eq '0x17' -and $_.ServiceName -notmatch '\$$' })
    $byUser = $rc4 | Group-Object AccountName | Sort-Object Count -Descending
    foreach ($g in ($byUser | Select-Object -First 10)) {
        $svcCount = @($g.Group | Select-Object -ExpandProperty ServiceName -Unique).Count
        if ($g.Count -ge 10 -or $svcCount -ge 5) {
            Add-DFinding -RuleId 'DGL-220' -Severity CRITICAL `
                -Title 'Kerberoasting suspected (RC4 service ticket volume)' `
                -Evidence "$($g.Name): $($g.Count) RC4 tickets for $svcCount distinct services from $($g.Group[0].IpAddress)" `
                -Mitre 'T1558.003' -Artifact '11_evt_4769_kerberos' `
                -Why 'One account requesting RC4 tickets for many services is the signature of Kerberoasting'
        }
    }

    # --- 4768: TGT - RC4 downgrade ---
    $tgt = Get-DWinEvents -LogName 'Security' -Id 4768
    $tgtRows = @(foreach ($e in $tgt) {
        [PSCustomObject]@{
            TimeUtc     = ConvertTo-DUtcString $e.TimeCreated
            AccountName = Get-DProp $e 0
            Domain      = Get-DProp $e 1
            TicketEnc   = Get-DProp $e 7
            PreAuthType = Get-DProp $e 8
            IpAddress   = Get-DProp $e 9
            Status      = Get-DProp $e 6
        }
    })
    Export-DArtifact -Name '11_evt_4768_tgt' -Data $tgtRows -SubDir events

    # PreAuthType 0 = pre-auth yok = AS-REP roastable hesap
    foreach ($r in @($tgtRows | Where-Object { $_.PreAuthType -eq '0' } |
                     Group-Object AccountName | Select-Object -First 10)) {
        Add-DFinding -RuleId 'DGL-221' -Severity HIGH `
            -Title 'TGT requested without pre-authentication (AS-REP roast)' `
            -Evidence "$($r.Name): $($r.Count) istek, kaynak: $($r.Group[0].IpAddress)" `
            -Mitre 'T1558.004' -Artifact '11_evt_4768_tgt' `
            -Why 'Accounts without pre-authentication are open to offline password cracking'
    }

    foreach ($r in @($tgtRows | Where-Object { $_.TicketEnc -eq '0x17' } |
                     Group-Object AccountName | Select-Object -First 10)) {
        Add-DFinding -RuleId 'DGL-222' -Severity MEDIUM `
            -Title 'TGT issued with RC4 (encryption downgrade)' `
            -Evidence "$($r.Name): $($r.Count) RC4 TGT" `
            -Mitre 'T1558' -Artifact '11_evt_4768_tgt' `
            -Why 'Overpass-the-hash attacks use RC4'
    }

    # --- 4771: pre-auth basarisiz = parola deneme ---
    $preauth = Get-DWinEvents -LogName 'Security' -Id 4771
    $paRows = @(foreach ($e in $preauth) {
        [PSCustomObject]@{
            TimeUtc     = ConvertTo-DUtcString $e.TimeCreated
            AccountName = Get-DProp $e 0
            Status      = Get-DProp $e 4
            PreAuthType = Get-DProp $e 5
            IpAddress   = Get-DProp $e 6
        }
    })
    Export-DArtifact -Name '11_evt_4771_preauth' -Data $paRows -SubDir events

    foreach ($g in @($paRows | Group-Object IpAddress | Sort-Object Count -Descending |
                     Select-Object -First 5)) {
        if ($g.Count -ge 20) {
            $u = @($g.Group | Select-Object -ExpandProperty AccountName -Unique).Count
            Add-DFinding -RuleId 'DGL-223' -Severity HIGH `
                -Title 'Kerberos password guessing (4771 volume)' `
                -Evidence "$($g.Name): $($g.Count) pre-auth failures across $u distinct accounts" `
                -Mitre 'T1110.003' -Artifact '11_evt_4771_preauth'
        }
    }

    # --- 4662: DCSync tespiti ---
    $ds = Get-DWinEvents -LogName 'Security' -Id 4662 -Max 50000
    $dcsync = @(foreach ($e in $ds) {
        $props = Get-DProp $e 8
        if ($props -match '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') {
            [PSCustomObject]@{
                TimeUtc = ConvertTo-DUtcString $e.TimeCreated
                User    = "$(Get-DProp $e 2)\$(Get-DProp $e 1)"
                Sid     = Get-DProp $e 0
                Properties = $props
            }
        }
    })
    Export-DArtifact -Name '11_evt_4662_dcsync' -Data $dcsync -SubDir events

    foreach ($r in $dcsync) {
        # DC makine hesaplari normaldir, kullanici hesaplari degildir
        if ($r.User -notmatch '\$$') {
            Add-DFinding -RuleId 'DGL-224' -Severity CRITICAL `
                -Title 'DCSync attempt (directory replication right used)' `
                -Evidence "$($r.TimeUtc) $($r.User)" `
                -Mitre 'T1003.006' -Artifact '11_evt_4662_dcsync' -Timestamp $r.TimeUtc `
                -Why 'A non-DC principal used replication rights and can pull every password hash'
            Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'DCSync' `
                -Description "DCSync: $($r.User)" -Severity CRITICAL
        }
    }

    # --- 4776: NTLM ---
    $ntlm = Get-DWinEvents -LogName 'Security' -Id 4776
    $ntlmRows = @(foreach ($e in $ntlm) {
        [PSCustomObject]@{
            TimeUtc     = ConvertTo-DUtcString $e.TimeCreated
            Package     = Get-DProp $e 0
            AccountName = Get-DProp $e 1
            Workstation = Get-DProp $e 2
            Status      = Get-DProp $e 3
        }
    })
    Export-DArtifact -Name '11_evt_4776_ntlm' -Data $ntlmRows -SubDir events

    Write-DLog "  4769:$($tgsRows.Count) 4768:$($tgtRows.Count) 4771:$($paRows.Count) DCSync:$($dcsync.Count)" -Level DEBUG
}

Register-DModule -Name 'Events: collection statistics' -Phase 2 -Body {
    Export-DArtifact -Name '11_event_stats' -Data @($Script:EventStats) -SubDir events
    $capped = @($Script:EventStats | Where-Object Capped)
    $missing = @($Script:EventStats | Where-Object Status -eq 'CHANNEL_NOT_FOUND')
    Write-DLog "  $($Script:EventStats.Count) kanal sorgusu ($($capped.Count) cap, $($missing.Count) kanal yok)" -Level DEBUG
}

# ============================================================================
#  MODUL: DOSYA SISTEMI - SUPHELI DOSYALAR
# ============================================================================

Register-DModule -Name 'File system scan' -Phase 3 -SkipOnQuick `
    -Description 'Recently written executables in targeted directories' -Body {

    # NOT: C:\ recurse ASLA yapilmaz. Bu 12 dizin gercek bulgularin %95'ini icerir.
    $cutoff = $Script:Ctx.WindowStart
    $found  = New-Object System.Collections.ArrayList
    $scanned = 0

    if (-not $Script:ScanPaths) { $Script:ScanPaths = Get-DScanPaths }
    foreach ($root in $Script:ScanPaths) {
        if (-not (Test-Path $root)) { continue }
        try {
            Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.LastWriteTime -ge $cutoff -and
                    $Script:InterestingExt -contains $_.Extension.ToLowerInvariant()
                } | ForEach-Object {
                    $scanned++
                    if ($scanned -gt 5000) { return }
                    $f = $_
                    $sig = Get-DSignature -Path $f.FullName

                    # MOTW / Zone.Identifier - dosya nereden indirildi
                    $zone = $null; $refUrl = $null
                    try {
                        $ads = Get-Content -LiteralPath $f.FullName -Stream 'Zone.Identifier' -ErrorAction Stop
                        if ($ads) {
                            $zone = ($ads | Where-Object { $_ -match 'ZoneId=(\d)' } |
                                     ForEach-Object { $Matches[1] }) -join ''
                            $refUrl = ($ads | Where-Object { $_ -match '^(HostUrl|ReferrerUrl)=(.+)' } |
                                       ForEach-Object { $Matches[2] }) -join ' | '
                        }
                    } catch { }

                    # Timestomp gostergesi: olusturma > degistirme, veya .000 ms
                    $stomped = $false
                    try {
                        if ($f.CreationTime -gt $f.LastWriteTime.AddMinutes(1)) { $stomped = $true }
                        if ($f.LastWriteTime.Millisecond -eq 0 -and
                            $f.CreationTime.Millisecond -eq 0 -and
                            $f.LastAccessTime.Millisecond -eq 0) { $stomped = $true }
                    } catch { }

                    $null = $found.Add([PSCustomObject]@{
                        FullName     = $f.FullName
                        Extension    = $f.Extension
                        SizeKB       = [math]::Round($f.Length / 1KB, 2)
                        CreatedUtc   = ConvertTo-DUtcString $f.CreationTime
                        ModifiedUtc  = ConvertTo-DUtcString $f.LastWriteTime
                        AccessedUtc  = ConvertTo-DUtcString $f.LastAccessTime
                        Signed       = $sig.IsValid
                        Signer       = $sig.Signer
                        SigStatus    = $sig.Status
                        IsMicrosoft  = $sig.IsMicrosoft
                        SHA256       = Get-DFileHashSafe -Path $f.FullName
                        ZoneId       = $zone
                        DownloadUrl  = $refUrl
                        TimestompSuspect = $stomped
                        SuspiciousPath   = Test-DSuspiciousPath -Path $f.FullName
                    })
                }
        } catch { }
    }

    $arr = @($found)
    Export-DArtifact -Name '13_recent_files' -Data $arr

    if ($scanned -ge 5000) {
        Add-DFinding -RuleId 'DGL-019' -Severity INFO `
            -Title 'File scan limit reached' `
            -Evidence "Stopped at 5000 files (-Days $Days)" -Artifact '13_recent_files' `
            -Why 'Narrow the analysis window'
    }

    # --- TRIAGE ---
    foreach ($f in $arr) {
        if ($f.SuspiciousPath -and $f.Extension -match '(?i)\.(exe|dll|scr|sys)$' -and -not $f.IsMicrosoft) {
            Add-DFinding -RuleId 'DGL-230' -Severity HIGH `
                -Title 'New executable in a suspicious directory' `
                -Evidence "$($f.FullName) @ $($f.ModifiedUtc) [$($f.SizeKB) KB]" `
                -Mitre 'T1105' -Artifact '13_recent_files' -Timestamp $f.ModifiedUtc
            Add-DTimelineEvent -Timestamp $f.ModifiedUtc -Source 'FileSystem' `
                -Description "File written: $(Split-Path $f.FullName -Leaf)" `
                -Detail $f.FullName -Severity HIGH
        }

        if ($f.DownloadUrl) {
            Add-DFinding -RuleId 'DGL-231' -Severity MEDIUM `
                -Title 'File downloaded from the internet (MOTW)' `
                -Evidence "$($f.FullName) <- $($f.DownloadUrl)" `
                -Mitre 'T1105' -Artifact '13_recent_files' -Timestamp $f.ModifiedUtc `
                -Why 'The Zone.Identifier alternate data stream carries the download source'
            $null = Test-DIoc -Value $f.DownloadUrl -Context $f.FullName -Artifact '13_recent_files'
        }

        if ($f.TimestompSuspect -and -not $f.IsMicrosoft) {
            Add-DFinding -RuleId 'DGL-232' -Severity MEDIUM `
                -Title 'Timestamp manipulation suspected' `
                -Evidence "$($f.FullName) created:$($f.CreatedUtc) modified:$($f.ModifiedUtc)" `
                -Mitre 'T1070.006' -Artifact '13_recent_files' `
                -Why 'Creation time is later than modification time, or the millisecond fields are zero'
        }

        if ($f.SHA256) {
            $null = Test-DIoc -Value $f.SHA256 -Context $f.FullName -Artifact '13_recent_files'
        }
    }

    Write-DLog "  $($arr.Count) recently written files" -Level DEBUG
}

# ============================================================================
#  MODUL: WEBSHELL AVI
# ============================================================================

Register-DModule -Name 'Webshell hunt' -Phase 3 -Scope 'Server' -SkipOnQuick `
    -Description 'Script files in web roots plus content pattern scanning' -Body {

    # Web kok dizinlerini bul
    $webRoots = New-Object System.Collections.ArrayList
    foreach ($p in @('C:\inetpub\wwwroot', 'C:\inetpub', "$env:SystemDrive\wwwroot",
                     'C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy',
                     'C:\Program Files\Microsoft\Exchange Server\V15\ClientAccess',
                     'C:\xampp\htdocs', 'C:\Apache24\htdocs', 'C:\tomcat\webapps')) {
        if (Test-Path $p) { $null = $webRoots.Add($p) }
    }

    # IIS site yollarini metabase'den al
    try {
        Import-Module WebAdministration -ErrorAction Stop
        Get-Website -ErrorAction Stop | ForEach-Object {
            $ph = $_.PhysicalPath
            if ($ph) {
                $ph = [Environment]::ExpandEnvironmentVariables($ph)
                if ((Test-Path $ph) -and ($webRoots -notcontains $ph)) { $null = $webRoots.Add($ph) }
            }
        }
    } catch { }

    if ($webRoots.Count -eq 0) {
        Write-DLog '  Web kok dizini bulunamadi, atlandi' -Level DEBUG
        return
    }

    # Webshell icerik imzalari
    $shellPatterns = @(
        @{ P = '(?i)eval\s*\(\s*(request|base64_decode|\$_(POST|GET|REQUEST))'; N = 'eval with user input'; S = 'CRITICAL' }
        @{ P = '(?i)Request\.(Item|Form|QueryString)\s*\[.{1,40}\].{0,80}(Execute|Eval|Process)'; N = 'ASPX command execution'; S = 'CRITICAL' }
        @{ P = '(?i)System\.Diagnostics\.Process.{0,60}Start'; N = 'Process.Start (ASPX)'; S = 'HIGH' }
        @{ P = '(?i)(cmd\.exe|/c\s+|powershell).{0,60}(Request|param)'; N = 'Komut satiri + istek parametresi'; S = 'CRITICAL' }
        @{ P = '(?i)\$_(POST|GET|REQUEST)\s*\[.{1,30}\]\s*\)?\s*;?\s*$'; N = 'PHP direct input execution'; S = 'HIGH' }
        @{ P = '(?i)(shell_exec|passthru|proc_open|popen|system)\s*\('; N = 'PHP shell fonksiyonu'; S = 'HIGH' }
        @{ P = '(?i)Runtime\.getRuntime\(\)\.exec'; N = 'JSP command execution'; S = 'CRITICAL' }
        @{ P = '(?i)FromBase64String.{0,60}(Load|Invoke|Assembly)'; N = '.NET assembly loading'; S = 'CRITICAL' }
        @{ P = '(?i)(Chopper|China\s?Chopper|antsword|behinder|godzilla|weevely)'; N = 'Known webshell name'; S = 'CRITICAL' }
        @{ P = '(?i)Server\.CreateObject\s*\(\s*.WScript\.Shell'; N = 'ASP WScript.Shell'; S = 'CRITICAL' }
    )

    $webExt = @('.aspx', '.asp', '.ashx', '.asmx', '.php', '.jsp', '.jspx', '.war', '.cfm', '.cshtml')
    $hits   = New-Object System.Collections.ArrayList
    $allWeb = New-Object System.Collections.ArrayList

    foreach ($root in $webRoots) {
        try {
            Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue |
                Where-Object { $webExt -contains $_.Extension.ToLowerInvariant() } |
                ForEach-Object {
                    $f = $f = $_
                    $isNew = ($f.LastWriteTime -ge $Script:Ctx.WindowStart)

                    $null = $allWeb.Add([PSCustomObject]@{
                        FullName    = $f.FullName
                        SizeKB      = [math]::Round($f.Length / 1KB, 2)
                        CreatedUtc  = ConvertTo-DUtcString $f.CreationTime
                        ModifiedUtc = ConvertTo-DUtcString $f.LastWriteTime
                        IsNew       = $isNew
                        SHA256      = Get-DFileHashSafe -Path $f.FullName
                    })

                    # Icerik taramasi - 2 MB ustu dosyayi okuma
                    if ($f.Length -gt 2MB) { return }
                    $content = $null
                    try {
                        $content = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop
                    } catch { return }
                    if (-not $content) { return }

                    foreach ($sp in $shellPatterns) {
                        if ($content -match $sp.P) {
                            $snippet = $Matches[0]
                            if ($snippet.Length -gt 200) { $snippet = $snippet.Substring(0, 200) }
                            $null = $hits.Add([PSCustomObject]@{
                                FullName    = $f.FullName
                                Pattern     = $sp.N
                                Severity    = $sp.S
                                Snippet     = ($snippet -replace '\s+', ' ')
                                ModifiedUtc = ConvertTo-DUtcString $f.LastWriteTime
                                IsNew       = $isNew
                                SHA256      = Get-DFileHashSafe -Path $f.FullName
                            })
                            break
                        }
                    }
                }
        } catch { }
    }

    Export-DArtifact -Name '13_web_files' -Data @($allWeb)
    Export-DArtifact -Name '13_webshell_hits' -Data @($hits)

    foreach ($h in $hits) {
        $sev = if ($h.IsNew) { 'CRITICAL' } else { $h.Severity }
        Add-DFinding -RuleId 'DGL-240' -Severity $sev `
            -Title "WEBSHELL suspected: $($h.Pattern)" `
            -Evidence "$($h.FullName) @ $($h.ModifiedUtc) :: $($h.Snippet)" `
            -Mitre 'T1505.003' -Artifact '13_webshell_hits' -Timestamp $h.ModifiedUtc `
            -Why 'A command execution pattern matched inside the web root'
        Add-DTimelineEvent -Timestamp $h.ModifiedUtc -Source 'Webshell' `
            -Description "Webshell suspected: $(Split-Path $h.FullName -Leaf)" `
            -Detail $h.FullName -Severity CRITICAL
    }

    # Pattern eslesmese bile analiz penceresi icinde YENI web dosyasi supheli
    foreach ($w in @($allWeb | Where-Object IsNew)) {
        if ($hits.FullName -contains $w.FullName) { continue }
        Add-DFinding -RuleId 'DGL-241' -Severity HIGH `
            -Title 'New file written to the web root inside the analysis window' `
            -Evidence "$($w.FullName) @ $($w.ModifiedUtc) [$($w.SizeKB) KB]" `
            -Mitre 'T1505.003' -Artifact '13_web_files' -Timestamp $w.ModifiedUtc `
            -Why 'A web file changing outside deployment may indicate a webshell drop'
    }

    Write-DLog "  $($webRoots.Count) web roots, $($allWeb.Count) files, $($hits.Count) pattern matches" -Level DEBUG
}

# ============================================================================
#  MODUL: EXFIL IZLERI
# ============================================================================

Register-DModule -Name 'Exfiltration traces' -Phase 3 -SkipOnQuick `
    -Description 'Archives, exfiltration tools, SRUM network usage' -Body {

    # --- Buyuk / yeni arsiv dosyalari ---
    $archExt = @('.rar', '.7z', '.zip', '.tar', '.gz', '.cab', '.iso', '.bak')
    $arch = New-Object System.Collections.ArrayList

    if (-not $Script:ScanPaths) { $Script:ScanPaths = Get-DScanPaths }
    foreach ($root in $Script:ScanPaths) {
        if (-not (Test-Path $root)) { continue }
        try {
            Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue |
                Where-Object {
                    $archExt -contains $_.Extension.ToLowerInvariant() -and
                    $_.LastWriteTime -ge $Script:Ctx.WindowStart
                } | ForEach-Object {
                    $null = $arch.Add([PSCustomObject]@{
                        FullName    = $_.FullName
                        SizeMB      = [math]::Round($_.Length / 1MB, 2)
                        CreatedUtc  = ConvertTo-DUtcString $_.CreationTime
                        ModifiedUtc = ConvertTo-DUtcString $_.LastWriteTime
                        SuspiciousPath = Test-DSuspiciousPath -Path $_.FullName
                    })
                }
        } catch { }
    }
    $archArr = @($arch)
    Export-DArtifact -Name '13_archives' -Data $archArr

    foreach ($a in $archArr) {
        $sev = if ($a.SizeMB -gt 100 -or $a.SuspiciousPath) { 'HIGH' } else { 'MEDIUM' }
        Add-DFinding -RuleId 'DGL-250' -Severity $sev `
            -Title 'Archive created inside the analysis window' `
            -Evidence "$($a.FullName) [$($a.SizeMB) MB] @ $($a.ModifiedUtc)" `
            -Mitre 'T1560' -Artifact '13_archives' -Timestamp $a.ModifiedUtc `
            -Why 'Attackers archive files during the collection stage'
        Add-DTimelineEvent -Timestamp $a.ModifiedUtc -Source 'Exfil' `
            -Description "Archive created: $(Split-Path $a.FullName -Leaf)" `
            -Detail "$($a.SizeMB) MB" -Severity $sev
    }

    # --- Exfil / tunel araclarinin diskteki varligi ---
    $toolNames = $Script:ExfilBins + @('psexec.exe', 'psexec64.exe', 'mimikatz.exe',
                 'procdump.exe', 'procdump64.exe', 'nmap.exe', 'advanced_port_scanner.exe',
                 'netscan.exe', 'anydesk.exe', 'teamviewer.exe', 'screenconnect.exe',
                 'atera.exe', 'splashtop.exe', 'rustdesk.exe', 'putty.exe')
    $tools = New-Object System.Collections.ArrayList

    if (-not $Script:ScanPaths) { $Script:ScanPaths = Get-DScanPaths }
    foreach ($root in $Script:ScanPaths) {
        if (-not (Test-Path $root)) { continue }
        try {
            Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue |
                Where-Object { $toolNames -contains $_.Name.ToLowerInvariant() } |
                ForEach-Object {
                    $null = $tools.Add([PSCustomObject]@{
                        FullName    = $_.FullName
                        SizeKB      = [math]::Round($_.Length / 1KB, 2)
                        CreatedUtc  = ConvertTo-DUtcString $_.CreationTime
                        ModifiedUtc = ConvertTo-DUtcString $_.LastWriteTime
                        SHA256      = Get-DFileHashSafe -Path $_.FullName
                    })
                }
        } catch { }
    }
    $toolArr = @($tools)
    Export-DArtifact -Name '13_attacker_tools' -Data $toolArr

    foreach ($t in $toolArr) {
        Add-DFinding -RuleId 'DGL-251' -Severity CRITICAL `
            -Title 'Attacker or remote access tool found on disk' `
            -Evidence "$($t.FullName) @ $($t.ModifiedUtc)" `
            -Mitre 'T1219' -Artifact '13_attacker_tools' -Timestamp $t.ModifiedUtc `
            -Why 'These tools do not legitimately live in user directories'
    }

    # --- SRUM: uygulama basina ag kullanimi (exfil hacminin kaniti) ---
    $srum = "$env:SystemRoot\System32\sru\SRUDB.dat"
    if (Test-Path $srum) {
        try {
            $si = Get-Item $srum -Force -ErrorAction Stop
            Export-DArtifact -Name '13_srum_info' -Data ([PSCustomObject]@{
                Path        = $srum
                SizeMB      = [math]::Round($si.Length / 1MB, 2)
                ModifiedUtc = ConvertTo-DUtcString $si.LastWriteTime
                Note        = 'Uygulama basina gonderilen/alinan byte. Cevrimdisi parse gerekir (srum-dump / KAPE).'
            })
        } catch { }
    }

    Write-DLog "  $($archArr.Count) archives, $($toolArr.Count) attacker tools" -Level DEBUG
}

# ============================================================================
#  MODUL: KULLANICI AKTIVITESI
# ============================================================================

Register-DModule -Name 'User activity' -Phase 3 `
    -Description 'PSReadLine history (ALL users), RDP history, USB, Prefetch' -Body {

    # --- PowerShell konsol gecmisi ---
    # ESKI SCRIPT BUGU: Get-History kullaniyordu, script kendi oturumunda calistigi
    # icin DAIMA BOS donuyordu. Gercek hedef PSReadLine dosyalari.
    $hist = New-Object System.Collections.ArrayList
    try {
        Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $u = $_.Name
            $hf = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
            if (-not (Test-Path $hf)) { return }
            try {
                $fi = Get-Item $hf -Force -ErrorAction Stop
                $ln = 0
                Get-Content $hf -ErrorAction Stop | ForEach-Object {
                    $ln++
                    if ($_.Trim()) {
                        $null = $hist.Add([PSCustomObject]@{
                            User        = $u
                            LineNumber  = $ln
                            Command     = $_
                            FileModifiedUtc = ConvertTo-DUtcString $fi.LastWriteTime
                        })
                    }
                }
            } catch { }
        }
    } catch { }
    $histArr = @($hist)
    Export-DArtifact -Name '14_ps_history' -Data $histArr

    foreach ($h in $histArr) {
        Test-DEventCmdLine -CommandLine $h.Command -RuleId 'DGL-260' `
            -Context "PSReadLine [$($h.User)] line $($h.LineNumber)" `
            -Artifact '14_ps_history' -Timestamp $h.FileModifiedUtc
        $dec = ConvertFrom-DEncodedCommand -Text $h.Command
        if ($dec) {
            Add-DFinding -RuleId 'DGL-261' -Severity HIGH `
                -Title 'Encoded command decoded from console history' `
                -Evidence "[$($h.User)] $($dec.Substring(0, [Math]::Min(400, $dec.Length)))" `
                -Mitre 'T1027' -Artifact '14_ps_history'
        }
    }

    # --- RDP baglanti gecmisi (bu hosttan nereye baglanildi) ---
    $rdpHist = New-Object System.Collections.ArrayList
    foreach ($hive in (Get-DUserHives)) {
        $base = "$($hive.RegRoot)\Software\Microsoft\Terminal Server Client\Servers"
        try {
            Get-ChildItem $base -ErrorAction Stop | ForEach-Object {
                $un = (Get-DRegValues -Path $_.PSPath | Where-Object Name -eq 'UsernameHint')
                $null = $rdpHist.Add([PSCustomObject]@{
                    User         = $hive.User
                    RemoteHost   = $_.PSChildName
                    UsernameHint = if ($un) { $un.Value } else { $null }
                })
            }
        } catch { }
        # Default MRU
        foreach ($v in (Get-DRegValues -Path "$($hive.RegRoot)\Software\Microsoft\Terminal Server Client\Default")) {
            if ($v.Name -match '^MRU\d+$') {
                $null = $rdpHist.Add([PSCustomObject]@{
                    User = $hive.User; RemoteHost = $v.Value; UsernameHint = "(MRU:$($v.Name))"
                })
            }
        }
    }
    $rdpArr = @($rdpHist)
    Export-DArtifact -Name '14_rdp_history' -Data $rdpArr

    foreach ($r in $rdpArr) {
        Add-DFinding -RuleId 'DGL-262' -Severity MEDIUM `
            -Title 'RDP connection history on this host' `
            -Evidence "$($r.User) -> $($r.RemoteHost) [$($r.UsernameHint)]" `
            -Mitre 'T1021.001' -Artifact '14_rdp_history' `
            -Why 'Spread map: which systems were reached from this machine'
    }

    # --- Eslenmis surucu gecmisi ---
    $mounts = New-Object System.Collections.ArrayList
    foreach ($hive in (Get-DUserHives)) {
        try {
            Get-ChildItem "$($hive.RegRoot)\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" `
                -ErrorAction Stop | Where-Object { $_.PSChildName -match '^##' } | ForEach-Object {
                    $null = $mounts.Add([PSCustomObject]@{
                        User = $hive.User
                        RemotePath = ($_.PSChildName -replace '^##', '\\' -replace '#', '\')
                    })
                }
        } catch { }
    }
    Export-DArtifact -Name '14_mounted_shares' -Data @($mounts)

    # --- USB cihazlar ---
    $usb = @()
    try {
        $usb = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -ErrorAction Stop |
            ForEach-Object {
                $devClass = $_.PSChildName
                Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $v = Get-DRegValues -Path $_.PSPath
                    [PSCustomObject]@{
                        DeviceClass  = $devClass
                        Serial       = $_.PSChildName
                        FriendlyName = ($v | Where-Object Name -eq 'FriendlyName').Value
                        Service      = ($v | Where-Object Name -eq 'Service').Value
                    }
                }
            })
    } catch { }
    Export-DArtifact -Name '14_usb_devices' -Data $usb

    # --- Prefetch (calistirma kaniti) ---
    $pf = @()
    try {
        $pf = @(Get-ChildItem "$env:SystemRoot\Prefetch" -Filter '*.pf' -ErrorAction Stop |
            ForEach-Object {
                [PSCustomObject]@{
                    Name        = $_.Name
                    Program     = ($_.BaseName -split '-')[0]
                    CreatedUtc  = ConvertTo-DUtcString $_.CreationTime
                    ModifiedUtc = ConvertTo-DUtcString $_.LastWriteTime
                    SizeKB      = [math]::Round($_.Length / 1KB, 2)
                }
            })
    } catch { }
    Export-DArtifact -Name '14_prefetch' -Data $pf

    if ($pf.Count -eq 0 -and $Script:Ctx.IsWorkstation) {
        Add-DFinding -RuleId 'DGL-263' -Severity MEDIUM `
            -Title 'No Prefetch entries present' -Evidence 'Prefetch directory is empty or disabled' `
            -Mitre 'T1070' -Artifact '14_prefetch' `
            -Why 'Prefetch may be disabled, losing evidence of execution'
    }

    # Analiz penceresi icinde ilk kez calistirilan supheli programlar
    foreach ($p in @($pf | Where-Object { $_.CreatedUtc })) {
        try {
            if (((Get-Date) - [DateTime]$p.CreatedUtc).TotalDays -lt $Days) {
                $prog = $p.Program.ToLowerInvariant()
                if (($Script:ExfilBins -contains $prog) -or ($Script:LolBasExec -contains $prog) -or
                    $prog -match '(?i)(psexec|mimikatz|procdump|nmap|rclone|anydesk|rustdesk)') {
                    Add-DFinding -RuleId 'DGL-264' -Severity HIGH `
                        -Title 'Suspicious program executed inside the analysis window (Prefetch)' `
                        -Evidence "$($p.Program) first run: $($p.CreatedUtc), last: $($p.ModifiedUtc)" `
                        -Mitre 'T1204' -Artifact '14_prefetch' -Timestamp $p.CreatedUtc
                    Add-DTimelineEvent -Timestamp $p.CreatedUtc -Source 'Prefetch' `
                        -Description "Program executed: $($p.Program)" -Severity HIGH
                }
            }
        } catch { }
    }

    # --- Geri donusum kutusu ---
    $recycle = @()
    try {
        $recycle = @(Get-ChildItem 'C:\$Recycle.Bin' -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $Script:Ctx.WindowStart } |
            Select-Object -First 500 | ForEach-Object {
                [PSCustomObject]@{
                    FullName    = $_.FullName
                    SizeKB      = [math]::Round($_.Length / 1KB, 2)
                    DeletedUtc  = ConvertTo-DUtcString $_.LastWriteTime
                }
            })
    } catch { }
    Export-DArtifact -Name '14_recycle_bin' -Data $recycle

    Write-DLog "  history:$($histArr.Count) rdp:$($rdpArr.Count) usb:$($usb.Count) prefetch:$($pf.Count)" -Level DEBUG
}

# ============================================================================
#  MODUL: IN-MEMORY CODE
# ============================================================================

Register-DModule -Name 'In-memory code' -Phase 1 `
    -Description 'Executable memory with no file behind it, and modules missing from disk' -Body {

    # The honest version of memory analysis for an agent that must not drop a
    # driver or a 40 MB acquisition tool onto the host it is examining.
    #
    # What this finds: committed memory that is executable but PRIVATE, meaning
    # no file on disk backs it. Legitimate code is mapped from an image; code
    # written into private memory and then marked executable is what reflective
    # loaders, shellcode and unpacked payloads look like.
    #
    # What it cannot find: anything hidden by a kernel rootkit, and the content
    # of those regions. For that you need a real memory image.

    $signature = @'
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool CloseHandle(IntPtr h);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern int VirtualQueryEx(IntPtr h, IntPtr addr,
    ref MEMORY_BASIC_INFORMATION buf, uint len);

[StructLayout(LayoutKind.Sequential)]
public struct MEMORY_BASIC_INFORMATION {
    public IntPtr BaseAddress;
    public IntPtr AllocationBase;
    public uint   AllocationProtect;
    public IntPtr RegionSize;
    public uint   State;
    public uint   Protect;
    public uint   Type;
}
'@

    $api = $null
    try {
        # No -UsingNamespace: Add-Type already imports InteropServices for
        # -MemberDefinition, and naming it again is a compile error.
        $api = Add-Type -MemberDefinition $signature -Name 'DMem' -Namespace 'Douglas' `
                        -PassThru -EA Stop
    } catch {
        Write-DLog "  Memory inspection unavailable: $($_.Exception.Message)" -Level WARN
        Add-DFinding -RuleId 'DGL-299' -Severity INFO `
            -Title 'In-memory inspection could not run' `
            -Evidence $_.Exception.Message -Artifact '19_memory_regions' `
            -Why 'Injected code living only in memory would not be seen on this run.'
        return
    }

    # PAGE_EXECUTE* protections. Anything with execute rights matters; combined
    # with WRITE it matters more, because that is a region still being built.
    $EXEC = @{
        0x10 = 'EXECUTE'; 0x20 = 'EXECUTE_READ'
        0x40 = 'EXECUTE_READWRITE'; 0x80 = 'EXECUTE_WRITECOPY'
    }
    $MEM_COMMIT  = 0x1000
    $MEM_PRIVATE = 0x20000
    $PROCESS_QUERY_INFORMATION = 0x0400

    $regions = New-Object System.Collections.ArrayList
    $perProcess = @{}
    $examined = 0
    $denied = 0

    $targets = @()
    if ($Script:ProcIndex -and $Script:ProcIndex.Count -gt 0) {
        $targets = @($Script:ProcIndex.Values)
    } else {
        try {
            $targets = @(Get-Process -EA Stop | ForEach-Object {
                [PSCustomObject]@{ PID = $_.Id; Name = $_.ProcessName; Path = $null
                                   User = $null; SuspiciousPath = $false; Signed = $null }
            })
        } catch { }
    }

    foreach ($pr in $targets) {
        $procId = [int]$pr.PID
        if ($procId -le 4) { continue }

        $handle = [IntPtr]::Zero
        try {
            $handle = $api::OpenProcess($PROCESS_QUERY_INFORMATION, $false, $procId)
        } catch { }
        if ($handle -eq [IntPtr]::Zero) { $denied++; continue }
        $examined++

        try {
            $addr = [IntPtr]::Zero
            $mbi = New-Object Douglas.DMem+MEMORY_BASIC_INFORMATION
            $size = [Runtime.InteropServices.Marshal]::SizeOf($mbi)
            $found = 0
            $bytes = 0
            $rwx = 0

            # 128 TB of address space; walk until VirtualQueryEx stops answering.
            while ($api::VirtualQueryEx($handle, $addr, [ref]$mbi, $size) -eq $size) {
                $regionSize = [int64]$mbi.RegionSize
                if ($regionSize -le 0) { break }

                if (($mbi.State -eq $MEM_COMMIT) -and
                    ($mbi.Type -eq $MEM_PRIVATE) -and
                    ($EXEC.ContainsKey([int]$mbi.Protect))) {

                    $found++
                    $bytes += $regionSize
                    if ([int]$mbi.Protect -eq 0x40) { $rwx++ }

                    if ($found -le 6) {
                        $null = $regions.Add([PSCustomObject]@{
                            PID         = $procId
                            Process     = $pr.Name
                            Path        = $pr.Path
                            BaseAddress = ('0x{0:X}' -f [int64]$mbi.BaseAddress)
                            SizeKB      = [math]::Round($regionSize / 1KB, 1)
                            Protection  = $EXEC[[int]$mbi.Protect]
                            Writable    = ([int]$mbi.Protect -in 0x40, 0x80)
                        })
                    }
                }

                $next = [int64]$mbi.BaseAddress + $regionSize
                if ($next -le [int64]$addr) { break }
                $addr = [IntPtr]$next
            }

            if ($found -gt 0) {
                $perProcess[$procId] = [PSCustomObject]@{
                    PID = $procId; Process = $pr.Name; Path = $pr.Path
                    User = $pr.User; Regions = $found
                    TotalKB = [math]::Round($bytes / 1KB, 1)
                    RwxRegions = $rwx
                    SuspiciousPath = [bool]$pr.SuspiciousPath
                    Signed = $pr.Signed
                }
            }
        } catch {
        } finally {
            $null = $api::CloseHandle($handle)
        }
    }

    Export-DArtifact -Name '19_memory_regions' -Data @($regions)
    $summary = @($perProcess.Values | Sort-Object -Property @{E={$_.RwxRegions};D=$true},
                                                   @{E={$_.TotalKB};D=$true})
    Export-DArtifact -Name '19_memory_summary' -Data $summary

    # --- TRIAGE ---
    # Private executable memory is not rare on its own: .NET, JIT engines and
    # browsers all produce it legitimately. What matters is the combination.
    $jitFriendly = '(?i)^(powershell|pwsh|w3wp|dotnet|devenv|msbuild|chrome|msedge|firefox|' +
                   'java|javaw|node|python|sqlservr|SearchIndexer|MsMpEng|explorer)$'

    foreach ($p in $summary) {
        $base = ($p.Process -replace '\.exe$', '')
        $isJit = ($base -match $jitFriendly)

        if ($p.RwxRegions -gt 0 -and -not $isJit) {
            Add-DFinding -RuleId 'DGL-290' -Severity HIGH `
                -Title 'Writable and executable private memory in a process' `
                -Evidence "$($p.Process) (PID $($p.PID)) - $($p.RwxRegions) RWX regions, $($p.TotalKB) KB" `
                -Mitre 'T1055' -Artifact '19_memory_summary' `
                -Why 'Memory that is both writable and executable is where shellcode is staged. Compilers and browsers do this legitimately; a service should not.'
        }

        if ($p.SuspiciousPath -and $p.Regions -gt 0) {
            Add-DFinding -RuleId 'DGL-291' -Severity CRITICAL `
                -Title 'Process in a suspicious directory holds unbacked executable memory' `
                -Evidence "$($p.Process) (PID $($p.PID)) - $($p.Regions) regions, $($p.TotalKB) KB [$($p.Path)]" `
                -Mitre 'T1055' -Artifact '19_memory_summary' `
                -Why 'Executable memory with no file behind it, in a process already running from a temporary directory.'
        }

        # A large amount of unbacked executable memory in a process that has no
        # business generating code is the reflective-loading shape.
        if (-not $isJit -and $p.TotalKB -gt 1024) {
            Add-DFinding -RuleId 'DGL-292' -Severity MEDIUM `
                -Title 'Unusually large unbacked executable memory' `
                -Evidence "$($p.Process) (PID $($p.PID)) - $($p.TotalKB) KB across $($p.Regions) regions" `
                -Mitre 'T1620' -Artifact '19_memory_summary' `
                -Why 'Reflectively loaded modules live in private executable memory rather than being mapped from a file.'
        }
    }

    # --- Loaded modules whose file is gone from disk ---
    $ghostModules = New-Object System.Collections.ArrayList
    try {
        foreach ($proc in @(Get-Process -EA Stop)) {
            try {
                # One entry per process and path: a module mapped several
                # times would otherwise fill the report with the same line.
                $seenPaths = @{}
                foreach ($m in @($proc.Modules)) {
                    $mp = $m.FileName
                    if (-not $mp -or $seenPaths.ContainsKey($mp)) { continue }
                    $seenPaths[$mp] = $true
                    if (Test-Path -LiteralPath $mp -PathType Leaf -EA SilentlyContinue) { continue }
                    $null = $ghostModules.Add([PSCustomObject]@{
                        PID = $proc.Id; Process = $proc.ProcessName
                        Module = $m.ModuleName; Path = $mp
                    })
                }
            } catch { }
        }
    } catch { }
    Export-DArtifact -Name '19_missing_modules' -Data @($ghostModules)

    foreach ($g in @($ghostModules | Select-Object -First 20)) {
        Add-DFinding -RuleId 'DGL-293' -Severity HIGH `
            -Title 'Loaded module is no longer on disk' `
            -Evidence "$($g.Process) (PID $($g.PID)) -> $($g.Path)" `
            -Mitre 'T1070.004' -Artifact '19_missing_modules' `
            -Why 'The file was deleted after it loaded. Deleting the payload once it is running is standard practice.'
    }

    Add-DFinding -RuleId 'DGL-294' -Severity INFO `
        -Title 'Memory inspection is region-level only' `
        -Evidence "$examined processes examined, $denied could not be opened" `
        -Artifact '19_memory_summary' `
        -Why 'Region protections were read, not their contents. A full memory image and offline analysis is the next step where this points at something.'

    Write-DLog "  memory: $examined processes, $($summary.Count) with unbacked exec memory, $($ghostModules.Count) missing modules" -Level DEBUG
}

# ============================================================================
#  MODUL: ROOTKIT INDICATORS
# ============================================================================

Register-DModule -Name 'Rootkit indicators' -Phase 1 `
    -Description 'Cross-view comparison and kernel-level hiding checks' -Body {

    # A rootkit's job is to make something invisible. We cannot see what is
    # hidden, but we can see the *disagreement* between two ways of asking the
    # same question. That gap is the finding.
    #
    # This is not a kernel-level scanner and does not claim to be. It catches
    # user-mode and API-hooking hiding, which is what most commodity rootkits
    # do, and reports honestly where it cannot see.

    $rows = New-Object System.Collections.ArrayList

    # --- 1. Process cross-view: WMI vs the process API ---
    $wmiPids = @()
    $apiPids = @()
    try { $wmiPids = @(Get-CimInstance Win32_Process -EA Stop | Select-Object -ExpandProperty ProcessId) }
    catch { try { $wmiPids = @(Get-WmiObject Win32_Process -EA Stop | Select-Object -ExpandProperty ProcessId) } catch { } }
    try { $apiPids = @(Get-Process -EA Stop | Select-Object -ExpandProperty Id) } catch { }

    if ($wmiPids.Count -gt 0 -and $apiPids.Count -gt 0) {
        $onlyWmi = @($wmiPids | Where-Object { $apiPids -notcontains $_ })
        $onlyApi = @($apiPids | Where-Object { $wmiPids -notcontains $_ })

        $null = $rows.Add([PSCustomObject]@{
            Check = 'Process cross-view'; Source1 = 'Win32_Process'; Count1 = $wmiPids.Count
            Source2 = 'Get-Process'; Count2 = $apiPids.Count
            OnlyIn1 = ($onlyWmi -join ','); OnlyIn2 = ($onlyApi -join ',')
        })

        # A handful of differences is normal: processes start and exit between
        # the two calls. A large or one-sided gap is not.
        if ($onlyApi.Count -ge 3) {
            Add-DFinding -RuleId 'DGL-280' -Severity HIGH `
                -Title 'Processes visible to the API but not to WMI' `
                -Evidence "PIDs: $($onlyApi -join ', ')" `
                -Mitre 'T1014' -Artifact '17_rootkit_checks' `
                -Why 'WMI is a common hooking target. A process hidden from it but not from the process API is the classic cross-view discrepancy.'
        }
        if ($onlyWmi.Count -ge 3) {
            Add-DFinding -RuleId 'DGL-281' -Severity MEDIUM `
                -Title 'Processes visible to WMI but not to the API' `
                -Evidence "PIDs: $($onlyWmi -join ', ')" `
                -Mitre 'T1014' -Artifact '17_rootkit_checks' `
                -Why 'Usually processes that exited between the two queries; worth a second look if the gap is wide.'
        }
    }

    # --- 2. Service cross-view: registry vs the service manager ---
    $regSvc = @()
    $scmSvc = @()
    try {
        $regSvc = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -EA Stop |
                    Select-Object -ExpandProperty PSChildName)
    } catch { }
    try { $scmSvc = @(Get-CimInstance Win32_Service -EA Stop | Select-Object -ExpandProperty Name) } catch { }

    if ($regSvc.Count -gt 0 -and $scmSvc.Count -gt 0) {
        # Drivers and filter entries live in the registry without being services,
        # so only the reverse direction is interesting.
        $hiddenFromReg = @($scmSvc | Where-Object { $regSvc -notcontains $_ })
        $null = $rows.Add([PSCustomObject]@{
            Check = 'Service cross-view'; Source1 = 'Registry'; Count1 = $regSvc.Count
            Source2 = 'Win32_Service'; Count2 = $scmSvc.Count
            OnlyIn1 = ''; OnlyIn2 = ($hiddenFromReg -join ',')
        })
        if ($hiddenFromReg.Count -gt 0) {
            Add-DFinding -RuleId 'DGL-282' -Severity HIGH `
                -Title 'Service running with no registry entry' `
                -Evidence ($hiddenFromReg -join ', ') `
                -Mitre 'T1014' -Artifact '17_rootkit_checks' `
                -Why 'Every real service is defined in the registry. One that is not has been hidden from it.'
        }
    }

    # --- 3. Driver signing enforcement and test mode ---
    $ciCfg = New-Object System.Collections.ArrayList
    try {
        $bcd = bcdedit /enum '{current}' 2>$null
        $txt = ($bcd -join ' ')
        $testSigning = ($txt -match '(?i)testsigning\s+Yes')
        $nointegrity = ($txt -match '(?i)nointegritychecks\s+Yes')
        $debug       = ($txt -match '(?i)^\s*debug\s+Yes' -or $txt -match '(?i)\sdebug\s+Yes')

        $null = $ciCfg.Add([PSCustomObject]@{
            Setting = 'TestSigning'; Value = $testSigning })
        $null = $ciCfg.Add([PSCustomObject]@{
            Setting = 'NoIntegrityChecks'; Value = $nointegrity })
        $null = $ciCfg.Add([PSCustomObject]@{ Setting = 'KernelDebug'; Value = $debug })

        if ($testSigning) {
            Add-DFinding -RuleId 'DGL-283' -Severity CRITICAL `
                -Title 'Driver test signing is enabled' `
                -Evidence 'bcdedit: testsigning Yes' `
                -Mitre 'T1553' -Artifact '17_rootkit_checks' `
                -Why 'With test signing on, any self-signed driver loads into the kernel. This is how an unsigned rootkit gets in.'
        }
        if ($nointegrity) {
            Add-DFinding -RuleId 'DGL-284' -Severity CRITICAL `
                -Title 'Kernel integrity checks are disabled' `
                -Evidence 'bcdedit: nointegritychecks Yes' `
                -Mitre 'T1553' -Artifact '17_rootkit_checks' `
                -Why 'Driver signature enforcement is off entirely.'
        }
        if ($debug) {
            Add-DFinding -RuleId 'DGL-285' -Severity HIGH `
                -Title 'Kernel debugging is enabled' `
                -Evidence 'bcdedit: debug Yes' `
                -Mitre 'T1562.001' -Artifact '17_rootkit_checks' `
                -Why 'A kernel debugger can read and modify anything, and disables some protections.'
        }
    } catch { }
    Export-DArtifact -Name '17_boot_config' -Data @($ciCfg)

    # --- 4. Suspicious kernel filter drivers ---
    # Legitimate filters come from AV, backup and virtualisation vendors and are
    # signed. An unsigned filter sitting between the OS and the file system is
    # exactly where a rootkit wants to be.
    $filters = @()
    try {
        $filters = @(Get-CimInstance Win32_SystemDriver -EA Stop |
            Where-Object { $_.State -eq 'Running' } | ForEach-Object {
                $path = $_.PathName
                if ($path) { $path = [Environment]::ExpandEnvironmentVariables(($path -replace '^\\\?\?\\', '')) }
                $sig = Get-DSignature -Path $path
                [PSCustomObject]@{
                    Name = $_.Name; DisplayName = $_.DisplayName; Path = $path
                    Signed = $sig.IsValid; Signer = $sig.Signer; IsMicrosoft = $sig.IsMicrosoft
                    StartMode = $_.StartMode
                }
            } | Where-Object { -not $_.IsMicrosoft })
    } catch { }
    Export-DArtifact -Name '17_nonmicrosoft_drivers' -Data $filters

    foreach ($f in @($filters | Where-Object { $false -eq $_.Signed })) {
        Add-DFinding -RuleId 'DGL-286' -Severity CRITICAL `
            -Title 'Unsigned non-Microsoft driver is loaded' `
            -Evidence "$($f.Name) -> $($f.Path)" `
            -Mitre 'T1014' -Artifact '17_nonmicrosoft_drivers' `
            -Why 'Unsigned kernel code should not load on a healthy modern build. Check test signing above.'
    }

    # --- 5. SSDT-style hook proxy: services whose ImagePath has no file ---
    $ghost = @()
    try {
        $ghost = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -EA Stop | ForEach-Object {
            $ip = (Get-DRegValues -Path $_.PSPath | Where-Object Name -eq 'ImagePath')
            if (-not $ip -or -not $ip.Value) { return }
            $bin = Get-DCleanPath -CommandLine ([Environment]::ExpandEnvironmentVariables(
                       ($ip.Value -replace '^\\\?\?\\', '')))
            if (-not $bin -or $bin -match '^\\SystemRoot|^system32\\') { return }
            if (Test-Path -LiteralPath $bin -PathType Leaf -EA SilentlyContinue) { return }
            [PSCustomObject]@{ Service = $_.PSChildName; ImagePath = $ip.Value }
        })
    } catch { }
    Export-DArtifact -Name '17_missing_service_binaries' -Data $ghost

    foreach ($g in @($ghost | Select-Object -First 20)) {
        Add-DFinding -RuleId 'DGL-287' -Severity MEDIUM `
            -Title 'Service points at a binary that is not there' `
            -Evidence "$($g.Service) -> $($g.ImagePath)" `
            -Mitre 'T1574' -Artifact '17_missing_service_binaries' `
            -Why 'Either a leftover from removed software, or a file hidden from this view. It is also a hijack opportunity.'
    }

    Export-DArtifact -Name '17_rootkit_checks' -Data @($rows)

    # Say plainly what this cannot see, so a clean result is not over-read.
    Add-DFinding -RuleId 'DGL-288' -Severity INFO `
        -Title 'Rootkit checks are cross-view only' `
        -Evidence 'No kernel driver was loaded and no raw disk or memory was read.' `
        -Artifact '17_rootkit_checks' `
        -Why 'A rootkit hiding below this level would not be found here. For a suspected kernel rootkit, take a memory image and analyse it offline.'

    Write-DLog "  cross-view: $($rows.Count) checks, $(@($filters).Count) non-Microsoft drivers, $(@($ghost).Count) missing binaries" -Level DEBUG
}

# ============================================================================
#  MODUL: EXTERNAL CONNECTION SUMMARY
# ============================================================================

Register-DModule -Name 'External endpoints' -Phase 1 `
    -Description 'Every address this host reaches outside private space' -Body {

    # The network module already records connections. This pulls the outside
    # world out of that into one table, because "what does this box talk to on
    # the internet" is the first question asked in an incident and nobody
    # should have to filter a 400-row connection dump to answer it.

    $privateRegex = '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|0\.0\.0\.0$|::1$|::$|fe80:|224\.|239\.|255\.)'
    $endpoints = @{}

    function Add-DEndpoint {
        param([string]$Address, [string]$Port, [string]$Proc, [string]$Path,
              [string]$Source, [bool]$Suspicious, [bool]$Unsigned)
        if (-not $Address -or $Address -match $privateRegex) { return }
        if (-not $endpoints.ContainsKey($Address)) {
            $endpoints[$Address] = [PSCustomObject]@{
                Address = $Address; Ports = New-Object System.Collections.ArrayList
                Processes = New-Object System.Collections.ArrayList
                Paths = New-Object System.Collections.ArrayList
                Sources = New-Object System.Collections.ArrayList
                Connections = 0; Suspicious = $false; Unsigned = $false; RDNS = $null
            }
        }
        $e = $endpoints[$Address]
        $e.Connections++
        if ($Port -and $e.Ports -notcontains $Port) { $null = $e.Ports.Add($Port) }
        if ($Proc -and $e.Processes -notcontains $Proc) { $null = $e.Processes.Add($Proc) }
        if ($Path -and $e.Paths -notcontains $Path) { $null = $e.Paths.Add($Path) }
        if ($Source -and $e.Sources -notcontains $Source) { $null = $e.Sources.Add($Source) }
        if ($Suspicious) { $e.Suspicious = $true }
        if ($Unsigned)   { $e.Unsigned = $true }
    }

    # Live TCP
    try {
        foreach ($c in @(Get-NetTCPConnection -EA Stop)) {
            $pi = if ($Script:ProcIndex) { $Script:ProcIndex[[int]$c.OwningProcess] } else { $null }
            Add-DEndpoint -Address $c.RemoteAddress -Port ([string]$c.RemotePort) `
                -Proc $(if ($pi) { $pi.Name }) -Path $(if ($pi) { $pi.Path }) `
                -Source 'TCP' -Suspicious $(if ($pi) { [bool]$pi.SuspiciousPath } else { $false }) `
                -Unsigned $(if ($pi) { ($false -eq $pi.Signed) } else { $false })
        }
    } catch { }

    # DNS cache answers: where names resolved to, even if the connection is gone
    try {
        foreach ($d in @(Get-DnsClientCache -EA Stop | Where-Object { $_.Data })) {
            if ($d.Data -match '^\d{1,3}(\.\d{1,3}){3}$') {
                Add-DEndpoint -Address $d.Data -Port '' -Proc '' -Path '' `
                    -Source "DNS:$($d.Entry)" -Suspicious $false -Unsigned $false
                if ($endpoints.ContainsKey($d.Data) -and -not $endpoints[$d.Data].RDNS) {
                    $endpoints[$d.Data].RDNS = $d.Entry
                }
            }
        }
    } catch { }

    # Reverse lookups for the ones we will actually show
    $rows = @($endpoints.Values | Sort-Object -Property @{E={$_.Suspicious};D=$true},
                                                @{E={$_.Connections};D=$true})
    if (-not $NoResolve) {
        foreach ($e in ($rows | Select-Object -First 40)) {
            if ($e.RDNS) { continue }
            try { $e.RDNS = [Net.Dns]::GetHostEntry($e.Address).HostName } catch { }
        }
    }

    $flat = @($rows | ForEach-Object {
        [PSCustomObject]@{
            Address     = $_.Address
            RDNS        = $_.RDNS
            Connections = $_.Connections
            Ports       = ($_.Ports -join ',')
            Processes   = ($_.Processes -join ',')
            Paths       = ($_.Paths -join ' | ')
            Sources     = ($_.Sources -join ',')
            Suspicious  = $_.Suspicious
            Unsigned    = $_.Unsigned
        }
    })
    Export-DArtifact -Name '04_external_endpoints' -Data $flat -AsJson

    foreach ($e in $flat) {
        $null = Test-DIoc -Value $e.Address -Context "external endpoint ($($e.Processes))" `
                -Artifact '04_external_endpoints'
        if ($e.RDNS) {
            $null = Test-DIoc -Value $e.RDNS -Context "external endpoint" `
                    -Artifact '04_external_endpoints'
        }
    }

    $susCount = @($flat | Where-Object Suspicious).Count
    if ($flat.Count -gt 0) {
        Add-DFinding -RuleId 'DGL-289' -Severity INFO `
            -Title 'External endpoints contacted by this host' `
            -Evidence "$($flat.Count) addresses outside private space, $susCount reached by a process in a suspicious directory" `
            -Artifact '04_external_endpoints' `
            -Why 'The full list is in 04_external_endpoints.csv and drives the console graph.'
    }

    Write-DLog "  $($flat.Count) external endpoints ($susCount suspicious)" -Level DEBUG
}

# ============================================================================
#  MODUL: SERTIFIKA DEPOSU
# ============================================================================

Register-DModule -Name 'Certificate stores' -Phase 3 `
    -Description 'Rogue root CA detection' -Body {

    $certs = New-Object System.Collections.ArrayList
    foreach ($store in 'Root', 'CA', 'TrustedPublisher') {
        try {
            Get-ChildItem "Cert:\LocalMachine\$store" -ErrorAction Stop | ForEach-Object {
                $null = $certs.Add([PSCustomObject]@{
                    Store       = $store
                    Subject     = $_.Subject
                    Issuer      = $_.Issuer
                    Thumbprint  = $_.Thumbprint
                    NotBeforeUtc = ConvertTo-DUtcString $_.NotBefore
                    NotAfterUtc  = ConvertTo-DUtcString $_.NotAfter
                    SelfSigned  = ($_.Subject -eq $_.Issuer)
                })
            }
        } catch { }
    }
    $arr = @($certs)
    Export-DArtifact -Name '15_certificates' -Data $arr

    $knownCA = 'Microsoft|VeriSign|DigiCert|GlobalSign|Thawte|GeoTrust|Baltimore|Entrust|' +
               'COMODO|Sectigo|GoDaddy|Symantec|Starfield|AddTrust|USERTrust|Certum|' +
               'QuoVadis|SwissSign|T-TeleSec|Amazon|Google|ISRG|Let.s Encrypt|Actalis|Buypass|' +
               'D-TRUST|E-Tugra|TUBITAK|Hellenic|SecureTrust|Network Solutions|Go Daddy|' +
               'Staat der Nederlanden|Certigna|AffirmTrust|Chambers|Autoridad|NetLock|TeliaSonera'

    foreach ($c in @($arr | Where-Object { $_.Store -eq 'Root' -and $_.SelfSigned })) {
        if ($c.Subject -notmatch "(?i)($knownCA)") {
            $sev = 'MEDIUM'
            try {
                if ($c.NotBeforeUtc -and
                    ((Get-Date) - [DateTime]$c.NotBeforeUtc).TotalDays -lt 365) { $sev = 'HIGH' }
            } catch { }
            Add-DFinding -RuleId 'DGL-270' -Severity $sev `
                -Title 'Unrecognised certificate in the trusted root store' `
                -Evidence "$($c.Subject) [gecerlilik: $($c.NotBeforeUtc)] $($c.Thumbprint)" `
                -Mitre 'T1553.004' -Artifact '15_certificates' `
                -Why 'A rogue root CA enables TLS interception and code signing forgery'
        }
    }

    Write-DLog "  $($arr.Count) certificates" -Level DEBUG
}

# ============================================================================
#  HTML RAPOR URETICI
# ============================================================================

function ConvertTo-DHtmlSafe {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return ($Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' `
                  -replace '"', '&quot;' -replace "'", '&#39;')
}

function New-DHtmlReport {
    <#
        Tek dosya, tamamen offline HTML. CDN yok - IR ortami cogu zaman izole.
        Boyut kontrolu: artefakt basina ilk 500 satir gomulur, tam veri CSV'de kalir.
    #>
    $ctx  = $Script:Ctx
    $out  = Join-Path $ctx.OutputDir 'REPORT.html'

    $sevOrder = @{ CRITICAL = 0; HIGH = 1; MEDIUM = 2; LOW = 3; INFO = 4 }
    $findings = @($Script:Findings | Sort-Object @{E = { $sevOrder[$_.Severity] } }, TimeUtc)

    $crit = @($findings | Where-Object Severity -eq 'CRITICAL').Count
    $high = @($findings | Where-Object Severity -eq 'HIGH').Count
    $med  = @($findings | Where-Object Severity -eq 'MEDIUM').Count
    $low  = @($findings | Where-Object Severity -eq 'LOW').Count
    $info = @($findings | Where-Object Severity -eq 'INFO').Count

    $riskColor = switch ($ctx.RiskLevel) {
        'CRITICAL' { '#ff3b30' } 'HIGH' { '#ff6b35' } 'MEDIUM' { '#ffb340' }
        'LOW' { '#4aa8ff' } default { '#34c759' }
    }

    # --- Bulgu satirlari ---
    $sbF = New-Object System.Text.StringBuilder
    foreach ($f in $findings) {
        $null = $sbF.Append('<tr class="f" data-sev="' + $f.Severity + '">')
        $null = $sbF.Append('<td><span class="badge s-' + $f.Severity + '">' + $f.Severity + '</span></td>')
        $null = $sbF.Append('<td class="mono dim">' + (ConvertTo-DHtmlSafe $f.RuleId) + '</td>')
        $null = $sbF.Append('<td><b>' + (ConvertTo-DHtmlSafe $f.Title) + '</b>')
        if ($f.Why) { $null = $sbF.Append('<div class="why">' + (ConvertTo-DHtmlSafe $f.Why) + '</div>') }
        $null = $sbF.Append('</td>')
        $null = $sbF.Append('<td class="mono ev">' + (ConvertTo-DHtmlSafe $f.Evidence) + '</td>')
        $null = $sbF.Append('<td class="mono dim">' + (ConvertTo-DHtmlSafe $f.Mitre) + '</td>')
        $null = $sbF.Append('<td class="mono dim">' + (ConvertTo-DHtmlSafe $f.TimeUtc) + '</td>')
        $null = $sbF.Append('<td class="mono dim">' + (ConvertTo-DHtmlSafe $f.Artifact) + '</td>')
        $null = $sbF.Append('</tr>')
    }
    if ($findings.Count -eq 0) {
        $null = $sbF.Append('<tr><td colspan="7" class="dim">No findings.</td></tr>')
    }

    # --- Timeline: saat bazli yogunluk ---
    $tl = @($Script:Timeline | Sort-Object TimeUtc)
    $buckets = @{}
    foreach ($t in $tl) {
        try {
            $k = ([DateTime]$t.TimeUtc).ToString('yyyy-MM-dd HH:00')
            if (-not $buckets.ContainsKey($k)) { $buckets[$k] = 0 }
            $buckets[$k]++
        } catch { }
    }
    $sorted = @($buckets.GetEnumerator() | Sort-Object Name)
    $maxB   = 1
    if ($sorted.Count -gt 0) {
        $maxB = ($sorted | Measure-Object -Property Value -Maximum).Maximum
        if ($maxB -lt 1) { $maxB = 1 }
    }

    $sbChart = New-Object System.Text.StringBuilder
    $barW = if ($sorted.Count -gt 0) { [math]::Max(2, [math]::Floor(1100 / [math]::Max(1, $sorted.Count))) } else { 4 }
    $x = 0
    foreach ($b in $sorted) {
        $h = [math]::Max(2, [math]::Round(($b.Value / $maxB) * 130))
        $y = 140 - $h
        $null = $sbChart.Append('<rect x="' + $x + '" y="' + $y + '" width="' + ($barW - 1) +
                '" height="' + $h + '" fill="#4aa8ff"><title>' + $b.Name + ' : ' + $b.Value +
                ' events</title></rect>')
        $x += $barW
    }

    # --- Timeline satirlari (en kritik 800) ---
    $tlShow = @($tl | Where-Object { $_.Severity -in 'CRITICAL', 'HIGH', 'MEDIUM' } |
                Select-Object -First 800)
    if ($tlShow.Count -lt 200) {
        $tlShow = @($tl | Select-Object -First 400)
    }
    $sbT = New-Object System.Text.StringBuilder
    foreach ($t in $tlShow) {
        $null = $sbT.Append('<tr class="f" data-sev="' + $t.Severity + '">')
        $null = $sbT.Append('<td class="mono">' + (ConvertTo-DHtmlSafe $t.TimeUtc) + '</td>')
        $null = $sbT.Append('<td><span class="badge s-' + $t.Severity + '">' + $t.Severity + '</span></td>')
        $null = $sbT.Append('<td class="mono dim">' + (ConvertTo-DHtmlSafe $t.Source) + '</td>')
        $null = $sbT.Append('<td>' + (ConvertTo-DHtmlSafe $t.Description) + '</td>')
        $null = $sbT.Append('<td class="mono ev">' + (ConvertTo-DHtmlSafe $t.Detail) + '</td>')
        $null = $sbT.Append('</tr>')
    }

    # --- Artefakt tablolari (her biri ilk 500 satir) ---
    $sbA = New-Object System.Text.StringBuilder
    $artDirs = @(
        (Join-Path $ctx.OutputDir 'artifacts'),
        (Join-Path $ctx.OutputDir 'events')
    )
    $tabList = New-Object System.Collections.ArrayList

    foreach ($dir in $artDirs) {
        if (-not (Test-Path $dir)) { continue }
        foreach ($csv in (Get-ChildItem $dir -Filter '*.csv' | Sort-Object Name)) {
            $rows = @()
            try { $rows = @(Import-Csv -Path $csv.FullName -ErrorAction Stop) } catch { continue }
            if ($rows.Count -eq 0) { continue }

            $id = ($csv.BaseName -replace '[^a-zA-Z0-9]', '_')
            $null = $tabList.Add([PSCustomObject]@{ Id = $id; Name = $csv.BaseName; Count = $rows.Count })

            $cols = $rows[0].PSObject.Properties.Name
            $null = $sbA.Append('<div class="pane" id="p_' + $id + '">')
            $null = $sbA.Append('<div class="ptitle">' + (ConvertTo-DHtmlSafe $csv.BaseName) +
                    ' <span class="dim">(' + $rows.Count + ' rows')
            if ($rows.Count -gt 500) {
                $null = $sbA.Append(' - first 500 shown, full data in ' + $csv.Name)
            }
            $null = $sbA.Append(')</span></div>')
            $null = $sbA.Append('<input class="tblsearch" placeholder="Bu tabloda ara..." ' +
                    'oninput="filterTable(this,' + "'t_$id'" + ')"><div class="scroll"><table id="t_' + $id + '"><thead><tr>')
            foreach ($c in $cols) { $null = $sbA.Append('<th>' + (ConvertTo-DHtmlSafe $c) + '</th>') }
            $null = $sbA.Append('</tr></thead><tbody>')

            foreach ($r in ($rows | Select-Object -First 500)) {
                $cls = ''
                if ($r.PSObject.Properties.Name -contains 'SuspiciousPath' -and
                    $r.SuspiciousPath -eq 'True') { $cls = ' class="hl-bad"' }
                elseif ($r.PSObject.Properties.Name -contains 'Signed' -and
                        $r.Signed -eq 'False') { $cls = ' class="hl-warn"' }
                $null = $sbA.Append('<tr' + $cls + '>')
                foreach ($c in $cols) {
                    $v = [string]$r.$c
                    if ($v.Length -gt 300) { $v = $v.Substring(0, 300) + '...' }
                    $null = $sbA.Append('<td class="mono">' + (ConvertTo-DHtmlSafe $v) + '</td>')
                }
                $null = $sbA.Append('</tr>')
            }
            $null = $sbA.Append('</tbody></table></div></div>')
        }
    }

    $sbTabs = New-Object System.Text.StringBuilder
    foreach ($t in $tabList) {
        $null = $sbTabs.Append('<button class="tab" onclick="showPane(' + "'$($t.Id)'" + ',this)">' +
                (ConvertTo-DHtmlSafe $t.Name) + ' <span class="cnt">' + $t.Count + '</span></button>')
    }

    # --- Hatalar / kapsam ---
    $sbE = New-Object System.Text.StringBuilder
    foreach ($e in @($Script:Errors | Select-Object -First 200)) {
        $null = $sbE.Append('<tr><td class="mono">' + (ConvertTo-DHtmlSafe $e.Module) +
                '</td><td class="mono dim">' + (ConvertTo-DHtmlSafe $e.Type) +
                '</td><td class="mono ev">' + (ConvertTo-DHtmlSafe $e.Message) + '</td></tr>')
    }

    $sbM = New-Object System.Text.StringBuilder
    foreach ($m in @($Script:ModuleStats | Sort-Object DurationMs -Descending)) {
        $null = $sbM.Append('<tr><td class="mono">' + (ConvertTo-DHtmlSafe $m.Module) +
                '</td><td class="mono">' + $m.Phase + '</td><td class="mono">' +
                (ConvertTo-DHtmlSafe $m.Status) + '</td><td class="mono">' +
                [math]::Round($m.DurationMs / 1000, 1) + ' s</td><td class="mono">' +
                $m.ErrorCount + '</td></tr>')
    }

    $ips = ($ctx.IPAddresses -join ', ')
    $dur = [math]::Round(((Get-Date) - $Script:StartTime).TotalSeconds, 1)

    # --- Sablon ---
    $html = @'
<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Douglas-042 :: {{HOST}}</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#0d1117;color:#c9d1d9;font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
.mono{font-family:ui-monospace,Consolas,"Courier New",monospace;font-size:12px}
.dim{color:#7d8590}
header{background:#161b22;border-bottom:2px solid #21262d;padding:16px 24px}
h1{margin:0 0 4px;font-size:20px;letter-spacing:.5px}
h1 span{color:#4aa8ff}
.meta{display:flex;flex-wrap:wrap;gap:18px;font-size:12px;color:#8b949e;margin-top:8px}
.meta b{color:#c9d1d9;font-weight:600}
.riskbar{padding:14px 24px;background:{{RISKCOLOR}};color:#0d1117;font-weight:700;font-size:16px;
  display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}
.counts{display:flex;gap:8px;flex-wrap:wrap}
.counts button{border:0;padding:6px 14px;border-radius:4px;cursor:pointer;font-weight:700;font-size:12px;
  font-family:inherit;color:#fff}
.c-CRITICAL{background:#ff3b30}.c-HIGH{background:#ff6b35}.c-MEDIUM{background:#b8860b}
.c-LOW{background:#2b6cb0}.c-INFO{background:#4a5568}.c-ALL{background:#30363d}
main{padding:20px 24px;max-width:100%}
section{margin-bottom:28px}
h2{font-size:15px;text-transform:uppercase;letter-spacing:1px;color:#8b949e;
  border-bottom:1px solid #21262d;padding-bottom:8px;margin:0 0 12px}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{text-align:left;padding:8px 10px;background:#161b22;color:#8b949e;font-weight:600;
  position:sticky;top:0;border-bottom:1px solid #30363d;white-space:nowrap;cursor:pointer}
th:hover{color:#c9d1d9}
td{padding:7px 10px;border-bottom:1px solid #1c2128;vertical-align:top}
tr:hover td{background:#161b22}
.scroll{max-height:70vh;overflow:auto;border:1px solid #21262d;border-radius:6px}
.badge{padding:2px 8px;border-radius:3px;font-size:10.5px;font-weight:700;color:#fff;white-space:nowrap}
.s-CRITICAL{background:#ff3b30}.s-HIGH{background:#ff6b35}.s-MEDIUM{background:#b8860b}
.s-LOW{background:#2b6cb0}.s-INFO{background:#4a5568}
.why{color:#7d8590;font-size:11.5px;margin-top:3px;font-weight:400}
.ev{word-break:break-all;max-width:640px;color:#a5d6ff}
.hl-bad td{background:#2d1215}.hl-bad:hover td{background:#3d1a1e}
.hl-warn td{background:#2b2410}.hl-warn:hover td{background:#3a3016}
#search{width:100%;padding:10px 14px;background:#0d1117;border:1px solid #30363d;
  border-radius:6px;color:#c9d1d9;font-size:13px;margin-bottom:12px;font-family:inherit}
.tblsearch{width:100%;padding:7px 12px;background:#0d1117;border:1px solid #30363d;
  border-radius:4px;color:#c9d1d9;font-size:12px;margin-bottom:8px;font-family:inherit}
input:focus{outline:none;border-color:#4aa8ff}
.tabs{display:flex;flex-wrap:wrap;gap:5px;margin-bottom:14px}
.tab{background:#161b22;border:1px solid #30363d;color:#8b949e;padding:6px 11px;
  border-radius:4px;cursor:pointer;font-size:11.5px;font-family:ui-monospace,monospace}
.tab:hover{border-color:#4aa8ff;color:#c9d1d9}
.tab.on{background:#1f6feb;color:#fff;border-color:#1f6feb}
.cnt{opacity:.65;font-size:10px}
.pane{display:none}.pane.on{display:block}
.ptitle{font-size:13px;font-weight:600;margin-bottom:8px;color:#c9d1d9}
svg{background:#161b22;border:1px solid #21262d;border-radius:6px;width:100%;height:150px}
.note{background:#161b22;border-left:3px solid #4aa8ff;padding:12px 16px;font-size:12.5px;
  border-radius:0 4px 4px 0;color:#8b949e;margin-bottom:14px}
footer{padding:20px 24px;color:#484f58;font-size:11.5px;border-top:1px solid #21262d;margin-top:30px}
@media print{body{background:#fff;color:#000}.tabs,#search,.tblsearch{display:none}
 .scroll{max-height:none}.pane{display:block!important}}
</style></head><body>
<header>
<h1>DOUGLAS-<span>042</span> &nbsp;|&nbsp; Incident Response Report</h1>
<div class="meta">
<span><b>{{HOST}}</b> ({{IP}})</span>
<span>Role: <b>{{ROLE}}</b></span>
<span>Domain: <b>{{DOMAIN}}</b></span>
<span>OS: <b>{{OS}}</b> build {{BUILD}}</span>
<span>Collected: <b>{{COLLECTED}}</b> UTC</span>
<span>Window: last <b>{{DAYS}}</b> days</span>
<span>Duration: <b>{{DURATION}}</b> s</span>
<span>Operator: <b>{{OPERATOR}}</b></span>
</div></header>

<div class="riskbar">
<span>RISK: {{RISKLEVEL}} &nbsp;(score {{RISKSCORE}})</span>
<div class="counts">
<button class="c-ALL" onclick="fsev('')">ALL {{TOTAL}}</button>
<button class="c-CRITICAL" onclick="fsev('CRITICAL')">CRITICAL {{CRIT}}</button>
<button class="c-HIGH" onclick="fsev('HIGH')">HIGH {{HIGH}}</button>
<button class="c-MEDIUM" onclick="fsev('MEDIUM')">MEDIUM {{MED}}</button>
<button class="c-LOW" onclick="fsev('LOW')">LOW {{LOW}}</button>
<button class="c-INFO" onclick="fsev('INFO')">INFO {{INFO}}</button>
</div></div>

<main>
<section>
<h2>Findings</h2>
<input id="search" placeholder="Search findings and timeline (path, user, IP, MITRE ID...)"
 oninput="gsearch(this.value)">
<div class="scroll"><table id="findings"><thead><tr>
<th onclick="sortT('findings',0)">Severity</th><th onclick="sortT('findings',1)">Rule</th>
<th onclick="sortT('findings',2)">Finding</th><th>Evidence</th>
<th onclick="sortT('findings',4)">MITRE</th><th onclick="sortT('findings',5)">Time (UTC)</th>
<th onclick="sortT('findings',6)">Artifact</th>
</tr></thead><tbody>{{FINDINGS}}</tbody></table></div>
</section>

<section>
<h2>Timeline</h2>
<div class="note">Event density by hour. Tall bars mark the activity window - attacker work usually
clusters into a narrow span. Hover a bar for the count.</div>
<svg viewBox="0 0 1100 150" preserveAspectRatio="none">{{CHART}}</svg>
<div class="scroll" style="margin-top:12px"><table id="timeline"><thead><tr>
<th onclick="sortT('timeline',0)">Time (UTC)</th><th onclick="sortT('timeline',1)">Severity</th>
<th onclick="sortT('timeline',2)">Source</th><th>Description</th><th>Detail</th>
</tr></thead><tbody>{{TIMELINE}}</tbody></table></div>
</section>

<section>
<h2>Artifacts</h2>
<div class="tabs">{{TABS}}</div>
{{PANES}}
</section>

<section>
<h2>Module Performance</h2>
<div class="scroll" style="max-height:300px"><table><thead><tr>
<th>Module</th><th>Phase</th><th>Status</th><th>Duration</th><th>Errors</th>
</tr></thead><tbody>{{MODSTATS}}</tbody></table></div>
</section>

<section>
<h2>Errors and Skipped Modules</h2>
<div class="note">"No data" and "the command failed" are different things. This table shows what
could not be collected - weigh it when judging the scope of the analysis.</div>
<div class="scroll" style="max-height:300px"><table><thead><tr>
<th>Module</th><th>Type</th><th>Message</th></tr></thead><tbody>{{ERRORS}}</tbody></table></div>
</section>

<section>
<h2>Out of Scope</h2>
<div class="note">
NOT COLLECTED here: memory image (WinPmem/DumpIt), disk image (FTK Imager),
full browser history parsing, ShellBag/Jumplist reconstruction, network capture (PCAP).<br><br>
<b>Important:</b> this ran on a live system. File access times and Prefetch may have
been altered. If a forensic image is taken, account for this collection's timestamp.
</div></section>
</main>

<footer>
Douglas-042 v{{VERSION}} &nbsp;|&nbsp; OnBT / Behind24 Blue Team &nbsp;|&nbsp;
{{ARTCOUNT}} artifact files &nbsp;|&nbsp; Full data is in the CSV/JSON files beside this report &nbsp;|&nbsp;
See MANIFEST.json for integrity verification
</footer>

<script>
function fsev(s){
  document.querySelectorAll('tr.f').forEach(function(r){
    r.style.display = (!s || r.dataset.sev===s) ? '' : 'none';
  });
  document.getElementById('search').value='';
}
function gsearch(q){
  q=q.toLowerCase();
  document.querySelectorAll('tr.f').forEach(function(r){
    r.style.display = (!q || r.innerText.toLowerCase().indexOf(q)>-1) ? '' : 'none';
  });
}
function filterTable(inp,tid){
  var q=inp.value.toLowerCase();
  var t=document.getElementById(tid);
  if(!t)return;
  t.querySelectorAll('tbody tr').forEach(function(r){
    r.style.display = (!q || r.innerText.toLowerCase().indexOf(q)>-1) ? '' : 'none';
  });
}
function showPane(id,btn){
  document.querySelectorAll('.pane').forEach(function(p){p.classList.remove('on')});
  document.querySelectorAll('.tab').forEach(function(t){t.classList.remove('on')});
  var p=document.getElementById('p_'+id);
  if(p)p.classList.add('on');
  if(btn)btn.classList.add('on');
}
var sortDir={};
function sortT(tid,col){
  var t=document.getElementById(tid);
  if(!t)return;
  var tb=t.tBodies[0];
  var rows=Array.prototype.slice.call(tb.rows);
  var k=tid+'_'+col;
  sortDir[k]=!sortDir[k];
  var d=sortDir[k]?1:-1;
  rows.sort(function(a,b){
    var x=(a.cells[col]?a.cells[col].innerText:'').trim();
    var y=(b.cells[col]?b.cells[col].innerText:'').trim();
    var nx=parseFloat(x), ny=parseFloat(y);
    if(!isNaN(nx)&&!isNaN(ny))return (nx-ny)*d;
    return x.localeCompare(y)*d;
  });
  rows.forEach(function(r){tb.appendChild(r)});
}
var ft=document.querySelector('.tab');
if(ft)ft.click();
</script></body></html>
'@

    $repl = [ordered]@{
        '{{HOST}}'      = (ConvertTo-DHtmlSafe $ctx.ComputerName)
        '{{IP}}'        = (ConvertTo-DHtmlSafe $ips)
        '{{ROLE}}'      = (ConvertTo-DHtmlSafe $ctx.DomainRole)
        '{{DOMAIN}}'    = (ConvertTo-DHtmlSafe ([string]$ctx.Domain))
        '{{OS}}'        = (ConvertTo-DHtmlSafe ([string]$ctx.OSCaption))
        '{{BUILD}}'     = (ConvertTo-DHtmlSafe ([string]$ctx.OSBuild))
        '{{COLLECTED}}' = $Script:StartTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        '{{DAYS}}'      = [string]$Days
        '{{DURATION}}'  = [string]$dur
        '{{OPERATOR}}'  = (ConvertTo-DHtmlSafe ([string]$ctx.Operator))
        '{{RISKLEVEL}}' = [string]$ctx.RiskLevel
        '{{RISKSCORE}}' = [string]$ctx.RiskScore
        '{{RISKCOLOR}}' = $riskColor
        '{{TOTAL}}'     = [string]$findings.Count
        '{{CRIT}}'      = [string]$crit
        '{{HIGH}}'      = [string]$high
        '{{MED}}'       = [string]$med
        '{{LOW}}'       = [string]$low
        '{{INFO}}'      = [string]$info
        '{{FINDINGS}}'  = $sbF.ToString()
        '{{CHART}}'     = $sbChart.ToString()
        '{{TIMELINE}}'  = $sbT.ToString()
        '{{TABS}}'      = $sbTabs.ToString()
        '{{PANES}}'     = $sbA.ToString()
        '{{MODSTATS}}'  = $sbM.ToString()
        '{{ERRORS}}'    = $sbE.ToString()
        '{{VERSION}}'   = $Script:Version
        '{{ARTCOUNT}}'  = [string]$Script:Manifest.Count
    }
    foreach ($k in $repl.Keys) { $html = $html.Replace($k, $repl[$k]) }

    try {
        [IO.File]::WriteAllText($out, $html, [Text.UTF8Encoding]::new($true))
        $sizeMB = [math]::Round((Get-Item $out).Length / 1MB, 2)
        Write-DLog "HTML report written ($sizeMB MB)" -Level OK
        return $out
    } catch {
        Write-DLog "HTML rapor olusturulamadi: $($_.Exception.Message)" -Level ERROR
        return $null
    }
}

# ============================================================================
#  MODUL: HAM ADLI ARTEFAKT (-CollectRaw)
# ============================================================================

Register-DModule -Name 'Raw forensic artifacts' -Phase 4 `
    -Description 'Copying locked files through a VSS snapshot' -Body {

    $rawDir = Join-Path $Script:Ctx.OutputDir 'raw'
    $copied = New-Object System.Collections.ArrayList
    $shadow = $null
    $shadowPath = $null

    # --- VSS snapshot olustur (kilitli dosyalara erisim icin) ---
    try {
        Write-DLog '  VSS snapshot olusturuluyor...' -Level INFO
        $res = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create `
               -Arguments @{ Volume = 'C:\'; Context = 'ClientAccessible' } -ErrorAction Stop
        if ($res.ReturnValue -eq 0 -and $res.ShadowID) {
            $shadow = Get-CimInstance Win32_ShadowCopy -Filter "ID='$($res.ShadowID)'" -ErrorAction Stop
            if ($shadow) {
                $shadowPath = $shadow.DeviceObject + '\'
                Write-DLog "  VSS snapshot hazir: $($res.ShadowID)" -Level OK
            }
        } else {
            Write-DLog "  VSS snapshot olusturulamadi (kod: $($res.ReturnValue))" -Level WARN
        }
    } catch {
        Write-DLog "  VSS kullanilamiyor: $($_.Exception.Message)" -Level WARN
    }

    function Copy-DRaw {
        param([string]$Relative, [string]$DestName, [switch]$Directory)

        $src = if ($shadowPath) { Join-Path $shadowPath $Relative } else { "C:\$Relative" }
        $dst = Join-Path $rawDir $DestName

        try {
            if ($Directory) {
                if (-not (Test-Path $src)) { return }
                $null = New-Item -Path $dst -ItemType Directory -Force -ErrorAction Stop
                $n = 0; $bytes = 0
                Get-ChildItem -LiteralPath $src -File -Force -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        try {
                            Copy-Item -LiteralPath $_.FullName -Destination $dst -Force -ErrorAction Stop
                            $n++; $bytes += $_.Length
                        } catch { }
                    }
                $null = $copied.Add([PSCustomObject]@{
                    Artifact = $DestName; Source = $Relative; Type = 'Directory'
                    Files = $n; SizeMB = [math]::Round($bytes / 1MB, 2); SHA256 = $null
                })
            } else {
                if (-not (Test-Path $src)) { return }
                Copy-Item -LiteralPath $src -Destination $dst -Force -ErrorAction Stop
                $fi = Get-Item $dst -ErrorAction Stop
                $null = $copied.Add([PSCustomObject]@{
                    Artifact = $DestName; Source = $Relative; Type = 'File'
                    Files = 1; SizeMB = [math]::Round($fi.Length / 1MB, 2)
                    SHA256 = Get-DFileHashSafe -Path $dst -MaxSizeMB 2000
                })
            }
            Write-DLog "    + $DestName" -Level DEBUG
        } catch {
            Write-DLog "    - $DestName kopyalanamadi: $($_.Exception.Message)" -Level WARN
        }
    }

    # --- Registry hive'lari ---
    foreach ($h in 'SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY') {
        Copy-DRaw -Relative "Windows\System32\config\$h" -DestName "hive_$h"
    }

    # --- Amcache: calistirilmis her binary'nin SHA1'i, DOSYA SILINMIS OLSA BILE ---
    Copy-DRaw -Relative 'Windows\AppCompat\Programs\Amcache.hve' -DestName 'Amcache.hve'
    Copy-DRaw -Relative 'Windows\AppCompat\Programs\RecentFileCache.bcf' -DestName 'RecentFileCache.bcf'

    # --- SRUM: uygulama basina ag kullanimi = exfil hacmi ---
    Copy-DRaw -Relative 'Windows\System32\sru\SRUDB.dat' -DestName 'SRUDB.dat'

    # --- Kullanici hive'lari ---
    try {
        Get-ChildItem 'C:\Users' -Directory -ErrorAction Stop | ForEach-Object {
            $u = $_.Name
            Copy-DRaw -Relative "Users\$u\NTUSER.DAT" -DestName "NTUSER_$u.dat"
            Copy-DRaw -Relative "Users\$u\AppData\Local\Microsoft\Windows\UsrClass.dat" `
                      -DestName "UsrClass_$u.dat"
            Copy-DRaw -Relative "Users\$u\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat" `
                      -DestName "WebCache_$u.dat"
        }
    } catch { }

    # --- Event loglari ---
    Copy-DRaw -Relative 'Windows\System32\winevt\Logs' -DestName 'evtx' -Directory

    # --- Prefetch ---
    Copy-DRaw -Relative 'Windows\Prefetch' -DestName 'Prefetch' -Directory

    # --- Scheduled task XML'leri ---
    Copy-DRaw -Relative 'Windows\System32\Tasks' -DestName 'Tasks' -Directory

    # --- IIS loglari (sunucu) ---
    if ($Script:Ctx.IsServer) {
        try {
            $iisLog = 'C:\inetpub\logs\LogFiles'
            if (Test-Path $iisLog) {
                $dst = Join-Path $rawDir 'IISLogs'
                $null = New-Item -Path $dst -ItemType Directory -Force -ErrorAction Stop
                $n = 0; $bytes = 0
                Get-ChildItem $iisLog -Recurse -File -Filter '*.log' -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -ge $Script:Ctx.WindowStart } |
                    ForEach-Object {
                        try {
                            Copy-Item -LiteralPath $_.FullName `
                                -Destination (Join-Path $dst "$($_.Directory.Name)_$($_.Name)") `
                                -Force -ErrorAction Stop
                            $n++; $bytes += $_.Length
                        } catch { }
                    }
                $null = $copied.Add([PSCustomObject]@{
                    Artifact = 'IISLogs'; Source = $iisLog; Type = 'Directory'
                    Files = $n; SizeMB = [math]::Round($bytes / 1MB, 2); SHA256 = $null
                })
            }
        } catch { }
    }

    # --- $MFT ve $UsnJrnl:$J ---
    # NOT: Bunlar ozel NTFS akislaridir, Copy-Item ile alinamaz.
    # Adli olarak dogru yontem RawCopy/KAPE'dir. Sadece not dusuyoruz.
    $null = $copied.Add([PSCustomObject]@{
        Artifact = 'MFT_UsnJrnl'; Source = 'C:\$MFT , C:\$Extend\$UsnJrnl:$J'
        Type = 'NOT_COLLECTED'; Files = 0; SizeMB = 0
        SHA256 = 'NTFS ozel akislari - RawCopy.exe / KAPE / FTK Imager ile alinmalidir'
    })

    # --- VSS snapshot temizligi ---
    if ($shadow) {
        try {
            Remove-CimInstance -InputObject $shadow -ErrorAction Stop
            Write-DLog '  VSS snapshot removed' -Level DEBUG
        } catch {
            Write-DLog "  VSS snapshot silinemedi (elle silin: $($shadow.ID))" -Level WARN
        }
    }

    $arr = @($copied)
    Export-DArtifact -Name '16_raw_collection' -Data $arr
    $totalMB = ($arr | Measure-Object -Property SizeMB -Sum).Sum
    Write-DLog "  $($arr.Count) artefakt, toplam $([math]::Round($totalMB, 1)) MB" -Level OK
}

# ============================================================================
#  UZAKTAN TOPLU TARAMA (FAN-OUT)
# ============================================================================

function Invoke-DRemoteCollection {
    <#
        -ComputerName verildiginde calisir. Script kendini hedeflere gonderir,
        her host kendi klasorunu uretir, sonra frekans analizi yapilir.
    #>
    param([string[]]$Targets)

    Write-Host ''
    Write-Host '  === UZAKTAN TOPLU TARAMA ===' -ForegroundColor White -BackgroundColor DarkMagenta
    Write-DLog "$($Targets.Count) hedef, throttle: $ThrottleLimit" -Level INFO

    $scriptPath = $PSCommandPath
    if (-not $scriptPath -or -not (Test-Path $scriptPath)) {
        Write-DLog 'Script yolu belirlenemedi - uzaktan tarama yapilamiyor' -Level ERROR
        return
    }
    $scriptText = Get-Content -Path $scriptPath -Raw -Encoding UTF8

    $base = if ($OutputPath) { $OutputPath }
            else { Join-Path (Split-Path $scriptPath -Parent) 'Output' }
    $null = New-Item -Path $base -ItemType Directory -Force -ErrorAction SilentlyContinue

    # --- Erisilebilirlik on kontrolu ---
    Write-DLog 'Hedefler kontrol ediliyor...' -Level INFO
    $reachable = New-Object System.Collections.ArrayList
    $dead      = New-Object System.Collections.ArrayList

    foreach ($t in $Targets) {
        $ok = $false
        try {
            $null = Test-WSMan -ComputerName $t -ErrorAction Stop
            $ok = $true
        } catch { }
        if ($ok) { $null = $reachable.Add($t) }
        else { $null = $dead.Add([PSCustomObject]@{ Computer = $t; Reason = 'WinRM erisilemiyor' }) }
    }
    Write-DLog "Erisilebilir: $($reachable.Count) / $($Targets.Count)" -Level OK
    if ($dead.Count -gt 0) {
        $dead | Export-Csv -Path (Join-Path $base 'UNREACHABLE.csv') `
                -NoTypeInformation -Encoding UTF8 -Force
        Write-DLog "$($dead.Count) host erisilemedi -> UNREACHABLE.csv" -Level WARN
    }
    if ($reachable.Count -eq 0) { return }

    # --- Uzak calistirma ---
    $remoteBlock = {
        param($ScriptText, $Days, $MaxEvents, $Quick, $NoResolve)

        $tmp = Join-Path $env:TEMP "Douglas-042_$([guid]::NewGuid().ToString('N')).ps1"
        $localOut = Join-Path $env:TEMP 'DouglasOut'
        try {
            [IO.File]::WriteAllText($tmp, $ScriptText, [Text.UTF8Encoding]::new($true))

            $splat = @{ Days = $Days; OutputPath = $localOut; MaxEventsPerChannel = $MaxEvents }
            if ($Quick)     { $splat['Quick'] = $true }
            if ($NoResolve) { $splat['NoResolve'] = $true }

            & $tmp @splat *> $null

            # Uretilen zip'i bul ve byte olarak dondur
            $zip = Get-ChildItem $localOut -Filter '*.zip' -ErrorAction SilentlyContinue |
                   Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($zip) {
                $bytes = [IO.File]::ReadAllBytes($zip.FullName)
                return [PSCustomObject]@{
                    Computer = $env:COMPUTERNAME; Status = 'OK'
                    ZipName = $zip.Name; ZipBytes = $bytes; Error = $null
                }
            }
            return [PSCustomObject]@{
                Computer = $env:COMPUTERNAME; Status = 'NO_OUTPUT'
                ZipName = $null; ZipBytes = $null; Error = 'Zip uretilmedi'
            }
        } catch {
            return [PSCustomObject]@{
                Computer = $env:COMPUTERNAME; Status = 'FAILED'
                ZipName = $null; ZipBytes = $null; Error = $_.Exception.Message
            }
        } finally {
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            Remove-Item $localOut -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    $icmArgs = @{
        ComputerName  = $reachable.ToArray()
        ScriptBlock   = $remoteBlock
        ArgumentList  = @($scriptText, $Days, $MaxEventsPerChannel, [bool]$Quick, [bool]$NoResolve)
        ThrottleLimit = $ThrottleLimit
        ErrorAction   = 'SilentlyContinue'
    }
    if ($Credential) { $icmArgs['Credential'] = $Credential }

    Write-DLog 'Remote collection started (allow a few minutes per host)...' -Level INFO
    $results = @(Invoke-Command @icmArgs)

    # --- Sonuclari kaydet ---
    $summary = New-Object System.Collections.ArrayList
    foreach ($r in $results) {
        if ($r.Status -eq 'OK' -and $r.ZipBytes) {
            try {
                $dst = Join-Path $base $r.ZipName
                [IO.File]::WriteAllBytes($dst, $r.ZipBytes)
                $null = $summary.Add([PSCustomObject]@{
                    Computer = $r.Computer; Status = 'OK'; File = $r.ZipName
                    SizeMB = [math]::Round($r.ZipBytes.Length / 1MB, 2); Error = $null
                })
                Write-DLog "  $($r.Computer) OK -> $($r.ZipName)" -Level OK
            } catch {
                $null = $summary.Add([PSCustomObject]@{
                    Computer = $r.Computer; Status = 'SAVE_FAILED'; File = $null
                    SizeMB = 0; Error = $_.Exception.Message
                })
            }
        } else {
            $null = $summary.Add([PSCustomObject]@{
                Computer = $r.Computer; Status = $r.Status; File = $null
                SizeMB = 0; Error = $r.Error
            })
            Write-DLog "  $($r.Computer) $($r.Status): $($r.Error)" -Level WARN
        }
    }
    $summary | Export-Csv -Path (Join-Path $base 'SWEEP_SUMMARY.csv') `
               -NoTypeInformation -Encoding UTF8 -Force

    # --- Frekans analizi (stack counting) ---
    # IR'de en hizli sonuc veren teknik: 1 makinede gorulen sey supheli.
    Write-DLog 'Frekans analizi yapiliyor...' -Level INFO
    $extract = Join-Path $base '_extract'
    $null = New-Item -Path $extract -ItemType Directory -Force -ErrorAction SilentlyContinue

    $allFindings = New-Object System.Collections.ArrayList
    $stackData   = @{ services = @{}; autoruns = @{}; tasks = @{} }

    foreach ($s in @($summary | Where-Object Status -eq 'OK')) {
        $zp  = Join-Path $base $s.File
        $dst = Join-Path $extract ($s.File -replace '\.zip$', '')
        try {
            Expand-Archive -Path $zp -DestinationPath $dst -Force -ErrorAction Stop
        } catch { continue }

        $fcsv = Join-Path $dst 'FINDINGS.csv'
        if (Test-Path $fcsv) {
            try {
                Import-Csv $fcsv -ErrorAction Stop | ForEach-Object { $null = $allFindings.Add($_) }
            } catch { }
        }

        $map = @{
            services = @{ File = 'artifacts\05_services.csv';  Key = { "$($_.Name) | $($_.BinaryPath)" } }
            autoruns = @{ File = 'artifacts\07_autoruns.csv';   Key = { "$($_.Category) | $($_.Name) | $($_.BinaryPath)" } }
            tasks    = @{ File = 'artifacts\06_scheduled_tasks.csv'; Key = { "$($_.TaskPath)$($_.TaskName) | $($_.BinaryPath)" } }
        }
        foreach ($k in $map.Keys) {
            $p = Join-Path $dst $map[$k].File
            if (-not (Test-Path $p)) { continue }
            try {
                Import-Csv $p -ErrorAction Stop | ForEach-Object {
                    $key = & $map[$k].Key
                    if (-not $key -or $key -match '^\s*\|\s*\|?\s*$') { return }
                    if (-not $stackData[$k].ContainsKey($key)) {
                        $stackData[$k][$key] = New-Object System.Collections.ArrayList
                    }
                    $null = $stackData[$k][$key].Add($s.Computer)
                }
            } catch { }
        }
    }

    $hostCount = @($summary | Where-Object Status -eq 'OK').Count
    foreach ($k in $stackData.Keys) {
        $stack = @($stackData[$k].GetEnumerator() | ForEach-Object {
            [PSCustomObject]@{
                Item       = $_.Key
                HostCount  = $_.Value.Count
                Percent    = if ($hostCount -gt 0) {
                                 [math]::Round(($_.Value.Count / $hostCount) * 100, 1) } else { 0 }
                Hosts      = (($_.Value | Select-Object -First 10) -join ', ')
                Rarity     = if ($_.Value.Count -eq 1) { 'TEKIL - INCELE' }
                             elseif ($_.Value.Count -le 3) { 'NADIR' }
                             else { 'YAYGIN' }
            }
        } | Sort-Object HostCount)
        $stack | Export-Csv -Path (Join-Path $base "STACK_$k.csv") `
                 -NoTypeInformation -Encoding UTF8 -Force
        $rare = @($stack | Where-Object HostCount -eq 1).Count
        Write-DLog "  STACK_$k : $($stack.Count) benzersiz, $rare tekil" -Level OK
    }

    $allFindings | Export-Csv -Path (Join-Path $base 'ALL_FINDINGS.csv') `
                   -NoTypeInformation -Encoding UTF8 -Force

    # Host risk siralamasi
    $ranking = @($allFindings | Group-Object Host | ForEach-Object {
        $c = @($_.Group | Where-Object Severity -eq 'CRITICAL').Count
        $h = @($_.Group | Where-Object Severity -eq 'HIGH').Count
        $m = @($_.Group | Where-Object Severity -eq 'MEDIUM').Count
        $l = @($_.Group | Where-Object Severity -eq 'LOW').Count
        [PSCustomObject]@{
            Host = $_.Name; Score = ($c * 10) + ($h * 5) + ($m * 2) + $l
            CRITICAL = $c; HIGH = $h; MEDIUM = $m; LOW = $l; TOTAL = $_.Count
        }
    } | Sort-Object Score -Descending)
    $ranking | Export-Csv -Path (Join-Path $base 'HOST_RANKING.csv') `
               -NoTypeInformation -Encoding UTF8 -Force

    Write-Host ''
    Write-Host '  === TARAMA OZETI ===' -ForegroundColor White -BackgroundColor DarkMagenta
    Write-Host ("   Hedef: {0}  |  Basarili: {1}  |  Erisilemedi: {2}" -f `
                $Targets.Count, $hostCount, $dead.Count)
    Write-Host ''
    Write-Host '   EN YUKSEK RISKLI HOSTLAR:' -ForegroundColor Red
    foreach ($r in ($ranking | Select-Object -First 15)) {
        $col = if ($r.CRITICAL -gt 0) { 'Red' } elseif ($r.HIGH -gt 0) { 'Yellow' } else { 'Gray' }
        Write-Host ("     {0,-20} skor {1,-5} C:{2} H:{3} M:{4}" -f `
                    $r.Host, $r.Score, $r.CRITICAL, $r.HIGH, $r.MEDIUM) -ForegroundColor $col
    }
    Write-Host ''
    Write-Host ("   CIKTI: {0}" -f $base) -ForegroundColor Green
    Write-Host '   STACK_*.csv dosyalarinda HostCount=1 olan satirlar oncelikli inceleme hedefidir.' -ForegroundColor DarkGray
    Write-Host ''
}

# ============================================================================
#  SIGMA KURAL MOTORU  (-SigmaFile)
# ============================================================================

# Rules arrive pre-compiled from the console: YAML parsing, the condition
# grammar and field mapping are all resolved there. What lands here is a flat
# structure of field/operator/values plus a boolean tree, so this evaluator
# stays small enough to read and fast enough to run over 100k events.

$Script:SigmaRules = @()
$Script:SigmaStats = $null

function Import-DSigmaRules {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path $Path)) {
        Write-DLog "Sigma rule file not found: $Path" -Level WARN
        return
    }
    try {
        $raw = Get-Content -Path $Path -Raw -Encoding UTF8 -ErrorAction Stop
        $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-DLog "Could not read the Sigma rule file: $($_.Exception.Message)" -Level ERROR
        return
    }

    $rules = if ($parsed.rules) { @($parsed.rules) } else { @($parsed) }
    $Script:SigmaRules = $rules
    Write-DLog "Sigma rules loaded: $($rules.Count)" -Level OK
}

function ConvertTo-DEventRecord {
    <#
        Turn an event into a name-keyed hashtable.

        Read from the event XML rather than the Properties array: property
        order differs between Windows builds, so positional access silently
        reads the wrong field on the one host where it matters. The XML carries
        the real names Windows wrote.
    #>
    param([Parameter(Mandatory)]$Event)

    $rec = @{
        EventID       = [string]$Event.Id
        Channel       = [string]$Event.LogName
        Provider_Name = [string]$Event.ProviderName
        Computer      = [string]$Event.MachineName
        TimeUtc       = ConvertTo-DUtcString $Event.TimeCreated
        Level         = [string]$Event.LevelDisplayName
    }
    try {
        $xml = [xml]$Event.ToXml()
        foreach ($d in $xml.Event.EventData.Data) {
            if ($d.Name) { $rec[[string]$d.Name] = [string]$d.'#text' }
        }
        # Some providers put content in UserData instead of EventData.
        if ($xml.Event.UserData) {
            foreach ($node in $xml.Event.UserData.ChildNodes) {
                foreach ($child in $node.ChildNodes) {
                    if ($child.Name) { $rec[[string]$child.Name] = [string]$child.InnerText }
                }
            }
        }
    } catch { }

    # Keyword searches test the whole record, so keep a flattened copy.
    $rec['__all'] = ($rec.Values -join ' ')
    return $rec
}

function Test-DSigmaField {
    param([hashtable]$Record, $Cond)

    $fieldName = [string]$Cond.field

    if ($Cond.null_check) {
        return (-not $Record.ContainsKey($fieldName)) -or
               [string]::IsNullOrEmpty([string]$Record[$fieldName])
    }

    $actual = if ($fieldName -eq '*') { [string]$Record['__all'] }
              elseif ($Record.ContainsKey($fieldName)) { [string]$Record[$fieldName] }
              else { $null }

    if ($null -eq $actual) { return $false }

    $op = [string]$Cond.op
    $needAll = ([string]$Cond.match -eq 'all')
    $hits = 0
    $values = @($Cond.values)

    foreach ($v in $values) {
        $val = [string]$v
        $match = switch ($op) {
            'equals'     { $actual -eq $val }
            'contains'   { $actual -like "*$val*" }
            'startswith' { $actual -like "$val*" }
            'endswith'   { $actual -like "*$val" }
            're'         { try { $actual -match $val } catch { $false } }
            'cidr'       { Test-DCidrMatch -Address $actual -Cidr $val }
            'lt'         { (Test-DNumeric $actual) -and [double]$actual -lt  [double]$val }
            'lte'        { (Test-DNumeric $actual) -and [double]$actual -le  [double]$val }
            'gt'         { (Test-DNumeric $actual) -and [double]$actual -gt  [double]$val }
            'gte'        { (Test-DNumeric $actual) -and [double]$actual -ge  [double]$val }
            default      { $actual -eq $val }
        }
        if ($match) {
            if (-not $needAll) { return $true }
            $hits++
        } elseif ($needAll) {
            return $false
        }
    }
    if ($needAll) { return ($hits -eq $values.Count) }
    return $false
}

function Test-DNumeric {
    param([string]$Value)
    return ($Value -match '^-?\d+(\.\d+)?$')
}

function Test-DCidrMatch {
    param([string]$Address, [string]$Cidr)
    try {
        $parts = $Cidr -split '/'
        if ($parts.Count -ne 2) { return $false }
        $net = [Net.IPAddress]::Parse($parts[0]).GetAddressBytes()
        $ip  = [Net.IPAddress]::Parse($Address).GetAddressBytes()
        if ($net.Length -ne $ip.Length) { return $false }
        [Array]::Reverse($net); [Array]::Reverse($ip)
        $netInt = [BitConverter]::ToUInt32($net, 0)
        $ipInt  = [BitConverter]::ToUInt32($ip, 0)
        $bits = [int]$parts[1]
        if ($bits -le 0) { return $true }
        $mask = [uint32]([uint32]::MaxValue -shl (32 - $bits))
        return (($netInt -band $mask) -eq ($ipInt -band $mask))
    } catch { return $false }
}

function Test-DSigmaSelection {
    param([hashtable]$Record, $Groups)
    # Groups are OR'd; the fields inside a group are AND'd.
    foreach ($group in @($Groups)) {
        $all = $true
        foreach ($cond in @($group)) {
            if (-not (Test-DSigmaField -Record $Record -Cond $cond)) { $all = $false; break }
        }
        if ($all) { return $true }
    }
    return $false
}

function Test-DSigmaCondition {
    param([hashtable]$Record, $Node, $Selections)

    if ($Node.PSObject.Properties.Name -contains 'sel') {
        $name = [string]$Node.sel
        return Test-DSigmaSelection -Record $Record -Groups $Selections.$name
    }

    $op = [string]$Node.op
    $args = @($Node.args)
    switch ($op) {
        'not' { return -not (Test-DSigmaCondition -Record $Record -Node $args[0] -Selections $Selections) }
        'and' {
            foreach ($a in $args) {
                if (-not (Test-DSigmaCondition -Record $Record -Node $a -Selections $Selections)) { return $false }
            }
            return $true
        }
        'or' {
            foreach ($a in $args) {
                if (Test-DSigmaCondition -Record $Record -Node $a -Selections $Selections) { return $true }
            }
            return $false
        }
    }
    return $false
}

function Format-DSigmaEvidence {
    param([hashtable]$Record)
    # Show the fields an analyst reads first, in a stable order.
    $keys = 'ProcessCommandLine', 'NewProcessName', 'ParentProcessName', 'Image',
            'TargetFilename', 'TargetObject', 'ScriptBlockText', 'ServiceName',
            'ImagePath', 'DestAddress', 'DestPort', 'PipeName', 'Query',
            'SubjectUserName', 'TargetUserName', 'IpAddress', 'LogonType'
    $parts = New-Object System.Collections.ArrayList
    foreach ($k in $keys) {
        if ($Record.ContainsKey($k) -and -not [string]::IsNullOrWhiteSpace([string]$Record[$k])) {
            $v = [string]$Record[$k]
            if ($v.Length -gt 220) { $v = $v.Substring(0, 220) + '...' }
            $null = $parts.Add("$k=$v")
        }
    }
    if ($parts.Count -eq 0) {
        $null = $parts.Add("EventID=$($Record['EventID']) on $($Record['Channel'])")
    }
    return ($parts -join ' | ')
}

Register-DModule -Name 'Sigma rules' -Phase 2 `
    -Description 'Community detection rules evaluated against collected events' -Body {

    if (-not $Script:SigmaRules -or $Script:SigmaRules.Count -eq 0) {
        Write-DLog '  No Sigma rules supplied, skipped' -Level DEBUG
        return
    }

    # One pass per channel: querying the same log once per rule would be
    # hundreds of reads of the same data.
    $byChannel = @{}
    foreach ($rule in $Script:SigmaRules) {
        $ch = [string]$rule.channel
        if (-not $byChannel.ContainsKey($ch)) { $byChannel[$ch] = New-Object System.Collections.ArrayList }
        $null = $byChannel[$ch].Add($rule)
    }

    $matches = New-Object System.Collections.ArrayList
    $stats   = New-Object System.Collections.ArrayList
    $ruleHits = @{}

    foreach ($channel in $byChannel.Keys) {
        $rules = @($byChannel[$channel])

        # Restrict the query to the event ids the rules care about. If any rule
        # in the channel wants everything, we have to read everything.
        $ids = New-Object System.Collections.ArrayList
        $wantsAll = $false
        foreach ($r in $rules) {
            $rIds = @($r.event_ids)
            if ($rIds.Count -eq 0) { $wantsAll = $true; break }
            foreach ($i in $rIds) { if ($ids -notcontains $i) { $null = $ids.Add([int]$i) } }
        }

        $events = @()
        try {
            $events = if ($wantsAll) { Get-DWinEvents -LogName $channel }
                      else { Get-DWinEvents -LogName $channel -Id $ids.ToArray() }
        } catch {
            $null = $stats.Add([PSCustomObject]@{
                Channel = $channel; Rules = $rules.Count; Events = 0
                Matches = 0; Status = "Query failed: $($_.Exception.Message)"
            })
            continue
        }

        if ($events.Count -eq 0) {
            $null = $stats.Add([PSCustomObject]@{
                Channel = $channel; Rules = $rules.Count; Events = 0
                Matches = 0; Status = 'No events in window'
            })
            continue
        }

        $channelMatches = 0
        foreach ($evt in $events) {
            $rec = ConvertTo-DEventRecord -Event $evt
            $evtId = [string]$rec['EventID']

            foreach ($rule in $rules) {
                $rIds = @($rule.event_ids)
                if ($rIds.Count -gt 0 -and ($rIds -notcontains [int]$evtId)) { continue }

                $hit = $false
                try {
                    $hit = Test-DSigmaCondition -Record $rec -Node $rule.condition `
                                                -Selections $rule.selections
                } catch { $hit = $false }

                if (-not $hit) { continue }

                $channelMatches++
                $key = [string]$rule.id
                if (-not $ruleHits.ContainsKey($key)) { $ruleHits[$key] = 0 }
                $ruleHits[$key]++

                # Cap per rule: a broad rule can match thousands of events and
                # drown every other finding in the report.
                if ($ruleHits[$key] -gt 25) { continue }

                $evidence = Format-DSigmaEvidence -Record $rec
                $null = $matches.Add([PSCustomObject]@{
                    RuleId    = $key
                    Title     = [string]$rule.title
                    Level     = [string]$rule.level
                    Channel   = $channel
                    EventID   = $evtId
                    TimeUtc   = [string]$rec['TimeUtc']
                    Mitre     = [string]$rule.mitre
                    Evidence  = $evidence
                    Source    = [string]$rule.source
                })

                Add-DFinding -RuleId "SIGMA-$key" -Severity ([string]$rule.severity) `
                    -Title "Sigma: $([string]$rule.title)" `
                    -Evidence "$($rec['TimeUtc']) [$channel/$evtId] $evidence" `
                    -Mitre ([string]$rule.mitre) -Artifact '12_sigma_matches' `
                    -Timestamp ([string]$rec['TimeUtc']) `
                    -Why ([string]$rule.description)

                Add-DTimelineEvent -Timestamp ([string]$rec['TimeUtc']) -Source 'Sigma' `
                    -Description ([string]$rule.title) -Detail $evidence `
                    -Severity ([string]$rule.severity)
            }
        }

        $null = $stats.Add([PSCustomObject]@{
            Channel = $channel; Rules = $rules.Count; Events = $events.Count
            Matches = $channelMatches; Status = 'OK'
        })
        Write-DLog "  $channel : $($rules.Count) rules over $($events.Count) events, $channelMatches matches" -Level DEBUG
    }

    Export-DArtifact -Name '12_sigma_matches' -Data @($matches) -SubDir events
    Export-DArtifact -Name '12_sigma_stats' -Data @($stats) -SubDir events

    # A rule that matched more than the cap is reported once so the number is
    # never silently wrong.
    foreach ($key in $ruleHits.Keys) {
        if ($ruleHits[$key] -gt 25) {
            $rule = $Script:SigmaRules | Where-Object { [string]$_.id -eq $key } | Select-Object -First 1
            Add-DFinding -RuleId 'DGL-022' -Severity INFO `
                -Title 'Sigma rule matched more events than are shown' `
                -Evidence "$($rule.title): $($ruleHits[$key]) matches, first 25 recorded" `
                -Artifact '12_sigma_matches' `
                -Why 'A broad rule can bury every other finding. Review it in the console.'
        }
    }

    $Script:SigmaStats = @($stats)
    Write-DLog "  Sigma: $($matches.Count) matches from $($Script:SigmaRules.Count) rules" -Level OK
}

# ============================================================================
#  YARA STRING ENGINE  (-YaraFile)
# ============================================================================

# Rules arrive pre-compiled from the console. There is no YARA engine in
# PowerShell, so what runs here is string, hex and regex matching over file
# contents plus a boolean tree — the part of the language that does file
# detection. Rules needing PE structure, integer reads or offsets are refused
# at compile time rather than half-evaluated here.

$Script:YaraRules = @()

function Import-DYaraRules {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path $Path)) {
        Write-DLog "YARA rule file not found: $Path" -Level WARN
        return
    }
    try {
        $parsed = (Get-Content -Path $Path -Raw -Encoding UTF8 -EA Stop) | ConvertFrom-Json -EA Stop
    } catch {
        Write-DLog "Could not read the YARA rule file: $($_.Exception.Message)" -Level ERROR
        return
    }
    $Script:YaraRules = if ($parsed.rules) { @($parsed.rules) } else { @($parsed) }
    Write-DLog "YARA rules loaded: $($Script:YaraRules.Count)" -Level OK
}

function Test-DYaraString {
    param([string]$Ascii, [string]$Wide, [string]$Hex, $Str)

    switch ([string]$Str.kind) {
        'hex' {
            if (-not $Hex) { return $false }
            try { return [bool]($Hex -match [string]$Str.pattern) } catch { return $false }
        }
        'regex' {
            $opts = if ($Str.nocase) { 'IgnoreCase' } else { 'None' }
            try {
                $rx = New-Object Text.RegularExpressions.Regex(
                          [string]$Str.pattern, [Text.RegularExpressions.RegexOptions]$opts)
                if ($rx.IsMatch($Ascii)) { return $true }
                if ($Wide -and $rx.IsMatch($Wide)) { return $true }
            } catch { }
            return $false
        }
        default {
            $needle = [string]$Str.value
            if (-not $needle) { return $false }
            $cmp = if ($Str.nocase) { 'OrdinalIgnoreCase' } else { 'Ordinal' }

            $hay = New-Object System.Collections.ArrayList
            if ($Str.ascii -ne $false) { $null = $hay.Add($Ascii) }
            if ($Str.wide) { $null = $hay.Add($Wide) }
            if ($hay.Count -eq 0) { $null = $hay.Add($Ascii) }

            foreach ($h in $hay) {
                if (-not $h) { continue }
                $idx = $h.IndexOf($needle, [StringComparison]$cmp)
                if ($idx -lt 0) { continue }
                if (-not $Str.fullword) { return $true }
                # fullword: the match must not be flanked by word characters.
                $before = if ($idx -gt 0) { $h[$idx - 1] } else { ' ' }
                $afterI = $idx + $needle.Length
                $after  = if ($afterI -lt $h.Length) { $h[$afterI] } else { ' ' }
                if ($before -notmatch '\w' -and $after -notmatch '\w') { return $true }
            }

            if ($Str.base64) {
                try {
                    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($needle))
                    if ($Ascii.IndexOf($b64, [StringComparison]::Ordinal) -ge 0) { return $true }
                } catch { }
            }
            return $false
        }
    }
}

function Test-DYaraCondition {
    param($Node, [hashtable]$Hits)

    if ($null -eq $Node) { return $false }
    $names = $Node.PSObject.Properties.Name

    if ($names -contains 'const') { return [bool]$Node.const }
    if ($names -contains 'str')   { return [bool]$Hits[[string]$Node.str] }

    switch ([string]$Node.op) {
        'count' {
            $need = [int]$Node.need
            $have = 0
            foreach ($id in @($Node.ids)) { if ($Hits[[string]$id]) { $have++ } }
            return ($have -ge $need)
        }
        'not' { return -not (Test-DYaraCondition -Node @($Node.args)[0] -Hits $Hits) }
        'and' {
            foreach ($a in @($Node.args)) {
                if (-not (Test-DYaraCondition -Node $a -Hits $Hits)) { return $false }
            }
            return $true
        }
        'or' {
            foreach ($a in @($Node.args)) {
                if (Test-DYaraCondition -Node $a -Hits $Hits) { return $true }
            }
            return $false
        }
    }
    return $false
}

function Invoke-DYaraScan {
    <# Run every loaded rule against one file. Returns matching rule objects. #>
    param([Parameter(Mandatory)][string]$Path, [int]$MaxBytes = 8MB)

    if ($Script:YaraRules.Count -eq 0) { return @() }

    $bytes = $null
    $size = 0
    try {
        $fi = Get-Item -LiteralPath $Path -Force -EA Stop
        $size = $fi.Length
        if ($size -eq 0 -or $size -gt $MaxBytes) { return @() }
        $bytes = [IO.File]::ReadAllBytes($Path)
    } catch { return @() }

    # Three views of the same bytes. Built once per file, not once per rule:
    # with 2000 rules the difference is minutes.
    $ascii = [Text.Encoding]::GetEncoding(28591).GetString($bytes)   # latin-1, byte-preserving
    $wide  = $null
    $hex   = $null

    $matched = New-Object System.Collections.ArrayList
    foreach ($rule in $Script:YaraRules) {
        if ($rule.filesize_min -and $size -lt [int]$rule.filesize_min) { continue }
        if ($rule.filesize_max -and $size -gt [int]$rule.filesize_max) { continue }

        $strs = @($rule.strings)
        if ($null -eq $wide -and @($strs | Where-Object { $_.wide }).Count -gt 0) {
            try { $wide = [Text.Encoding]::Unicode.GetString($bytes) } catch { $wide = '' }
        }
        if ($null -eq $hex -and @($strs | Where-Object { $_.kind -eq 'hex' }).Count -gt 0) {
            try { $hex = [BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant() }
            catch { $hex = '' }
        }

        $hits = @{}
        foreach ($st in $strs) {
            $hits[[string]$st.id] = Test-DYaraString -Ascii $ascii -Wide $wide -Hex $hex -Str $st
        }

        if (Test-DYaraCondition -Node $rule.condition -Hits $hits) {
            $which = @($strs | Where-Object { $hits[[string]$_.id] } |
                       Select-Object -First 4 | ForEach-Object { [string]$_.id })
            $null = $matched.Add([PSCustomObject]@{
                Rule = [string]$rule.name; Severity = [string]$rule.severity
                Description = [string]$rule.description
                Strings = ($which -join ',')
                Source = [string]$rule.source
            })
        }
    }
    return @($matched)
}

Register-DModule -Name 'YARA scan' -Phase 3 -SkipOnQuick `
    -Description 'Community YARA rules over recently written and suspicious files' -Body {

    if ($Script:YaraRules.Count -eq 0) {
        Write-DLog '  No YARA rules supplied, skipped' -Level DEBUG
        return
    }

    # Scanning every file on the volume with 2000 rules would take hours. The
    # candidate set is what the file modules already flagged as interesting:
    # recently written executables, web files and attacker tooling.
    $candidates = New-Object System.Collections.ArrayList
    foreach ($art in '13_recent_files', '13_web_files', '13_attacker_tools', '13_archives') {
        $csv = Join-Path $Script:Ctx.OutputDir "artifacts\$art.csv"
        if (-not (Test-Path $csv)) { continue }
        try {
            foreach ($r in @(Import-Csv $csv -EA Stop)) {
                if ($r.FullName -and $candidates -notcontains $r.FullName) {
                    $null = $candidates.Add($r.FullName)
                }
            }
        } catch { }
    }

    # Plus anything currently running from a suspicious location.
    if ($Script:ProcIndex) {
        foreach ($pr in $Script:ProcIndex.Values) {
            if ($pr.Path -and $pr.SuspiciousPath -and $candidates -notcontains $pr.Path) {
                $null = $candidates.Add($pr.Path)
            }
        }
    }

    $hits = New-Object System.Collections.ArrayList
    $scanned = 0
    foreach ($file in $candidates) {
        if ($scanned -ge 3000) { break }
        $scanned++
        foreach ($m in (Invoke-DYaraScan -Path $file)) {
            $null = $hits.Add([PSCustomObject]@{
                File = $file; Rule = $m.Rule; Severity = $m.Severity
                Description = $m.Description; Strings = $m.Strings; Source = $m.Source
            })
        }
    }

    Export-DArtifact -Name '18_yara_matches' -Data @($hits)
    Export-DArtifact -Name '18_yara_stats' -Data @([PSCustomObject]@{
        RulesLoaded = $Script:YaraRules.Count
        FilesScanned = $scanned
        Candidates = $candidates.Count
        Matches = $hits.Count
    })

    foreach ($h in $hits) {
        $sev = if ($h.Severity -in 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO') { $h.Severity } else { 'HIGH' }
        Add-DFinding -RuleId "YARA-$($h.Rule)" -Severity $sev `
            -Title "YARA: $($h.Rule)" `
            -Evidence "$($h.File)  [strings: $($h.Strings)]" `
            -Mitre 'T1027' -Artifact '18_yara_matches' `
            -Why $(if ($h.Description) { $h.Description } else { 'A community YARA rule matched this file.' })
        Add-DTimelineEvent -Timestamp (Get-Date) -Source 'YARA' `
            -Description "YARA match: $($h.Rule)" -Detail $h.File -Severity $sev
    }

    Write-DLog "  YARA: $($hits.Count) matches over $scanned files ($($Script:YaraRules.Count) rules)" -Level OK
}

# ============================================================================
#  CUSTOM RULES  (-CustomRuleFile)
# ============================================================================

# Rules written in the console, evaluated against the artifact tables this
# collector just produced. Sigma reads event logs and YARA reads file content;
# these read everything else — services, tasks, autoruns, connections, accounts.

$Script:CustomRules = @()

function Import-DCustomRules {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) {
        Write-DLog "Custom rule file not found: $Path" -Level WARN
        return
    }
    try {
        $parsed = (Get-Content -Path $Path -Raw -Encoding UTF8 -EA Stop) | ConvertFrom-Json -EA Stop
    } catch {
        Write-DLog "Could not read the custom rule file: $($_.Exception.Message)" -Level ERROR
        return
    }
    $Script:CustomRules = if ($parsed.rules) { @($parsed.rules) } else { @($parsed) }
    Write-DLog "Custom rules loaded: $($Script:CustomRules.Count)" -Level OK
}

function Test-DCustomCondition {
    param($Row, $Cond)

    $field = [string]$Cond.field
    $raw = $null
    try { $raw = $Row.$field } catch { }
    $value = if ($null -eq $raw) { '' } else { [string]$raw }
    $target = [string]$Cond.value
    $op = [string]$Cond.op

    switch ($op) {
        'is_empty'     { return [string]::IsNullOrWhiteSpace($value) }
        'is_not_empty' { return -not [string]::IsNullOrWhiteSpace($value) }
        'is_true'      { return ($value.Trim().ToLowerInvariant() -in 'true', '1', 'yes') }
        'is_false'     { return ((-not [string]::IsNullOrWhiteSpace($value)) -and
                                 ($value.Trim().ToLowerInvariant() -notin 'true', '1', 'yes')) }
        'equals'       { return ($value -ieq $target) }
        'not_equals'   { return ($value -ine $target) }
        'contains'     { return ($value.IndexOf($target, [StringComparison]::OrdinalIgnoreCase) -ge 0) }
        'not_contains' { return ($value.IndexOf($target, [StringComparison]::OrdinalIgnoreCase) -lt 0) }
        'starts_with'  { return $value.StartsWith($target, [StringComparison]::OrdinalIgnoreCase) }
        'ends_with'    { return $value.EndsWith($target, [StringComparison]::OrdinalIgnoreCase) }
        're'           { try { return [bool]($value -imatch $target) } catch { return $false } }
        'regex'        { try { return [bool]($value -imatch $target) } catch { return $false } }
        'gt' {
            $a = 0.0; $b = 0.0
            if ([double]::TryParse($value, [ref]$a) -and [double]::TryParse($target, [ref]$b)) {
                return ($a -gt $b)
            }
            return $false
        }
        'lt' {
            $a = 0.0; $b = 0.0
            if ([double]::TryParse($value, [ref]$a) -and [double]::TryParse($target, [ref]$b)) {
                return ($a -lt $b)
            }
            return $false
        }
    }
    return $false
}

function Test-DCustomRule {
    param($Rule, $Row)
    $conds = @($Rule.conditions)
    if ($conds.Count -eq 0) { return $false }
    $needAll = ([string]$Rule.match -ne 'any')

    foreach ($c in $conds) {
        $hit = Test-DCustomCondition -Row $Row -Cond $c
        if ($needAll -and -not $hit) { return $false }
        if (-not $needAll -and $hit) { return $true }
    }
    return $needAll
}

Register-DModule -Name 'Custom rules' -Phase 3 `
    -Description 'Detections written in the console, run over collected artifacts' -Body {

    if ($Script:CustomRules.Count -eq 0) {
        Write-DLog '  No custom rules supplied, skipped' -Level DEBUG
        return
    }

    # Group by artifact so each CSV is read once rather than once per rule.
    $byArtifact = @{}
    foreach ($r in $Script:CustomRules) {
        $a = [string]$r.artifact
        if (-not $byArtifact.ContainsKey($a)) { $byArtifact[$a] = New-Object System.Collections.ArrayList }
        $null = $byArtifact[$a].Add($r)
    }

    $stats = New-Object System.Collections.ArrayList
    $total = 0

    foreach ($artifact in $byArtifact.Keys) {
        $rules = @($byArtifact[$artifact])

        $csv = $null
        foreach ($sub in 'artifacts', 'events') {
            $candidate = Join-Path $Script:Ctx.OutputDir "$sub\$artifact.csv"
            if (Test-Path $candidate) { $csv = $candidate; break }
        }
        if (-not $csv) {
            $null = $stats.Add([PSCustomObject]@{
                Artifact = $artifact; Rules = $rules.Count; Rows = 0
                Matches = 0; Status = 'Artifact not produced on this host'
            })
            continue
        }

        $rows = @()
        try { $rows = @(Import-Csv -Path $csv -EA Stop) } catch { }
        if ($rows.Count -eq 0) {
            $null = $stats.Add([PSCustomObject]@{
                Artifact = $artifact; Rules = $rules.Count; Rows = 0
                Matches = 0; Status = 'No rows'
            })
            continue
        }

        $matches = 0
        foreach ($row in $rows) {
            foreach ($rule in $rules) {
                if (-not (Test-DCustomRule -Rule $rule -Row $row)) { continue }
                $matches++
                $total++

                # Build evidence from whichever identifying columns this row has.
                $parts = New-Object System.Collections.ArrayList
                foreach ($k in 'Name', 'TaskName', 'FullName', 'Address', 'Process',
                               'ProcessName', 'Path', 'BinaryPath', 'PathName',
                               'Value', 'RemoteAddress', 'CommandLine') {
                    $v = $null
                    try { $v = $row.$k } catch { }
                    if ($v -and -not [string]::IsNullOrWhiteSpace([string]$v)) {
                        $sv = [string]$v
                        if ($sv.Length -gt 160) { $sv = $sv.Substring(0, 160) + '...' }
                        $null = $parts.Add("$k=$sv")
                    }
                    if ($parts.Count -ge 3) { break }
                }
                $evidence = if ($parts.Count) { $parts -join ' | ' } else { "row in $artifact" }

                Add-DFinding -RuleId ([string]$rule.rule_id) -Severity ([string]$rule.severity) `
                    -Title ([string]$rule.title) -Evidence $evidence `
                    -Mitre ([string]$rule.mitre) -Artifact $artifact `
                    -Why $(if ($rule.why) { [string]$rule.why } else { 'Matched a rule written in the console.' })
            }
        }

        $null = $stats.Add([PSCustomObject]@{
            Artifact = $artifact; Rules = $rules.Count; Rows = $rows.Count
            Matches = $matches; Status = 'OK'
        })
    }

    Export-DArtifact -Name '20_custom_rule_stats' -Data @($stats)
    Write-DLog "  Custom rules: $total matches from $($Script:CustomRules.Count) rules" -Level OK
}

# ============================================================================
#  ANA AKIS
# ============================================================================

Show-Banner

# --- Onkosul: yonetici ---
$adminInfo = Test-DAdmin
if (-not $adminInfo.IsAdmin) {
    Write-Host '  [x] Douglas-042 yonetici yetkisiyle calistirilmalidir.' -ForegroundColor Red
    Write-Host '      Ornek: Start-Process powershell -Verb RunAs' -ForegroundColor DarkGray
    exit 1
}

# --- Onkosul: PS surumu ---
$Script:Caps = Get-DCapabilities
if ($Script:Caps.PSMajor -lt 4) {
    Write-Host '  [x] PowerShell 4.0+ gereklidir. Mevcut: ' -NoNewline -ForegroundColor Red
    Write-Host $Script:Caps.PSVersion -ForegroundColor Red
    exit 1
}
if (-not $Script:Caps.IsPS5Plus) {
    Write-Host '  [!] PowerShell 4.0 tespit edildi - fallback modu aktif.' -ForegroundColor Yellow
    Write-Host '      Bazi moduller sinirli veri toplayacak (2012 R2 uyumluluk).' -ForegroundColor DarkGray
    Write-Host ''
}

# --- UZAKTAN TOPLU TARAMA MODU ---
# -ComputerName verildiyse lokal toplama yapilmaz; script hedeflere gonderilir.
if ($ComputerName -and $ComputerName.Count -gt 0) {
    $Script:Ctx = @{ ComputerName = $env:COMPUTERNAME; OutputDir = $null; LogFile = $null }
    Invoke-DRemoteCollection -Targets $ComputerName
    exit 0
}

# --- Baglam ---
$Script:Ctx = Get-DHostContext -AdminInfo $adminInfo
$Script:Ctx.OutputDir = Initialize-DOutput -Root $OutputPath
$Script:Ctx.LogFile   = Join-Path $Script:Ctx.OutputDir 'logs\douglas.log'

Write-DLog ("Koleksiyon basladi: {0} ({1}) | Rol: {2} | Operator: {3}" -f `
            $Script:Ctx.ComputerName, $Script:Ctx.PrimaryIP,
            $Script:Ctx.DomainRole, $Script:Ctx.Operator) -Level OK
Write-DLog ("Pencere: son {0} gun (>= {1} UTC)" -f `
            $Days, $Script:Ctx.WindowStartUtc.ToString('yyyy-MM-dd HH:mm')) -Level INFO
Write-DLog ("Cikti: {0}" -f $Script:Ctx.OutputDir) -Level INFO
if ($Quick)      { Write-DLog 'QUICK MODE - phase 3 will be skipped' -Level WARN }
if ($CollectRaw) { Write-DLog 'RAW COLLECTION enabled - this may produce several GB' -Level WARN }

# --- IOC ---
if ($ProgressFile) { $Script:ProgressPath = $ProgressFile }

# Rules switched off in the console. Read before anything can fire, and read
# defensively: an unreadable list means "run everything", never "run nothing".
if ($DisabledRuleFile -and (Test-Path $DisabledRuleFile)) {
    try {
        $off = Get-Content $DisabledRuleFile -ErrorAction Stop |
               ForEach-Object { $_.Trim() } |
               Where-Object { $_ -and -not $_.StartsWith('#') }
        foreach ($id in $off) { $Script:DisabledRules[$id] = $true }
        if ($Script:DisabledRules.Count -gt 0) {
            Write-DLog ("Rules disabled in the console: {0}" -f $Script:DisabledRules.Count) -Level INFO
        }
    } catch {
        Write-DLog "Could not read the disabled rule list; running every rule." -Level WARN
    }
}

if ($LiveFindingFile) {
    $Script:LiveFindingPath = $LiveFindingFile
    try { Set-Content -LiteralPath $LiveFindingFile -Value '' -Encoding UTF8 -ErrorAction Stop }
    catch { $Script:LiveFindingPath = '' }
}

if ($MinSeverity -and $MinSeverity -ne 'INFO') {
    $Script:MinSeverityRank = $Script:SeverityRank[$MinSeverity]
    Write-DLog "Severity floor: $MinSeverity and above" -Level INFO
}
if ($Profile -and $Profile -ne 'auto') {
    Write-DLog "Scan profile: $Profile (overrides the detected role)" -Level INFO
}

if ($IocFile) { Import-DIocs -Path $IocFile }
if ($SigmaFile) { Import-DSigmaRules -Path $SigmaFile }
if ($YaraFile)  { Import-DYaraRules -Path $YaraFile }
if ($CustomRuleFile) { Import-DCustomRules -Path $CustomRuleFile }

# --- Transcript ---
try {
    Start-Transcript -Path (Join-Path $Script:Ctx.OutputDir 'logs\transcript.log') `
                     -Force -ErrorAction SilentlyContinue | Out-Null
} catch { }

# --- Fazlar ---
try {
    Invoke-DPhase -Phase 0 -Title 'HOST IDENTITY'
    Invoke-DPhase -Phase 1 -Title 'VOLATILE DATA'
    Invoke-DPhase -Phase 2 -Title 'EVENT LOGS'
    if (-not $Quick) {
        Invoke-DPhase -Phase 3 -Title 'FILE SYSTEM & ARTIFACTS'
    }
    if ($CollectRaw) {
        Invoke-DPhase -Phase 4 -Title 'RAW FORENSIC ARTIFACTS'
    }
} catch {
    Write-DLog "CRITICAL: the phase engine stopped - $($_.Exception.Message)" -Level ERROR
} finally {
    Complete-DCollection
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
    try {
        [Threading.Thread]::CurrentThread.CurrentCulture = $Script:OriginalCulture
    } catch { }
}
