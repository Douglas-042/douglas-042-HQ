"""Analyst guidance for each detection rule.

The collector emits a title, evidence and a one-line reason. That is enough to
know something fired, and not enough to decide what to do about it at 3am.
This adds the three things an analyst actually asks next:

    looks_for   what the rule actually tested, so the finding can be verified
    benign      the ways this fires legitimately, so it can be ruled out
    next_step   the concrete action that either confirms or clears it

Lives on the server rather than in the collector so that guidance can be
improved without redeploying agents, and so existing collections benefit
immediately.
"""
from __future__ import annotations

CATALOG: dict[str, dict[str, str]] = {
    # --- Services and persistence -----------------------------------------
    "DGL-001": {
        "looks_for": "A service whose binary sits in Temp, AppData or ProgramData "
                     "rather than System32 or Program Files.",
        "benign": "Some line-of-business and legacy software genuinely installs "
                  "into ProgramData. Check whether the binary is signed and "
                  "whether the service predates the incident.",
        "next_step": "Read the binary's signature and creation time in "
                     "05_services.csv, then check the 7045 event for who "
                     "installed it and when.",
    },
    "DGL-030": {
        "looks_for": "An autorun entry pointing at a file that no longer exists.",
        "benign": "Uninstallers frequently leave orphaned Run keys behind.",
        "next_step": "Harmless on its own, but the missing path is a hijack "
                     "opportunity: anything writable there runs at logon.",
    },
    "DGL-042": {
        "looks_for": "A process using a Windows system binary name from a "
                     "directory that is not its real home.",
        "benign": "Almost never legitimate. A genuine svchost.exe only ever "
                  "runs from System32 or SysWOW64.",
        "next_step": "Treat as confirmed malware. Hash the binary, check the "
                     "parent process, and look for the persistence that starts it.",
    },
    "DGL-060": {
        "looks_for": "A service binary that changed inside the analysis window.",
        "benign": "A software update or patch cycle changes service binaries "
                  "legitimately. Correlate with the patch history.",
        "next_step": "Compare the binary's signature with the vendor's and check "
                     "whether a matching update was installed that day.",
    },
    "DGL-063": {
        "looks_for": "A service name that scores as randomly generated: mixed "
                     "digits and letters, few vowels, or several case flips.",
        "benign": "Some vendors use hashed or GUID-like service names. The rule "
                  "excludes known Windows services and common product prefixes.",
        "next_step": "Cobalt Strike installs its SMB beacon this way. Check the "
                     "binary path and the 7045 event that created it.",
    },
    "DGL-070": {
        "looks_for": "Autorun entries across every ASEP location: Run keys, "
                     "startup folders, services, tasks and shell extensions.",
        "benign": "Most autoruns on a workstation are legitimate. Severity here "
                  "comes from signature status and location, not existence.",
        "next_step": "Compare against a known-good host. Frequency analysis in "
                     "the console does this across the fleet automatically.",
    },
    "DGL-080": {
        "looks_for": "Winlogon Userinit or Shell values that differ from the "
                     "Windows defaults.",
        "benign": "Some enterprise management agents append to Userinit. A "
                  "trailing comma and a signed binary is normal.",
        "next_step": "The expected values are userinit.exe and explorer.exe. "
                     "Anything appended runs at every interactive logon.",
    },
    "DGL-082": {
        "looks_for": "An IFEO Debugger value on an accessibility binary such as "
                     "sethc.exe or utilman.exe.",
        "benign": "Legitimate debugger registrations exist but are rare and "
                  "usually point at a real debugger.",
        "next_step": "This is the classic sticky-keys backdoor: it grants SYSTEM "
                     "from the logon screen without credentials. Remove it and "
                     "assume the host was accessible to anyone at the console.",
    },
    "DGL-084": {
        "looks_for": "A DLL in the LSA Security Packages or Authentication "
                     "Packages list that is not a Microsoft default.",
        "benign": "Some smartcard and MFA products register here legitimately.",
        "next_step": "A DLL loaded into LSA sees credentials in clear text. "
                     "Verify the publisher; if unknown, rotate every credential "
                     "used on this host.",
    },
    "DGL-090": {
        "looks_for": "A WMI event filter bound to a consumer, which is how "
                     "fileless persistence survives reboots without a file.",
        "benign": "SCCM and some monitoring agents create subscriptions. Check "
                  "the consumer's command and namespace.",
        "next_step": "Read the consumer command in 08_wmi_persistence.csv. "
                     "This survives reinstall of everything except WMI itself.",
    },

    # --- Execution ---------------------------------------------------------
    "DGL-043": {
        "looks_for": "Command lines matching known attacker tooling patterns: "
                     "credential dumping, shadow copy deletion, tunnelling, "
                     "log clearing and similar.",
        "benign": "Administrators legitimately run some of these. What matters "
                  "is who ran it, from where, and whether it fits their role.",
        "next_step": "Take the parent process and the user from the finding, and "
                     "check whether that person was working at that time.",
    },
    "DGL-044": {
        "looks_for": "A web server worker process (w3wp.exe) spawning a command "
                     "interpreter.",
        "benign": "Effectively never. A healthy IIS worker does not start cmd.exe.",
        "next_step": "Confirmed webshell execution. Find the web file written "
                     "closest to this timestamp in 13_webshell_hits.csv.",
    },
    "DGL-047": {
        "looks_for": "Several discovery commands (whoami, net, nltest, systeminfo) "
                     "running within a short window.",
        "benign": "An administrator troubleshooting can produce this pattern.",
        "next_step": "Hands-on-keyboard reconnaissance looks exactly like this. "
                     "Check what ran immediately afterwards.",
    },
    "DGL-144": {
        "looks_for": "Base64-encoded PowerShell, decoded and written into the "
                     "report in clear text.",
        "benign": "Some management tooling encodes commands routinely.",
        "next_step": "Read the decoded command in the evidence field. It usually "
                     "names the second-stage payload and its source.",
    },
    "DGL-150": {
        "looks_for": "PowerShell's own script block logging flagging a block as "
                     "suspicious at Warning level.",
        "benign": "Fires on some legitimate obfuscated or minified scripts.",
        "next_step": "PowerShell records these even when script block logging is "
                     "off. Read the block itself in the event log artifacts.",
    },

    # --- Credential access -------------------------------------------------
    "DGL-114": {
        "looks_for": "WDigest UseLogonCredential set to 1, which puts plaintext "
                     "passwords back into LSASS memory.",
        "benign": "No legitimate reason exists on a modern system. Some old "
                  "applications required it a decade ago.",
        "next_step": "An attacker sets this then waits for logons. Assume every "
                     "credential used since it was set is compromised.",
    },
    "DGL-210": {
        "looks_for": "Sysmon event 10 showing a handle opened to LSASS with "
                     "read-memory access rights.",
        "benign": "Some EDR and backup products legitimately read LSASS. Check "
                  "the source process against your installed security stack.",
        "next_step": "If the source is not a known security product, treat every "
                     "credential on this host as stolen and rotate them.",
    },
    "DGL-220": {
        "looks_for": "One account requesting RC4 service tickets for many "
                     "different services in a short window.",
        "benign": "Legacy applications sometimes request RC4 tickets in volume.",
        "next_step": "This is Kerberoasting. The requested service accounts are "
                     "now subject to offline cracking; rotate their passwords.",
    },
    "DGL-224": {
        "looks_for": "Event 4662 showing directory replication rights used by a "
                     "principal that is not a domain controller.",
        "benign": "Azure AD Connect and some backup products replicate "
                  "legitimately. Verify the account is one of them.",
        "next_step": "Otherwise this is DCSync: every password hash in the domain "
                     "can be pulled. Plan a krbtgt reset.",
    },

    # --- Defence evasion and anti-forensics --------------------------------
    "DGL-014": {
        "looks_for": "A log that is large, not full, and yet holds no history. "
                     "Capacity, fill level and oldest record are checked together.",
        "benign": "A freshly built or recently reconfigured host looks the same. "
                  "Check the OS install date.",
        "next_step": "If the host is not new, the log was cleared. Everything "
                     "absent from this report becomes unprovable rather than absent.",
    },
    "DGL-110": {
        "looks_for": "A Defender protection component reporting as disabled.",
        "benign": "A third-party AV takes over and disables Defender legitimately. "
                  "Check whether another product is registered.",
        "next_step": "If Defender is the only product, find who disabled it and "
                     "when, then check what ran in the window that followed.",
    },
    "DGL-112": {
        "looks_for": "Defender exclusion paths, read from the cmdlet, the "
                     "registry and Group Policy so a local override is not missed.",
        "benign": "Database and application servers legitimately exclude their "
                  "data directories.",
        "next_step": "An excluded directory is where the payload lives. Scan "
                     "every excluded path by hand.",
    },
    "DGL-172": {
        "looks_for": "Event 1102, the record Windows writes when the Security "
                     "log is cleared.",
        "benign": "Log rotation does not produce 1102. Deliberate clearing does.",
        "next_step": "The event names the account that cleared it. That account "
                     "is either compromised or was used by the attacker.",
    },
    "DGL-232": {
        "looks_for": "Creation time later than modification time, or all three "
                     "timestamps with zeroed millisecond fields.",
        "benign": "Some installers and archive extractors set timestamps in ways "
                  "that trip this.",
        "next_step": "Zeroed milliseconds are the signature of a timestomping "
                     "tool. Use $MFT rather than the file system view to confirm.",
    },

    # --- Lateral movement --------------------------------------------------
    "DGL-050": {
        "looks_for": "netsh portproxy rules, which forward a local port to "
                     "another host.",
        "benign": "Occasionally used legitimately for development or legacy "
                  "application access.",
        "next_step": "Almost always a pivot. The rule names the destination — "
                     "collect from that host next.",
    },
    "DGL-160": {
        "looks_for": "Logon Type 9, which is what RunAs with /netonly produces.",
        "benign": "Administrators using runas legitimately produce this.",
        "next_step": "Type 9 is the standard trace of pass-the-hash and "
                     "overpass-the-hash. Check what the session did next.",
    },
    "DGL-164": {
        "looks_for": "A successful logon for an account that had just accumulated "
                     "failed attempts.",
        "benign": "Someone mistyping a password then getting it right.",
        "next_step": "Distinguish by volume and source. Dozens of failures from "
                     "one address followed by success is a successful brute force.",
    },
    "DGL-191": {
        "looks_for": "RDPClient event 1024, written when this host initiates an "
                     "outbound RDP connection.",
        "benign": "Jump boxes and administrator workstations do this constantly.",
        "next_step": "On a server this is rarely normal. The destinations form "
                     "the spread map — collect from each of them.",
    },

    # --- Initial access and web -------------------------------------------
    "DGL-240": {
        "looks_for": "Web files containing command-execution patterns: eval on "
                     "user input, Process.Start, known webshell names.",
        "benign": "Some frameworks and admin panels legitimately contain these "
                  "constructs. Check whether the file belongs to the application.",
        "next_step": "Compare against the deployment package. Anything not in it "
                     "was placed by someone else.",
    },
    "DGL-241": {
        "looks_for": "Any file appearing in a web root inside the analysis window.",
        "benign": "An actual deployment produces exactly this. Check your release "
                  "calendar first.",
        "next_step": "If no deployment happened, the file was uploaded. Check the "
                     "IIS logs around that timestamp for the request that wrote it.",
    },

    # --- Collection and exfiltration --------------------------------------
    "DGL-250": {
        "looks_for": "Archive files created inside the analysis window, weighted "
                     "by size and location.",
        "benign": "Backup jobs create archives on a schedule.",
        "next_step": "Staging data into an archive precedes exfiltration. Check "
                     "the contents and whether it left the network.",
    },
    "DGL-251": {
        "looks_for": "Known attacker and remote-access tooling on disk: rclone, "
                     "mega, AnyDesk, PsExec, mimikatz, procdump and similar.",
        "benign": "Your own administrators may use PsExec or AnyDesk. Check "
                  "against the approved software list.",
        "next_step": "Unapproved remote access software is how attackers keep a "
                     "way back in after you close the original hole.",
    },

    # --- Visibility gaps ---------------------------------------------------
    "DGL-140": {
        "looks_for": "The absence of any 4688 process creation events.",
        "benign": "Not a finding about the attacker, but about your telemetry.",
        "next_step": "Enable process creation auditing with command line capture. "
                     "Without it, execution history is invisible in future incidents.",
    },
    "DGL-141": {
        "looks_for": "4688 events present but with no command line field.",
        "benign": "This is the default configuration; command lines require a "
                  "separate policy setting.",
        "next_step": "Enable ProcessCreationIncludeCmdLine_Enabled. Process names "
                     "alone rarely answer the question you will be asking.",
    },
    "DGL-016": {
        "looks_for": "The requested lookback window exceeding what the logs "
                     "actually retain.",
        "benign": "Normal on hosts with small log files.",
        "next_step": "Scope your conclusions to the shorter window. Increase log "
                     "sizes before the next incident.",
    },
    "DGL-017": {
        "looks_for": "Sysmon not installed.",
        "benign": "Expected on most estates; Sysmon is not installed by default.",
        "next_step": "Sysmon supplies process, network and LSASS-access telemetry "
                     "Windows does not. Deploying it materially improves the next "
                     "investigation.",
    },
    "DGL-020": {
        "looks_for": "Additional fixed volumes present, but none of the known "
                     "directory names matched on them.",
        "benign": "Common when a second disk holds only databases or VM images.",
        "next_step": "If a web root or file share lives on that volume, point a "
                     "separate scan at it.",
    },

    # --- Host and collection scope ----------------------------------------
    "DGL-000": {
        "looks_for": "An OS install date inside the last seven days.",
        "benign": "A genuinely new build, or a machine reimaged as part of normal provisioning.",
        "next_step": "If nobody rebuilt this host, the rebuild was the cleanup. Ask who did it and when.",
    },
    "DGL-002": {
        "looks_for": "The most recent hotfix being more than 90 days old.",
        "benign": "Air-gapped and appliance-like hosts patch on their own schedule.",
        "next_step": "Cross-check the OS build against known exploited vulnerabilities for it. An unpatched edge server is the likeliest way in.",
    },
    "DGL-015": {
        "looks_for": "An event log channel that exists but is switched off.",
        "benign": "Some channels are disabled by default and were never enabled.",
        "next_step": "Check whether it was recently disabled. An attacker turning off a channel leaves this exact trace.",
    },
    "DGL-018": {
        "looks_for": "A channel returning as many events as the collection cap allows.",
        "benign": "Busy servers legitimately produce this volume.",
        "next_step": "Data is truncated, so absence proves nothing. Re-run with a shorter window or a higher -MaxEventsPerChannel.",
    },
    "DGL-019": {
        "looks_for": "The file scan stopping at its 5000-file ceiling.",
        "benign": "Expected on a host with a lot of recent file churn.",
        "next_step": "Narrow -Days. Any file written after the cut-off point was not examined.",
    },
    "DGL-021": {
        "looks_for": "An enabled local account whose password is not required.",
        "benign": "Almost never legitimate on a server.",
        "next_step": "Anyone who can reach the login prompt can use this account. Disable it or set a password today.",
    },
    "DGL-022": {
        "looks_for": "Guest or the built-in Administrator being enabled.",
        "benign": "Some older estates keep the built-in Administrator active for break-glass use.",
        "next_step": "Check the last logon time. A built-in account enabled recently is an attacker's fallback route.",
    },
    "DGL-023": {
        "looks_for": "A user profile directory created inside the analysis window.",
        "benign": "Ordinary on a workstation; unusual on a server nobody logs into.",
        "next_step": "Match the profile name against the accounts created in event 4720.",
    },
    "DGL-024": {
        "looks_for": "More members in local Administrators than a typical build carries.",
        "benign": "Common on developer machines and in estates where admin is granted broadly.",
        "next_step": "Every member is a route to SYSTEM. Compare against another host built the same way.",
    },
    "DGL-L027": {
        "looks_for": "Whether auditd is running and its log is readable, which "
                     "is what Sigma execution rules on Linux are evaluated against.",
        "benign": "Expected on a host where auditd was never installed. It is a "
                  "statement about coverage, not about the host being compromised.",
        "next_step": "Without it a clean sweep is unproven rather than clean. "
                     "Install auditd, load a ruleset, and re-run: "
                     "apt install auditd && systemctl enable --now auditd",
    },
    "DGL-025": {
        "looks_for": "Whether any detections were switched off in the console for this hunt, "
                     "and how many findings that suppressed.",
        "benign": "Expected whenever somebody has deliberately turned a category off. "
                  "It is a notice, not a problem with the host.",
        "next_step": "A quiet result should never be mistaken for a clean one. If this "
                     "hunt looks unusually empty, this names the reason: re-enable the "
                     "rules in DGL rules to see what they would have found.",
    },

    # --- Autoruns ----------------------------------------------------------
    "DGL-031": {
        "looks_for": "An autorun entry whose binary carries no valid signature.",
        "benign": "Small vendors and in-house tools frequently ship unsigned.",
        "next_step": "Judge it by location and age rather than signature alone. Unsigned plus a temp directory is the pairing that matters.",
    },
    "DGL-032": {
        "looks_for": "An autorun pointing at a path that no longer exists.",
        "benign": "Uninstallers routinely leave these behind.",
        "next_step": "Harmless in itself, but anything writable at that path will run at the next logon. Remove the entry.",
    },
    "DGL-033": {
        "looks_for": "An autorun command matching a known attacker pattern.",
        "benign": "Some management agents genuinely invoke PowerShell at startup.",
        "next_step": "Read the full command in 07_autoruns.csv. Persistence that runs a downloader is the common shape.",
    },

    # --- Processes ---------------------------------------------------------
    "DGL-040": {
        "looks_for": "A running process whose image sits in Temp, AppData or ProgramData.",
        "benign": "Installers and some updaters legitimately run from temp while working.",
        "next_step": "Check the parent process and how long it has been running. A long-lived process in a temp directory is not an installer.",
    },
    "DGL-041": {
        "looks_for": "An unsigned process running out of a user profile.",
        "benign": "Portable tools and developer builds look exactly like this.",
        "next_step": "Hash it and check the network connections attributed to that PID.",
    },
    "DGL-045": {
        "looks_for": "A running archiving, tunnelling or remote-access tool.",
        "benign": "7-Zip and PuTTY are on plenty of admin desktops.",
        "next_step": "Question the timing and the account, not the tool. Compression at 3am on a file server is the collection stage.",
    },
    "DGL-046": {
        "looks_for": "A process whose image path could not be read.",
        "benign": "Protected processes and some security products refuse this.",
        "next_step": "Also happens when the image was deleted from disk after launch, which is deliberate. Check whether the PID still has network connections.",
    },

    # --- Network -----------------------------------------------------------
    "DGL-051": {
        "looks_for": "A per-user proxy auto-config URL being set.",
        "benign": "Corporate environments set this through policy.",
        "next_step": "If it was set per-user rather than by policy, a malicious PAC file can route traffic through attacker infrastructure. Fetch and read the file.",
    },
    "DGL-052": {
        "looks_for": "The hosts file changing inside the analysis window.",
        "benign": "Developers and some installers edit it.",
        "next_step": "Read the entries. Security vendor domains pointed at 127.0.0.1 is a blocking technique; other redirects can be interception.",
    },
    "DGL-053": {
        "looks_for": "A process in a suspicious directory holding a connection to an external address.",
        "benign": "Rare. Legitimate software in temp directories does not usually keep long-lived outbound sessions.",
        "next_step": "This is the clearest C2 signature the tool produces. Take the address and check it across the fleet.",
    },
    "DGL-054": {
        "looks_for": "An unsigned process talking to an address outside private ranges.",
        "benign": "In-house tools and some updaters are unsigned and legitimately reach the internet.",
        "next_step": "Check what the destination is. Reputation aside, an unsigned binary you cannot account for is worth hashing.",
    },
    "DGL-055": {
        "looks_for": "A suspicious process listening on 0.0.0.0, accepting connections from anywhere.",
        "benign": "Servers listen on all interfaces by design; the finding weighs the binary, not the bind.",
        "next_step": "A listener that is unsigned or lives in a temp directory is a backdoor. Check which firewall rule lets it through.",
    },
    "DGL-056": {
        "looks_for": "A Windows Firewall profile switched off.",
        "benign": "Some estates disable it in favour of a third-party firewall.",
        "next_step": "Find when it was disabled and what happened next. Attackers turn it off for C2 and lateral movement.",
    },
    "DGL-057": {
        "looks_for": "An inbound firewall rule allowing traffic to a binary in a suspicious location.",
        "benign": "Rarely legitimate. Real applications are installed before their rules are written.",
        "next_step": "This is how a backdoor stays reachable. Remove the rule and examine the binary.",
    },

    # --- Services ----------------------------------------------------------
    "DGL-061": {
        "looks_for": "A service path containing spaces without quotes.",
        "benign": "Very common in older software; usually a packaging defect rather than an attack.",
        "next_step": "Check whether a parent directory is writable by non-admins. Only then is it exploitable.",
    },
    "DGL-062": {
        "looks_for": "A service binary whose contents changed inside the analysis window.",
        "benign": "Patch cycles and software updates do this legitimately.",
        "next_step": "Match the change time against your patch window. A service binary changing outside one is service hijacking.",
    },
    "DGL-064": {
        "looks_for": "PsExec-style remote execution services (PSEXESVC and its variants).",
        "benign": "Administrators use PsExec. So does almost every intrusion.",
        "next_step": "The 7045 event names who installed it and when. Match that against your change record.",
    },
    "DGL-065": {
        "looks_for": "An attacker pattern inside a service's binary path or arguments.",
        "benign": "Rare. Service paths are normally plain executable references.",
        "next_step": "A service whose path is a PowerShell one-liner is persistence, not a service.",
    },

    # --- Scheduled tasks ---------------------------------------------------
    "DGL-071": {
        "looks_for": "A task defined at the root of the task library rather than in a folder.",
        "benign": "Some installers create tasks at the root.",
        "next_step": "Windows keeps its own tasks in folders. Attacker-created tasks are usually left at the root.",
    },
    "DGL-072": {
        "looks_for": "A scheduled task running an unsigned binary.",
        "benign": "In-house scripts and small vendors are unsigned.",
        "next_step": "Combine with the task's author and creation date, both in 06_scheduled_tasks.csv.",
    },
    "DGL-073": {
        "looks_for": "A non-Microsoft task configured to run as SYSTEM.",
        "benign": "Backup and management agents legitimately need SYSTEM.",
        "next_step": "SYSTEM plus an unsigned binary plus a recent creation date is persistence.",
    },
    "DGL-074": {
        "looks_for": "An attacker pattern in a task's command or arguments.",
        "benign": "Some management tooling invokes PowerShell from tasks.",
        "next_step": "Read the full Execute and Arguments fields. Encoded commands here are the clearest signal.",
    },
    "DGL-075": {
        "looks_for": "A task created inside the analysis window.",
        "benign": "Software installs create tasks routinely.",
        "next_step": "Correlate with TaskScheduler event 106, which names the account that created it.",
    },

    # --- Registry persistence ---------------------------------------------
    "DGL-081": {
        "looks_for": "AppInit_DLLs holding a value.",
        "benign": "A handful of old accessibility and input products still use it.",
        "next_step": "This key is empty on a healthy modern system, and a DLL here loads into every process using user32.dll.",
    },
    "DGL-083": {
        "looks_for": "A SilentProcessExit MonitorProcess entry.",
        "benign": "Effectively never used legitimately.",
        "next_step": "The named binary runs whenever the monitored process exits — a persistence trigger disguised as diagnostics.",
    },
    "DGL-085": {
        "looks_for": "An AppCertDlls entry.",
        "benign": "Empty by default; no mainstream product uses it.",
        "next_step": "A DLL here loads on every CreateProcess call. Treat as confirmed persistence.",
    },
    "DGL-086": {
        "looks_for": "A Time Provider DLL that is not the Windows default.",
        "benign": "Some precision-timing and virtualisation products register their own.",
        "next_step": "Verify the publisher. The time service runs as SYSTEM and starts early, which is why this location gets abused.",
    },
    "DGL-087": {
        "looks_for": "UserInitMprLogonScript being set.",
        "benign": "Absent by default; occasionally used by legacy logon scripting.",
        "next_step": "Runs at every logon with the user's rights. Read the script it points at.",
    },
    "DGL-088": {
        "looks_for": "A BITS transfer job configured on the host.",
        "benign": "Windows Update and management agents use BITS constantly.",
        "next_step": "Check the remote URL and the job's notification command. BITS both downloads and persists, and evades most inspection.",
    },
    "DGL-089": {
        "looks_for": "A Winlogon value set where the default is empty.",
        "benign": "Some enterprise agents append to these.",
        "next_step": "Anything here runs at every interactive logon before the desktop appears.",
    },
    "DGL-091": {
        "looks_for": "An attacker pattern in the command a WMI consumer runs.",
        "benign": "Management tooling uses consumers, but rarely with encoded commands.",
        "next_step": "Read the full consumer command. This is fileless persistence and survives most cleanup.",
    },
    "DGL-100": {
        "looks_for": "An open named pipe matching known C2 framework naming.",
        "benign": "Legitimate software uses named pipes heavily; the patterns here are framework defaults.",
        "next_step": "Identify the owning process. Cobalt Strike's SMB beacon is the common source.",
    },

    # --- Security posture --------------------------------------------------
    "DGL-111": {
        "looks_for": "Defender signatures older than a healthy update cadence.",
        "benign": "Isolated hosts fall behind naturally.",
        "next_step": "Check whether updates were blocked deliberately. Stale signatures plus an exclusion is a pattern.",
    },
    "DGL-115": {
        "looks_for": "No AMSI provider registered on the host.",
        "benign": "Some minimal server builds genuinely have none.",
        "next_step": "Without AMSI, script content is not scanned at all. Check whether the provider registration was removed.",
    },
    "DGL-116": {
        "looks_for": "An audit policy subcategory set to no auditing.",
        "benign": "Default Windows policy leaves several categories off.",
        "next_step": "Not an attack in itself, but it defines what the next investigation will be able to see. Enable it.",
    },
    "DGL-117": {
        "looks_for": "No volume shadow copies present.",
        "benign": "Copies are disabled on plenty of servers by policy.",
        "next_step": "If they were enabled before, deletion precedes ransomware. Check for vssadmin in the command line findings.",
    },
    "DGL-120": {
        "looks_for": "A share granting Everyone full control.",
        "benign": "Occurs in older estates and on deliberately public shares.",
        "next_step": "This is a lateral movement path and a ransomware amplifier. Check what the share contains.",
    },
    "DGL-121": {
        "looks_for": "A drive root exposed as a share.",
        "benign": "Administrative shares (C$) are default and are not what this reports.",
        "next_step": "A non-default share of a whole drive exposes the OS. Check who created it.",
    },

    # --- Drivers -----------------------------------------------------------
    "DGL-130": {
        "looks_for": "A loaded driver whose file sits in a temp or user directory.",
        "benign": "Rare. Legitimate drivers are installed to System32\\drivers.",
        "next_step": "This is the shape of a bring-your-own-vulnerable-driver attack. Identify the driver and check it against the Microsoft blocklist.",
    },
    "DGL-131": {
        "looks_for": "A loaded driver with no valid signature.",
        "benign": "Test-signed drivers exist in development environments.",
        "next_step": "Kernel code without a signature should not load on a modern build. Check whether test signing was enabled.",
    },
    "DGL-132": {
        "looks_for": "A driver file written inside the analysis window.",
        "benign": "Driver updates and hardware installs do this.",
        "next_step": "Correlate with CodeIntegrity events and the service that loads it.",
    },

    # --- Event evidence ----------------------------------------------------
    "DGL-142": {
        "looks_for": "A 4688 record showing execution from a suspicious directory.",
        "benign": "Installers again — check whether the process is still running.",
        "next_step": "Historical evidence: the file may already be gone. The command line in the event is what survives.",
    },
    "DGL-146": {
        "looks_for": "A parent-child pair in historical 4688 records that does not occur normally.",
        "benign": "Some management tooling produces odd-looking chains.",
        "next_step": "Same weight as the live process finding, except the process has already exited. The timestamp anchors the intrusion.",
    },
    "DGL-152": {
        "looks_for": "Evidence of a PowerShell Remoting session.",
        "benign": "Standard practice in estates that manage servers remotely.",
        "next_step": "Check the source host and account. Remoting from an unexpected workstation is lateral movement.",
    },
    "DGL-161": {
        "looks_for": "Logon type 8, where the password crossed the network in clear text.",
        "benign": "Some legacy applications and basic-auth IIS setups produce it.",
        "next_step": "Assume that password is known to anyone who was watching the wire. Rotate it.",
    },
    "DGL-162": {
        "looks_for": "An RDP session originating outside private address space.",
        "benign": "Only if RDP is deliberately internet-facing, which is its own problem.",
        "next_step": "Internet-exposed RDP is among the most common initial access vectors. Check the account and what it did next.",
    },
    "DGL-163": {
        "looks_for": "A volume of 4625 failures from one source, shaped as spraying or brute force.",
        "benign": "A misconfigured service with stale credentials produces this too.",
        "next_step": "Look for a success from the same source afterwards. That is DGL-164 and it changes everything.",
    },
    "DGL-165": {
        "looks_for": "Event 4648, a logon using credentials typed explicitly rather than the current session's.",
        "benign": "Administrators using runas produce this legitimately.",
        "next_step": "One of the most reliable lateral movement indicators. The event names both the source and the target.",
    },
    "DGL-166": {
        "looks_for": "An interactive logon between midnight and 5am UTC.",
        "benign": "Shift work, overseas teams and scheduled maintenance.",
        "next_step": "Weigh against the account's normal pattern rather than the clock alone.",
    },
    "DGL-171": {
        "looks_for": "A member added to a privileged group.",
        "benign": "Routine administration, if it matches a change record.",
        "next_step": "The event names who made the change. Privilege escalation and persistence both look like this.",
    },
    "DGL-173": {
        "looks_for": "Event 4697, a service installed as recorded by the Security log.",
        "benign": "Software installs create services.",
        "next_step": "Cross-check against 7045 in the System log. Attackers sometimes clear one and not the other.",
    },
    "DGL-180": {
        "looks_for": "Event 7045, a new service installed.",
        "benign": "Normal during software deployment.",
        "next_step": "Read the image path and service name. This event is the single best record of PsExec-style lateral movement.",
    },
    "DGL-181": {
        "looks_for": "A newly installed service whose name scores as randomly generated.",
        "benign": "Some vendors use hashed service names; known Windows services are excluded.",
        "next_step": "Cobalt Strike's SMB beacon installs exactly this way. Treat as confirmed until proven otherwise.",
    },
    "DGL-183": {
        "looks_for": "A security service's start type being changed.",
        "benign": "Legitimate when swapping security products.",
        "next_step": "Set to disabled means it will not come back after reboot. Find who changed it.",
    },
    "DGL-184": {
        "looks_for": "A security service stopping outside a shutdown.",
        "benign": "Crashes happen, particularly during updates.",
        "next_step": "Check what ran in the minutes that followed. Stopping protection is preparation, not an end in itself.",
    },
    "DGL-185": {
        "looks_for": "System event 104, written when a log is cleared.",
        "benign": "Log rotation does not produce this. Deliberate clearing does.",
        "next_step": "The event names the account and the channel. Everything missing from that channel is now unprovable.",
    },
    "DGL-190": {
        "looks_for": "RDP event 1149 with a source address outside private ranges.",
        "benign": "Only where RDP is intentionally exposed.",
        "next_step": "The event carries the username. Check whether that account should be reaching this host at all.",
    },
    "DGL-192": {
        "looks_for": "WinRM authentication events.",
        "benign": "Standard in estates managed with PowerShell Remoting or Ansible.",
        "next_step": "Check the source. WinRM from a workstation that does not normally manage servers is lateral movement.",
    },
    "DGL-201": {
        "looks_for": "WMI-Activity event 5861, a permanent event subscription being registered.",
        "benign": "SCCM and some monitoring agents register subscriptions.",
        "next_step": "This is direct evidence of WMI persistence, recorded by Windows itself. Read the consumer it names.",
    },
    "DGL-203": {
        "looks_for": "A file transferred over BITS.",
        "benign": "Windows Update uses BITS for everything.",
        "next_step": "Check the URL. Attackers use BITS precisely because it looks like Windows Update.",
    },
    "DGL-204": {
        "looks_for": "CodeIntegrity refusing to load an unsigned driver or image.",
        "benign": "Occurs with test-signed and older drivers.",
        "next_step": "The trace of a failed BYOVD attempt. Identify the file it blocked.",
    },
    "DGL-205": {
        "looks_for": "A firewall rule being added or changed.",
        "benign": "Software installs add rules routinely.",
        "next_step": "Match against the binary the rule refers to. A new inbound allow for an unknown program is a backdoor being made reachable.",
    },
    "DGL-211": {
        "looks_for": "Sysmon event 8, a thread created in another process.",
        "benign": "Some debuggers, injection-based security tools and older software do this.",
        "next_step": "Check the source and target images. Injection into lsass.exe or a browser is the pattern that matters.",
    },
    "DGL-212": {
        "looks_for": "Sysmon recording the creation of a pipe matching C2 naming.",
        "benign": "The patterns are framework defaults, not general pipe names.",
        "next_step": "Sysmon names the creating process, which the live pipe listing cannot always do.",
    },
    "DGL-213": {
        "looks_for": "Sysmon event 25, where a running image no longer matches its file on disk.",
        "benign": "Effectively never legitimate.",
        "next_step": "Process hollowing or herpaderping: the process is not running the code its path claims. Treat as confirmed malware.",
    },
    "DGL-214": {
        "looks_for": "Sysmon events 19 to 21, WMI filter and consumer registration.",
        "benign": "Same caveat as other WMI findings: management tooling does register subscriptions.",
        "next_step": "Sysmon captures the full consumer definition, which is usually more readable than the WMI repository dump.",
    },
    "DGL-221": {
        "looks_for": "A TGT requested for an account with pre-authentication disabled.",
        "benign": "Some legacy integrations require it.",
        "next_step": "These accounts can be cracked offline without a single failed logon. Re-enable pre-auth or rotate the password.",
    },
    "DGL-222": {
        "looks_for": "A TGT issued with RC4 rather than AES.",
        "benign": "Older domain functional levels and legacy clients still negotiate RC4.",
        "next_step": "Overpass-the-hash produces RC4 tickets. Correlate with logon type 9 on the same account.",
    },
    "DGL-223": {
        "looks_for": "A volume of 4771 Kerberos pre-authentication failures.",
        "benign": "A service account with a stale password produces a steady stream.",
        "next_step": "Many accounts from one source is spraying; one account from many sources is brute force. The shape tells you which.",
    },

    # --- Files and artifacts ----------------------------------------------
    "DGL-230": {
        "looks_for": "An executable written into a suspicious directory inside the analysis window.",
        "benign": "Installers stage binaries in temp while working.",
        "next_step": "Check the signature and whether anything has executed it. Prefetch will tell you.",
    },
    "DGL-231": {
        "looks_for": "A Zone.Identifier stream showing the file came from the internet.",
        "benign": "Any file a user downloaded legitimately carries this.",
        "next_step": "The stream holds the source URL. That URL is often the most useful indicator in the whole report.",
    },
    "DGL-261": {
        "looks_for": "An encoded command found in PSReadLine console history and decoded.",
        "benign": "Some tooling encodes commands routinely.",
        "next_step": "Console history survives reboots and is per-user. The decoded text names what was actually run and by whom.",
    },
    "DGL-262": {
        "looks_for": "Registry records of RDP connections made from this host.",
        "benign": "Normal on an administrator's workstation or a jump box.",
        "next_step": "This is the spread map. Each destination is a host to collect from next.",
    },
    "DGL-263": {
        "looks_for": "An empty or absent Prefetch directory on a workstation.",
        "benign": "Prefetch is disabled on SSDs in some builds, and on most servers by default.",
        "next_step": "If it should be enabled, its absence means execution evidence was deleted.",
    },
    "DGL-264": {
        "looks_for": "A Prefetch entry showing a suspicious program ran inside the analysis window.",
        "benign": "Administrators run some of these tools legitimately.",
        "next_step": "Prefetch proves execution even when the binary is gone. The first-run timestamp anchors the intrusion.",
    },
    "DGL-270": {
        "looks_for": "A self-signed certificate in the trusted root store that is not a known CA.",
        "benign": "Corporate TLS inspection appliances install their own root, legitimately.",
        "next_step": "Verify it is yours. A rogue root enables both traffic interception and code signing forgery.",
    },
    "DGL-113": {
        "looks_for": "A Defender threat detection, with its remediation outcome.",
        "benign": "A detection that was cleaned is Defender working as intended.",
        "next_step": "A detection that could NOT be remediated is the one that matters: the file is still there and Defender could not remove it.",
    },
    "DGL-143": {
        "looks_for": "An attacker command-line pattern inside a historical 4688 record.",
        "benign": "Administrators run some of these commands legitimately.",
        "next_step": "The process has already exited; the command line is what survives. Check the account and the parent.",
    },
    "DGL-145": {
        "looks_for": "A base64 payload found inside a 4688 command line and decoded.",
        "benign": "Some management tooling encodes routinely.",
        "next_step": "Read the decoded text in the evidence. It usually names the second stage and where it came from.",
    },
    "DGL-151": {
        "looks_for": "An attacker pattern inside a PowerShell 4104 script block.",
        "benign": "Legitimate administrative scripts can contain matching text.",
        "next_step": "Script block logging captures the full body. Read it rather than judging on the pattern alone.",
    },
    "DGL-170": {
        "looks_for": "An account created, enabled, deleted or its password reset.",
        "benign": "Routine administration when it matches a change record.",
        "next_step": "The event names both the target account and who acted. Account creation is a common persistence step.",
    },
    "DGL-174": {
        "looks_for": "A change to audit policy or another security setting.",
        "benign": "Hardening projects produce these legitimately.",
        "next_step": "Check the direction of the change. Auditing being turned off is preparation for something.",
    },
    "DGL-175": {
        "looks_for": "Security events 4698 and 4702, a scheduled task created or updated.",
        "benign": "Software installs create tasks.",
        "next_step": "The event names the account. Compare with the task definitions in 06_scheduled_tasks.csv.",
    },
    "DGL-182": {
        "looks_for": "A service start type changed, recorded in the System log.",
        "benign": "Normal during maintenance and software installation.",
        "next_step": "Matters most for security services. Check what the new start type is.",
    },
    "DGL-200": {
        "looks_for": "TaskScheduler events 106 and 140, a task registered or updated.",
        "benign": "Normal during software installation.",
        "next_step": "This channel records the acting user, which the task XML does not always preserve.",
    },
    "DGL-202": {
        "looks_for": "Defender reporting its own protection being disabled or altered.",
        "benign": "Occurs legitimately when another security product takes over.",
        "next_step": "Defender recording its own shutdown is a strong signal. Check what ran immediately afterwards.",
    },
    "DGL-260": {
        "looks_for": "An attacker pattern in PSReadLine console history.",
        "benign": "Administrators type some of these commands.",
        "next_step": "History is per-user and survives reboots, so it attributes the command to a person rather than a process.",
    },
    "DGL-IOC": {
        "looks_for": "A direct match against the indicator list supplied with the hunt.",
        "benign": "Only if the indicator itself is wrong — a hash of a common file, or a shared hosting address.",
        "next_step": "Treat according to the indicator's provenance. A hash match is near-certain; an IP match may be shared infrastructure.",
    },
}

# Fallback guidance by rule family, so a rule without a specific entry still
# tells the analyst something more than its title.
FAMILY_HINTS: dict[tuple[int, int], str] = {
    (1, 19): "Host, service and collection-scope checks.",
    (20, 39): "Account, group and autorun hygiene.",
    (40, 59): "Process and network behaviour.",
    (60, 79): "Service and scheduled task configuration.",
    (80, 99): "Registry persistence and WMI.",
    (100, 119): "Security tooling posture and logging configuration.",
    (140, 159): "Process creation and PowerShell event evidence.",
    (160, 179): "Authentication and account change events.",
    (180, 199): "Service, RDP and remote management events.",
    (200, 229): "Sysmon, Kerberos and directory service events.",
    (230, 259): "File system, webshell and exfiltration artifacts.",
    (260, 279): "User activity, history and certificate stores.",
}


# ---------------------------------------------------------------------------
# Categories
#
# The rule ids are grouped by number, and that grouping is real — DGL-04x are
# process rules, DGL-08x are registry persistence — but until now it only
# existed in the numbering. A list of 150 rules with no grouping is a list
# nobody tunes: to switch off the noisy half of one area you had to know which
# numbers that area used.
#
# Ranges rather than a per-rule mapping, because the numbering is the
# categorisation. A new rule slotted into its family is categorised the moment
# it gets an id, with nothing else to update.
#
# Every rule falls in exactly one category, and the ranges are contiguous and
# complete — an "Other" bucket appearing in the console would mean this table
# had drifted from the collector, which is worth noticing rather than hiding.
# ---------------------------------------------------------------------------

CATEGORIES: list[dict] = [
    {
        "id": "collection",
        "name": "Collection integrity",
        "range": (0, 29),
        "summary": "Whether this hunt could see what it needed to.",
        "detail": "Log retention, disabled channels, collection caps, missing Sysmon. "
                  "These fire about the sweep itself rather than the host: they tell "
                  "you when a clean result means 'nothing found' and when it means "
                  "'could not look'. Switching them off makes every later result "
                  "harder to trust.",
    },
    {
        "id": "autoruns",
        "name": "Autoruns and startup",
        "range": (30, 39),
        "summary": "Anything that runs on its own at boot or logon.",
        "detail": "Run keys, startup folders and the binaries they point at — "
                  "unsigned, missing, or sitting somewhere they should not. The "
                  "oldest persistence mechanism there is, and still the most used.",
    },
    {
        "id": "process",
        "name": "Processes and network",
        "range": (40, 59),
        "summary": "What is running now, and who it is talking to.",
        "detail": "Live process state: binaries masquerading as system files, "
                  "unsigned executables in user profiles, discovery command "
                  "bursts, tunnelling, and outbound connections from processes "
                  "that have no business making them. Where a live C2 usually "
                  "shows up first.",
    },
    {
        "id": "services",
        "name": "Services and tasks",
        "range": (60, 79),
        "summary": "Service and scheduled task configuration.",
        "detail": "Service binaries outside Program Files, unquoted paths, "
                  "randomly generated service names, tasks running as SYSTEM or "
                  "created inside the analysis window. Cobalt Strike's SMB "
                  "beacon installs itself here.",
    },
    {
        "id": "registry",
        "name": "Persistence mechanisms",
        "range": (80, 99),
        "summary": "Things arranged to come back, that are not a program.",
        "detail": "On Windows: Winlogon, AppInit_DLLs, IFEO debuggers, LSA "
                  "packages, BITS jobs and WMI subscriptions. On Linux: cron, "
                  "systemd units, shell startup files and LD_PRELOAD. Quiet, "
                  "durable, and invisible to a process list on either.",
    },
    {
        "id": "posture",
        "name": "Security posture",
        "range": (100, 129),
        "summary": "Whether the host's own defences are still switched on.",
        "detail": "Defender components disabled, stale signatures, exclusions "
                  "added, AMSI missing, audit categories turned off, shares "
                  "granting Everyone full control. Attackers turn these off "
                  "early, so a change here is often the first move.",
    },
    {
        "id": "drivers",
        "name": "Drivers and kernel",
        "range": (130, 139),
        "summary": "Code running below the operating system.",
        "detail": "Drivers loaded from odd directories, unsigned drivers, and "
                  "drivers written during the window. A malicious driver "
                  "outranks everything else on the host, because it can lie to "
                  "every tool that would find it.",
    },
    {
        "id": "execution",
        "name": "Execution evidence",
        "range": (140, 159),
        "summary": "What ran earlier, from the event log.",
        "detail": "4688 process creation, PowerShell script blocks, decoded "
                  "encoded commands, suspicious parent-child pairs. This is how "
                  "you see what happened before the sweep started, provided the "
                  "logging was there to capture it.",
    },
    {
        "id": "authentication",
        "name": "Authentication and accounts",
        "range": (160, 179),
        "summary": "Who logged in, from where, and what changed.",
        "detail": "RDP from outside private space, brute force and spraying, a "
                  "success following a run of failures, out-of-hours logons, "
                  "privileged group changes. Lateral movement shows here before "
                  "it shows anywhere else.",
    },
    {
        "id": "remote",
        "name": "Remote access",
        "range": (180, 199),
        "summary": "Remote execution and management events.",
        "detail": "7045 service installs, security services stopped, logs "
                  "cleared, inbound and outbound RDP, WinRM authentication. "
                  "Outbound RDP from a server is rarely something a server "
                  "should be doing.",
    },
    {
        "id": "advanced",
        "name": "Sysmon, Kerberos and AD",
        "range": (200, 229),
        "summary": "The evidence you get when the extra logging exists.",
        "detail": "LSASS access, process injection, C2 named pipes, process "
                  "tampering, Kerberoasting, AS-REP roasting, DCSync. The "
                  "highest-fidelity rules in the set, and the ones that stay "
                  "silent without Sysmon or directory-service auditing.",
    },
    {
        "id": "files",
        "name": "Files, webshells and exfiltration",
        "range": (230, 259),
        "summary": "What was written to disk, and what left.",
        "detail": "New executables in suspicious directories, mark-of-the-web "
                  "downloads, timestomping, webshells in web roots, archives "
                  "created inside the window, attacker tooling on disk.",
    },
    {
        "id": "activity",
        "name": "User activity and trust",
        "range": (260, 279),
        "summary": "Traces a person leaves, and what the host trusts.",
        "detail": "Console history, decoded commands from it, RDP connection "
                  "history, Prefetch execution evidence, and unrecognised "
                  "certificates in the trusted root store.",
    },
    {
        "id": "rootkit",
        "name": "Rootkit and memory",
        "range": (280, 299),
        "summary": "Things hiding from the tools that would list them.",
        "detail": "Cross-view process comparisons, services with no registry "
                  "entry, test signing and kernel debugging enabled, unbacked "
                  "executable memory, modules no longer on disk. Expensive to "
                  "run and the only rules that look for something actively "
                  "concealing itself.",
    },
]

# Rules whose id is not a number — currently only the indicator match, which
# belongs with the indicator feeds rather than any detection family.
SPECIAL_CATEGORY = {
    "DGL-IOC": "indicators",
}

CATEGORY_EXTRA = [
    {
        "id": "indicators",
        "name": "Indicator matches",
        "range": None,
        "summary": "A value from your feeds was found on the host.",
        "detail": "Not a heuristic: an address, hash or domain from a feed you "
                  "loaded was seen in live activity on the host. Switching this "
                  "off disables indicator matching entirely, which is almost "
                  "never what anyone wants.",
    },
]


# The Linux collector has its own numbering, and it does not follow the Windows
# one. Reusing the Windows ranges put webshells under "Security posture" and
# missing auth logs under "Drivers and kernel" — categories exist so a family
# can be switched off together, and that is worse than useless when the family
# is wrong. Mapped explicitly instead, onto the same category ids so both
# platforms share one set of groupings.
LINUX_RANGES: list[tuple[int, int, str]] = [
    (0, 0, "collection"),        # install age — scope of what can be seen
    (21, 26, "authentication"),  # passwordless, uid 0, sudoers, privileged groups
    (27, 28, "collection"),      # auditd coverage, per-rule cap notice
    (40, 59, "process"),         # live processes and command lines
    (60, 69, "posture"),         # host configuration
    (70, 79, "registry"),        # cron, systemd, shell startup, LD_PRELOAD
    (80, 89, "remote"),          # ssh, authorized_keys, sshd config
    (90, 99, "drivers"),         # kernel taint and modules
    (100, 109, "files"),         # setuid, immutable attributes
    (110, 119, "files"),         # webshells and WordPress
    (120, 129, "activity"),      # shell history
    (130, 132, "authentication"),
    (133, 139, "collection"),    # unreadable or empty logs
]

def category_for(rule_id: str) -> str:
    """Which category a rule belongs to, from its number.

    The Linux collector numbers its rules DGL-L021, DGL-L120 and so on, using
    the same ranges as the Windows set with an L in front. Reading the digits
    without stripping that prefix made every Linux rule fall through to
    "Collection integrity" — so DGL-L120, a download piped into a shell, was
    filed as a note about whether the sweep could see anything. The whole point
    of the categories is to make a family switchable together, and that is not
    possible when a third of the catalogue is in the wrong one.
    """
    if rule_id in SPECIAL_CATEGORY:
        return SPECIAL_CATEGORY[rule_id]

    tail = rule_id.split("-")[-1] if "-" in rule_id else rule_id
    linux = tail[:1] in ("L", "l")
    digits = tail.lstrip("Ll")
    try:
        number = int(digits)
    except (ValueError, TypeError):
        return "indicators" if "IOC" in rule_id.upper() else "collection"

    if linux:
        for low, high, cat_id in LINUX_RANGES:
            if low <= number <= high:
                return cat_id
        return "collection"

    for cat in CATEGORIES:
        low, high = cat["range"]
        if low <= number <= high:
            return cat["id"]
    return "collection"


def categories() -> list[dict]:
    """Every category, in the order the console should show them."""
    return [
        {k: v for k, v in cat.items() if k != "range"}
        for cat in CATEGORIES
    ] + CATEGORY_EXTRA


def category_name(cat_id: str) -> str:
    for cat in CATEGORIES + CATEGORY_EXTRA:
        if cat["id"] == cat_id:
            return cat["name"]
    return cat_id


def guidance_for(rule_id: str) -> dict[str, str] | None:
    """Return analyst guidance for a rule, or a family hint, or nothing."""
    if not rule_id:
        return None
    if rule_id in CATALOG:
        return CATALOG[rule_id]

    try:
        number = int(rule_id.split("-")[-1])
    except (ValueError, IndexError):
        return None

    for (low, high), hint in FAMILY_HINTS.items():
        if low <= number <= high:
            return {"family": hint}
    return None

# The name each rule reports when it fires. Kept here so the console can show
# what a rule detects before it has ever fired — a catalogue listing 134 rules
# as "(not seen yet)" tells an operator nothing about what the tool checks.
TITLES: dict[str, str] = {
    "DGL-000": "Operating system installed less than 7 days ago",
    "DGL-001": "Service binary sits in a suspicious directory",
    "DGL-002": "System unpatched for 90+ days",
    "DGL-014": "Event log may have been cleared",
    "DGL-015": "Critical event log channel is disabled",
    "DGL-016": "Requested window exceeds log retention",
    "DGL-017": "Sysmon is not installed",
    "DGL-018": "Event collection cap reached - data is incomplete",
    "DGL-019": "File scan limit reached",
    "DGL-020": "Additional volumes present but no known directories matched",
    "DGL-021": "Active account requires no password",
    "DGL-022": "Built-in account is enabled",
    "DGL-023": "Rule reported more findings than are shown",
    "DGL-024": "Unusually large local Administrators group",
    "DGL-025": "Some detections are switched off in the console",
    "DGL-L027": "Execution records are not available on this Linux host",

    # --- Linux collector detections --------------------------------------
    # Taken from the collector itself, so the two cannot drift. Without
    # these the rules screen listed only the Windows set, and a Linux-only
    # estate could not see or switch off the rules actually running on it.
    "DGL-L000": "Operating system installed less than 7 days ago",
    "DGL-L021": "Account has no password",
    "DGL-L022": "Non-root account has uid 0",
    "DGL-L023": "System account has an interactive shell",
    "DGL-L024": "The account database changed inside the analysis window",
    "DGL-L025": "Passwordless sudo is configured",
    "DGL-L026": "Membership of a privileged group",
    "DGL-L028": "Rule reported more findings than are shown",
    "DGL-L040": "Running process whose executable was deleted",
    "DGL-L041": "Process running from a world-writable or temporary directory",
    "DGL-L042": "Base64 decoding in a command line",
    "DGL-L043": "Download piped straight into a shell",
    "DGL-L044": "Reverse shell pattern in a command line",
    "DGL-L045": "Cryptocurrency miner running",
    "DGL-L052": "The hosts file changed inside the analysis window",
    "DGL-L070": "A cron entry changed inside the analysis window",
    "DGL-L071": "Suspicious command in a cron entry",
    "DGL-L072": "A systemd unit was written inside the analysis window",
    "DGL-L073": "A systemd unit runs a binary from a temporary directory",
    "DGL-L074": "A systemd unit runs a shell command rather than a program",
    "DGL-L075": "A shell startup file changed inside the analysis window",
    "DGL-L076": "A shell startup file runs a downloader or shell",
    "DGL-L077": "/etc/ld.so.preload is populated",
    "DGL-L078": "LD_PRELOAD is set in the environment",
    "DGL-L080": "An authorized_keys file changed inside the analysis window",
    "DGL-L081": "An SSH key carries forced options",
    "DGL-L082": "sshd permits root login",
    "DGL-L083": "sshd permits empty passwords",
    "DGL-L084": "The sshd configuration changed inside the analysis window",
    "DGL-L090": "The kernel is tainted",
    "DGL-L100": "setuid binary in a writable location",
    "DGL-L101": "setuid binary created inside the analysis window",
    "DGL-L102": "Immutable attribute set on a file",
    "DGL-L111": "Obfuscated code in a web file",
    "DGL-L112": "New script written into the web root",
    "DGL-L113": "World-writable file in the web root",
    "DGL-L114": "Executable script inside the WordPress uploads directory",
    "DGL-L115": "wp-config.php changed inside the analysis window",
    "DGL-L116": "WordPress $sub file changed inside the analysis window",
    "DGL-L120": "Download piped into a shell, from history",
    "DGL-L121": "Anti-forensic command in shell history",
    "DGL-L122": "Account management command in shell history",
    "DGL-L123": "Reverse shell command in shell history",
    "DGL-L124": "Shell history is redirected to /dev/null",
    "DGL-L130": "Repeated authentication failures from one address",
    "DGL-L131": "Successful login after repeated failures",
    "DGL-L132": "Direct root login over SSH",
    "DGL-L133": "No readable authentication log",
    "DGL-L134": "A log file is empty",
    "DGL-030": "Autorun runs from a suspicious directory",
    "DGL-031": "Unsigned autorun binary",
    "DGL-032": "Autorun target is missing",
    "DGL-033": "Autorun command matches a known-suspicious pattern",
    "DGL-040": "Process running from a suspicious directory",
    "DGL-041": "Unsigned process running from a user profile",
    "DGL-042": "System binary in an unexpected location (masquerading)",
    "DGL-043": "Command line matches a known-suspicious pattern",
    "DGL-044": "Suspicious parent-child process relationship",
    "DGL-045": "Archiving, exfiltration or tunnelling tool running",
    "DGL-046": "Process path could not be read",
    "DGL-047": "Multiple discovery commands running together",
    "DGL-050": "netsh portproxy rule present (tunnelling)",
    "DGL-051": "User proxy AutoConfigURL is set",
    "DGL-052": "Hosts file modified inside the analysis window",
    "DGL-053": "Suspicious process talking to an external address (possible C2)",
    "DGL-054": "Unsigned process communicating with an external address",
    "DGL-055": "Suspicious process listening on all interfaces (backdoor)",
    "DGL-056": "Firewall profile disabled",
    "DGL-057": "Firewall rule allows inbound traffic to a suspicious binary",
    "DGL-060": "Service binary is unsigned",
    "DGL-061": "Unquoted service path (binary hijack risk)",
    "DGL-062": "Service binary changed inside the analysis window",
    "DGL-063": "Service name looks randomly generated",
    "DGL-064": "Remote execution service detected",
    "DGL-065": "Service path contains a suspicious command",
    "DGL-070": "Scheduled task runs from a suspicious directory",
    "DGL-071": "Task defined at the root of the task library",
    "DGL-072": "Scheduled task runs an unsigned binary",
    "DGL-073": "Non-Microsoft task runs as SYSTEM",
    "DGL-074": "Scheduled task command matches a suspicious pattern",
    "DGL-075": "Scheduled task created inside the analysis window",
    "DGL-080": "A Winlogon value was modified inside the window",
    "DGL-081": "AppInit_DLLs is set",
    "DGL-082": "IFEO Debugger is set",
    "DGL-083": "SilentProcessExit MonitorProcess is set",
    "DGL-084": "Unknown entry in the LSA package list",
    "DGL-085": "AppCertDlls entry present",
    "DGL-086": "Non-standard Time Provider DLL",
    "DGL-087": "UserInitMprLogonScript is set",
    "DGL-088": "BITS transfer job present",
    "DGL-089": "A Winlogon persistence value is set",
    "DGL-090": "WMI permanent event subscription present",
    "DGL-091": "WMI event consumer runs a suspicious command",
    "DGL-100": "Named pipe matches a known C2 pattern",
    "DGL-110": "Defender protection component disabled",
    "DGL-111": "Defender signatures are out of date",
    "DGL-112": "Defender exclusion configured",
    "DGL-113": "Defender threat detection",
    "DGL-114": "Security setting weakened",
    "DGL-115": "No AMSI provider registered",
    "DGL-116": "Critical audit category is disabled",
    "DGL-117": "No shadow copies found",
    "DGL-120": "Share grants Everyone full control",
    "DGL-121": "Drive root is shared",
    "DGL-130": "Driver loaded from a suspicious directory",
    "DGL-131": "Unsigned driver loaded",
    "DGL-132": "Driver written inside the analysis window",
    "DGL-140": "No process creation auditing (4688) recorded",
    "DGL-141": "4688 events carry no command line",
    "DGL-142": "Process previously executed from a suspicious directory",
    "DGL-143": "Suspicious command in a historical process record",
    "DGL-144": "Encoded PowerShell command decoded",
    "DGL-145": "Suspicious command inside a decoded payload",
    "DGL-146": "Suspicious parent-child pair in event history",
    "DGL-150": "PowerShell flagged the script block as suspicious",
    "DGL-151": "Suspicious command in a PowerShell script block",
    "DGL-152": "PowerShell Remoting session detected",
    "DGL-160": "Logon Type 9 (NewCredentials/RunAs) detected",
    "DGL-161": "Logon Type 8 (NetworkCleartext)",
    "DGL-162": "RDP session from outside private address space",
    "DGL-163": "Brute force or password spraying suspected",
    "DGL-164": "SUCCESSFUL logon after repeated failures",
    "DGL-165": "Remote access using explicit credentials",
    "DGL-166": "Out-of-hours interactive logon (00:00-05:00 UTC)",
    "DGL-170": "Account created, changed or removed",
    "DGL-171": "Member added to a privileged group",
    "DGL-172": "Anti-forensic activity recorded",
    "DGL-173": "Service installation recorded (4697)",
    "DGL-174": "Suspicious command in a service installation event",
    "DGL-175": "Scheduled task created or updated",
    "DGL-180": "New service installed (7045)",
    "DGL-181": "Service installed with a random name",
    "DGL-182": "Suspicious command in a new service path",
    "DGL-183": "Security service start type was changed",
    "DGL-184": "Security service stopped unexpectedly",
    "DGL-185": "Event log cleared (System 104)",
    "DGL-190": "RDP connection from outside private address space (1149)",
    "DGL-191": "OUTBOUND RDP connection from this host",
    "DGL-192": "WinRM authentication",
    "DGL-200": "Scheduled task registered or updated",
    "DGL-201": "WMI permanent event subscription recorded (5861)",
    "DGL-202": "Defender protection changed",
    "DGL-203": "File transferred over BITS",
    "DGL-204": "Code integrity violation (unsigned driver or image)",
    "DGL-205": "Firewall rule added or changed inside the window",
    "DGL-210": "Access to LSASS memory (credential dump)",
    "DGL-211": "CreateRemoteThread (process injection)",
    "DGL-212": "Named pipe matching a C2 pattern was created",
    "DGL-213": "Process tampering (hollowing / herpaderping)",
    "DGL-214": "Sysmon WMI event record (persistence)",
    "DGL-220": "Kerberoasting suspected (RC4 service ticket volume)",
    "DGL-221": "TGT requested without pre-authentication (AS-REP roast)",
    "DGL-222": "TGT issued with RC4 (encryption downgrade)",
    "DGL-223": "Kerberos password guessing (4771 volume)",
    "DGL-224": "DCSync attempt (directory replication right used)",
    "DGL-230": "New executable in a suspicious directory",
    "DGL-231": "File downloaded from the internet (MOTW)",
    "DGL-232": "Timestamp manipulation suspected",
    "DGL-240": "Webshell pattern found in a web-served file",
    "DGL-241": "New file written to the web root inside the analysis window",
    "DGL-250": "Archive created inside the analysis window",
    "DGL-251": "Attacker or remote access tool found on disk",
    "DGL-260": "Suspicious command in console history",
    "DGL-261": "Encoded command decoded from console history",
    "DGL-262": "RDP connection history on this host",
    "DGL-263": "No Prefetch entries present",
    "DGL-264": "Suspicious program executed inside the analysis window (Prefetch)",
    "DGL-270": "Unrecognised certificate in the trusted root store",
    "DGL-280": "Processes visible to the API but not to WMI",
    "DGL-281": "Processes visible to WMI but not to the API",
    "DGL-282": "Service running with no registry entry",
    "DGL-283": "Driver test signing is enabled",
    "DGL-284": "Kernel integrity checks are disabled",
    "DGL-285": "Kernel debugging is enabled",
    "DGL-286": "Unsigned non-Microsoft driver is loaded",
    "DGL-287": "Service points at a binary that is not there",
    "DGL-288": "Rootkit checks are cross-view only",
    "DGL-289": "External endpoints contacted by this host",
    "DGL-290": "Writable and executable private memory in a process",
    "DGL-291": "Process in a suspicious directory holds unbacked executable memory",
    "DGL-292": "Unusually large unbacked executable memory",
    "DGL-293": "Loaded module is no longer on disk",
    "DGL-294": "Memory inspection is region-level only",
    "DGL-299": "In-memory inspection could not run",
    # Was copied out of the collector with its PowerShell interpolation intact,
    # so the rules list showed "IOC match ($($Script:Iocs[$k]))". The live
    # finding carries the feed name in its own title; this is the catalogue
    # entry, which has to read as a sentence on its own.
    "DGL-IOC": "A value from your indicator feeds was found on the host",
}


def title_for(rule_id: str) -> str:
    return TITLES.get(rule_id, "")
