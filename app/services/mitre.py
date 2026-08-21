"""MITRE ATT&CK mapping for the techniques Douglas-042 can detect.

Deliberately a static table rather than a live fetch: incident response happens
on isolated networks, and a matrix that only renders when the console has
internet is a matrix that is missing exactly when it matters.

Only the techniques this tool actually emits are listed. Showing the full
enterprise matrix with 600 empty cells would bury the handful that fired.
"""
from __future__ import annotations

from collections import Counter

# Ordered as the ATT&CK matrix is read, left to right.
TACTIC_ORDER = [
    ("reconnaissance", "Reconnaissance"),
    ("resource-development", "Resource Development"),
    ("initial-access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege-escalation", "Privilege Escalation"),
    ("defense-evasion", "Defense Evasion"),
    ("credential-access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral-movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("command-and-control", "Command & Control"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
]

# technique id -> (name, [tactics])
TECHNIQUES: dict[str, tuple[str, list[str]]] = {
    "T1003": ("OS Credential Dumping", ["credential-access"]),
    "T1003.001": ("LSASS Memory", ["credential-access"]),
    "T1003.002": ("Security Account Manager", ["credential-access"]),
    "T1005": ("Data from Local System", ["collection"]),
    "T1007": ("System Service Discovery", ["discovery"]),
    "T1012": ("Query Registry", ["discovery"]),
    "T1016": ("System Network Configuration Discovery", ["discovery"]),
    "T1018": ("Remote System Discovery", ["discovery"]),
    "T1021": ("Remote Services", ["lateral-movement"]),
    "T1021.001": ("Remote Desktop Protocol", ["lateral-movement"]),
    "T1021.002": ("SMB / Windows Admin Shares", ["lateral-movement"]),
    "T1021.006": ("Windows Remote Management", ["lateral-movement"]),
    "T1027": ("Obfuscated Files or Information", ["defense-evasion"]),
    "T1027.005": ("Indicator Removal from Tools", ["defense-evasion"]),
    "T1033": ("System Owner/User Discovery", ["discovery"]),
    "T1036": ("Masquerading", ["defense-evasion"]),
    "T1036.005": ("Match Legitimate Name or Location", ["defense-evasion"]),
    "T1037": ("Boot or Logon Initialization Scripts",
              ["persistence", "privilege-escalation"]),
    "T1037.001": ("Logon Script (Windows)", ["persistence", "privilege-escalation"]),
    "T1046": ("Network Service Discovery", ["discovery"]),
    "T1047": ("Windows Management Instrumentation", ["execution"]),
    "T1048": ("Exfiltration Over Alternative Protocol", ["exfiltration"]),
    "T1053": ("Scheduled Task/Job", ["execution", "persistence", "privilege-escalation"]),
    "T1053.005": ("Scheduled Task", ["execution", "persistence", "privilege-escalation"]),
    "T1055": ("Process Injection", ["defense-evasion", "privilege-escalation"]),
    "T1055.012": ("Process Hollowing", ["defense-evasion", "privilege-escalation"]),
    "T1056": ("Input Capture", ["collection", "credential-access"]),
    "T1057": ("Process Discovery", ["discovery"]),
    "T1059": ("Command and Scripting Interpreter", ["execution"]),
    "T1059.001": ("PowerShell", ["execution"]),
    "T1059.003": ("Windows Command Shell", ["execution"]),
    "T1068": ("Exploitation for Privilege Escalation", ["privilege-escalation"]),
    "T1069": ("Permission Groups Discovery", ["discovery"]),
    "T1070": ("Indicator Removal", ["defense-evasion"]),
    "T1070.001": ("Clear Windows Event Logs", ["defense-evasion"]),
    "T1070.004": ("File Deletion", ["defense-evasion"]),
    "T1070.006": ("Timestomp", ["defense-evasion"]),
    "T1071": ("Application Layer Protocol", ["command-and-control"]),
    "T1071.001": ("Web Protocols", ["command-and-control"]),
    "T1074": ("Data Staged", ["collection"]),
    "T1078": ("Valid Accounts", ["defense-evasion", "persistence",
                                 "privilege-escalation", "initial-access"]),
    "T1078.001": ("Default Accounts", ["defense-evasion", "persistence",
                                       "privilege-escalation", "initial-access"]),
    "T1078.002": ("Domain Accounts", ["defense-evasion", "persistence",
                                      "privilege-escalation", "initial-access"]),
    "T1078.003": ("Local Accounts", ["defense-evasion", "persistence",
                                     "privilege-escalation", "initial-access"]),
    "T1082": ("System Information Discovery", ["discovery"]),
    "T1087": ("Account Discovery", ["discovery"]),
    "T1090": ("Proxy", ["command-and-control"]),
    "T1090.001": ("Internal Proxy", ["command-and-control"]),
    "T1098": ("Account Manipulation", ["persistence", "privilege-escalation"]),
    "T1105": ("Ingress Tool Transfer", ["command-and-control"]),
    "T1110": ("Brute Force", ["credential-access"]),
    "T1110.003": ("Password Spraying", ["credential-access"]),
    "T1112": ("Modify Registry", ["defense-evasion"]),
    "T1133": ("External Remote Services", ["initial-access", "persistence"]),
    "T1134": ("Access Token Manipulation", ["defense-evasion", "privilege-escalation"]),
    "T1135": ("Network Share Discovery", ["discovery"]),
    "T1136": ("Create Account", ["persistence"]),
    "T1136.001": ("Local Account", ["persistence"]),
    "T1140": ("Deobfuscate/Decode Files or Information", ["defense-evasion"]),
    "T1190": ("Exploit Public-Facing Application", ["initial-access"]),
    "T1197": ("BITS Jobs", ["defense-evasion", "persistence"]),
    "T1204": ("User Execution", ["execution"]),
    "T1210": ("Exploitation of Remote Services", ["lateral-movement"]),
    "T1218": ("System Binary Proxy Execution", ["defense-evasion"]),
    "T1218.011": ("Rundll32", ["defense-evasion"]),
    "T1219": ("Remote Access Software", ["command-and-control"]),
    "T1484": ("Domain Policy Modification", ["defense-evasion", "privilege-escalation"]),
    "T1489": ("Service Stop", ["impact"]),
    "T1490": ("Inhibit System Recovery", ["impact"]),
    "T1505": ("Server Software Component", ["persistence"]),
    "T1505.003": ("Web Shell", ["persistence"]),
    "T1543": ("Create or Modify System Process", ["persistence", "privilege-escalation"]),
    "T1543.003": ("Windows Service", ["persistence", "privilege-escalation"]),
    "T1546": ("Event Triggered Execution", ["persistence", "privilege-escalation"]),
    "T1546.003": ("WMI Event Subscription", ["persistence", "privilege-escalation"]),
    "T1546.008": ("Accessibility Features", ["persistence", "privilege-escalation"]),
    "T1546.009": ("AppCert DLLs", ["persistence", "privilege-escalation"]),
    "T1546.010": ("AppInit DLLs", ["persistence", "privilege-escalation"]),
    "T1546.012": ("Image File Execution Options Injection",
                  ["persistence", "privilege-escalation"]),
    "T1547": ("Boot or Logon Autostart Execution", ["persistence", "privilege-escalation"]),
    "T1547.001": ("Registry Run Keys / Startup Folder",
                  ["persistence", "privilege-escalation"]),
    "T1547.002": ("Authentication Package", ["persistence", "privilege-escalation"]),
    "T1547.003": ("Time Providers", ["persistence", "privilege-escalation"]),
    "T1547.004": ("Winlogon Helper DLL", ["persistence", "privilege-escalation"]),
    "T1547.005": ("Security Support Provider", ["persistence", "privilege-escalation"]),
    "T1548": ("Abuse Elevation Control Mechanism",
              ["defense-evasion", "privilege-escalation"]),
    "T1550": ("Use Alternate Authentication Material",
              ["defense-evasion", "lateral-movement"]),
    "T1550.002": ("Pass the Hash", ["defense-evasion", "lateral-movement"]),
    "T1552": ("Unsecured Credentials", ["credential-access"]),
    "T1552.002": ("Credentials in Registry", ["credential-access"]),
    "T1553": ("Subvert Trust Controls", ["defense-evasion"]),
    "T1553.004": ("Install Root Certificate", ["defense-evasion"]),
    "T1555": ("Credentials from Password Stores", ["credential-access"]),
    "T1557": ("Adversary-in-the-Middle", ["credential-access", "collection"]),
    "T1558": ("Steal or Forge Kerberos Tickets", ["credential-access"]),
    "T1558.003": ("Kerberoasting", ["credential-access"]),
    "T1558.004": ("AS-REP Roasting", ["credential-access"]),
    "T1560": ("Archive Collected Data", ["collection"]),
    "T1562": ("Impair Defenses", ["defense-evasion"]),
    "T1562.001": ("Disable or Modify Tools", ["defense-evasion"]),
    "T1562.002": ("Disable Windows Event Logging", ["defense-evasion"]),
    "T1562.004": ("Disable or Modify System Firewall", ["defense-evasion"]),
    "T1563": ("Remote Service Session Hijacking", ["lateral-movement"]),
    "T1564": ("Hide Artifacts", ["defense-evasion"]),
    "T1565": ("Data Manipulation", ["impact"]),
    "T1565.001": ("Stored Data Manipulation", ["impact"]),
    "T1569": ("System Services", ["execution"]),
    "T1569.002": ("Service Execution", ["execution"]),
    "T1571": ("Non-Standard Port", ["command-and-control"]),
    "T1572": ("Protocol Tunneling", ["command-and-control"]),
    "T1574": ("Hijack Execution Flow", ["defense-evasion", "persistence",
                                        "privilege-escalation"]),
    "T1574.009": ("Path Interception by Unquoted Path",
                  ["defense-evasion", "persistence", "privilege-escalation"]),
    "T1574.011": ("Services Registry Permissions Weakness",
                  ["defense-evasion", "persistence", "privilege-escalation"]),
    "T1614": ("System Location Discovery", ["discovery"]),
    "T1620": ("Reflective Code Loading", ["defense-evasion"]),
    # --- Techniques the community Sigma ruleset references ------------------
    # Added so a rule's finding shows a name rather than a bare number, and so
    # it lands in the right matrix column instead of the unmapped bucket.
    "T1040": ("Network Sniffing", ["credential-access", "discovery"]),
    "T1049": ("System Network Connections Discovery", ["discovery"]),
    "T1052": ("Exfiltration Over Physical Medium", ["exfiltration"]),
    "T1052.001": ("Exfiltration over USB", ["exfiltration"]),
    "T1056.001": ("Keylogging", ["collection", "credential-access"]),
    "T1071.004": ("DNS", ["command-and-control"]),
    "T1072": ("Software Deployment Tools", ["execution", "lateral-movement"]),
    "T1080": ("Taint Shared Content", ["lateral-movement"]),
    "T1083": ("File and Directory Discovery", ["discovery"]),
    "T1091": ("Replication Through Removable Media",
              ["initial-access", "lateral-movement"]),
    "T1095": ("Non-Application Layer Protocol", ["command-and-control"]),
    "T1102": ("Web Service", ["command-and-control"]),
    "T1104": ("Multi-Stage Channels", ["command-and-control"]),
    "T1106": ("Native API", ["execution"]),
    "T1113": ("Screen Capture", ["collection"]),
    "T1114": ("Email Collection", ["collection"]),
    "T1115": ("Clipboard Data", ["collection"]),
    "T1119": ("Automated Collection", ["collection"]),
    "T1120": ("Peripheral Device Discovery", ["discovery"]),
    "T1123": ("Audio Capture", ["collection"]),
    "T1124": ("System Time Discovery", ["discovery"]),
    "T1125": ("Video Capture", ["collection"]),
    "T1127": ("Trusted Developer Utilities Proxy Execution", ["defense-evasion"]),
    "T1127.001": ("MSBuild", ["defense-evasion"]),
    "T1129": ("Shared Modules", ["execution"]),
    "T1137": ("Office Application Startup", ["persistence"]),
    "T1137.006": ("Add-ins", ["persistence"]),
    "T1176": ("Browser Extensions", ["persistence"]),
    "T1187": ("Forced Authentication", ["credential-access"]),
    "T1195": ("Supply Chain Compromise", ["initial-access"]),
    "T1200": ("Hardware Additions", ["initial-access"]),
    "T1201": ("Password Policy Discovery", ["discovery"]),
    "T1202": ("Indirect Command Execution", ["defense-evasion"]),
    "T1203": ("Exploitation for Client Execution", ["execution"]),
    "T1207": ("Rogue Domain Controller", ["defense-evasion"]),
    "T1211": ("Exploitation for Defense Evasion", ["defense-evasion"]),
    "T1212": ("Exploitation for Credential Access", ["credential-access"]),
    "T1213": ("Data from Information Repositories", ["collection"]),
    "T1216": ("System Script Proxy Execution", ["defense-evasion"]),
    "T1216.001": ("PubPrn", ["defense-evasion"]),
    "T1217": ("Browser Information Discovery", ["discovery"]),
    "T1220": ("XSL Script Processing", ["defense-evasion"]),
    "T1221": ("Template Injection", ["defense-evasion"]),
    "T1222": ("File and Directory Permissions Modification", ["defense-evasion"]),
    "T1482": ("Domain Trust Discovery", ["discovery"]),
    "T1485": ("Data Destruction", ["impact"]),
    "T1486": ("Data Encrypted for Impact", ["impact"]),
    "T1491": ("Defacement", ["impact"]),
    "T1495": ("Firmware Corruption", ["impact"]),
    "T1496": ("Resource Hijacking", ["impact"]),
    "T1497": ("Virtualization/Sandbox Evasion", ["defense-evasion", "discovery"]),
    "T1498": ("Network Denial of Service", ["impact"]),
    "T1499": ("Endpoint Denial of Service", ["impact"]),
    "T1518": ("Software Discovery", ["discovery"]),
    "T1518.001": ("Security Software Discovery", ["discovery"]),
    "T1526": ("Cloud Service Discovery", ["discovery"]),
    "T1528": ("Steal Application Access Token", ["credential-access"]),
    "T1529": ("System Shutdown/Reboot", ["impact"]),
    "T1539": ("Steal Web Session Cookie", ["credential-access"]),
    "T1542": ("Pre-OS Boot", ["defense-evasion", "persistence"]),
    "T1542.003": ("Bootkit", ["defense-evasion", "persistence"]),
    "T1547.006": ("Kernel Modules and Extensions", ["persistence", "privilege-escalation"]),
    "T1547.009": ("Shortcut Modification", ["persistence", "privilege-escalation"]),
    "T1547.014": ("Active Setup", ["persistence", "privilege-escalation"]),
    "T1548.002": ("Bypass User Account Control",
                  ["defense-evasion", "privilege-escalation"]),
    "T1552.001": ("Credentials In Files", ["credential-access"]),
    "T1552.004": ("Private Keys", ["credential-access"]),
    "T1552.006": ("Group Policy Preferences", ["credential-access"]),
    "T1553.003": ("SIP and Trust Provider Hijacking", ["defense-evasion"]),
    "T1553.005": ("Mark-of-the-Web Bypass", ["defense-evasion"]),
    "T1555.003": ("Credentials from Web Browsers", ["credential-access"]),
    "T1556": ("Modify Authentication Process",
              ["credential-access", "defense-evasion", "persistence"]),
    "T1559": ("Inter-Process Communication", ["execution"]),
    "T1559.001": ("Component Object Model", ["execution"]),
    "T1561": ("Disk Wipe", ["impact"]),
    "T1562.003": ("Impair Command History Logging", ["defense-evasion"]),
    "T1562.006": ("Indicator Blocking", ["defense-evasion"]),
    "T1564.001": ("Hidden Files and Directories", ["defense-evasion"]),
    "T1564.004": ("NTFS File Attributes", ["defense-evasion"]),
    "T1566": ("Phishing", ["initial-access"]),
    "T1566.001": ("Spearphishing Attachment", ["initial-access"]),
    "T1566.002": ("Spearphishing Link", ["initial-access"]),
    "T1567": ("Exfiltration Over Web Service", ["exfiltration"]),
    "T1567.002": ("Exfiltration to Cloud Storage", ["exfiltration"]),
    "T1568": ("Dynamic Resolution", ["command-and-control"]),
    "T1570": ("Lateral Tool Transfer", ["lateral-movement"]),
    "T1573": ("Encrypted Channel", ["command-and-control"]),
    "T1587": ("Develop Capabilities", ["resource-development"]),
    "T1587.001": ("Malware", ["resource-development"]),
    "T1588": ("Obtain Capabilities", ["resource-development"]),
    "T1588.002": ("Tool", ["resource-development"]),
    "T1608": ("Stage Capabilities", ["resource-development"]),
    "T1611": ("Escape to Host", ["privilege-escalation"]),
    "T1622": ("Debugger Evasion", ["defense-evasion", "discovery"]),
    "T1647": ("Plist File Modification", ["defense-evasion"]),
    "T1649": ("Steal or Forge Authentication Certificates", ["credential-access"]),
    "T1650": ("Acquire Access", ["resource-development"]),
    "T1651": ("Cloud Administration Command", ["execution"]),
    "T1657": ("Financial Theft", ["impact"]),
    # T1685/T1686 are recent additions the community ruleset already uses.
    "T1685": ("Deceptive Content and Interaction", ["initial-access", "execution"]),
    "T1685.001": ("Deceptive Instructions", ["initial-access", "execution"]),
    "T1685.005": ("Deceptive Prompt Injection", ["initial-access", "execution"]),
    "T1686": ("Compromise Software Environment", ["persistence"]),
    "T1686.003": ("Development Tooling", ["persistence"]),
    "T1001": ("Data Obfuscation", ["command-and-control"]),
    "T1001.003": ("Protocol or Service Impersonation", ["command-and-control"]),
    "T1008": ("Fallback Channels", ["command-and-control"]),
    "T1010": ("Application Window Discovery", ["discovery"]),
    "T1020": ("Automated Exfiltration", ["exfiltration"]),
    "T1039": ("Data from Network Shared Drive", ["collection"]),
    "T1041": ("Exfiltration Over C2 Channel", ["exfiltration"]),
    "T1132": ("Data Encoding", ["command-and-control"]),
    "T1132.001": ("Standard Encoding", ["command-and-control"]),
    "T1185": ("Browser Session Hijacking", ["collection"]),
    "T1531": ("Account Access Removal", ["impact"]),
    "T1554": ("Compromise Host Software Binary", ["persistence"]),
    "T1584": ("Compromise Infrastructure", ["resource-development"]),
    "T1590": ("Gather Victim Network Information", ["reconnaissance"]),
    "T1590.001": ("Domain Properties", ["reconnaissance"]),
    "T1593": ("Search Open Websites/Domains", ["reconnaissance"]),
    "T1593.003": ("Code Repositories", ["reconnaissance"]),
    "T1595": ("Active Scanning", ["reconnaissance"]),
    "T1615": ("Group Policy Discovery", ["discovery"]),
    "T1689": ("Abuse Elevation Control Mechanism", ["privilege-escalation"]),
}

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def technique_name(tid: str) -> str:
    if tid in TECHNIQUES:
        return TECHNIQUES[tid][0]
    parent = tid.split(".")[0]
    if parent in TECHNIQUES:
        return TECHNIQUES[parent][0]
    return tid


def _tactics_for(tid: str) -> list[str]:
    if tid in TECHNIQUES:
        return TECHNIQUES[tid][1]
    parent = tid.split(".")[0]
    if parent in TECHNIQUES:
        return TECHNIQUES[parent][1]
    return []


def build_matrix(findings: list[dict]) -> dict:
    """Group findings into ATT&CK tactic columns.

    A technique that belongs to several tactics appears in each of its columns,
    which is how the real matrix works. The count stays attached to the
    technique, so the same number shows in every column it occupies rather than
    being divided between them.
    """
    counts: Counter = Counter()
    worst: dict[str, str] = {}
    hosts: dict[str, set] = {}

    for f in findings:
        tid = (f.get("mitre") or "").strip()
        if not tid or not tid.startswith("T"):
            continue
        counts[tid] += 1
        sev = (f.get("severity") or "INFO").upper()
        if SEV_RANK.get(sev, 0) > SEV_RANK.get(worst.get(tid, "INFO"), 0):
            worst[tid] = sev
        host = f.get("hostname")
        if host:
            hosts.setdefault(tid, set()).add(host)

    columns = []
    placed = set()
    for slug, label in TACTIC_ORDER:
        cells = []
        for tid, count in counts.items():
            if slug in _tactics_for(tid):
                cells.append({
                    "id": tid,
                    "name": technique_name(tid),
                    "description": technique_description(tid),
                    "count": count,
                    "severity": worst.get(tid, "INFO"),
                    "hosts": len(hosts.get(tid, ())),
                })
                placed.add(tid)
        cells.sort(key=lambda c: (-SEV_RANK.get(c["severity"], 0), -c["count"], c["id"]))
        columns.append({
            "slug": slug,
            "tactic": label,
            "techniques": cells,
            "total": sum(c["count"] for c in cells),
        })

    # Techniques we detected but have no tactic mapping for. Better to show
    # them in their own bucket than to drop evidence on the floor.
    unmapped = [
        {
            "id": tid, "name": technique_name(tid), "count": count,
            "severity": worst.get(tid, "INFO"), "hosts": len(hosts.get(tid, ())),
        }
        for tid, count in counts.items() if tid not in placed
    ]
    unmapped.sort(key=lambda c: -c["count"])

    return {
        "columns": columns,
        "unmapped": unmapped,
        "technique_count": len(counts),
        "finding_count": sum(counts.values()),
        "tactics_hit": sum(1 for c in columns if c["techniques"]),
        "tactic_count": len(TACTIC_ORDER),
    }


# What a technique actually means, in a sentence an analyst can read at 3am.
# Written for the techniques this tool emits plus the most common Sigma ones;
# anything else falls back to its name and tactic, which is still better than
# a bare number.
DESCRIPTIONS: dict[str, str] = {
    "T1003": "Stealing credential material from the operating system so accounts can be reused elsewhere.",
    "T1003.001": "Reading LSASS process memory, where Windows keeps credentials for logged-on users.",
    "T1003.002": "Dumping the SAM database to recover local account password hashes.",
    "T1003.003": "Extracting NTDS.dit from a domain controller, which contains every domain password hash.",
    "T1003.006": "Abusing directory replication to pull password hashes without touching the DC's disk.",
    "T1005": "Collecting files from the local system ahead of exfiltration.",
    "T1007": "Listing services to find security products and something worth abusing.",
    "T1012": "Reading the registry to learn about the system and its software.",
    "T1016": "Discovering network configuration to plan movement.",
    "T1018": "Finding other machines on the network to move to next.",
    "T1021": "Logging into other systems with valid credentials, the quiet way to move laterally.",
    "T1021.001": "Moving between machines over Remote Desktop.",
    "T1021.002": "Using SMB and administrative shares (C$, ADMIN$) to reach other systems.",
    "T1021.006": "Using WinRM or PowerShell Remoting to run commands on other machines.",
    "T1027": "Obfuscating code or data so that inspection and signatures do not catch it.",
    "T1033": "Identifying the current user and their privileges.",
    "T1036": "Making a malicious file look legitimate by its name, location or metadata.",
    "T1036.005": "Naming a file after a Windows binary but placing it somewhere Windows never would.",
    "T1046": "Scanning for services on the network to find what can be attacked.",
    "T1047": "Using WMI to execute code, often to run commands on remote machines.",
    "T1048": "Sending stolen data out over a protocol other than the main C2 channel.",
    "T1053": "Scheduling a job so code runs later or repeatedly, surviving reboots.",
    "T1053.005": "Creating a Windows scheduled task for persistence or to run as SYSTEM.",
    "T1055": "Running code inside another process so it inherits that process's trust.",
    "T1055.012": "Replacing a legitimate process's memory with malicious code after it starts.",
    "T1057": "Listing running processes to find security tools and injection targets.",
    "T1059": "Running commands through a shell or scripting interpreter.",
    "T1059.001": "Using PowerShell to execute attacker code, often encoded or downloaded.",
    "T1059.003": "Using cmd.exe to run commands, frequently from another compromised process.",
    "T1068": "Exploiting a flaw to gain higher privileges, including loading a vulnerable driver.",
    "T1069": "Enumerating groups to find which accounts hold administrative rights.",
    "T1070": "Deleting or altering evidence so the intrusion cannot be reconstructed.",
    "T1070.001": "Clearing Windows event logs to destroy the record of what happened.",
    "T1070.004": "Deleting files used during the intrusion.",
    "T1070.006": "Altering file timestamps so malicious files blend into the system's history.",
    "T1071": "Using ordinary application protocols for command and control so traffic looks normal.",
    "T1071.001": "Running command and control over HTTP or HTTPS to blend in with web traffic.",
    "T1074": "Gathering data into one place before taking it out of the network.",
    "T1078": "Using legitimate accounts rather than malware, which defeats most detection.",
    "T1078.001": "Using built-in accounts such as Guest or the local Administrator.",
    "T1078.002": "Using compromised domain accounts to move through the estate.",
    "T1078.003": "Using local accounts on a machine to gain or keep access.",
    "T1082": "Gathering details about the host to decide what to do next.",
    "T1087": "Listing accounts to find targets worth compromising.",
    "T1090": "Routing traffic through an intermediary to hide its real destination.",
    "T1090.001": "Forwarding ports on a compromised host to reach systems behind it.",
    "T1098": "Changing account properties or group membership to keep access.",
    "T1105": "Downloading additional tools or payloads onto a compromised machine.",
    "T1110": "Guessing passwords in volume until one works.",
    "T1110.003": "Trying one common password against many accounts to avoid lockouts.",
    "T1112": "Changing registry values to persist, weaken defences or store data.",
    "T1133": "Using internet-facing remote access such as RDP or VPN to get in and stay in.",
    "T1134": "Manipulating access tokens to act as another user.",
    "T1136": "Creating a new account so access survives password resets.",
    "T1136.001": "Creating a local account on a compromised machine.",
    "T1140": "Decoding or decrypting payloads at runtime to defeat static inspection.",
    "T1190": "Exploiting a vulnerability in an internet-facing application to get initial access.",
    "T1197": "Using the Background Intelligent Transfer Service to download files and persist.",
    "T1204": "Getting a user to run the malicious file themselves.",
    "T1210": "Exploiting a service on another machine to move laterally.",
    "T1218": "Running code through a signed Windows binary so it inherits that binary's trust.",
    "T1218.011": "Using rundll32.exe to execute code from a DLL and evade allow-listing.",
    "T1219": "Installing legitimate remote access software as a durable backdoor.",
    "T1484": "Changing domain or group policy to grant access or weaken controls.",
    "T1489": "Stopping services, usually security products or databases before encryption.",
    "T1490": "Deleting shadow copies and backups so the damage cannot be undone.",
    "T1505": "Adding a component to a server application so it keeps serving the attacker.",
    "T1505.003": "Planting a web shell so commands can be run through the web server.",
    "T1543": "Creating or altering a system process so code runs at boot with high privilege.",
    "T1543.003": "Installing or modifying a Windows service for persistence, often as SYSTEM.",
    "T1546": "Setting a trigger so code runs whenever some ordinary event occurs.",
    "T1546.003": "Binding a WMI event filter to a consumer so code runs with no file on disk.",
    "T1546.008": "Replacing an accessibility binary so it can be launched from the logon screen.",
    "T1546.009": "Registering a DLL that loads into every process created on the system.",
    "T1546.010": "Registering a DLL that loads into every process using user32.dll.",
    "T1546.012": "Setting a debugger on a program so something else runs in its place.",
    "T1547": "Configuring code to run automatically at boot or logon.",
    "T1547.001": "Adding an entry to a Run key or the Startup folder.",
    "T1547.002": "Registering a DLL into LSA, which sees credentials in clear text.",
    "T1547.003": "Registering a DLL with the time service, which runs early and as SYSTEM.",
    "T1547.004": "Modifying Winlogon so code runs at every interactive logon.",
    "T1547.005": "Registering a Security Support Provider that loads into LSASS.",
    "T1548": "Bypassing controls such as UAC to run with higher privileges.",
    "T1550": "Authenticating with stolen material rather than a password.",
    "T1550.002": "Authenticating with a stolen password hash rather than the password.",
    "T1552": "Finding credentials that were left somewhere readable.",
    "T1552.002": "Recovering credentials stored in the registry.",
    "T1553": "Undermining the trust controls that decide what code is allowed to run.",
    "T1553.004": "Installing a root certificate so attacker-signed code and TLS are trusted.",
    "T1555": "Extracting credentials from password managers and stores.",
    "T1557": "Intercepting traffic between two parties to capture or alter it.",
    "T1558": "Forging or stealing Kerberos tickets to authenticate as someone else.",
    "T1558.003": "Requesting service tickets in bulk to crack service account passwords offline.",
    "T1558.004": "Requesting tickets for accounts without pre-authentication to crack them offline.",
    "T1560": "Compressing and often encrypting collected data before taking it out.",
    "T1560.001": "Archiving data with a utility such as rar or 7-Zip, usually with a password.",
    "T1562": "Turning off or weakening security controls so activity is not seen.",
    "T1562.001": "Disabling or reconfiguring antivirus and EDR, commonly with exclusions.",
    "T1562.002": "Disabling Windows event logging so activity leaves no record.",
    "T1562.004": "Disabling the firewall to allow inbound access or outbound C2.",
    "T1563": "Taking over an existing remote session rather than authenticating.",
    "T1564": "Hiding files, windows or accounts so an operator does not notice them.",
    "T1564.003": "Running with a hidden window so the user sees nothing.",
    "T1565.001": "Altering stored data, including the hosts file, to change how the system behaves.",
    "T1569": "Abusing the service control manager to execute code.",
    "T1569.002": "Installing a service to run a command, the mechanism behind PsExec.",
    "T1571": "Using an unusual port for command and control to evade port-based rules.",
    "T1572": "Tunnelling traffic inside another protocol to bypass network controls.",
    "T1574": "Hijacking how a program finds what it loads so attacker code runs instead.",
    "T1574.009": "Exploiting an unquoted service path by placing a binary in a parent directory.",
    "T1574.011": "Abusing weak service registry permissions to change what a service runs.",
    "T1037.001": "Setting a logon script that runs every time the user signs in.",
    "T1135": "Enumerating network shares to find data worth taking.",
    "T1620": "Loading code directly into memory so nothing is written to disk.",
}


def technique_description(tid: str) -> str:
    """One sentence on what the technique is, empty if unknown."""
    if tid in DESCRIPTIONS:
        return DESCRIPTIONS[tid]
    parent = tid.split(".")[0]
    return DESCRIPTIONS.get(parent, "")


def tactics_for(tid: str) -> list[str]:
    """Human-readable tactic names a technique belongs to."""
    slugs = _tactics_for(tid)
    labels = dict(TACTIC_ORDER)
    return [labels[s] for s in slugs if s in labels]


def technique_detail(tid: str) -> dict:
    """Everything the console shows about a technique."""
    tid = (tid or "").strip()
    if not tid:
        return {}
    return {
        "id": tid,
        "name": technique_name(tid),
        "description": technique_description(tid),
        "tactics": tactics_for(tid),
        "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
    }
