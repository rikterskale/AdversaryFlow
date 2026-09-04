"""
Command catalog for AdversaryFlow development labs.

For each ATT&CK technique the catalog provides lab-oriented commands that
exercise related tools, APIs, and artifacts. The catalog is designed for
detection validation in disposable development environments.

Each entry declares a command platform, command, operational note, and optional
cleanup command.

`get_commands()` returns curated commands when available and otherwise a
tactic-aware fallback, so every technique has an explicit catalog result.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .command_safety import command_record, technique_exercise_record


def _c(platform: str, command: str, note: str = "", cleanup: str = "", **metadata: Any) -> Dict[str, Any]:
    return command_record(platform, command, note, cleanup, **metadata)


# ---------------------------------------------------------------------------
# Curated library: ATT&CK technique id -> list of lab proxy commands.
# ---------------------------------------------------------------------------

CURATED: Dict[str, List[Dict[str, Any]]] = {
    # ---- Execution ------------------------------------------------------
    "T1059.001": [_c("windows", "powershell.exe -NoProfile -Command \"Write-Host 'AdversaryFlow lab PowerShell exec test'\"",
                     "Inline PowerShell to exercise script-block / EDR logging.")],
    "T1059.003": [_c("windows", "cmd.exe /c \"echo AdversaryFlow lab cmd exec test\"",
                     "Lab cmd.exe child process for command-line logging.")],
    "T1059.004": [_c("linux", "/bin/bash -c \"echo AdversaryFlow lab shell exec test\"",
                     "Lab bash invocation for shell-execution telemetry."),
                  _c("macos", "/bin/bash -c \"echo AdversaryFlow lab shell exec test\"")],
    "T1059.005": [_c("windows", "cscript.exe //B //Nologo //E:vbscript nul 2>nul & echo AdversaryFlow lab WSH host test",
                     "Invokes the Windows Script Host binary without a malicious script.")],
    "T1059.006": [_c("windows", "python -c \"print('AdversaryFlow lab python exec test')\"",
                     "Runs the Python interpreter with a lab marker one-liner."),
                  _c("linux", "python3 -c \"print('AdversaryFlow lab python exec test')\"")],
    "T1059.007": [_c("windows", "mshta.exe about:blank & echo AdversaryFlow lab scripting-host proxy",
                     "Launches mshta against a blank page (no remote script).",
                     "taskkill /IM mshta.exe /F 2>nul")],
    "T1053.005": [_c("windows", "schtasks /Create /TN AdversaryFlowLab /TR \"cmd.exe /c echo hi\" /SC ONCE /ST 23:59 /F",
                     "Creates a lab one-time scheduled task to trip task-creation detections.",
                     "schtasks /Delete /TN AdversaryFlowLab /F")],
    "T1053.003": [_c("linux", "( crontab -l 2>/dev/null; echo '# AdversaryFlow lab cron marker' ) | crontab -",
                     "Adds a lab comment line to the user crontab.",
                     "crontab -l | grep -v 'AdversaryFlow lab cron marker' | crontab -")],
    "T1204.002": [_c("windows", "cmd.exe /c \"echo AdversaryFlow lab 'user opened attachment' proxy\"",
                     "Simulates the child process a macro would spawn — no real document.")],
    "T1047": [_c("windows", "wmic os get caption,version /format:list", "Read-only WMI query (proxy for WMI execution)."),
              _c("windows", "powershell -NoProfile -Command \"Get-CimInstance Win32_OperatingSystem | Select Caption,Version\"")],
    "T1106": [_c("windows", "powershell -NoProfile -Command \"[Diagnostics.Process]::Start('notepad.exe'); Start-Sleep 2; Stop-Process -Name notepad\"",
                 "Native process-creation API spawns and closes notepad.", "taskkill /IM notepad.exe /F 2>nul")],
    "T1569.002": [_c("windows", "sc.exe query wuauserv", "Lab service query (proxy for service execution).")],
    "T1203": [_c("windows", "cmd.exe /c \"echo AdversaryFlow lab exploitation-for-execution proxy (no exploit run)\"",
                 "Bounded lab simulation only — no real exploit is ever executed.")],
    "T1129": [_c("windows", "powershell -NoProfile -Command \"[Reflection.Assembly]::LoadWithPartialName('System.Xml') | Out-Null; 'lab module load'\"",
                 "Loads a lab assembly to exercise image-load telemetry.")],

    # ---- Discovery ------------------------------------------------------
    "T1087.001": [_c("windows", "net user", "Local account enumeration."), _c("linux", "cat /etc/passwd")],
    "T1087.002": [_c("windows", "net group \"Domain Admins\" /domain", "Domain group enumeration (read-only).")],
    "T1087.003": [_c("windows", "powershell -NoProfile -Command \"Get-LocalGroupMember Administrators -ErrorAction SilentlyContinue\"",
                     "Reads local Administrators membership.")],
    "T1082": [_c("windows", "systeminfo", "Host information discovery."),
              _c("linux", "uname -a && cat /etc/os-release"), _c("macos", "system_profiler SPSoftwareDataType")],
    "T1083": [_c("windows", "dir C:\\Users /s /b 2>nul | more +1", "Read-only file/directory enumeration."),
              _c("linux", "find /home -maxdepth 2 -type f 2>/dev/null | head")],
    "T1057": [_c("windows", "tasklist", "Process discovery."), _c("linux", "ps aux"), _c("macos", "ps aux")],
    "T1518.001": [_c("windows", "powershell -NoProfile -Command \"Get-CimInstance Win32_Service | ? {$_.Name -match 'defender|sense|falcon|crowd|carbon|cylance|sentinel'} | Select Name,State\"",
                     "Read-only enumeration of security software services.")],
    "T1518": [_c("windows", "wmic product get name,version 2>nul | more", "Installed-software discovery (read-only).")],
    "T1016": [_c("windows", "ipconfig /all", "Network configuration discovery."), _c("linux", "ip addr && ip route")],
    "T1049": [_c("windows", "netstat -ano", "Network connection discovery."), _c("linux", "ss -tunap")],
    "T1018": [_c("windows", "net view /all", "Remote system discovery (read-only)."),
              _c("windows", "nltest /dclist: 2>nul")],
    "T1033": [_c("windows", "whoami /all", "Owner/user discovery."), _c("linux", "id && whoami")],
    "T1007": [_c("windows", "sc.exe query type= service state= all | more", "Service discovery.")],
    "T1069.001": [_c("windows", "net localgroup", "Local permission-group discovery.")],
    "T1069.002": [_c("windows", "net group /domain", "Domain permission-group discovery.")],
    "T1201": [_c("windows", "net accounts", "Password-policy discovery."), _c("linux", "cat /etc/login.defs 2>/dev/null | grep -i pass")],
    "T1124": [_c("windows", "net time \\\\localhost & w32tm /query /status 2>nul", "System time discovery.")],
    "T1010": [_c("windows", "powershell -NoProfile -Command \"Get-Process | ? {$_.MainWindowTitle} | Select ProcessName,MainWindowTitle\"",
                 "Application-window discovery.")],
    "T1046": [_c("windows", "powershell -NoProfile -Command \"Test-NetConnection -ComputerName localhost -Port 445 | Select RemoteAddress,TcpTestSucceeded\"",
                 "Single lab local port check (not a scan).")],
    "T1135": [_c("windows", "net share", "Network share discovery.")],
    "T1120": [_c("windows", "wmic path Win32_PnPEntity get Name 2>nul | more", "Peripheral device discovery.")],
    "T1012": [_c("windows", "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Registry query (read-only).")],
    "T1497.001": [_c("windows", "wmic computersystem get model,manufacturer", "Lab virtualization/sandbox check (read-only).")],
    "T1614": [_c("windows", "wmic os get locale,countrycode,oslanguage /format:list", "System location discovery.")],

    # ---- Credential Access ---------------------------------------------
    "T1003.001": [_c("windows", "cmd.exe /c \"echo AdversaryFlow lab LSASS-access proxy && tasklist | findstr lsass\"",
                     "Locates lsass without dumping it — no memory is read.")],
    "T1003.002": [_c("windows", "reg save HKLM\\SAM %TEMP%\\af_sam_test.hiv 2>nul & echo (requires admin; lab copy)",
                     "Lab SAM export to a temp file to trip credential-store access alerts.",
                     "del %TEMP%\\af_sam_test.hiv 2>nul")],
    "T1552.001": [_c("windows", "findstr /si password *.xml *.ini *.txt 2>nul | more", "Searches files for 'password' strings (read-only)."),
                  _c("linux", "grep -rIl --include=*.conf -e password /etc 2>/dev/null | head")],
    "T1555": [_c("windows", "cmdkey /list", "Enumerates stored credentials (read-only).")],
    "T1555.003": [_c("windows", "dir /s /b \"%LocalAppData%\\Google\\Chrome\\User Data\\Default\\Login Data\" 2>nul",
                     "Locates the browser credential store without reading it.")],
    "T1558.003": [_c("windows", "setspn -q */* 2>nul | more", "SPN discovery (Kerberoasting recon, no ticket requested).")],
    "T1110": [_c("windows", "cmd.exe /c \"echo AdversaryFlow lab brute-force proxy - no auth attempts made\"",
                 "Bounded lab simulation only — no authentication attempts are generated.")],
    "T1056.001": [_c("windows", "cmd.exe /c \"echo AdversaryFlow lab keylogging proxy - no hooks installed\"",
                     "Bounded lab simulation only — no input hooks are installed.")],

    # ---- Persistence ----------------------------------------------------
    "T1547.001": [_c("windows", "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v AdversaryFlowLab /t REG_SZ /d \"cmd.exe /c echo hi\" /f",
                     "Lab Run-key write to trip autostart detections.",
                     "reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v AdversaryFlowLab /f")],
    "T1543.003": [_c("windows", "sc.exe create AdversaryFlowLab binPath= \"cmd.exe /c echo hi\" start= demand & echo (requires admin)",
                     "Creates a lab, non-running service.",
                     "sc.exe delete AdversaryFlowLab")],
    "T1546.003": [_c("windows", "powershell -NoProfile -Command \"Get-WmiObject __EventFilter -Namespace root\\subscription | Select Name\"",
                     "Read-only enumeration of WMI event subscriptions.")],
    "T1136.001": [_c("windows", "net user AdversaryFlowTmp * /add & echo (requires admin; enter a unique temporary password)",
                     "Creates a lab local account and prompts for a unique password.",
                     "net user AdversaryFlowTmp /delete")],
    "T1098": [_c("windows", "net user %USERNAME% & echo AdversaryFlow lab account-manipulation proxy (read-only)",
                 "Read-only account inspection as an account-manipulation proxy.")],
    "T1574.002": [_c("windows", "cmd.exe /c \"echo AdversaryFlow lab DLL-side-load proxy - no DLL planted\"",
                     "Bounded lab simulation only — no DLL is planted.")],
    "T1505.003": [_c("windows", "cmd.exe /c \"echo AdversaryFlow lab web-shell proxy - no file written to webroot\"",
                     "Bounded lab simulation only — nothing is written to a web root.")],

    # ---- Privilege Escalation ------------------------------------------
    "T1548.002": [_c("windows", "cmd.exe /c \"whoami /groups | findstr /i S-1-16-12288 || echo not elevated\"",
                     "Reads the integrity level (UAC-bypass proxy, read-only).")],
    "T1134": [_c("windows", "whoami /priv", "Enumerates token privileges (read-only).")],
    "T1055": [_c("windows", "powershell -NoProfile -Command \"[Diagnostics.Process]::Start('notepad.exe'); Start-Sleep 1; Stop-Process -Name notepad\"",
                 "Spawns/kills notepad as a lab process-interaction proxy — no injection.",
                 "taskkill /IM notepad.exe /F 2>nul")],

    # ---- Defense Evasion -----------------------------------------------
    "T1070.001": [_c("windows", "wevtutil qe Security /c:1 /rd:true /f:text 2>nul", "Reads (not clears) an event-log entry as a lab proxy.")],
    "T1070.004": [_c("windows", "echo AdversaryFlow lab > %TEMP%\\af_marker.txt & del %TEMP%\\af_marker.txt",
                     "Creates and deletes a lab temp file (file-deletion telemetry).")],
    "T1112": [_c("windows", "reg add HKCU\\Software\\AdversaryFlowLab /v test /t REG_SZ /d lab /f",
                 "Lab registry modification under a scratch key.",
                 "reg delete HKCU\\Software\\AdversaryFlowLab /f")],
    "T1027": [_c("windows", "powershell -NoProfile -Command \"[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('AdversaryFlow lab'))\"",
                 "Base64-encodes a lab string (obfuscation proxy).")],
    "T1140": [_c("windows", "powershell -NoProfile -Command \"[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('QWR2ZXJzYXJ5Rmxvdw=='))\"",
                 "Decodes a lab base64 string (deobfuscation proxy).")],
    "T1218.005": [_c("windows", "mshta.exe about:blank & echo AdversaryFlow lab mshta LOLBin proxy",
                     "Runs the mshta LOLBin against a blank page.", "taskkill /IM mshta.exe /F 2>nul")],
    "T1218.011": [_c("windows", "rundll32.exe user32.dll,LockWorkStation & echo (locks screen - lab LOLBin)",
                     "Uses rundll32 to call a lab, documented export.")],
    "T1197": [_c("windows", "bitsadmin /list & echo AdversaryFlow lab BITS proxy", "Lists BITS jobs (read-only LOLBin use).")],
    "T1562.001": [_c("windows", "sc.exe query windefend", "Read-only query of the defender service (does NOT disable it).")],
    "T1036": [_c("windows", "copy %WINDIR%\\System32\\calc.exe %TEMP%\\svch0st.exe & echo (lab rename)",
                 "Copies calc.exe under a masquerading name in temp.", "del %TEMP%\\svch0st.exe 2>nul")],
    "T1497": [_c("windows", "wmic bios get serialnumber & wmic computersystem get model", "Lab sandbox/VM checks (read-only).")],
    "T1553.002": [_c("windows", "powershell -NoProfile -Command \"Get-AuthenticodeSignature $env:WINDIR\\System32\\notepad.exe | Select Status\"",
                     "Reads code-signature status (read-only).")],

    # ---- Lateral Movement ----------------------------------------------
    "T1021.001": [_c("windows", "cmdkey /list & echo AdversaryFlow lab RDP-proxy (no session opened)",
                     "Enumerates stored RDP creds without opening a session.")],
    "T1021.002": [_c("windows", "net use \\\\localhost\\IPC$ & echo (lab IPC connection)",
                     "Opens a lab loopback SMB/IPC session.", "net use \\\\localhost\\IPC$ /delete 2>nul")],
    "T1021.006": [_c("windows", "powershell -NoProfile -Command \"Test-WSMan -ComputerName localhost | Select ProductVendor\"",
                     "Lab WinRM check against localhost.")],
    "T1570": [_c("windows", "copy %WINDIR%\\System32\\calc.exe %TEMP%\\af_lateral.exe & echo (lab local copy)",
                 "Local file copy as a lateral-tool-transfer proxy.", "del %TEMP%\\af_lateral.exe 2>nul")],

    # ---- Collection -----------------------------------------------------
    "T1560.001": [_c("windows", "powershell -NoProfile -Command \"Compress-Archive -Path $env:WINDIR\\win.ini -DestinationPath $env:TEMP\\af_collect.zip -Force\"",
                     "Archives a lab file as a collection/staging proxy.", "del %TEMP%\\af_collect.zip 2>nul"),
                  _c("linux", "tar czf /tmp/af_collect.tgz /etc/hostname 2>/dev/null && rm -f /tmp/af_collect.tgz")],
    "T1005": [_c("windows", "dir /s /b %USERPROFILE%\\*.docx %USERPROFILE%\\*.xlsx 2>nul | more", "Read-only search for local documents.")],
    "T1113": [_c("windows", "powershell -NoProfile -Command \"Add-Type -AssemblyName System.Windows.Forms; [Windows.Forms.SendKeys]::SendWait('')\"",
                 "No-op screenshot-API proxy (does not save an image).")],
    "T1039": [_c("windows", "net view \\\\localhost & echo AdversaryFlow lab network-share-collection proxy",
                 "Enumerates shares as a share-collection proxy.")],
    "T1114.001": [_c("windows", "dir /s /b \"%LocalAppData%\\Microsoft\\Outlook\\*.ost\" 2>nul", "Locates local mail store (read-only).")],

    # ---- Command and Control -------------------------------------------
    "T1071.001": [_c("windows", "powershell -NoProfile -Command \"Invoke-WebRequest https://example.com -UseBasicParsing | Select StatusCode\"",
                     "Lab HTTPS request to an example host (app-layer C2 proxy)."),
                  _c("linux", "curl -s -o /dev/null -w '%{http_code}\\n' https://example.com")],
    "T1105": [_c("windows", "powershell -NoProfile -Command \"Invoke-WebRequest https://example.com/index.html -OutFile $env:TEMP\\af_download.html\"",
                 "Lab ingress tool-transfer proxy to a temp file.", "del %TEMP%\\af_download.html 2>nul"),
              _c("linux", "curl -s https://example.com -o /tmp/af_download.html && rm -f /tmp/af_download.html")],
    "T1571": [_c("windows", "powershell -NoProfile -Command \"Test-NetConnection example.com -Port 8080 | Select TcpTestSucceeded\"",
                 "Single lab connection attempt to a non-standard port.")],
    "T1573": [_c("windows", "powershell -NoProfile -Command \"Invoke-WebRequest https://example.com -UseBasicParsing | Select StatusCode\"",
                 "Encrypted-channel proxy (ordinary TLS request to an example host).")],
    "T1090": [_c("windows", "netsh interface portproxy show all & echo AdversaryFlow lab proxy-config read",
                 "Read-only view of port-proxy configuration.")],
    "T1568": [_c("windows", "nslookup example.com", "Lab DNS resolution (dynamic-resolution proxy).")],

    # ---- Exfiltration ---------------------------------------------------
    "T1041": [_c("windows", "powershell -NoProfile -Command \"$b=[Text.Encoding]::UTF8.GetBytes('lab'); (Invoke-WebRequest -Uri https://example.com -Method POST -Body $b -UseBasicParsing).StatusCode\"",
                 "Posts a tiny lab body to an example host (C2-channel exfil proxy).")],
    "T1567.002": [_c("windows", "powershell -NoProfile -Command \"Resolve-DnsName storage.googleapis.com | Select Name\"",
                     "Resolves a cloud-storage host (exfil-to-cloud proxy, no upload).")],
    "T1048": [_c("windows", "nslookup example.com & echo AdversaryFlow lab alt-protocol-exfil proxy",
                 "Lab DNS lookup as an alternative-protocol exfil proxy.")],
    "T1030": [_c("windows", "cmd.exe /c \"echo AdversaryFlow lab data-transfer-size-limits proxy\"",
                 "Bounded lab simulation only — no data is transferred.")],

    # ---- Impact ---------------------------------------------------------
    "T1486": [_c("windows", "echo AdversaryFlow lab > %TEMP%\\af_ransim.txt & type %TEMP%\\af_ransim.txt & del %TEMP%\\af_ransim.txt",
                 "Writes/reads/deletes ONE temp file — no real encryption occurs.")],
    "T1490": [_c("windows", "vssadmin list shadows & echo AdversaryFlow lab proxy (does NOT delete shadows)",
                 "Lists shadow copies read-only — never deletes them.")],
    "T1489": [_c("windows", "sc.exe query wuauserv & echo AdversaryFlow lab service-stop proxy (read-only)",
                 "Queries a service without stopping it.")],
    "T1529": [_c("windows", "cmd.exe /c \"echo AdversaryFlow lab shutdown proxy - no shutdown issued\"",
                 "Bounded lab simulation only — no shutdown/reboot is issued.")],
    "T1491.001": [_c("windows", "cmd.exe /c \"echo AdversaryFlow lab defacement proxy - nothing changed\"",
                     "Bounded lab simulation only.")],

    # ---- Initial Access -------------------------------------------------
    "T1566.001": [_c("windows", "cmd.exe /c \"echo AdversaryFlow lab spearphishing-attachment proxy - no email/file involved\"",
                     "Bounded lab simulation proxy for the delivery step (nothing is sent).")],
    "T1566.002": [_c("windows", "powershell -NoProfile -Command \"Invoke-WebRequest https://example.com -UseBasicParsing | Select StatusCode\"",
                     "Lab HTTPS fetch as a phishing-link click proxy.")],
    "T1078": [_c("windows", "whoami /all & echo AdversaryFlow lab valid-accounts proxy (read-only)",
                 "Read-only identity inspection — no credentials used.")],
    "T1190": [_c("windows", "cmd.exe /c \"echo AdversaryFlow lab exploit-public-app proxy - no exploit run\"",
                 "Bounded lab simulation only — no exploitation is performed.")],
    "T1189": [_c("windows", "powershell -NoProfile -Command \"Invoke-WebRequest https://example.com -UseBasicParsing | Select StatusCode\"",
                 "Lab web fetch as a drive-by-compromise proxy.")],
}


# ---------------------------------------------------------------------------
# Tactic-aware fallback: guarantees every technique is runnable.
# ---------------------------------------------------------------------------

TACTIC_FALLBACK: Dict[str, Dict[str, str]] = {
    "reconnaissance": _c("windows", "nslookup {domain} & echo AdversaryFlow lab recon proxy for {tid}",
                         "Lab DNS lookup as a reconnaissance proxy."),
    "resource-development": _c("windows", "cmd.exe /c \"echo AdversaryFlow lab resource-development proxy for {tid} - nothing provisioned\"",
                              "Bounded lab simulation — no infrastructure/tooling is provisioned."),
    "initial-access": _c("windows", "cmd.exe /c \"echo AdversaryFlow lab initial-access proxy for {tid} - no delivery performed\"",
                        "Bounded lab simulation for the delivery step."),
    "execution": _c("windows", "cmd.exe /c \"echo AdversaryFlow lab execution proxy for {tid}\"",
                   "Spawns a lab child process to exercise execution telemetry."),
    "persistence": _c("windows", "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run & echo AdversaryFlow lab persistence-inspection for {tid}",
                     "Read-only inspection of a common persistence location."),
    "privilege-escalation": _c("windows", "whoami /priv & echo AdversaryFlow lab privesc proxy for {tid}",
                              "Read-only privilege enumeration."),
    "defense-evasion": _c("windows", "powershell -NoProfile -Command \"[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('AdversaryFlow {tid}'))\"",
                         "Lab obfuscation proxy (base64 of a marker string)."),
    "stealth": _c("windows", "powershell -NoProfile -Command \"[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('AdversaryFlow {tid}'))\"",
                 "Lab obfuscation proxy (base64 of a marker string)."),
    "defense-impairment": _c("windows", "sc.exe query windefend & echo AdversaryFlow lab defense-impairment proxy for {tid} (read-only)",
                            "Read-only query of a security service (nothing disabled)."),
    "credential-access": _c("windows", "cmdkey /list & echo AdversaryFlow lab credential-access proxy for {tid}",
                           "Read-only enumeration of stored credentials."),
    "discovery": _c("windows", "systeminfo & echo AdversaryFlow lab discovery proxy for {tid}",
                   "Lab read-only host discovery."),
    "lateral-movement": _c("windows", "net view /all & echo AdversaryFlow lab lateral-movement proxy for {tid}",
                          "Read-only remote-system enumeration (no session opened)."),
    "collection": _c("windows", "dir /s /b %USERPROFILE%\\*.docx 2>nul | more & echo AdversaryFlow lab collection proxy for {tid}",
                    "Read-only search for local documents."),
    "command-and-control": _c("windows", "powershell -NoProfile -Command \"Invoke-WebRequest https://example.com -UseBasicParsing | Select StatusCode\"",
                             "Lab HTTPS request to an example host as a C2 proxy."),
    "exfiltration": _c("windows", "nslookup example.com & echo AdversaryFlow lab exfiltration proxy for {tid} - no data sent",
                      "Lab DNS lookup; no data leaves the host."),
    "impact": _c("windows", "cmd.exe /c \"echo AdversaryFlow lab impact proxy for {tid} - system unchanged\"",
                "Bounded lab simulation for impact-oriented telemetry."),
}

GENERIC_FALLBACK = _c("windows", "cmd.exe /c \"echo AdversaryFlow lab proxy for {tid} ({name})\"",
                      "Bounded lab simulation for a newly introduced technique.")


# Merge the large technique-indexed extension into the curated core. The core wins on
# any id collision (hand-tuned entries take precedence over the bulk expansion).
from .command_catalog_extended import EXTENDED as _EXTENDED  # noqa: E402 - must follow CURATED

for _tid, _cmds in _EXTENDED.items():
    CURATED.setdefault(_tid, _cmds)

# Generic echo/file proxies are replaced only after the complete catalog is
# assembled, because the dictionary key is the authoritative technique ID.
for _tid, _cmds in CURATED.items():
    _expanded: List[Dict[str, Any]] = []
    for _command in _cmds:
        if "bounded lab simulation" in _command["note"].lower():
            _expanded.extend(
                technique_exercise_record(_tid, {**_command, "platform": _platform})
                for _platform in ("windows", "linux", "macos")
            )
        else:
            _expanded.append(_command)
    CURATED[_tid] = _expanded


def get_commands(technique_id: str, technique_name: str, tactics: List[str],
                 target_domain: str = "example.com") -> Dict[str, Any]:
    """Return lab commands for a technique.

    Result: {"source": "curated"|"fallback", "commands": [ {platform, command,
    note, cleanup}, ... ]}. Always returns at least one runnable command.
    """
    if technique_id in CURATED:
        return {"source": "curated", "commands": CURATED[technique_id]}

    tactic = tactics[0] if tactics else ""
    template = TACTIC_FALLBACK.get(tactic, GENERIC_FALLBACK)
    cmd = dict(template)
    cmd["command"] = cmd["command"].format(tid=technique_id, name=technique_name, domain=target_domain)
    cmd["note"] = cmd["note"] + " (auto-generated bounded simulation for a technique introduced after this catalog release)"
    return {"source": "fallback", "commands": [cmd]}
