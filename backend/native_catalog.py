"""Native inspection recipes and explicitly bounded alternatives for POSIX gaps.

Host inspection is read-only. Bounded exercises use synthetic data, temporary
directories and loopback only; they never reproduce harmful host changes.
"""
from __future__ import annotations

from typing import Any, Dict

from .command_safety import command_record, technique_exercise_record
from .lab_exercises import PORTABLE_EXERCISE_IDS
from .platform_support import PORTABLE_GAPS

# (Linux command, macOS command, tools on Linux, tools on macOS, fidelity, purpose)
NATIVE_RECIPES = {
    "T1005": ("ls -la .", "ls -la .", ["ls"], ["ls"], "lab_proxy", "Inspect filenames in the current lab directory; no document contents are collected."),
    "T1007": ("systemctl list-units --type=service --state=running --no-pager", "launchctl list", ["systemctl"], ["launchctl"], "direct", "Enumerate local service state; Linux requires a systemd host."),
    "T1010": ("wmctrl -l", "osascript -e 'tell application \"System Events\" to get name of every application process whose background only is false'", ["wmctrl"], ["osascript"], "direct", "List local GUI applications; requires an X11 session on Linux or System Events automation permission on macOS."),
    "T1014": ("lsmod", "system_profiler SPExtensionsDataType", ["lsmod"], ["system_profiler"], "lab_proxy", "Inspect kernel/module inventory; no rootkit is installed or loaded."),
    "T1016": ("ip address show", "ifconfig", ["ip"], ["ifconfig"], "direct", "Read local interface configuration without sending probes."),
    "T1016.001": ("ip route show default", "route -n get default", ["ip"], ["route"], "lab_proxy", "Inspect the default route; this does not prove Internet connectivity."),
    "T1016.002": ("nmcli device status", "networksetup -listallhardwareports", ["nmcli"], ["networksetup"], "lab_proxy", "Inspect network adapters; no active wireless scan is performed."),
    "T1018": ("ip neigh show", "arp -a", ["ip"], ["arp"], "direct", "Read the local neighbor cache; no remote discovery probe is sent."),
    "T1033": ("id", "id", ["id"], ["id"], "direct", "Read the current execution identity and groups."),
    "T1036.001": ("openssl version", "codesign --verify --verbose /usr/bin/true", ["openssl"], ["codesign"], "lab_proxy", "Verify a known system utility signature; no invalid signature is created and no binary is modified."),
    "T1046": ("ss -lntu", "lsof -nP -iTCP -sTCP:LISTEN", ["ss"], ["lsof"], "lab_proxy", "Inspect locally listening services; no remote network scan is performed."),
    "T1049": ("ss -ant", "lsof -nP -i", ["ss"], ["lsof"], "direct", "Enumerate local socket state without DNS resolution or connection attempts."),
    "T1053": ("crontab -l", "crontab -l", ["crontab"], ["crontab"], "lab_proxy", "Inspect this user's scheduled jobs; an absent crontab may return non-zero. Nothing is scheduled."),
    "T1053.002": ("atq", "atq", ["atq"], ["atq"], "lab_proxy", "Inspect queued at jobs; no job is created."),
    "T1053.003": ("crontab -l", "crontab -l", ["crontab"], ["crontab"], "lab_proxy", "Inspect this user's crontab; no cron persistence is installed."),
    "T1055": ("ps -axo pid,comm", "ps -axo pid,comm", ["ps"], ["ps"], "lab_proxy", "Inspect process identifiers only; no process injection or termination occurs."),
    "T1059": ("sh -c 'printf \"AdversaryFlow shell execution\\n\"'", "sh -c 'printf \"AdversaryFlow shell execution\\n\"'", ["sh"], ["sh"], "direct", "Run a harmless child shell and print a lab marker."),
    "T1059.007": ("node -e 'console.log(\"AdversaryFlow JavaScript lab\")'", "node -e 'console.log(\"AdversaryFlow JavaScript lab\")'", ["node"], ["node"], "direct", "Execute a harmless local JavaScript marker; requires Node.js."),
    "T1069": ("getent group", "dscl . -list /Groups", ["getent"], ["dscl"], "direct", "Enumerate local group names; no membership changes."),
    "T1069.001": ("getent group", "dscl . -list /Groups", ["getent"], ["dscl"], "direct", "Enumerate local group names; no membership changes."),
    "T1078": ("id", "id", ["id"], ["id"], "lab_proxy", "Inspect the current identity only; no authentication or account takeover is attempted."),
    "T1078.001": ("id", "id", ["id"], ["id"], "lab_proxy", "Inspect the current identity only; default credentials are never attempted."),
    "T1078.002": ("id", "id", ["id"], ["id"], "lab_proxy", "Inspect current identity/group context only; no domain login is attempted."),
    "T1078.003": ("id", "id", ["id"], ["id"], "lab_proxy", "Inspect the current local identity only; no account login is attempted."),
    "T1083": ("ls -la .", "ls -la .", ["ls"], ["ls"], "direct", "Enumerate the current lab directory without recursive collection."),
    "T1087": ("getent passwd", "dscl . -list /Users", ["getent"], ["dscl"], "direct", "Enumerate local account names; no password hashes or secrets are read."),
    "T1087.001": ("getent passwd", "dscl . -list /Users", ["getent"], ["dscl"], "direct", "Enumerate local accounts; no credential material is read."),
    "T1087.002": ("id", "id", ["id"], ["id"], "lab_proxy", "Inspect the current identity only; no domain account directory is queried."),
    "T1098": ("id", "id", ["id"], ["id"], "lab_proxy", "Inspect current account metadata; no account is changed."),
    "T1098.007": ("id", "id", ["id"], ["id"], "lab_proxy", "Inspect current group membership; no group is changed."),
    "T1106": ("python3 -c 'import os; print(os.getpid())'", "python3 -c 'import os; print(os.getpid())'", ["python3"], ["python3"], "direct", "Call the local process-ID API through Python; no injection or remote API call."),
    "T1120": ("lsusb", "system_profiler SPUSBDataType", ["lsusb"], ["system_profiler"], "direct", "Enumerate connected USB/peripheral inventory read-only."),
    "T1124": ("date -u", "date -u", ["date"], ["date"], "direct", "Read the local UTC system time."),
    "T1129": ("ldd /bin/ls", "otool -L /bin/ls", ["ldd"], ["otool"], "lab_proxy", "Inspect dependencies of a system utility; no untrusted module is loaded. macOS requires command-line developer tools."),
    "T1135": ("findmnt -t cifs,nfs,nfs4", "mount", ["findmnt"], ["mount"], "lab_proxy", "Inspect mounted filesystem/share metadata; no remote share is contacted."),
    "T1201": ("grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE)' /etc/login.defs", "pwpolicy -getglobalpolicy", ["grep"], ["pwpolicy"], "direct", "Inspect local password policy; privileges and policy availability depend on the host."),
    "T1222.002": ("ls -ld .", "ls -ld .", ["ls"], ["ls"], "lab_proxy", "Inspect current-directory permissions; no permission or ownership changes."),
    "T1497": ("systemd-detect-virt", "sysctl -n hw.model", ["systemd-detect-virt"], ["sysctl"], "lab_proxy", "Inspect virtualization/model hints only; no evasion behavior. Linux returns non-zero when no virtualization is detected."),
    "T1497.001": ("uname -a", "uname -a", ["uname"], ["uname"], "lab_proxy", "Read system hints only; no evasion or payload decision."),
    "T1497.002": ("who", "who", ["who"], ["who"], "lab_proxy", "Inspect logged-in session metadata; no user input is captured."),
    "T1497.003": ("uptime", "uptime", ["uptime"], ["uptime"], "lab_proxy", "Read uptime only; no sandbox detection decision."),
    "T1518": ("command -v sh bash python3 git", "system_profiler SPApplicationsDataType", [], ["system_profiler"], "direct", "Inventory installed tools/applications; missing tools may produce non-zero output."),
    "T1518.001": ("ps -axo pid,comm", "ps -axo pid,comm", ["ps"], ["ps"], "lab_proxy", "Inspect process names for operator review; no security control is changed."),
    "T1518.002": ("systemctl list-timers --all --no-pager", "tmutil destinationinfo", ["systemctl"], ["tmutil"], "lab_proxy", "Inspect timer/backup configuration read-only; this is a limited backup-discovery proxy."),
    "T1553.002": ("openssl version", "codesign --verify --verbose /usr/bin/true", ["openssl"], ["codesign"], "lab_proxy", "Inspect signing tools or verify a system utility; no trust store or signature is changed."),
    "T1558": ("klist", "klist", ["klist"], ["klist"], "lab_proxy", "List current ticket metadata only; no ticket is stolen or forged. Requires a configured Kerberos client."),
    "T1614": ("date +%Z", "date +%Z", ["date"], ["date"], "lab_proxy", "Read configured timezone as a location hint; no geolocation request."),
    "T1614.001": ("locale", "locale", ["locale"], ["locale"], "direct", "Read configured system-language and locale settings."),
    "T1652": ("lsmod", "system_profiler SPExtensionsDataType", ["lsmod"], ["system_profiler"], "direct", "Enumerate module/extension inventory read-only."),
    "T1653": ("cat /sys/power/state", "pmset -g", ["cat"], ["pmset"], "lab_proxy", "Inspect power settings only; Linux requires sysfs power support. No setting is changed."),
    "T1654": ("journalctl --user -n 20 --no-pager", "log show --last 1m --style compact --predicate 'process == \"adversaryflow\"'", ["journalctl"], ["log"], "direct", "Read a bounded local log selection; no log is deleted or cleared."),
    "T1669": ("nmcli device wifi list --rescan no", "networksetup -listallhardwareports", ["nmcli"], ["networksetup"], "lab_proxy", "Read cached wireless or adapter metadata; no active scan or connection."),
    "T1673": ("systemd-detect-virt", "sysctl -n hw.model", ["systemd-detect-virt"], ["sysctl"], "lab_proxy", "Read virtualization/model hints; no VM is changed."),
    "T1678": ("sleep 1", "sleep 1", ["sleep"], ["sleep"], "direct", "Delay this lab command by one second only."),
    "T1680": ("lsblk", "diskutil list", ["lsblk"], ["diskutil"], "direct", "Enumerate local storage metadata read-only."),
}


def extend_native_catalog(catalog: Dict[str, list[Dict[str, Any]]]) -> None:
    for technique_id, platforms in PORTABLE_GAPS.items():
        if technique_id not in catalog:
            raise ValueError(f"Native recipe references absent technique {technique_id}")
        records = catalog[technique_id]
        if technique_id in NATIVE_RECIPES:
            linux, macos, linux_tools, macos_tools, fidelity, note = NATIVE_RECIPES[technique_id]
            for platform in platforms:
                if any(record["platform"] == platform for record in records):
                    continue
                tools = linux_tools if platform == "linux" else macos_tools
                records.append(command_record(
                    platform, linux if platform == "linux" else macos, note,
                    risk="low", requires_admin=False, requires_network=False,
                    environment="endpoint", execution_role="endpoint_test",
                    required_tools=tools, required_credentials=[],
                    prerequisites=[f"{platform} command environment", "authorized disposable lab", *tools, note],
                    fidelity=fidelity, acknowledgment_required=False,
                    expected_output=note, expected_telemetry="Process/command-line activity plus the documented local inspection result.",
                    timeout_seconds=120 if "system_profiler" in tools else 60,
                ))
        elif technique_id in PORTABLE_EXERCISE_IDS:
            # A bounded alternative is separately selectable on every OS. It
            # does not replace the original platform-specific direct record.
            for platform in ("windows", "linux", "macos"):
                record = technique_exercise_record(technique_id, {"platform": platform})
                records.append({**record, "environment": "endpoint", "execution_role": "endpoint_test",
                                "required_tools": ["python" if platform == "windows" else "python3"],
                                "required_credentials": [],
                                "note": record["note"] + " Portable alternative; does not reproduce harmful OS behavior or validate equivalent adversary fidelity."})
        else:
            raise ValueError(f"Missing explicit native recipe or bounded scenario: {technique_id}")
