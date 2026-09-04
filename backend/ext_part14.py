"""Extended lab commands — Part 14: remaining stragglers."""
from .ext_helper import c

PART = {
    "T1040": [c("windows", "powershell -NoProfile -Command \"Get-NetAdapter|Select Name,Status; 'network-sniffing proxy (enumerate adapters only, no capture)'\"",
                "Enumerates network adapters (network-sniffing proxy; no packet capture)."),
              c("linux", "ip -br link & echo 'AF network-sniffing proxy (list interfaces only, no capture)'")],
    "T1204": [c("windows", "cmd.exe /c \"echo AF user-execution proxy - simulates the child process a user action would spawn\"",
                "Lab child process standing in for user-triggered execution.")],
    "T1491.002": [c("windows", "cmd.exe /c \"echo AF external-defacement proxy - no public content modified\"",
                    "Placeholder only — nothing public is modified.")],
    "T1678": [c("windows", "powershell -NoProfile -Command \"$t=Get-Date; Start-Sleep -Seconds 2; ((Get-Date)-$t).TotalSeconds\"",
                "Lab timed sleep (delay-execution / sandbox-evasion proxy).")],
    "T1679": [c("windows", "powershell -NoProfile -Command \"Get-MpPreference|Select -ExpandProperty ExclusionPath -EA SilentlyContinue; 'selective-exclusion proxy (read existing exclusions, none added)'\"",
                "Reads existing AV exclusions (selective-exclusion proxy; nothing added).")],
}
