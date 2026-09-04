"""Extended lab commands — Part 12: Reconnaissance (PRE).

These are PRE-compromise techniques an adversary performs on their own
infrastructure / OSINT sources. They do NOT fire endpoint detections, so every
entry is an honest, host-lab OSINT/planning proxy the operator runs against
targets they own or public data — clearly labelled as pre-compromise.
"""
from .ext_helper import c

_PRE = " (pre-compromise: OSINT/planning step, not an endpoint detection test)"


def r(cmd, note):
    return [c("pre", cmd, note + _PRE)]


PART = {
    "T1589": r("whois example.com 2>/dev/null || nslookup example.com", "Gathers victim identity info via WHOIS/DNS on a domain you own."),
    "T1589.001": r("echo 'AF gather-credentials proxy - search public breach/paste data for your own org'", "Bounded lab simulation — check breach-exposure of your own org."),
    "T1589.002": r("echo 'AF gather-email-addresses proxy - enumerate your own published addresses'", "Bounded lab simulation — enumerate your own published emails."),
    "T1589.003": r("echo 'AF gather-employee-names proxy - review your own public staff directory'", "Bounded lab simulation — review your own public directory."),
    "T1590": r("nslookup example.com & nslookup -type=NS example.com", "Gathers network info via DNS on a domain you own."),
    "T1590.001": r("nslookup -type=SOA example.com", "Reads domain properties (SOA) for a domain you own."),
    "T1590.004": r("tracert -h 5 example.com 2>nul || traceroute -m 5 example.com 2>/dev/null", "Maps network topology toward a host you own."),
    "T1590.005": r("nslookup example.com", "Resolves IP addresses for a domain you own."),
    "T1590.006": r("echo 'AF network-security-appliances proxy - inventory your own perimeter devices'", "Bounded lab simulation — inventory your own appliances."),
    "T1591": r("whois example.com 2>/dev/null || echo 'review your own org registration'", "Gathers org info via WHOIS on a domain you own."),
    "T1591.001": r("echo 'AF determine-physical-locations proxy - review your own public office locations'", "Bounded lab simulation — review your own locations."),
    "T1591.002": r("echo 'AF business-relationships proxy - review your own public partnerships'", "Bounded lab simulation — review your own partners."),
    "T1591.004": r("echo 'AF identify-roles proxy - review your own public org chart'", "Bounded lab simulation — review your own org chart."),
    "T1592": r("powershell -NoProfile -Command \"(Invoke-WebRequest https://example.com -Method Head -UseBasicParsing).Headers['Server']\"", "Reads server banner from a host you own (victim host info)."),
    "T1592.002": r("powershell -NoProfile -Command \"(Invoke-WebRequest https://example.com -UseBasicParsing).Headers['X-Powered-By']\"", "Reads software headers from a host you own."),
    "T1592.004": r("powershell -NoProfile -Command \"(Invoke-WebRequest https://example.com -UseBasicParsing).Headers.Keys\"", "Reads client-configuration hints from a host you own."),
    "T1593": r("echo 'AF search-open-websites/domains proxy - Google-dork your own domain'", "Bounded lab simulation — search public data about your own domain."),
    "T1593.001": r("echo 'AF search-social-media proxy - review your own org social presence'", "Bounded lab simulation — review your own social presence."),
    "T1593.002": r("echo 'AF search-engines proxy - run a lab search for your own org'", "Bounded lab simulation — search engines for your own org."),
    "T1593.003": r("git ls-remote https://github.com/mitre-attack/attack-stix-data 2>nul | head -1", "Lists a public repo (search-code-repositories proxy)."),
    "T1594": r("powershell -NoProfile -Command \"(Invoke-WebRequest https://example.com/robots.txt -UseBasicParsing).StatusCode\"", "Reads robots.txt from a website you own (search-victim-owned-websites)."),
    "T1595": r("powershell -NoProfile -Command \"Test-NetConnection example.com -Port 443|Select TcpTestSucceeded\"", "Single lab connectivity check to a host you own (active-scanning)."),
    "T1595.001": r("ping -n 1 example.com", "Single lab ping to a host you own (scanning-IP-blocks proxy; no sweep)."),
    "T1595.002": r("powershell -NoProfile -Command \"Test-NetConnection example.com -Port 80|Select TcpTestSucceeded\"", "Single lab port check on a host you own (vulnerability-scanning proxy; no scan)."),
    "T1595.003": r("echo 'AF wordlist-scanning proxy - fuzz only your own test endpoint'", "Bounded lab simulation — content-discovery only on your own endpoint."),
    "T1596": r("nslookup -type=MX example.com", "Queries an open technical database (DNS MX) for a domain you own."),
    "T1596.005": r("echo 'AF scan-databases proxy - review your own Shodan/Censys inventory'", "Bounded lab simulation — review your own external inventory."),
    "T1597": r("echo 'AF search-closed-sources proxy - no third-party/paid data accessed'", "Bounded lab simulation only."),
    "T1597.002": r("echo 'AF purchase-technical-data proxy - nothing purchased'", "Bounded lab simulation only."),
    "T1598": r("echo 'AF phishing-for-information proxy - no message sent'", "Bounded lab simulation only — no message is sent."),
    "T1598.001": r("echo 'AF spearphishing-service proxy - no message sent'", "Bounded lab simulation only."),
    "T1598.002": r("echo 'AF spearphishing-attachment (for info) proxy - no message sent'", "Bounded lab simulation only."),
    "T1598.003": r("echo 'AF spearphishing-link (for info) proxy - no message sent'", "Bounded lab simulation only."),
    "T1598.004": r("echo 'AF spearphishing-voice (for info) proxy - no call placed'", "Bounded lab simulation only."),
    "T1681": r("echo 'AF search-threat-vendor-data proxy - review your own threat-intel subscriptions'", "Bounded lab simulation — review your own threat-intel."),
    "T1682": r("echo 'AF query-public-AI-services proxy - lab OSINT query only'", "Bounded lab simulation — lab OSINT query."),
}
