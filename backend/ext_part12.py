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
    "T1589": r("nslookup localhost & echo AF gather-victim-identity proxy — no WHOIS query", "Loopback DNS as an identity-gathering proxy. Does not query WHOIS."),
    "T1589.001": r("echo 'AF gather-credentials proxy - search public breach/paste data for your own org'", "Bounded lab simulation — check breach-exposure of your own org."),
    "T1589.002": r("echo 'AF gather-email-addresses proxy - enumerate your own published addresses'", "Bounded lab simulation — enumerate your own published emails."),
    "T1589.003": r("echo 'AF gather-employee-names proxy - review your own public staff directory'", "Bounded lab simulation — review your own public directory."),
    "T1590": r("nslookup localhost & nslookup -type=NS localhost", "Loopback DNS as a network-info proxy."),
    "T1590.001": r("nslookup -type=SOA localhost", "Loopback SOA lookup as a domain-properties proxy."),
    "T1590.004": r("tracert -h 1 127.0.0.1 2>nul || traceroute -m 1 127.0.0.1 2>/dev/null", "Loopback traceroute. Does not map an external path."),
    "T1590.005": r("nslookup localhost", "Loopback DNS as an IP-resolution proxy."),
    "T1590.006": r("echo 'AF network-security-appliances proxy - inventory your own perimeter devices'", "Bounded lab simulation — inventory your own appliances."),
    "T1591": r("echo AF gather-org-info proxy — review your own org registration locally", "Does not query WHOIS or any third-party registrar."),
    "T1591.001": r("echo 'AF determine-physical-locations proxy - review your own public office locations'", "Bounded lab simulation — review your own locations."),
    "T1591.002": r("echo 'AF business-relationships proxy - review your own public partnerships'", "Bounded lab simulation — review your own partners."),
    "T1591.004": r("echo 'AF identify-roles proxy - review your own public org chart'", "Bounded lab simulation — review your own org chart."),
    "T1592": r("echo AF victim-host-info proxy — no remote banner is fetched", "Does not contact a remote host."),
    "T1592.002": r("echo AF software-header proxy — no remote headers are fetched", "Does not contact a remote host."),
    "T1592.004": r("echo AF client-config proxy — no remote headers are fetched", "Does not contact a remote host."),
    "T1593": r("echo 'AF search-open-websites/domains proxy - Google-dork your own domain'", "Bounded lab simulation — search public data about your own domain."),
    "T1593.001": r("echo 'AF search-social-media proxy - review your own org social presence'", "Bounded lab simulation — review your own social presence."),
    "T1593.002": r("echo 'AF search-engines proxy - run a lab search for your own org'", "Bounded lab simulation — search engines for your own org."),
    "T1593.003": r("git --version; echo 'AF search-code-repositories proxy - no remote fetch'", "Reports the local git client. Does not contact a remote repository."),
    "T1594": r("echo AF search-victim-owned-websites proxy — robots.txt is not fetched", "Does not contact a remote website."),
    "T1595": r("powershell -NoProfile -Command \"Test-NetConnection 127.0.0.1 -Port 9 | Select ComputerName,TcpTestSucceeded\"", "Loopback-only active-scanning proxy."),
    "T1595.001": r("ping -n 1 127.0.0.1", "Loopback ping (scanning-IP-blocks proxy; no sweep)."),
    "T1595.002": r("powershell -NoProfile -Command \"Test-NetConnection 127.0.0.1 -Port 9 | Select ComputerName,TcpTestSucceeded\"", "Loopback-only port check (vulnerability-scanning proxy; no scan)."),
    "T1595.003": r("echo 'AF wordlist-scanning proxy - fuzz only your own test endpoint'", "Bounded lab simulation — content-discovery only on your own endpoint."),
    "T1596": r("nslookup -type=MX localhost", "Loopback MX lookup as a technical-database proxy."),
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
