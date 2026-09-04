"""Extended lab commands — Part 13: Resource Development (PRE).

PRE-compromise infrastructure/capability development performed on the
adversary's own side. Not endpoint-detectable — every entry is an honest,
host-lab planning proxy that provisions/creates nothing.
"""
from .ext_helper import c

_PRE = " (pre-compromise: adversary-side planning step, not an endpoint detection test)"


def r(cmd, note):
    return [c("pre", cmd, note + _PRE)]


PART = {
    "T1583": r("echo 'AF acquire-infrastructure proxy - nothing provisioned'", "Bounded lab simulation — no infrastructure acquired."),
    "T1583.001": r("nslookup example.com & echo 'AF acquire-domains proxy - resolve a domain you own'", "Resolves a domain you own (acquire-domains proxy)."),
    "T1583.002": r("nslookup -type=NS example.com", "Reads NS records for a domain you own (acquire-DNS-server proxy)."),
    "T1583.003": r("echo 'AF acquire-VPS proxy - nothing provisioned'", "Bounded lab simulation only."),
    "T1583.004": r("echo 'AF acquire-server proxy - nothing provisioned'", "Bounded lab simulation only."),
    "T1583.005": r("echo 'AF acquire-botnet proxy - nothing provisioned'", "Bounded lab simulation only."),
    "T1583.006": r("powershell -NoProfile -Command \"Resolve-DnsName raw.githubusercontent.com|Select Name\"", "Resolves a public web-service host (acquire-web-services proxy)."),
    "T1583.007": r("echo 'AF acquire-serverless proxy - nothing provisioned'", "Bounded lab simulation only."),
    "T1583.008": r("echo 'AF malvertising proxy - no ad purchased/placed'", "Bounded lab simulation only."),
    "T1584": r("echo 'AF compromise-infrastructure proxy - nothing compromised'", "Bounded lab simulation only."),
    "T1584.001": r("nslookup example.com", "Resolves a domain you own (compromise-domains proxy)."),
    "T1584.002": r("nslookup -type=NS example.com", "Reads NS records for a domain you own (compromise-DNS-server proxy)."),
    "T1584.003": r("echo 'AF compromise-VPS proxy - nothing compromised'", "Bounded lab simulation only."),
    "T1584.004": r("echo 'AF compromise-server proxy - nothing compromised'", "Bounded lab simulation only."),
    "T1584.005": r("echo 'AF compromise-botnet proxy - nothing compromised'", "Bounded lab simulation only."),
    "T1584.006": r("echo 'AF compromise-web-services proxy - nothing compromised'", "Bounded lab simulation only."),
    "T1584.008": r("echo 'AF compromise-network-devices proxy - nothing compromised'", "Bounded lab simulation only."),
    "T1585": r("echo 'AF establish-accounts proxy - no account created'", "Bounded lab simulation only."),
    "T1585.001": r("echo 'AF establish-social-media-accounts proxy - no account created'", "Bounded lab simulation only."),
    "T1585.002": r("echo 'AF establish-email-accounts proxy - no account created'", "Bounded lab simulation only."),
    "T1585.003": r("echo 'AF establish-cloud-accounts proxy - no account created'", "Bounded lab simulation only."),
    "T1586.001": r("echo 'AF compromise-social-media-accounts proxy - nothing compromised'", "Bounded lab simulation only."),
    "T1586.002": r("echo 'AF compromise-email-accounts proxy - nothing compromised'", "Bounded lab simulation only."),
    "T1586.003": r("echo 'AF compromise-cloud-accounts proxy - nothing compromised'", "Bounded lab simulation only."),
    "T1587": r("echo 'AF develop-capabilities proxy - nothing developed'", "Bounded lab simulation only."),
    "T1587.001": r("echo 'AF develop-malware proxy - nothing developed'", "Bounded lab simulation only."),
    "T1587.002": r("powershell -NoProfile -Command \"New-SelfSignedCertificate -Type CodeSigning -Subject 'CN=AF-Test' -CertStoreLocation Cert:\\CurrentUser\\My -EA SilentlyContinue|Select Thumbprint\"",
                   "Creates a lab self-signed code-signing cert in your own user store (develop-code-signing-certs proxy)."),
    "T1587.003": r("powershell -NoProfile -Command \"New-SelfSignedCertificate -Subject 'CN=AF-Test' -CertStoreLocation Cert:\\CurrentUser\\My -EA SilentlyContinue|Select Thumbprint\"",
                   "Creates a lab self-signed cert in your own user store (develop-digital-certs proxy)."),
    "T1587.004": r("echo 'AF develop-exploits proxy - nothing developed'", "Bounded lab simulation only."),
    "T1588": r("echo 'AF obtain-capabilities proxy - nothing obtained'", "Bounded lab simulation only."),
    "T1588.001": r("echo 'AF obtain-malware proxy - nothing obtained'", "Bounded lab simulation only."),
    "T1588.002": r("where nmap.exe psexec.exe 2>nul & echo 'AF obtain-tool proxy - locate legitimate tools only'", "Locates already-installed legitimate tools (obtain-tool proxy)."),
    "T1588.003": r("echo 'AF obtain-code-signing-certs proxy - nothing obtained'", "Bounded lab simulation only."),
    "T1588.004": r("echo 'AF obtain-digital-certs proxy - nothing obtained'", "Bounded lab simulation only."),
    "T1588.005": r("echo 'AF obtain-exploits proxy - nothing obtained'", "Bounded lab simulation only."),
    "T1588.006": r("echo 'AF obtain-vulnerabilities proxy - review public CVE data only'", "Bounded lab simulation — review public CVE data."),
    "T1588.007": r("echo 'AF obtain-AI-capabilities proxy - lab only'", "Bounded lab simulation only."),
    "T1650": r("echo 'AF acquire-access proxy - no access broker engaged'", "Bounded lab simulation only."),
    "T1683": r("echo 'AF generate-content proxy - lab content only'", "Bounded lab simulation only."),
    "T1683.001": r("echo 'AF generate-written-content proxy - lab content only'", "Bounded lab simulation only."),
    "T1683.002": r("echo 'AF generate-audio-visual-content proxy - lab content only'", "Bounded lab simulation only."),
    # ---- Stage Capabilities ----
    "T1608": r("echo 'AF stage-capabilities proxy - nothing staged'", "Bounded lab simulation only."),
    "T1608.001": r("echo 'AF upload-malware proxy - nothing uploaded'", "Bounded lab simulation only."),
    "T1608.002": r("echo 'AF upload-tool proxy - nothing uploaded'", "Bounded lab simulation only."),
    "T1608.003": r("echo 'AF install-digital-certificate proxy - nothing installed on adversary infra'", "Bounded lab simulation only."),
    "T1608.004": r("echo 'AF drive-by-target proxy - no site prepared'", "Bounded lab simulation only."),
    "T1608.005": r("echo 'AF link-target proxy - no link staged'", "Bounded lab simulation only."),
    "T1608.006": r("echo 'AF SEO-poisoning proxy - nothing manipulated'", "Bounded lab simulation only."),
}
