import json
from urllib.parse import urlparse
from urllib.request import Request, urlopen


MITRE_ENTERPRISE_STIX = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"


def fetch_attack_bundle(url: str = MITRE_ENTERPRISE_STIX, timeout: int = 20) -> dict:
    if urlparse(url).scheme != "https":
        raise ValueError("Threat-intelligence source must use HTTPS")
    request = Request(url, headers={"User-Agent": "AdversaryFlow/0.1"})
    with urlopen(request, timeout=timeout) as response:  # nosec B310 - HTTPS-only source validation above.
        return json.load(response)


def find_technique(bundle: dict, technique_id: str) -> dict | None:
    for item in bundle.get("objects", []):
        external = item.get("external_references", [])
        if any(ref.get("external_id") == technique_id for ref in external):
            return item
    return None
