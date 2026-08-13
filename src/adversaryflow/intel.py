import json
from urllib.request import Request, urlopen


MITRE_ENTERPRISE_STIX = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"


def fetch_attack_bundle(url: str = MITRE_ENTERPRISE_STIX, timeout: int = 20) -> dict:
    request = Request(url, headers={"User-Agent": "AdversaryFlow/0.1"})
    with urlopen(request, timeout=timeout) as response:  # noqa: S310 - URL is configurable and operator-controlled.
        return json.load(response)


def find_technique(bundle: dict, technique_id: str) -> dict | None:
    for item in bundle.get("objects", []):
        external = item.get("external_references", [])
        if any(ref.get("external_id") == technique_id for ref in external):
            return item
    return None

