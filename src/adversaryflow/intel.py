import json
import re
import time
from http.client import IncompleteRead, RemoteDisconnected
from urllib.parse import quote
from urllib.parse import urlparse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


MITRE_ENTERPRISE_STIX = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
CTID_LIBRARY_TREE = "https://api.github.com/repos/center-for-threat-informed-defense/adversary_emulation_library/git/trees/master?recursive=1"
_ATTACK_ID = re.compile(r"(?<![A-Z0-9])T\d{4}(?:\.\d{3})?(?![A-Z0-9])")


def fetch_attack_bundle(
    url: str = MITRE_ENTERPRISE_STIX,
    timeout: int = 20,
    *,
    attempts: int = 3,
    retry_delay: float = 1.0,
) -> dict:
    if urlparse(url).scheme != "https":
        raise ValueError("Threat-intelligence source must use HTTPS")
    if attempts < 1:
        raise ValueError("ATT&CK fetch attempts must be at least 1")
    request = Request(url, headers={"User-Agent": "AdversaryFlow/0.1"})
    for attempt in range(attempts):
        try:
            with urlopen(request, timeout=timeout) as response:  # nosec B310 - HTTPS-only source validation above.
                return json.load(response)
        except HTTPError as exc:
            if exc.code not in {408, 425, 429} and exc.code < 500:
                raise
            error = exc
        except (URLError, TimeoutError, ConnectionError, IncompleteRead, RemoteDisconnected, json.JSONDecodeError) as exc:
            error = exc
        if attempt + 1 < attempts:
            time.sleep(retry_delay * (2 ** attempt))
    raise error


def find_technique(bundle: dict, technique_id: str) -> dict | None:
    for item in bundle.get("objects", []):
        external = item.get("external_references", [])
        if any(ref.get("external_id") == technique_id for ref in external):
            return item
    return None


def _attack_external_id(item: dict) -> str | None:
    return next((str(ref.get("external_id")) for ref in item.get("external_references", []) if re.fullmatch(r"T\d{4}(?:\.\d{3})?", str(ref.get("external_id", "")))), None)


def find_group(bundle: dict, actor: str) -> dict | None:
    """Find an ATT&CK intrusion set by its name or an exact alias."""
    wanted = actor.strip().casefold()
    for item in bundle.get("objects", []):
        if item.get("type") != "intrusion-set" or item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        names = [item.get("name", ""), *item.get("aliases", [])]
        if wanted in {str(name).strip().casefold() for name in names}:
            return item
    return None


def group_technique_ids(bundle: dict, actor: str) -> tuple[str, ...]:
    """Return current ATT&CK techniques related to an actor, without procedures."""
    group = find_group(bundle, actor)
    if not group:
        raise ValueError(f"Actor not found in MITRE ATT&CK: {actor}")
    attack_patterns = {item.get("id"): item for item in bundle.get("objects", []) if item.get("type") == "attack-pattern" and not item.get("revoked") and not item.get("x_mitre_deprecated")}
    identifiers = set()
    for relationship in bundle.get("objects", []):
        if relationship.get("type") != "relationship" or relationship.get("relationship_type") != "uses" or relationship.get("source_ref") != group.get("id") or relationship.get("revoked"):
            continue
        identifier = _attack_external_id(attack_patterns.get(relationship.get("target_ref"), {}))
        if identifier:
            identifiers.add(identifier)
    return tuple(sorted(identifiers))


def fetch_ctid_technique_ids(actor: str, tree_url: str = CTID_LIBRARY_TREE, timeout: int = 20, max_files: int = 64) -> tuple[str, ...]:
    """Read ATT&CK IDs from matching CTID plan files; never import executable content."""
    parsed = urlparse(tree_url)
    if parsed.scheme != "https" or parsed.hostname != "api.github.com":
        raise ValueError("CTID source must be the official HTTPS GitHub API")
    request = Request(tree_url, headers={"User-Agent": "AdversaryFlow/0.1", "Accept": "application/vnd.github+json"})
    with urlopen(request, timeout=timeout) as response:  # nosec B310
        tree = json.load(response)
    if tree.get("truncated"):
        raise ValueError("CTID repository listing was truncated; refusing incomplete enrichment")
    slug = re.sub(r"[^a-z0-9]", "", actor.casefold())
    paths = []
    for item in tree.get("tree", []):
        path = str(item.get("path", ""))
        first = path.split("/", 1)[0]
        if item.get("type") == "blob" and re.sub(r"[^a-z0-9]", "", first.casefold()) == slug and path.lower().endswith((".json", ".yaml", ".yml", ".md")) and int(item.get("size", 0)) <= 2_000_000:
            paths.append(path)
    identifiers = set()
    for path in sorted(paths)[:max_files]:
        raw_url = "https://raw.githubusercontent.com/center-for-threat-informed-defense/adversary_emulation_library/master/" + quote(path)
        with urlopen(Request(raw_url, headers={"User-Agent": "AdversaryFlow/0.1"}), timeout=timeout) as response:  # nosec B310
            text = response.read(2_000_001).decode("utf-8", errors="replace")
        if len(text) > 2_000_000:
            raise ValueError(f"CTID plan file exceeds the safe import limit: {path}")
        identifiers.update(_ATTACK_ID.findall(text))
    return tuple(sorted(identifiers))
