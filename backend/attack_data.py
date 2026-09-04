"""
Live MITRE ATT&CK data layer for AdversaryFlow.

Downloads the official ATT&CK STIX bundle (Enterprise / ICS / Mobile), caches it
to disk, and exposes helpers to:
  * list threat-actor groups (intrusion-sets) and campaigns
  * resolve the full set of techniques a chosen actor "uses"
  * order those techniques into an end-to-end ATT&CK kill-chain workflow

Data source: https://github.com/mitre-attack/attack-stix-data (official).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _default_cache_dir() -> str:
    configured = os.environ.get("ADVERSARYFLOW_CACHE_DIR")
    if configured:
        return os.path.abspath(os.path.expanduser(configured))
    if sys.platform == "win32":
        root = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(root, "AdversaryFlow", "Cache")
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/Caches/AdversaryFlow")
    root = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return os.path.join(root, "adversaryflow")


CACHE_DIR = _default_cache_dir()
OFFLINE = os.environ.get("ADVERSARYFLOW_OFFLINE", "").lower() in {"1", "true", "yes"}


def configure_cache_dir(path: str) -> None:
    """Override the process-local cache directory before loading a bundle."""
    global CACHE_DIR
    CACHE_DIR = os.path.abspath(os.path.expanduser(path))


def configure_offline(enabled: bool) -> None:
    """Control whether bundle loading may contact the upstream feed."""
    global OFFLINE
    OFFLINE = enabled

# Official ATT&CK STIX 2.1 bundles, "master" always tracks the latest release.
STIX_SOURCES: Dict[str, str] = {
    "enterprise": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "ics": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
    "mobile": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
}

# Refresh the on-disk cache when it is older than this many seconds (7 days).
CACHE_TTL_SECONDS = 7 * 24 * 3600
MAX_BUNDLE_BYTES = int(os.environ.get("ADVERSARYFLOW_MAX_BUNDLE_BYTES", str(128 * 1024 * 1024)))

# Fallback kill-chain order, used only if the STIX matrix can't be parsed. The
# authoritative order is derived at runtime from the x-mitre-matrix object, so
# this stays correct even as ATT&CK evolves its tactics (e.g. the split of
# "Defense Evasion" into "Stealth" + "Defense Impairment").
TACTIC_ORDER: List[str] = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "stealth",
    "defense-impairment",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

TACTIC_TITLES: Dict[str, str] = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "stealth": "Stealth",
    "defense-impairment": "Defense Impairment",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


# ---------------------------------------------------------------------------
# Bundle download / cache
# ---------------------------------------------------------------------------

_MEM_CACHE: Dict[str, Dict[str, Any]] = {}
_CACHE_LOCKS: Dict[str, threading.Lock] = {domain: threading.Lock() for domain in STIX_SOURCES}
_CACHE_EVENTS: Dict[str, Dict[str, Any]] = {}


def _cache_path(domain: str) -> str:
    return os.path.join(CACHE_DIR, f"{domain}-attack.json")


def _metadata_path(domain: str) -> str:
    return os.path.join(CACHE_DIR, f"{domain}-attack.meta.json")


def _cache_is_fresh(path: str) -> bool:
    if not os.path.exists(path):
        return False
    return (time.time() - os.path.getmtime(path)) < CACHE_TTL_SECONDS


def _read_metadata(domain: str) -> Dict[str, Any]:
    try:
        with open(_metadata_path(domain), "r", encoding="utf-8") as fh:
            value = json.load(fh)
            return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def _validate_bundle(bundle: Any, domain: str) -> Dict[str, Any]:
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise ValueError(f"downloaded {domain} ATT&CK data is not a STIX bundle")
    objects = bundle.get("objects")
    if not isinstance(objects, list) or not objects:
        raise ValueError(f"downloaded {domain} ATT&CK bundle contains no objects")
    if not any(isinstance(item, dict) and item.get("type") == "x-mitre-matrix" for item in objects):
        raise ValueError(f"downloaded {domain} ATT&CK bundle contains no matrix")
    return bundle


def _load_validated(path: str, domain: str, verify_provenance: bool = True) -> Dict[str, Any]:
    metadata = _read_metadata(domain) if verify_provenance else {}
    expected = metadata.get("sha256")
    if expected:
        digest = hashlib.sha256()
        with open(path, "rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        if not hmac.compare_digest(digest.hexdigest(), str(expected)):
            raise ValueError(f"cached {domain} ATT&CK bundle does not match its recorded SHA-256")
    with open(path, "r", encoding="utf-8") as fh:
        return _validate_bundle(json.load(fh), domain)


def _download(url: str, dest: str, domain: str, conditional: bool = True) -> Dict[str, Any]:
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    previous = _read_metadata(domain)
    headers = {"User-Agent": "AdversaryFlow/0.3"}
    if conditional and previous.get("etag"):
        headers["If-None-Match"] = str(previous["etag"])
    req = urllib.request.Request(url, headers=headers)
    try:
        response = urllib.request.urlopen(req, timeout=120)
    except urllib.error.HTTPError as exc:
        if exc.code == 304 and os.path.exists(dest):
            os.utime(dest, None)
            previous.update({"checked_at": datetime.now(timezone.utc).isoformat(), "stale": False})
            _write_metadata(domain, previous)
            return previous
        raise

    digest = hashlib.sha256()
    total = 0
    fd, tmp = tempfile.mkstemp(prefix=f".{domain}-attack-", suffix=".tmp", dir=os.path.dirname(dest))
    try:
        with response, os.fdopen(fd, "wb") as fh:
            declared = response.headers.get("Content-Length")
            if declared and int(declared) > MAX_BUNDLE_BYTES:
                raise ValueError(f"{domain} ATT&CK bundle exceeds the {MAX_BUNDLE_BYTES}-byte limit")
            _CACHE_EVENTS[domain] = {"status": "downloading", "bytes_received": 0, "content_length": int(declared) if declared else None}
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_BUNDLE_BYTES:
                    raise ValueError(f"{domain} ATT&CK bundle exceeds the {MAX_BUNDLE_BYTES}-byte limit")
                digest.update(chunk)
                fh.write(chunk)
                _CACHE_EVENTS[domain].update(bytes_received=total)
            fh.flush()
            os.fsync(fh.fileno())
        _CACHE_EVENTS[domain].update(status="validating", bytes_received=total)
        _load_validated(tmp, domain, verify_provenance=False)
        os.replace(tmp, dest)
        metadata = {
            "source_url": url,
            "downloaded_at": datetime.now(timezone.utc).isoformat(),
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "etag": response.headers.get("ETag"),
            "last_modified": response.headers.get("Last-Modified"),
            "sha256": digest.hexdigest(),
            "size_bytes": total,
            "stale": False,
        }
        _write_metadata(domain, metadata)
        return metadata
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _write_metadata(domain: str, metadata: Dict[str, Any]) -> None:
    path = _metadata_path(domain)
    fd, tmp = tempfile.mkstemp(prefix=f".{domain}-meta-", suffix=".tmp", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(metadata, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def load_bundle(domain: str = "enterprise", force_refresh: bool = False) -> Dict[str, Any]:
    """Return the parsed STIX bundle for a domain, using disk + memory cache."""
    if domain not in STIX_SOURCES:
        raise ValueError(f"Unknown ATT&CK domain: {domain}")

    with _CACHE_LOCKS[domain]:
        if not force_refresh and domain in _MEM_CACHE:
            return _MEM_CACHE[domain]

        path = _cache_path(domain)
        needs_download = force_refresh or not _cache_is_fresh(path)
        if force_refresh and OFFLINE:
            raise RuntimeError("cannot refresh the ATT&CK feed while offline mode is enabled")
        if needs_download and OFFLINE and not os.path.exists(path):
            raise RuntimeError(f"offline mode requires a cached {domain} ATT&CK bundle at {path}")
        if needs_download and not OFFLINE:
            try:
                metadata = _download(STIX_SOURCES[domain], path, domain)
                _CACHE_EVENTS[domain] = {"status": "fresh", **metadata}
            except Exception as exc:
                if not os.path.exists(path):
                    raise
                metadata = _read_metadata(domain)
                metadata.update({"stale": True, "refresh_error": str(exc)})
                _CACHE_EVENTS[domain] = {"status": "stale", **metadata}

        try:
            bundle = _load_validated(path, domain)
        except Exception as exc:
            if OFFLINE:
                raise RuntimeError(
                    f"cached {domain} ATT&CK bundle is invalid; reconnect and refresh or clear {path}"
                ) from exc
            _download(STIX_SOURCES[domain], path, domain, conditional=False)
            bundle = _load_validated(path, domain)

        _MEM_CACHE[domain] = bundle
        return bundle


def cache_status() -> Dict[str, Any]:
    """Return per-domain cache provenance without downloading data."""
    domains: Dict[str, Any] = {}
    now = time.time()
    for domain in STIX_SOURCES:
        path = _cache_path(domain)
        exists = os.path.exists(path)
        age = max(0, now - os.path.getmtime(path)) if exists else None
        domains[domain] = {
            "path": path,
            "exists": exists,
            "age_seconds": age,
            "fresh": bool(exists and age is not None and age < CACHE_TTL_SECONDS),
            "metadata": _CACHE_EVENTS.get(domain) or _read_metadata(domain),
        }
    return {"cache_dir": CACHE_DIR, "offline": OFFLINE, "domains": domains}


def clear_disk_cache() -> List[str]:
    """Remove only known AdversaryFlow cache files and return removed paths."""
    removed: List[str] = []
    clear_memory_cache()
    for domain in STIX_SOURCES:
        with _CACHE_LOCKS[domain]:
            for path in (_cache_path(domain), _metadata_path(domain)):
                if os.path.isfile(path):
                    os.unlink(path)
                    removed.append(path)
    return removed


# ---------------------------------------------------------------------------
# Indexing
# ---------------------------------------------------------------------------


class AttackIndex:
    """Parsed, query-friendly view over one or more STIX bundles."""

    def __init__(self, domains: List[str]):
        self.domains = domains
        self.bundle_ids: Dict[str, str] = {}
        self.objects_by_id: Dict[str, Dict[str, Any]] = {}
        # actor stix id -> list of technique stix ids (via 'uses' relationships)
        self.actor_uses: Dict[str, List[str]] = {}
        # authoritative kill-chain order, derived from the STIX matrix objects
        self.tactic_order: List[str] = []
        self.tactic_titles: Dict[str, str] = {}
        self._build()
        self._build_tactics()

    def _build(self) -> None:
        for domain in self.domains:
            bundle = load_bundle(domain)
            self.bundle_ids[domain] = str(bundle.get("id") or "unknown")
            for obj in bundle.get("objects", []):
                oid = obj.get("id")
                if not oid:
                    continue
                # Later domains should not clobber earlier identical ids; first wins.
                self.objects_by_id.setdefault(oid, obj)

        for obj in list(self.objects_by_id.values()):
            if obj.get("type") != "relationship":
                continue
            if obj.get("relationship_type") != "uses":
                continue
            src = obj.get("source_ref", "")
            tgt = obj.get("target_ref", "")
            if src.startswith(("intrusion-set--", "campaign--")) and tgt.startswith("attack-pattern--"):
                self.actor_uses.setdefault(src, []).append(tgt)

    def _build_tactics(self) -> None:
        """Derive the ordered kill chain from the x-mitre-matrix / tactic objects.

        Falls back to the module-level defaults if the matrix can't be read.
        Domains are concatenated in load order, so enterprise leads.
        """
        order: List[str] = []
        titles: Dict[str, str] = {}
        matrices = [o for o in self.objects_by_id.values() if o.get("type") == "x-mitre-matrix"]
        for matrix in matrices:
            for tref in matrix.get("tactic_refs", []):
                tac = self.objects_by_id.get(tref, {})
                short = tac.get("x_mitre_shortname")
                if short and short not in titles:
                    order.append(short)
                    titles[short] = tac.get("name", short.replace("-", " ").title())

        if order:
            self.tactic_order = order
            self.tactic_titles = titles
        else:  # pragma: no cover - only if the bundle lacks matrix objects
            self.tactic_order = list(TACTIC_ORDER)
            self.tactic_titles = dict(TACTIC_TITLES)

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _attack_id(obj: Dict[str, Any]) -> Optional[str]:
        for ref in obj.get("external_references", []):
            if ref.get("source_name") in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"):
                return ref.get("external_id")
        return None

    @staticmethod
    def _url(obj: Dict[str, Any]) -> Optional[str]:
        for ref in obj.get("external_references", []):
            if ref.get("source_name", "").startswith("mitre") and ref.get("url"):
                return ref.get("url")
        return None

    def _is_deprecated(self, obj: Dict[str, Any]) -> bool:
        return bool(obj.get("revoked") or obj.get("x_mitre_deprecated"))

    # -- public API -------------------------------------------------------

    def list_actors(self) -> List[Dict[str, Any]]:
        """All non-deprecated groups and campaigns, sorted by name."""
        actors: List[Dict[str, Any]] = []
        for obj in self.objects_by_id.values():
            if obj.get("type") not in ("intrusion-set", "campaign"):
                continue
            if self._is_deprecated(obj):
                continue
            attack_id = self._attack_id(obj)
            if not attack_id:
                continue
            actors.append(
                {
                    "stix_id": obj["id"],
                    "attack_id": attack_id,
                    "name": obj.get("name", "Unknown"),
                    "type": "group" if obj["type"] == "intrusion-set" else "campaign",
                    "aliases": [a for a in obj.get("aliases", []) if a != obj.get("name")],
                    "description": (obj.get("description") or "").split("\n")[0][:400],
                    "technique_count": len(set(self.actor_uses.get(obj["id"], []))),
                }
            )
        # Only surface actors that actually have techniques mapped.
        actors = [a for a in actors if a["technique_count"] > 0]
        actors.sort(key=lambda a: a["name"].lower())
        return actors

    def get_actor(self, stix_id: str) -> Optional[Dict[str, Any]]:
        obj = self.objects_by_id.get(stix_id)
        if not obj or obj.get("type") not in ("intrusion-set", "campaign"):
            return None
        return obj

    def technique(self, stix_id: str) -> Optional[Dict[str, Any]]:
        obj = self.objects_by_id.get(stix_id)
        if not obj or obj.get("type") != "attack-pattern":
            return None
        if self._is_deprecated(obj):
            return None

        tactics = [
            ph.get("phase_name")
            for ph in obj.get("kill_chain_phases", [])
            if ph.get("kill_chain_name") in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack")
        ]
        return {
            "stix_id": obj["id"],
            "attack_id": self._attack_id(obj),
            "name": obj.get("name", "Unknown"),
            "description": (obj.get("description") or "").split("\n\n")[0].strip(),
            "tactics": tactics,
            "platforms": obj.get("x_mitre_platforms", []),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "data_sources": obj.get("x_mitre_data_sources", []),
            "detection": (obj.get("x_mitre_detection") or "").strip(),
            "url": self._url(obj),
        }

    def actor_techniques(self, stix_id: str) -> List[Dict[str, Any]]:
        seen = set()
        out: List[Dict[str, Any]] = []
        for tid in self.actor_uses.get(stix_id, []):
            if tid in seen:
                continue
            seen.add(tid)
            t = self.technique(tid)
            if t:
                out.append(t)
        return out

    @property
    def data_version(self) -> str:
        return "|".join(f"{domain}:{self.bundle_ids.get(domain, 'unknown')}" for domain in self.domains)


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_INDEXES: Dict[Tuple[str, ...], AttackIndex] = {}
_INDEX_LOCK = threading.RLock()


def _domain_key(domains: Optional[List[str]]) -> Tuple[str, ...]:
    requested = domains or ["enterprise"]
    return tuple(dict.fromkeys(requested))


def get_index(domains: Optional[List[str]] = None, rebuild: bool = False) -> AttackIndex:
    key = _domain_key(domains)
    with _INDEX_LOCK:
        if rebuild or key not in _INDEXES:
            _INDEXES[key] = AttackIndex(list(key))
        return _INDEXES[key]


def refresh_index(domains: Optional[List[str]] = None) -> AttackIndex:
    """Serialize refresh and invalidate every derived domain combination."""
    key = _domain_key(domains)
    with _INDEX_LOCK:
        for domain in key:
            load_bundle(domain, force_refresh=True)
        _INDEXES.clear()
        index = AttackIndex(list(key))
        _INDEXES[key] = index
        return index


def loaded_index_status() -> Dict[str, Any]:
    """Return readiness metadata without triggering downloads or parsing."""
    with _INDEX_LOCK:
        return {
            "ready": bool(_INDEXES),
            "domain_sets": [list(key) for key in _INDEXES],
            "data_versions": [index.data_version for index in _INDEXES.values()],
            "cache": cache_status(),
        }


def clear_memory_cache() -> None:
    """Clear process-local indexes and bundles (primarily for tests/reloads)."""
    with _INDEX_LOCK:
        _INDEXES.clear()
        _MEM_CACHE.clear()
        _CACHE_EVENTS.clear()
