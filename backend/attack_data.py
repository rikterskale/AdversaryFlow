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

import json
import os
import time
import urllib.request
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")

# Official ATT&CK STIX 2.1 bundles, "master" always tracks the latest release.
STIX_SOURCES: Dict[str, str] = {
    "enterprise": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "ics": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
    "mobile": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
}

# Refresh the on-disk cache when it is older than this many seconds (7 days).
CACHE_TTL_SECONDS = 7 * 24 * 3600

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


def _cache_path(domain: str) -> str:
    return os.path.join(CACHE_DIR, f"{domain}-attack.json")


def _cache_is_fresh(path: str) -> bool:
    if not os.path.exists(path):
        return False
    return (time.time() - os.path.getmtime(path)) < CACHE_TTL_SECONDS


def _download(url: str, dest: str) -> None:
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "AdversaryFlow/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = resp.read()
    tmp = dest + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, dest)


def load_bundle(domain: str = "enterprise", force_refresh: bool = False) -> Dict[str, Any]:
    """Return the parsed STIX bundle for a domain, using disk + memory cache."""
    if domain not in STIX_SOURCES:
        raise ValueError(f"Unknown ATT&CK domain: {domain}")

    if not force_refresh and domain in _MEM_CACHE:
        return _MEM_CACHE[domain]

    path = _cache_path(domain)
    if force_refresh or not _cache_is_fresh(path):
        try:
            _download(STIX_SOURCES[domain], path)
        except Exception:
            # If the download fails but we have *some* cached copy, use it.
            if not os.path.exists(path):
                raise

    with open(path, "r", encoding="utf-8") as fh:
        bundle = json.load(fh)

    _MEM_CACHE[domain] = bundle
    return bundle


# ---------------------------------------------------------------------------
# Indexing
# ---------------------------------------------------------------------------


class AttackIndex:
    """Parsed, query-friendly view over one or more STIX bundles."""

    def __init__(self, domains: List[str]):
        self.domains = domains
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


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_INDEX: Optional[AttackIndex] = None


def get_index(domains: Optional[List[str]] = None, rebuild: bool = False) -> AttackIndex:
    global _INDEX
    if _INDEX is None or rebuild:
        _INDEX = AttackIndex(domains or ["enterprise"])
    return _INDEX
