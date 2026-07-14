from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class AttackCatalog:
    """Small dependency-free reader for a local Enterprise ATT&CK STIX bundle."""

    def __init__(self, bundle_path: str | Path) -> None:
        self.bundle_path = Path(bundle_path)
        if not self.bundle_path.exists():
            raise FileNotFoundError(self.bundle_path)
        payload = json.loads(self.bundle_path.read_text(encoding="utf-8"))
        self.objects: list[dict[str, Any]] = payload.get("objects", [])
        self.by_id = {obj.get("id"): obj for obj in self.objects if obj.get("id")}

    @staticmethod
    def external_id(obj: dict[str, Any]) -> str | None:
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                return ref["external_id"]
        return None

    def resolve_group(self, actor: str) -> dict[str, Any] | None:
        needle = actor.casefold().strip()
        candidates = []
        for obj in self.objects:
            if obj.get("type") != "intrusion-set" or obj.get("revoked"):
                continue
            names = [obj.get("name", ""), *obj.get("aliases", [])]
            ext_id = self.external_id(obj)
            if ext_id:
                names.append(ext_id)
            if any(needle == str(name).casefold() for name in names):
                candidates.append(obj)
        if not candidates:
            return None
        candidates.sort(key=lambda item: item.get("modified", ""), reverse=True)
        return candidates[0]

    def uses(self, group_id: str) -> dict[str, list[dict[str, Any]]]:
        techniques: list[dict[str, Any]] = []
        software: list[dict[str, Any]] = []
        campaigns: list[dict[str, Any]] = []
        for rel in self.objects:
            if (
                rel.get("type") != "relationship"
                or rel.get("relationship_type") != "uses"
                or rel.get("source_ref") != group_id
                or rel.get("revoked")
            ):
                continue
            target = self.by_id.get(rel.get("target_ref"))
            if not target or target.get("revoked"):
                continue
            item = {
                "name": target.get("name"),
                "external_id": self.external_id(target),
                "description": rel.get("description") or target.get("description"),
                "modified": target.get("modified"),
            }
            if target.get("type") == "attack-pattern":
                techniques.append(item)
            elif target.get("type") in {"malware", "tool"}:
                software.append(item)
            elif target.get("type") == "campaign":
                campaigns.append(item)
        return {
            "techniques": techniques,
            "software": software,
            "campaigns": campaigns,
        }
