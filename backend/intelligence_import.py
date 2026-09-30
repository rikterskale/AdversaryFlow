"""Bounded structured ATT&CK evidence imports and actor comparison.

Imports are review candidates only. This module does not infer report claims,
generate commands, or accept a mapping on behalf of an analyst.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

MAX_IMPORT_BYTES = 16 * 1024 * 1024
MAX_PROCEDURES = 4_000
MAX_TEXT_LENGTH = 2_000
ATTACK_ID = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
URL = re.compile(r"^https://[^\s<>\"]+$", re.IGNORECASE)


class IntelligenceImportError(ValueError):
    """The supplied structured source is invalid or exceeds import limits."""


@dataclass(frozen=True)
class ProcedureCandidate:
    candidate_id: str
    technique_id: str
    technique_name: str
    tactics: Tuple[str, ...]
    platforms: Tuple[str, ...]
    source_kind: str
    source_name: str
    source_url: Optional[str]
    source_sha256: str
    evidence_quote: str
    procedure: str
    confidence: Optional[float]
    review_status: str = "needs_review"
    reviewed_by: str = ""
    reviewed_at: str = ""
    accepted_by: str = ""
    accepted_at: str = ""


@dataclass(frozen=True)
class TechniqueComparison:
    report_only: Tuple[str, ...]
    attack_only: Tuple[str, ...]
    both: Tuple[str, ...]


def _bounded_text(value: Any, field: str, maximum: int = MAX_TEXT_LENGTH) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise IntelligenceImportError(f"{field} must be text")
    text = value.strip()
    if len(text) > maximum:
        raise IntelligenceImportError(f"{field} exceeds {maximum} characters")
    return text


def _attack_id(value: Any) -> str:
    candidate = str(value or "").strip().upper()
    if not ATTACK_ID.fullmatch(candidate):
        raise IntelligenceImportError(f"Invalid ATT&CK technique ID: {candidate or '(empty)'}")
    return candidate


def _confidence(value: Any) -> Optional[float]:
    if value in (None, ""):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise IntelligenceImportError("confidence must be a number between 0 and 1") from exc
    if not 0 <= number <= 1:
        raise IntelligenceImportError("confidence must be a number between 0 and 1")
    return number


def _source_url(value: Any) -> Optional[str]:
    text = _bounded_text(value, "source_url", 2_000)
    if not text:
        return None
    try:
        parsed = urlsplit(text)
        valid_port = parsed.port is None or 1 <= parsed.port <= 65_535
    except ValueError:
        valid_port = False
        parsed = urlsplit("")
    if (not URL.fullmatch(text) or parsed.scheme.lower() != "https" or not parsed.hostname
            or parsed.username is not None or parsed.password is not None or not valid_port):
        raise IntelligenceImportError("source_url must be an HTTPS URL")
    return text


def _string_values(value: Any, field: str) -> Tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        raise IntelligenceImportError(f"{field} must be an array of strings")
    values = []
    for item in value:
        if not isinstance(item, str):
            raise IntelligenceImportError(f"{field} must be an array of strings")
        if item.strip():
            values.append(item.strip().lower())
    return tuple(sorted(set(values)))


def _candidate(
    *, technique_id: Any, source_kind: str, source_name: str,
    source_url: Any, source_sha256: str, evidence_quote: Any = "",
    procedure: Any = "", confidence: Any = None, platforms: Sequence[str] = (),
    technique_name: str = "", tactics: Sequence[str] = (),
) -> ProcedureCandidate:
    tid = _attack_id(technique_id)
    quote = _bounded_text(evidence_quote, "evidence_quote")
    description = _bounded_text(procedure, "procedure")
    confidence_value = _confidence(confidence)
    clean_platforms = _string_values(platforms, "platforms")
    clean_tactics = _string_values(tactics, "tactics")
    name = _bounded_text(technique_name, "technique_name", 300)
    source_label = _bounded_text(source_name, "source_name", 300) or source_kind
    record_key = json.dumps([
        source_sha256, tid, quote, description, source_label, source_url,
        clean_platforms, confidence_value,
    ], ensure_ascii=False, separators=(",", ":"))
    candidate_id = hashlib.sha256(record_key.encode("utf-8")).hexdigest()[:24]
    return ProcedureCandidate(
        candidate_id=candidate_id,
        technique_id=tid,
        technique_name=name,
        tactics=clean_tactics,
        platforms=clean_platforms,
        source_kind=source_kind,
        source_name=source_label,
        source_url=_source_url(source_url),
        source_sha256=source_sha256,
        evidence_quote=quote,
        procedure=description,
        confidence=confidence_value,
    )


def _finish(source_kind: str, source_name: str, source_url: Any, raw: bytes,
            rows: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    digest = hashlib.sha256(raw).hexdigest()
    candidates: List[ProcedureCandidate] = []
    seen = set()
    for row in rows:
        item = _candidate(
            technique_id=row.get("technique_id", row.get("attack_technique", row.get("id"))),
            source_kind=source_kind,
            source_name=row.get("source_name") or source_name,
            source_url=row.get("source_url") or source_url,
            source_sha256=digest,
            evidence_quote=row.get("evidence_quote", row.get("quote", "")),
            procedure=row.get("procedure", row.get("description", "")),
            confidence=row.get("confidence"),
            platforms=row.get("platforms", ()),
            technique_name=row.get("technique_name", row.get("name", "")),
            tactics=row.get("tactics", ()),
        )
        if item.candidate_id not in seen:
            seen.add(item.candidate_id)
            candidates.append(item)
            if len(candidates) > MAX_PROCEDURES:
                raise IntelligenceImportError(f"Import exceeds the {MAX_PROCEDURES}-candidate limit")
    if not candidates:
        raise IntelligenceImportError("No ATT&CK technique IDs were found")
    return {
        "schema_version": "1.0",
        "source": {
            "kind": source_kind,
            "name": _bounded_text(source_name, "source_name", 300) or source_kind,
            "url": _source_url(source_url),
            "sha256": digest,
        },
        "candidates": [asdict(item) for item in candidates],
    }


def _parse_csv(raw: bytes, source_name: str, source_url: Any) -> Dict[str, Any]:
    try:
        text = raw.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text, newline=""))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise IntelligenceImportError("CSV must be valid UTF-8 with a header row") from exc
    if not reader.fieldnames:
        raise IntelligenceImportError("CSV must contain a header row")
    aliases = {
        "technique_id": ("technique_id", "attack_id", "attack_technique", "external_id", "id"),
        "source_name": ("source_name", "source", "report", "document"),
        "source_url": ("source_url", "url", "reference"),
        "evidence_quote": ("evidence_quote", "quote", "evidence", "citation"),
        "procedure": ("procedure", "behavior", "description", "procedure_description"),
        "confidence": ("confidence",),
        "platforms": ("platforms", "platform"),
        "technique_name": ("technique_name", "name"),
        "tactics": ("tactics", "tactic"),
    }
    normalized = {str(name).strip().lower(): name for name in reader.fieldnames}
    mapped = {field: next((normalized[key] for key in keys if key in normalized), None)
              for field, keys in aliases.items()}
    if mapped["technique_id"] is None:
        raise IntelligenceImportError("CSV needs a technique_id, attack_id, attack_technique, external_id, or id column")
    rows: List[Dict[str, Any]] = []
    try:
        for row in reader:
            if len(rows) >= MAX_PROCEDURES:
                raise IntelligenceImportError(f"Import exceeds the {MAX_PROCEDURES}-row limit")
            values = {field: row.get(column, "") if column else "" for field, column in mapped.items()}
            values["platforms"] = re.split(r"[;,|]", values["platforms"] or "")
            values["tactics"] = re.split(r"[;,|]", values["tactics"] or "")
            rows.append(values)
    except csv.Error as exc:
        raise IntelligenceImportError("CSV could not be parsed") from exc
    return _finish("csv", source_name, source_url, raw, rows)


def _parse_json(raw: bytes, source_name: str, source_url: Any) -> Dict[str, Any]:
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntelligenceImportError("JSON import is invalid or is not UTF-8") from exc
    if not isinstance(data, dict):
        raise IntelligenceImportError("JSON import must be an object")

    # ATT&CK Navigator layer: score is deliberately not interpreted as mapping
    # confidence because Navigator scores normally represent layer visualization.
    if isinstance(data.get("techniques"), list):
        layer_name = _bounded_text(data.get("name"), "layer name", 300) or source_name
        metadata_value = data.get("metadata")
        metadata: Mapping[str, Any] = metadata_value if isinstance(metadata_value, dict) else {}
        layer_url = metadata.get("url") or source_url
        rows: List[Dict[str, Any]] = []
        for entry in data["techniques"]:
            if not isinstance(entry, dict):
                raise IntelligenceImportError("Navigator layer techniques must be objects")
            if entry.get("enabled") is False:
                continue
            if len(rows) >= MAX_PROCEDURES:
                raise IntelligenceImportError(f"Import exceeds the {MAX_PROCEDURES}-row limit")
            rows.append({
                "technique_id": entry.get("techniqueID"),
                "procedure": entry.get("comment", ""),
                "platforms": entry.get("platforms", []),
            })
        return _finish("navigator_layer", layer_name, layer_url, raw, rows)

    # STIX bundles are accepted as structured mappings. Only ATT&CK technique
    # objects are imported; arbitrary relationship objects are not treated as
    # report evidence or accepted procedure mappings.
    objects = data.get("objects")
    if isinstance(objects, list):
        if data.get("type") != "bundle":
            raise IntelligenceImportError("STIX input must be a STIX 2.1 bundle")
        if any(obj.get("spec_version") not in (None, "2.1") for obj in objects if isinstance(obj, dict)):
            raise IntelligenceImportError("STIX input contains objects outside STIX 2.1")
        rows = []
        for obj in objects:
            if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            references = obj.get("external_references", [])
            if not isinstance(references, list):
                references = []
            technique_id = next((ref.get("external_id") for ref in references
                                 if isinstance(ref, dict) and ref.get("source_name") in {
                                     "mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"
                                 } and isinstance(ref.get("external_id"), str)
                                 and ATTACK_ID.fullmatch(ref["external_id"])), None)
            if not technique_id:
                continue
            if len(rows) >= MAX_PROCEDURES:
                raise IntelligenceImportError(f"Import exceeds the {MAX_PROCEDURES}-row limit")
            phases = obj.get("kill_chain_phases", [])
            if not isinstance(phases, list):
                phases = []
            tactics = [phase.get("phase_name") for phase in phases
                       if isinstance(phase, dict) and isinstance(phase.get("phase_name"), str)]
            platforms = obj.get("x_mitre_platforms", [])
            if not isinstance(platforms, list):
                platforms = []
            rows.append({
                "technique_id": technique_id,
                "technique_name": obj.get("name", ""),
                "platforms": platforms,
                "tactics": tactics,
            })
        bundle_name = _bounded_text(data.get("name"), "bundle name", 300) or source_name
        return _finish("stix2_bundle", bundle_name, source_url, raw, rows)

    raise IntelligenceImportError("JSON must be an ATT&CK Navigator layer or STIX 2.1 bundle")


def import_structured_source(content: Any, source_kind: Any, source_name: Any = "",
                             source_url: Any = None) -> Dict[str, Any]:
    """Parse a bounded CSV, Navigator layer, or STIX bundle into review candidates."""
    if isinstance(content, bytes):
        raw = content
    elif isinstance(content, str):
        raw = content.encode("utf-8")
    else:
        raise IntelligenceImportError("Import content must be text")
    if not raw or len(raw) > MAX_IMPORT_BYTES:
        raise IntelligenceImportError(f"Import must be between 1 byte and {MAX_IMPORT_BYTES} bytes")
    kind = str(source_kind or "").strip().lower()
    name = _bounded_text(source_name, "source_name", 300)
    if kind == "csv":
        return _parse_csv(raw, name, source_url)
    if kind in {"json", "navigator_layer", "stix2_bundle"}:
        return _parse_json(raw, name, source_url)
    raise IntelligenceImportError("Supported structured import kinds are csv and json")


def compare_techniques(imported_ids: Iterable[str], actor_ids: Iterable[str]) -> Dict[str, List[str]]:
    """Return deterministic report/import-only, ATT&CK-only, and shared IDs."""
    imported = {_attack_id(item) for item in imported_ids}
    actor = {_attack_id(item) for item in actor_ids}
    return {
        "report_only": sorted(imported - actor),
        "attack_only": sorted(actor - imported),
        "both": sorted(imported & actor),
    }
