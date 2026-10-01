"""Signed, versioned content packs for reviewed abilities and detections.

Packs are ZIP containers, but are never extracted. An Ed25519 signature covers
the canonical manifest; file digests in that manifest bind every payload.
Trust roots are supplied by the installation, separately from pack contents.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import hmac
import io
import json
import os
import re
import sys
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

MAX_PACK_BYTES = 20 * 1024 * 1024
MAX_PACK_UNCOMPRESSED_BYTES = 50 * 1024 * 1024
MAX_ABILITIES = 10_000
MAX_BINDINGS = 20_000
ALLOWED_FILES = {"abilities.json", "detection_bindings.json"}
PACK_ID_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")
TECHNIQUE_PATTERN = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
PLATFORMS = {"windows", "linux", "macos"}
EXECUTORS = {"cmd", "powershell", "bash"}
FIDELITIES = {"direct", "bounded_synthetic", "lab_proxy"}
SAFETY_CLASSES = {"none", "low", "medium", "high"}
DETECTION_PROVIDERS = {"sigma", "elastic", "splunk", "kql"}


class ContentPackError(ValueError):
    """A content pack is invalid, untrusted, or cannot be loaded."""


@dataclass(frozen=True)
class VerifiedAbility:
    ability: Dict[str, Any]
    pack_id: str
    pack_version: str
    signer_key_id: str


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ContentPackError("Content pack data must be valid JSON") from exc


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover - depends on installation extras
        raise ContentPackError("Signed content packs require the 'content-packs' installation extra") from exc
    return InvalidSignature, serialization, Ed25519PrivateKey, Ed25519PublicKey


def _trusted_keys(value: Optional[str] = None) -> Dict[str, bytes]:
    source = os.environ.get("ADVERSARYFLOW_CONTENT_TRUSTED_KEYS", "") if value is None else value
    if not source:
        return {}
    try:
        document = json.loads(source)
    except (TypeError, ValueError) as exc:
        raise ContentPackError("ADVERSARYFLOW_CONTENT_TRUSTED_KEYS must be a JSON object of key IDs to base64 public keys") from exc
    if not isinstance(document, dict) or len(document) > 100:
        raise ContentPackError("The content-pack trust store must contain at most 100 public keys")
    result: Dict[str, bytes] = {}
    for key_id, encoded in document.items():
        if not isinstance(key_id, str) or not PACK_ID_PATTERN.fullmatch(key_id) or not isinstance(encoded, str):
            raise ContentPackError("The content-pack trust store contains an invalid key entry")
        try:
            key = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError) as exc:
            raise ContentPackError(f"Trusted public key {key_id!r} is not valid base64") from exc
        if len(key) != 32:
            raise ContentPackError(f"Trusted Ed25519 public key {key_id!r} must be 32 bytes")
        result[key_id] = key
    return result


def _normalize_ability(raw: Any, *, require_identity: bool) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        raise ContentPackError("Every ability must be a JSON object")
    fields = {
        "technique_id", "platform", "executor", "command_template", "requirements", "cleanup", "rollback",
        "fidelity", "safety_class", "requires_admin", "requires_network", "network_targets", "side_effects",
        "timeout_seconds", "content_source", "review_status",
    }
    optional = {"ability_id", "content_sha256", "procedure_candidate_ids"}
    if set(raw) - fields - optional or fields - set(raw):
        raise ContentPackError("Ability fields do not match the versioned internal ability contract")
    if not isinstance(raw["technique_id"], str) or not TECHNIQUE_PATTERN.fullmatch(raw["technique_id"]):
        raise ContentPackError("Ability technique_id is invalid")
    if (not isinstance(raw["platform"], str) or raw["platform"] not in PLATFORMS
            or not isinstance(raw["executor"], str) or raw["executor"] not in EXECUTORS):
        raise ContentPackError("Ability platform or executor is unsupported")
    allowed_executors = {"cmd", "powershell"} if raw["platform"] == "windows" else {"bash"}
    if raw["executor"] not in allowed_executors:
        raise ContentPackError("Ability executor must match its platform")
    if not isinstance(raw["command_template"], str) or not raw["command_template"] or len(raw["command_template"]) > 10_000:
        raise ContentPackError("Ability command_template must contain 1 to 10000 characters")
    for key in ("cleanup", "rollback", "content_source"):
        if not isinstance(raw[key], str) or len(raw[key]) > 10_000:
            raise ContentPackError(f"Ability {key} is invalid")
    if (not isinstance(raw["fidelity"], str) or raw["fidelity"] not in FIDELITIES
            or not isinstance(raw["safety_class"], str) or raw["safety_class"] not in SAFETY_CLASSES):
        raise ContentPackError("Ability fidelity or safety class is unsupported")
    if raw["review_status"] != "reviewed":
        raise ContentPackError("Only reviewed abilities can be included in a signed release pack")
    if not isinstance(raw["requires_admin"], bool) or not isinstance(raw["requires_network"], bool):
        raise ContentPackError("Ability permission flags must be booleans")
    timeout = raw["timeout_seconds"]
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 0 <= timeout <= 3600:
        raise ContentPackError("Ability timeout_seconds must be from 0 to 3600")
    for key in ("requirements", "network_targets", "side_effects"):
        values = raw[key]
        if not isinstance(values, list) or len(values) > 100 or any(not isinstance(item, str) or len(item) > 2000 for item in values):
            raise ContentPackError(f"Ability {key} must be a bounded list of strings")
        if len(values) != len(set(values)):
            raise ContentPackError(f"Ability {key} cannot contain duplicates")
    procedure_ids = raw.get("procedure_candidate_ids", [])
    if not isinstance(procedure_ids, list) or len(procedure_ids) > 100 or any(not isinstance(item, str) or not item or len(item) > 128 for item in procedure_ids):
        raise ContentPackError("Ability procedure_candidate_ids is invalid")

    normalized = {key: raw[key] for key in fields}
    normalized["requirements"] = sorted(raw["requirements"])
    normalized["network_targets"] = sorted(raw["network_targets"])
    normalized["side_effects"] = sorted(raw["side_effects"])
    content_sha256 = _digest(_canonical(normalized))
    ability_id = _digest(f"{normalized['technique_id']}\0{normalized['platform']}\0{normalized['executor']}\0{content_sha256}".encode("utf-8"))[:24]
    if require_identity and (raw.get("content_sha256") != content_sha256 or raw.get("ability_id") != ability_id):
        raise ContentPackError(f"Ability identity or content digest is invalid for {normalized['technique_id']}")
    normalized["ability_id"] = ability_id
    normalized["content_sha256"] = content_sha256
    normalized["procedure_candidate_ids"] = sorted(set(procedure_ids))
    return normalized


def _validate_binding(raw: Any) -> Dict[str, Any]:
    required = {"technique_id", "provider", "rule_id", "title", "url", "content_sha256", "reviewed_by", "reviewed_at"}
    if not isinstance(raw, dict) or set(raw) != required:
        raise ContentPackError("Detection binding fields do not match the signed binding contract")
    if not isinstance(raw["technique_id"], str) or not TECHNIQUE_PATTERN.fullmatch(raw["technique_id"]):
        raise ContentPackError("Detection binding technique_id is invalid")
    if not isinstance(raw["provider"], str) or raw["provider"] not in DETECTION_PROVIDERS:
        raise ContentPackError("Detection provider must be sigma, elastic, splunk, or kql")
    for key, maximum in (("rule_id", 200), ("title", 500), ("reviewed_by", 120), ("reviewed_at", 100)):
        if not isinstance(raw[key], str) or not raw[key].strip() or len(raw[key]) > maximum:
            raise ContentPackError(f"Detection binding {key} is invalid")
    try:
        reviewed_at = datetime.fromisoformat(raw["reviewed_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContentPackError("Detection binding reviewed_at must be an ISO date-time") from exc
    if reviewed_at.tzinfo is None:
        raise ContentPackError("Detection binding reviewed_at must include a timezone")
    if not isinstance(raw["content_sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", raw["content_sha256"]):
        raise ContentPackError("Detection binding content_sha256 must be a SHA-256 digest")
    url = raw["url"]
    if url is not None and (not isinstance(url, str) or not url.startswith("https://") or len(url) > 2000):
        raise ContentPackError("Detection binding URL must be null or HTTPS")
    return dict(raw)


def _safe_zip(path: Path) -> Tuple[Dict[str, bytes], str]:
    try:
        if path.stat().st_size > MAX_PACK_BYTES:
            raise ContentPackError("Content pack exceeds the compressed size limit")
        raw = path.read_bytes()
        if len(raw) > MAX_PACK_BYTES:
            raise ContentPackError("Content pack exceeds the compressed size limit")
        pack_sha256 = _digest(raw)
        with zipfile.ZipFile(io.BytesIO(raw), "r") as archive:
            infos = archive.infolist()
            if not infos or len(infos) > len(ALLOWED_FILES) + 1:
                raise ContentPackError("Content pack has an unexpected number of files")
            total = 0
            files: Dict[str, bytes] = {}
            for info in infos:
                if info.is_dir() or info.filename not in {"manifest.json", *ALLOWED_FILES} or info.filename in files:
                    raise ContentPackError("Content pack contains an unsupported or duplicate path")
                # Reject Unix symlinks and encrypted members; no extraction occurs.
                mode = (info.external_attr >> 16) & 0xFFFF
                if (mode & 0o170000) == 0o120000 or info.flag_bits & 0x1:
                    raise ContentPackError("Content pack contains a link or encrypted member")
                total += info.file_size
                if total > MAX_PACK_UNCOMPRESSED_BYTES:
                    raise ContentPackError("Content pack exceeds the uncompressed size limit")
                files[info.filename] = archive.read(info)
            if "manifest.json" not in files or "abilities.json" not in files:
                raise ContentPackError("Content pack must include manifest.json and abilities.json")
            return files, pack_sha256
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        if isinstance(exc, ContentPackError):
            raise
        raise ContentPackError(f"Could not read content pack: {exc}") from exc


def verify_pack(path: str | Path, trusted_keys: Optional[str] = None) -> Dict[str, Any]:
    """Verify signature, payload digests, abilities, and optional detection bindings."""
    files, pack_sha256 = _safe_zip(Path(path))
    try:
        manifest = json.loads(files["manifest.json"].decode("utf-8"))
        abilities_doc = json.loads(files["abilities.json"].decode("utf-8"))
        bindings_doc = json.loads(files.get("detection_bindings.json", b"[]").decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ContentPackError("Content pack contains invalid UTF-8 JSON") from exc
    if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "pack_id", "pack_version", "attack_version", "files", "signer_key_id", "signature"}:
        raise ContentPackError("Content pack manifest does not match schema 1.0")
    if manifest["schema_version"] != "1.0" or not isinstance(manifest["pack_id"], str) or not PACK_ID_PATTERN.fullmatch(manifest["pack_id"]):
        raise ContentPackError("Content pack identity or schema version is invalid")
    if not isinstance(manifest["pack_version"], str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", manifest["pack_version"]):
        raise ContentPackError("Content pack version must use semantic version syntax")
    if not isinstance(manifest["attack_version"], str) or not manifest["attack_version"] or len(manifest["attack_version"]) > 100:
        raise ContentPackError("Content pack must pin its ATT&CK data version")
    if not isinstance(manifest["signer_key_id"], str) or not PACK_ID_PATTERN.fullmatch(manifest["signer_key_id"]):
        raise ContentPackError("Content pack signer key ID is invalid")
    file_digests = manifest["files"]
    if not isinstance(file_digests, dict) or set(file_digests) != set(files) - {"manifest.json"}:
        raise ContentPackError("Content pack manifest file list does not match its payload")
    for filename, expected in file_digests.items():
        if (not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected)
                or not hmac_compare(expected, _digest(files[filename]))):
            raise ContentPackError(f"Content pack payload digest does not match for {filename}")

    keys = _trusted_keys(trusted_keys)
    public_raw = keys.get(manifest["signer_key_id"])
    if public_raw is None:
        raise ContentPackError(f"Content pack signer {manifest['signer_key_id']!r} is not trusted")
    InvalidSignature, _, _, Ed25519PublicKey = _crypto()
    signed_manifest = {key: value for key, value in manifest.items() if key != "signature"}
    try:
        signature = base64.b64decode(manifest["signature"], validate=True)
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, _canonical(signed_manifest))
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise ContentPackError("Content pack signature verification failed") from exc

    if not isinstance(abilities_doc, list) or not 1 <= len(abilities_doc) <= MAX_ABILITIES:
        raise ContentPackError("Content pack abilities must be a non-empty bounded list")
    abilities = [_normalize_ability(item, require_identity=True) for item in abilities_doc]
    keys_seen = set()
    for ability in abilities:
        key = (ability["technique_id"], ability["platform"])
        if key in keys_seen:
            raise ContentPackError("A pack cannot define multiple abilities for one technique and platform")
        keys_seen.add(key)
    if not isinstance(bindings_doc, list) or len(bindings_doc) > MAX_BINDINGS:
        raise ContentPackError("Detection bindings must be a bounded list")
    bindings = [_validate_binding(item) for item in bindings_doc]
    return {
        "schema_version": "1.0", "pack_id": manifest["pack_id"], "pack_version": manifest["pack_version"],
        "attack_version": manifest["attack_version"], "signer_key_id": manifest["signer_key_id"],
        "pack_sha256": pack_sha256,
        "files": sorted(file_digests), "ability_count": len(abilities), "detection_binding_count": len(bindings),
        "abilities": abilities, "detection_bindings": bindings,
    }


def hmac_compare(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)


def sign_pack(document: Mapping[str, Any], private_key_path: str | Path, key_id: str) -> bytes:
    """Sign and serialize a content-pack source document with an Ed25519 PEM key."""
    if not isinstance(key_id, str) or not PACK_ID_PATTERN.fullmatch(key_id):
        raise ContentPackError("Signer key ID is invalid")
    if not isinstance(document, Mapping):
        raise ContentPackError("Content pack source must be an object")
    if set(document) != {"pack_id", "pack_version", "attack_version", "abilities", "detection_bindings"}:
        raise ContentPackError("Source pack fields must be pack_id, pack_version, attack_version, abilities, and detection_bindings")
    abilities_raw = document["abilities"]
    bindings_raw = document["detection_bindings"]
    if not isinstance(abilities_raw, list) or not 1 <= len(abilities_raw) <= MAX_ABILITIES:
        raise ContentPackError("Content pack abilities must be a non-empty bounded list")
    abilities = [_normalize_ability(item, require_identity=False) for item in abilities_raw]
    keys = [(item["technique_id"], item["platform"]) for item in abilities]
    if len(keys) != len(set(keys)):
        raise ContentPackError("A pack cannot define multiple abilities for one technique and platform")
    if not isinstance(bindings_raw, list) or len(bindings_raw) > MAX_BINDINGS:
        raise ContentPackError("Detection bindings must be a bounded list")
    bindings = [_validate_binding(item) for item in bindings_raw]
    if not isinstance(document["pack_id"], str) or not PACK_ID_PATTERN.fullmatch(document["pack_id"]):
        raise ContentPackError("Content pack ID is invalid")
    source = {
        "schema_version": "1.0", "pack_id": document["pack_id"], "pack_version": document["pack_version"],
        "attack_version": document["attack_version"],
    }
    if not isinstance(source["pack_version"], str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", source["pack_version"]):
        raise ContentPackError("Content pack version must use semantic version syntax")
    if not isinstance(source["attack_version"], str) or not source["attack_version"] or len(source["attack_version"]) > 100:
        raise ContentPackError("Content pack must pin its ATT&CK data version")
    files = {"abilities.json": _canonical(abilities), "detection_bindings.json": _canonical(bindings)}
    manifest: Dict[str, Any] = {
        **source,
        "files": {name: _digest(data) for name, data in sorted(files.items())},
        "signer_key_id": key_id,
    }
    _, serialization, Ed25519PrivateKey, _ = _crypto()
    try:
        private_bytes = Path(private_key_path).read_bytes()
        private_key = serialization.load_pem_private_key(private_bytes, password=None)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ContentPackError("Content pack signing requires an Ed25519 key")
        signature = private_key.sign(_canonical(manifest))
    except (OSError, ValueError, TypeError) as exc:
        if isinstance(exc, ContentPackError):
            raise
        raise ContentPackError("Could not load an unencrypted Ed25519 PEM private key") from exc
    manifest["signature"] = base64.b64encode(signature).decode("ascii")

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for filename, payload in [("manifest.json", _canonical(manifest)), *sorted(files.items())]:
            info = zipfile.ZipInfo(filename)
            info.external_attr = 0o644 << 16
            archive.writestr(info, payload)
    result = output.getvalue()
    if len(result) > MAX_PACK_BYTES:
        raise ContentPackError("Signed content pack exceeds the compressed size limit")
    return result


def installed_packs(directory: Optional[str] = None) -> Tuple[List[Dict[str, Any]], Dict[Tuple[str, str], VerifiedAbility], Dict[Tuple[str, str], List[Dict[str, Any]]]]:
    """Load all trusted packs from a configured directory, rejecting conflicts."""
    root = directory if directory is not None else os.environ.get("ADVERSARYFLOW_CONTENT_PACK_DIR", "")
    if not root:
        return [], {}, {}
    folder = Path(os.path.abspath(os.path.expanduser(root)))
    if not folder.exists():
        return [], {}, {}
    if not folder.is_dir():
        raise ContentPackError("ADVERSARYFLOW_CONTENT_PACK_DIR must be a directory")
    paths = sorted(path for path in folder.iterdir() if path.is_file() and path.suffix.lower() in {".zip", ".afpack"})
    summaries: List[Dict[str, Any]] = []
    abilities: Dict[Tuple[str, str], VerifiedAbility] = {}
    detections: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    pack_ids = set()
    for path in paths[:500]:
        verified = verify_pack(path)
        if verified["pack_id"] in pack_ids:
            raise ContentPackError(f"Multiple installed versions found for content pack {verified['pack_id']}")
        pack_ids.add(verified["pack_id"])
        summaries.append({key: verified[key] for key in ("pack_id", "pack_version", "attack_version", "signer_key_id", "pack_sha256", "ability_count", "detection_binding_count")})
        for ability in verified["abilities"]:
            key = (ability["technique_id"], ability["platform"])
            existing = abilities.get(key)
            if existing and existing.ability["content_sha256"] != ability["content_sha256"]:
                raise ContentPackError(f"Conflicting signed abilities are installed for {key[0]} on {key[1]}")
            abilities[key] = VerifiedAbility(ability, verified["pack_id"], verified["pack_version"], verified["signer_key_id"])
        for binding in verified["detection_bindings"]:
            key = (binding["technique_id"], binding["provider"])
            detections.setdefault(key, []).append({**binding, "pack_id": verified["pack_id"], "pack_version": verified["pack_version"], "signer_key_id": verified["signer_key_id"]})
    if len(paths) > 500:
        raise ContentPackError("Content pack directory contains more than 500 pack files")
    for values in detections.values():
        if len({item["content_sha256"] for item in values}) > 1:
            raise ContentPackError("Conflicting signed detection bindings are installed for one technique and provider")
    return summaries, abilities, detections


def _keygen(private_path: str, public_path: str) -> int:
    _, serialization, Ed25519PrivateKey, _ = _crypto()
    key = Ed25519PrivateKey.generate()
    private_bytes = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    public_bytes = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    private = Path(private_path)
    public = Path(public_path)
    if private.exists() or public.exists():
        raise ContentPackError("Refusing to overwrite an existing key file")
    private.write_bytes(private_bytes)
    with contextlib.suppress(OSError):
        os.chmod(private, 0o600)
    public.write_text(base64.b64encode(public_bytes).decode("ascii") + "\n", encoding="ascii")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m backend.content_pack")
    subparsers = parser.add_subparsers(dest="command", required=True)
    keygen = subparsers.add_parser("keygen", help="generate a signing key and raw base64 public key")
    keygen.add_argument("--private-key", required=True)
    keygen.add_argument("--public-key", required=True)
    sign = subparsers.add_parser("sign", help="sign a JSON content pack source")
    sign.add_argument("source")
    sign.add_argument("output")
    sign.add_argument("--private-key", required=True)
    sign.add_argument("--key-id", required=True)
    verify = subparsers.add_parser("verify", help="verify a pack with installed trust roots")
    verify.add_argument("pack")
    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            return _keygen(args.private_key, args.public_key)
        if args.command == "sign":
            source = json.loads(Path(args.source).read_text(encoding="utf-8"))
            data = sign_pack(source, args.private_key, args.key_id)
            output = Path(args.output)
            if output.exists():
                raise ContentPackError("Refusing to overwrite an existing content pack")
            output.write_bytes(data)
            return 0
        verified = verify_pack(args.pack)
        summary = {key: value for key, value in verified.items() if key not in {"abilities", "detection_bindings"}}
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    except (ContentPackError, OSError, ValueError, TypeError) as exc:
        print(f"Content pack operation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
