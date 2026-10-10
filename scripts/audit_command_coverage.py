"""Offline catalog/selection audit. Only --run-bounded executes synthetic fixtures.

Run as a module from the repository; --cache-dir must contain the pinned bundle.
Native, cloud, container and reconnaissance commands are never executed here.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import shutil
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from backend import attack_data
from backend.ability_model import catalog_ability
from backend.catalog_execution import PLATFORMS, identify_command, select_for_scope
from backend.command_catalog import CURATED
from backend.execution_kit import _apply_scope
from backend.lab_exercises import SCENARIOS, TECHNIQUE_SCENARIOS, run_exercise
from backend.platform_support import PORTABLE_GAPS


def _bash() -> str:
    """Return a working Bash. On Windows a bare "bash" can resolve to the WSL
    launcher in System32, which exits 1 without a distro; prefer Git Bash."""
    candidates = [shutil.which("bash")]
    if os.name == "nt":
        candidates += [r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files\Git\usr\bin\bash.exe"]
    for candidate in candidates:
        if not candidate:
            continue
        try:
            if subprocess.run([candidate, "--version"], capture_output=True, timeout=5, check=False).returncode == 0:
                return candidate
        except OSError:
            continue
    raise RuntimeError("A working Bash runtime is required to validate POSIX catalog commands")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def audit(cache: Path, output: Path, run_bounded: bool = False) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=True)
    attack_data.configure_cache_dir(str(cache))
    attack_data.configure_offline(True)
    attack_data.clear_memory_cache()
    index = attack_data.get_index(["enterprise"])
    actors = index.list_actors()
    techniques = {t["attack_id"]: t for actor in actors for t in index.actor_techniques(actor["stix_id"])}
    if set(techniques) - set(CURATED):
        raise ValueError(f"Actor-mapped techniques lack curated commands: {sorted(set(techniques) - set(CURATED))}")
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "schemas/adversaryflow-plan.schema.json").read_text())
    command_schema = {"$ref": "#/$defs/command", "$defs": schema["$defs"]}
    validator = Draft202012Validator(command_schema)
    ability_validator = Draft202012Validator(json.loads((root / "schemas/adversaryflow-ability.schema.json").read_text()))
    records = []
    syntax_count = 0
    bash = _bash()
    for tid, commands in sorted(CURATED.items()):
        for command in commands:
            if command != identify_command(command):
                raise ValueError(f"Invalid command identity: {tid}")
            if command["platform"] not in PLATFORMS or not command["prerequisites"] or not command["expected_telemetry"]:
                raise ValueError(f"Missing executor/prerequisite/telemetry declaration: {tid}")
            validator.validate(json.loads(json.dumps(command)))
            ability_validator.validate(json.loads(json.dumps(catalog_ability(tid, command).to_dict())))
            if command["platform"] != "windows":
                parsed = subprocess.run([bash, "-n", "-c", command["command"]], capture_output=True, text=True, timeout=5, check=False)
                if parsed.returncode:
                    raise ValueError(f"Invalid Bash syntax: {tid}: {parsed.stderr}")
                syntax_count += 1
            records.append({"technique_id": tid, **command})
    for tid, platforms in PORTABLE_GAPS.items():
        for platform in platforms:
            if not any(c["platform"] == platform and not c.get("unsupported") for c in CURATED[tid]):
                raise ValueError(f"Unfilled applicable coverage gap: {tid}/{platform}")
    cases = []
    matrix = []
    for tid, commands in sorted(CURATED.items()):
        info = techniques.get(tid, {"attack_id": tid, "name": tid, "platforms": []})
        for platform in PLATFORMS:
            compatible = [c for c in commands if c["platform"] == platform]
            for network, admin, high in itertools.product((False, True), repeat=3):
                scope = {"allow_network": network, "allow_admin": admin, "allow_high_risk": high}
                for selected_id in [None, *(c["command_id"] for c in compatible), "f" * 64]:
                    selected = select_for_scope(commands, platform, scope, selected_id)
                    if selected:
                        status = _apply_scope(selected, scope, platform).get("availability_status", "unsupported")
                    else:
                        endpoints = [p.lower() for p in info.get("platforms", []) if p.lower() in PLATFORMS]
                        na = not selected_id and endpoints and platform not in endpoints and all(c["environment"] == "endpoint" for c in commands)
                        status = "not_applicable" if na else "unsupported"
                    case = {"technique_id": tid, "platform": platform, **scope, "selected_id": selected_id,
                            "command_id": selected.get("command_id") if selected else None, "status": status}
                    cases.append(case)
                    if selected_id is None and not any((network, admin, high)) and tid in techniques:
                        matrix.append({**case, "name": info["name"], "attack_platforms": info.get("platforms", []),
                                       "fidelity": selected.get("fidelity") if selected else None,
                                       "required_tools": selected.get("required_tools", []) if selected else [],
                                       "required_credentials": selected.get("required_credentials", []) if selected else []})
    write(output / "catalog.json", {"techniques": [{**techniques.get(tid, {"attack_id": tid, "name": tid}),
                                                   "command_source": "curated", "commands": commands} for tid, commands in sorted(CURATED.items())],
                                    "cases": cases})
    write(output / "coverage-matrix.json", matrix)
    write(output / "command-records.json", records)
    receipts = []
    if run_bounded:
        receipt_dir = output / "receipts"
        receipt_dir.mkdir(exist_ok=True)
        for tid in sorted(TECHNIQUE_SCENARIOS):
            receipt = run_exercise(tid)
            payload = {k: v for k, v in receipt.items() if k != "receipt_sha256"}
            digest = sha(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
            if (receipt["status"] != "passed" or receipt["exit_code"] != 0 or not receipt["cleanup_verified"]
                    or digest != receipt["receipt_sha256"]):
                raise ValueError(f"Bounded fixture failed: {tid}")
            write(receipt_dir / f"{tid}.json", receipt)
            receipts.append(tid)
    summary = {"bundle_sha256": sha((cache / "enterprise-attack.json").read_bytes()), "data_version": index.data_version,
               "actors": len(actors), "mapped_techniques": len(techniques), "catalog_techniques": len(CURATED),
               "command_blocks": len(records), "bash_syntax_checks": syntax_count, "selection_cases": len(cases),
               "fidelity": dict(Counter(c["fidelity"] for c in records)),
               "default_availability": {p: dict(Counter(c["status"] for c in matrix if c["platform"] == p)) for p in PLATFORMS},
               "applicable_gaps_filled": sum(map(len, PORTABLE_GAPS.values())),
               "bounded_exercises": len(TECHNIQUE_SCENARIOS), "scenario_families": len(SCENARIOS), "receipts_passed": len(receipts),
               "limitations": ["Native Windows/macOS, Azure/AWS and Docker commands were not executed.",
                               "Tool/access declarations are not execution-host preflight or independent ATT&CK fidelity attestation.",
                               "Bounded receipts attest synthetic fixtures on this Linux host; they are self-reported.",
                               "Only the supplied cached Enterprise bundle is in this actor coverage audit."]}
    write(output / "summary.json", summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-bounded", action="store_true")
    args = parser.parse_args()
    print(json.dumps(audit(args.cache_dir.resolve(), args.output.resolve(), args.run_bounded), indent=2))


if __name__ == "__main__":
    main()
