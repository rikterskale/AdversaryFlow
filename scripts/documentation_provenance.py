"""Validate the high-impact documentation provenance register.

The register intentionally covers claims that can drift when interfaces,
routes, configuration, schemas, or CI support changes. It does not pretend to
prove the semantics of every prose sentence.
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REGISTER = ROOT / "docs" / "documentation_provenance.csv"
REQUIRED_COLUMNS = {
    "claim_id",
    "document",
    "anchor",
    "evidence_type",
    "evidence_path",
    "evidence_symbol",
    "verification",
}


def validate_register() -> list[str]:
    errors: list[str] = []
    if not REGISTER.is_file():
        return [f"missing provenance register: {REGISTER.relative_to(ROOT)}"]
    with REGISTER.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        columns = set(reader.fieldnames or ())
        missing = REQUIRED_COLUMNS - columns
        if missing:
            errors.append("provenance register is missing columns: " + ", ".join(sorted(missing)))
        seen: set[str] = set()
        for row_number, row in enumerate(reader, 2):
            claim_id = row.get("claim_id", "").strip()
            if not claim_id:
                errors.append(f"row {row_number} has no claim_id")
            elif claim_id in seen:
                errors.append(f"duplicate claim_id: {claim_id}")
            seen.add(claim_id)
            for field in REQUIRED_COLUMNS:
                if not row.get(field, "").strip():
                    errors.append(f"row {row_number} has an empty {field}")
            for field in ("document", "evidence_path"):
                value = row.get(field, "").strip()
                if value and not (ROOT / value).is_file():
                    errors.append(f"row {row_number} references missing {field}: {value}")
    return errors


def main() -> int:
    errors = validate_register()
    if errors:
        print("Documentation provenance gaps detected:")
        print("\n".join(f"- {error}" for error in errors))
        return 1
    print("Documentation provenance register passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
