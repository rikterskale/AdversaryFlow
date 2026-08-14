from pathlib import Path
from uuid import uuid4

import pytest
from adversaryflow.benign_procedures import assess, catalog, cleanup, run


def test_fixed_benign_procedures_are_local_reversible_and_assessable():
    result = run(["procedure-dummy-data-read", "procedure-canary-rename", "procedure-local-inventory"], Path("artifacts") / f"procedures-{uuid4()}")
    root = Path(result["run_dir"])
    assert len(result["procedures"]) == 3
    assert (root / "events.jsonl").is_file()
    assert (root / "work" / "canary.validation.checked").is_file()
    report = assess(root, ["procedure-local-inventory"])
    assert report["detection_gap_count"] == 2
    record = cleanup(root)
    assert record["scope"] == "run-owned work directory only"
    assert not (root / "work").exists()
    assert len(catalog()["procedures"]) >= 8
    with pytest.raises(ValueError):
        run([])
    with pytest.raises(ValueError):
        cleanup(root)
