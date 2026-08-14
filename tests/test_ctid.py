from pathlib import Path
from uuid import uuid4

import pytest
from adversaryflow.ctid import assess_fixture_evidence, create_fixture_bundle, fixtures


def test_ctid_fixture_bundle_is_local_benign_and_retestable():
    root = Path("artifacts") / f"ctid-{uuid4()}"
    created = create_fixture_bundle(root)
    bundle = Path(created["bundle"])
    assert (bundle / "fixtures.jsonl").is_file()
    assert (bundle / "manifest.json").is_file()
    assert len(created["fixtures"]) == 4
    assert all(item["source"] in {"entra-audit", "entra-signin", "endpoint"} for item in created["fixtures"])
    report = assess_fixture_evidence(bundle, ["fixture-suspicious-sign-in"])
    assert report["expected_fixture_count"] == 4
    assert report["observed_fixture_count"] == 1
    assert report["detection_gap_count"] == 3
    assert (bundle / "ctid-detection-gap-report.json").is_file()
    assert (bundle / "training-timeline.md").is_file()
    retest = create_fixture_bundle(root, created["run_id"])
    assert retest["run_id"] != created["run_id"]
    assert fixtures()["vocabulary"]["scenario"].startswith("CTID APT29")
    with pytest.raises(ValueError, match="inside the current working directory"):
        create_fixture_bundle(Path.cwd().parent)
