from pathlib import Path


def test_powershell_installer_is_location_independent_and_non_editable_by_default():
    installer = Path("scripts/install.ps1").read_text(encoding="utf-8")
    assert "Split-Path -Parent $PSScriptRoot" in installer
    assert '"--upgrade", $projectRoot' in installer
    assert '"--editable", "$projectRoot[dev]"' in installer
    assert "Rename or remove it, then rerun this script." in installer


def test_shell_installer_is_location_independent_and_non_editable_by_default():
    installer = Path("scripts/install.sh").read_text(encoding="utf-8")
    assert '${BASH_SOURCE[0]}' in installer
    assert '--upgrade "$project_root"' in installer
    assert '--editable "${project_root}[dev]"' in installer
    assert "Rename or remove it, then rerun this script." in installer
