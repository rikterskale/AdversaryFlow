import argparse
import json
import sys
from pathlib import Path

import yaml

from .audit import AuditLog
from . import __version__
from .ai import CampaignRequest, OfflinePlanner, validate_ai_draft
from .emulation import curated_linux_catalog_path, curated_macos_catalog_path, curated_windows_catalog_path, default_catalog_path, idpt_windows_collection_catalog_path, load_catalog
from .adapters import adapter_readiness
from .workflow import approve_draft, build_gap_report, campaign_integrity_hashes, load_campaign_draft, run_local_emulation, save_campaign_draft, verify_campaign_integrity
from .reports import write_campaign_reports
from .campaign_service import complete_saved_campaign
from .lifecycle import cancel_campaign, inspect_campaign, list_campaigns, reject_campaign, reset_campaign
from .doctor import run_doctor
from .support import create_support_bundle
from .provider import OpenAICompatiblePlanner, ProviderError, load_provider_config, provider_setup_instructions, validate_provider_config
from .profiles import activation_summary, allow_profile, list_profiles, policy_summary, remove_profile, save_profile, use_profile
from .manager import serve as serve_manager
from .intel import fetch_attack_bundle, fetch_ctid_technique_ids, find_technique
from .enrichment import build_enriched_coverage, write_enriched_coverage
from .benign_procedures import catalog as benign_procedure_catalog
from .models import RulesOfEngagement
from .planner import build_plan
from .coverage import coverage_dashboard
from .detection_mappings import write_bundle as write_detection_bundle
from .retest import create_gap_retest
from .product_tools import export_executive_summary, search_campaign_archive, update_campaign_archive, update_campaign_tags
from .telemetry import SUPPORTED_SOURCES, export_assessment, load_telemetry_records, normalize_export, planned_sensor_preflight, sensor_preflight, write_normalized
from .output import ExitCode, EXIT_CODE_HELP, respond, progress, dry_run_banner, severity, supports_color
from .completion import SUPPORTED_SHELLS
from .product_features import adapter_compatibility, author_catalog, branch_campaign, cleanup_retention, coverage_trends, import_detection_rules, list_campaign_templates, retention_preview, save_campaign_template, schedule_retest, score_detection_rules


def load_roe(path: str) -> RulesOfEngagement:
    if not Path(path).exists() and path == "examples/roe.yaml":
        path = str(__import__("importlib.resources", fromlist=["files"]).files("adversaryflow.resources").joinpath("roe.yaml"))
    with Path(path).open(encoding="utf-8") as handle:
        return RulesOfEngagement.from_mapping(yaml.safe_load(handle) or {})


def _quote_command(value: str) -> str:
    return '"' + value.replace('"', "") + '"'


def _pick_campaign(campaign_root: str) -> str | None:
    """Offer an interactive numbered picker of saved campaigns on a real terminal.

    Returns the chosen campaign id, or ``None`` when non-interactive or on any
    empty/invalid selection, so callers fall back to their normal usage error.
    """
    if not (sys.stdin.isatty() and sys.stderr.isatty()):
        return None
    try:
        campaigns = list_campaigns(campaign_root)
    except (OSError, ValueError):
        return None
    if not campaigns:
        return None
    sys.stderr.write("Select a saved campaign to resume (or press Enter to cancel):\n")
    for index, campaign in enumerate(campaigns, 1):
        sys.stderr.write(f"  {index}. {campaign.get('campaign_id')}  [{campaign.get('status', 'unknown')}]\n")
    sys.stderr.flush()
    try:
        choice = input("Campaign number: ").strip()
    except EOFError:
        return None
    if not choice.isdigit():
        return None
    number = int(choice)
    if 1 <= number <= len(campaigns):
        return str(campaigns[number - 1].get("campaign_id"))
    return None


def _campaign_table(campaigns: list[dict], *, enabled: bool) -> str:
    """Render saved campaigns as an aligned, severity-coloured text table."""
    if not campaigns:
        return "No saved campaigns yet. Create a draft with: adversaryflow campaign --actor <name> --objective <goal>"
    level = {"completed": "ok", "awaiting-approval": "warn", "rejected": "fail", "cancelled": "fail"}
    width = max((len(str(c.get("campaign_id", ""))) for c in campaigns), default=9)
    lines = [f"{'CAMPAIGN'.ljust(width)}  STATUS"]
    for campaign in campaigns:
        status = str(campaign.get("status", "unknown"))
        badge = severity(status, "", level.get(status, "info"), enabled=enabled).rstrip()
        lines.append(f"{str(campaign.get('campaign_id', '')).ljust(width)}  {badge}")
    return "\n".join(lines)


def _campaign_result_human(result: dict, *, enabled: bool) -> str:
    """One-line human summary for a drafted or completed campaign."""
    campaign_id = result.get("campaign_id", "?")
    if result.get("run_dir"):
        return severity("COMPLETED", f"{campaign_id} · local run at {result['run_dir']}", "ok", enabled=enabled)
    if result.get("stage") == "drafted":
        return severity("DRAFTED", f"{campaign_id} · {result.get('provider', 'offline')} · approval required", "warn", enabled=enabled)
    return severity(str(result.get("stage", "done")).upper(), str(campaign_id), "info", enabled=enabled)


def _doctor_human(result: dict, *, enabled: bool) -> str:
    """Human doctor report: per-check verdicts plus an ordered remediation plan."""
    lines = []
    for item in result.get("checks", []):
        passed = item.get("passed")
        badge = severity("PASS" if passed else "FAIL", f"{item.get('name')}: {item.get('detail')}", "ok" if passed else "fail", enabled=enabled)
        lines.append(badge)
    if result.get("fixes_applied"):
        lines.append(f"FIXED local folders: {', '.join(result['fixes_applied'])}")
    for item in result.get("guided_fixes", []):
        lines.append(f"NEXT {item.get('check')}: {item.get('fix')}")
    provider_readiness = result.get("provider_readiness")
    if provider_readiness:
        ready = provider_readiness.get("ready")
        lines.append(severity("PROVIDER READY" if ready else "PROVIDER NOT READY", provider_readiness.get("detail", ""), "ok" if ready else "warn", enabled=enabled))
    if result.get("passed"):
        lines.append(severity("READY", "All local safety checks passed.", "ok", enabled=enabled))
    else:
        guided = result.get("guided_fixes", [])
        if guided:
            windows = "windows" in str(result.get("platform", "")).lower()
            activate = ".\\.venv\\Scripts\\Activate.ps1" if windows else "source .venv/bin/activate"
            lines.append("")
            lines.append("Suggested next steps (in order):")
            for index, item in enumerate(guided, 1):
                lines.append(f"  {index}. {item.get('fix', '').strip()}")
            lines.append(f"  {len(guided) + 1}. Activate the environment and re-check: {activate} && adversaryflow doctor --fix")
    return "\n".join(lines)


def _why(technique: str, catalog_path: str) -> dict[str, object]:
    chosen = technique.strip().upper()
    abilities = [a for a in load_catalog(catalog_path) if a.technique_id == chosen or a.technique_id.startswith(chosen + ".")]
    return {"technique": chosen, "boundary": "This explains reviewed local synthetic behavior only; it is not an intrusion procedure.", "abilities": [{"name": a.name, "technique_id": a.technique_id, "what_it_does_in_the_lab": a.simulation_action, "expected_detections": [t.description for t in a.expected_telemetry], "safety": "Fixed, local, simulation-only action; no remote execution or target contact."} for a in abilities]}


def _explain_last(run_dir: str | None, output: str | None) -> dict[str, object]:
    root = Path(run_dir) if run_dir else Path("artifacts/runs")
    candidates = [p for p in root.glob("**/telemetry-gap-report.json") if p.is_file()]
    if not candidates:
        raise FileNotFoundError("No telemetry-gap-report.json was found under the run directory")
    report_path = max(candidates, key=lambda p: p.stat().st_mtime)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    gaps = report.get("gaps", report.get("detection_gaps", []))
    if not isinstance(gaps, list): gaps = []
    lines = ["# Last local run", "", f"Source: `{report_path.parent}`", "", f"Detection gaps: {len(gaps)}", "", "## What to fix next", ""]
    lines.extend(f"- {item.get('technique_id', item.get('ability_id', 'unknown'))}: review expected telemetry and retest the missing signal" for item in gaps[:3] if isinstance(item, dict))
    result = {"run_dir": str(report_path.parent), "gap_count": len(gaps), "top_gaps": gaps[:3]}
    if output:
        Path(output).write_text("\n".join(lines) + "\n", encoding="utf-8"); result["markdown"] = output
    return result


def interactive_workflow(roe_path: str = "examples/roe.yaml", catalog_path: str = "content/abilities/catalog.json", campaign_root: str = "artifacts/campaigns") -> None:
    """Run the safe MVP workflow as a guided terminal conversation."""
    print("AdversaryFlow interactive guide — LOCAL LAB ONLY")
    print("I will explain each step. Nothing executes without an explicit approval phrase.\n")
    doctor = run_doctor()
    print(f"[1/5] Local readiness: {'ready' if doctor['passed'] else 'needs attention'}")
    if not doctor["passed"]:
        print("I can apply only safe local folder fixes; no target or provider is contacted.")
        if input("Apply the safe local fix now? [Y/n] ").strip().lower() in {"", "y", "yes"}:
            doctor = run_doctor(fix=True)
            print("Readiness refreshed: " + ("ready" if doctor["passed"] else "still needs attention"))
        if not doctor["passed"]:
            print("Pause here, fix the listed readiness issues, then restart with: adversaryflow")
            return
    def ask(label: str, default: str) -> str:
        value = input(f"{label} [{default}]: ").strip()
        return value or default
    actor = ask("[2/5] Who are you modeling for defensive validation?", "APT29")
    objective = ask("What defensive outcome do you want to validate?", "validate endpoint process visibility")
    target = ask("RoE-approved target", "local-lab")
    platform = ask("Lab platform", "linux")
    print("\n[3/5] Building a fixed offline draft. This saves a reviewable plan only.")
    roe = load_roe(roe_path); abilities = load_catalog(catalog_path)
    draft = OfflinePlanner().draft(CampaignRequest(actor, target, objective, platform), abilities)
    validate_ai_draft(draft, roe, abilities)
    integrity = campaign_integrity_hashes(draft, roe, abilities)
    campaign_dir = save_campaign_draft(draft, integrity["plan_hash"], "offline", campaign_root, roe_hash=integrity["roe_sha256"], catalog_hash=integrity["catalog_sha256"], provider_metadata={"provider": "offline", "status": "interactive"})
    print(f"[4/5] Draft saved as {campaign_dir.name}. Review its scope, abilities, telemetry, and stop conditions.")
    if input("Open the read-only JSON review now? [Y/n] ").strip().lower() in {"", "y", "yes"}:
        print(json.dumps(inspect_campaign(campaign_root, campaign_dir.name), indent=2))
    if input("Proceed to the approval checkpoint? [y/N] ").strip().lower() not in {"y", "yes"}:
        print(f"[5/5] Done. Review later with: adversaryflow campaign inspect --campaign-id {campaign_dir.name}")
        return
    approver = ask("Named RoE approver", roe.approver_name)
    print("Approval starts only the fixed local synthetic adapter; it does not contact an external target.")
    if input(f"Type APPROVE {campaign_dir.name} to continue: ").strip() != f"APPROVE {campaign_dir.name}":
        print("[5/5] Approval cancelled. The draft remains reviewable and no run started.")
        return
    result = complete_saved_campaign(campaign_root, campaign_dir.name, roe, abilities, approver, "artifacts/runs")
    print(f"[5/5] Local synthetic run complete: {result.get('run_dir', 'see campaign record')}")


def completion_script(shell: str) -> str:
    commands = "interactive validate version why explain-last plan intel-sync draft demo doctor support-bundle capabilities adapter guide provider campaign telemetry detection coverage archive manager completion config template schedule retention branch catalog adapters"
    if shell == "bash":
        return f'_adversaryflow() {{ COMPREPLY=( $(compgen -W "{commands}" -- "${{COMP_WORDS[1]}}") ); }}\ncomplete -F _adversaryflow adversaryflow\n'
    if shell == "zsh":
        return f'#compdef adversaryflow\n_arguments "1:command:({commands})"\n'
    if shell == "fish":
        return f'complete -c adversaryflow -f -a "{commands}"\n'
    return f'Register-ArgumentCompleter -Native -CommandName adversaryflow -ScriptBlock {{ param($wordToComplete) "{commands}" -split " " | Where-Object {{ $_ -like "$wordToComplete*" }} }}\n'


CONFIG_KEYS = {"actor", "target", "objective", "platform", "catalog", "roe", "campaign_root", "output", "adapter", "fallback_offline"}


def load_cli_config(path: str | Path) -> dict[str, object]:
    try:
        config = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not load config {path}: {exc}") from exc
    if not isinstance(config, dict):
        raise ValueError("config must contain a JSON object")
    unknown = sorted(set(config) - CONFIG_KEYS)
    if unknown:
        raise ValueError(f"config contains unsupported keys: {', '.join(unknown)}")
    return config


def campaign_guide(actor: str, target: str, objective: str, interactive: bool) -> str:
    """Return a safe, copyable campaign walkthrough without executing a campaign."""
    if interactive:
        actor = input(f"Threat actor [{actor}]: ").strip() or actor
        target = input(f"RoE-approved target [{target}]: ").strip() or target
        objective = input(f"Defensive objective [{objective}]: ").strip() or objective
    draft_command = f"adversaryflow campaign --actor {_quote_command(actor)} --target {_quote_command(target)} --objective {_quote_command(objective)}"
    return "\n".join([
        "AdversaryFlow Campaign Guide (simulation-only)",
        "=" * 48,
        "This guide creates no campaign and runs no emulation. It only prepares your safe next command.",
        "",
        "1. Prepare the local environment",
        "   Run: adversaryflow doctor --json",
        "   Confirm your RoE and ability catalog pass before continuing.",
        "",
        "2. Confirm scope",
        f"   Target: {target}",
        "   The target must appear in the RoE allowlist and must not be excluded.",
        "   This tool permits only local synthetic simulation; it never creates exploit payloads, persistence, credential theft, evasion, lateral movement, or unrestricted network actions.",
        "",
        "3. Create a reviewable draft (no execution)",
        f"   Run: {draft_command}",
        "   This command creates a local draft only: it does not contact the target, run a command, use a hosted provider, approve the campaign, or start emulation.",
        "   Save the returned campaign ID. The draft is bound to its plan, RoE, and ability-catalog integrity hashes.",
        "",
        "4. Review before approval",
        "   Run: adversaryflow campaign inspect --campaign-id campaign-...",
        "   Check selected abilities, expected telemetry, stop conditions, assumptions, scope, and provider status.",
        "   If it should not proceed, record the decision with: adversaryflow campaign reject --campaign-id campaign-... --approver <RoE-approver> --reason \"Not scheduled\"",
        "",
        "5. Approve the local synthetic emulation",
        "   Only the approver named in the RoE can authorize it:",
        "   Run: adversaryflow campaign --campaign-id campaign-... --approve --approver <RoE-approver>",
        "   Resume rejects changed drafts, RoEs, or ability catalogs.",
        "",
        "6. Learn and retest",
        "   Review campaign-report.md, campaign-report.html, and telemetry-gap-report.json in the campaign/run artifacts.",
        "   Capture detection gaps, create a retest objective, and draft a new campaign rather than modifying an approved one.",
        "",
        "Need a visual walkthrough? Run: adversaryflow manager --open",
        "Need provider help? Run: adversaryflow provider diagnose",
        "Need diagnostics? Run: adversaryflow support-bundle",
    ])


def main() -> None:
    parser = argparse.ArgumentParser(prog="adversaryflow", description="Scoped purple-team campaign planning", epilog="Quick start: doctor --json, guide, campaign --actor APT29 --objective \"validate endpoint process visibility\", then campaign inspect --campaign-id ID.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config", help="optional JSON file containing shared CLI defaults")
    parser.add_argument("--quiet", action="store_true", help="suppress non-essential progress text")
    parser.add_argument("--interactive", action="store_true", help="launch the guided terminal workflow")
    # Output-mode flags shared by every subcommand (place after the command name).
    io_parent = argparse.ArgumentParser(add_help=False)
    io_group = io_parent.add_argument_group("output")
    io_group.add_argument("--json", action="store_true", help="force machine-readable JSON output")
    io_group.add_argument("--human", action="store_true", help="force human-readable output even when piped")
    io_group.add_argument("--verbose", action="store_true", help="include extra detail where available")
    io_group.add_argument("--no-color", action="store_true", help="disable ANSI colour in human output")
    # Guarantee the output attributes exist even when no subcommand (e.g. interactive) is used.
    parser.set_defaults(json=False, human=False, verbose=False, no_color=False)
    sub = parser.add_subparsers(dest="command", required=False)
    sub.add_parser("interactive", help="run the guided local-lab workflow")
    sub.add_parser("version", help="print the installed AdversaryFlow version")
    why = sub.add_parser("why", help="explain a reviewed technique in plain language")
    why.add_argument("technique")
    why.add_argument("--catalog", default="content/abilities/catalog.json")
    explain = sub.add_parser("explain-last", help="summarize the newest local run and its top gaps")
    explain.add_argument("--run-dir", default=None)
    explain.add_argument("--output", default=None)
    validate = sub.add_parser("validate", parents=[io_parent])
    validate.add_argument("roe")
    plan = sub.add_parser("plan", parents=[io_parent])
    plan.add_argument("--roe", required=True)
    plan.add_argument("--actor", required=True)
    plan.add_argument("--target", default="local-lab")
    plan.add_argument("--technique", required=True)
    plan.add_argument("--attack-bundle", help="read an ATT&CK STIX bundle from a local JSON file instead of fetching it")
    plan.add_argument("--audit", default="artifacts/audit.jsonl")
    intel_sync = sub.add_parser("intel-sync", parents=[io_parent], help="pull ATT&CK/CTID technique metadata and create synthetic-only coverage")
    intel_sync.add_argument("--actor", required=True)
    intel_sync.add_argument("--platform", default="windows")
    intel_sync.add_argument("--target", default="local-lab")
    intel_sync.add_argument("--catalog", default="content/abilities/catalog.json")
    intel_sync.add_argument("--output", default="artifacts/intel/enriched")
    intel_sync.add_argument("--mitre-only", action="store_true", help="skip the CTID library lookup")
    draft = sub.add_parser("draft", parents=[io_parent])
    draft.add_argument("--roe", required=True)
    draft.add_argument("--actor", required=True)
    draft.add_argument("--objective", required=True)
    draft.add_argument("--target", default="local-lab")
    draft.add_argument("--platform", default="linux")
    draft.add_argument("--catalog", default="content/abilities/catalog.json")
    demo = sub.add_parser("demo", parents=[io_parent], help="run the complete safe local workflow")
    demo.add_argument("--roe", default="examples/roe.yaml")
    demo.add_argument("--actor", default="APT29")
    demo.add_argument("--objective", default="validate endpoint process visibility")
    demo.add_argument("--platform", default="linux")
    demo.add_argument("--approver", default=None)
    demo.add_argument("--catalog", default="content/abilities/catalog.json")
    demo.add_argument("--output", default="artifacts/runs")
    demo.add_argument("--adapter", choices=("local-synthetic", "local-behavioral", "idpt-local"), default="local-synthetic")
    doctor = sub.add_parser("doctor", parents=[io_parent], help="diagnose installation and local runtime")
    doctor.add_argument("--roe", default="examples/roe.yaml")
    doctor.add_argument("--catalog", default="content/abilities/catalog.json")
    doctor.add_argument("--fix", action="store_true", help="apply safe local fixes, then diagnose again")
    support = sub.add_parser("support-bundle", parents=[io_parent], help="create a redacted troubleshooting bundle")
    support.add_argument("--output", default="artifacts/support")
    support.add_argument("--roe", default="examples/roe.yaml")
    sub.add_parser("capabilities", parents=[io_parent], help="list advertised capabilities")
    completion = sub.add_parser("completion", parents=[io_parent], help="print a shell completion script")
    completion.add_argument("shell", choices=SUPPORTED_SHELLS, help="the shell to generate completion for")
    explain = sub.add_parser("explain", parents=[io_parent], help="explain a process exit code")
    explain.add_argument("code", nargs="?", type=int, help="exit code to explain; omit to list all")
    adapter = sub.add_parser("adapter", parents=[io_parent], help="inspect the fixed local execution adapter")
    adapter_sub = adapter.add_subparsers(dest="adapter_command", required=True)
    adapter_status = adapter_sub.add_parser("status", help="show read-only adapter readiness")
    adapter_status.add_argument("--catalog", default="content/abilities/catalog.json")
    adapter_status.add_argument("--name", choices=("local-synthetic", "local-behavioral", "idpt-local"), default="local-synthetic")
    guide = sub.add_parser("guide", parents=[io_parent], help="walk through the safe campaign workflow and next steps")
    guide.add_argument("--actor", default="APT29")
    guide.add_argument("--target", default="local-lab")
    guide.add_argument("--objective", default="validate endpoint process visibility")
    guide.add_argument("--interactive", action="store_true", help="prompt for draft-command details without executing a campaign")
    config_command = sub.add_parser("config", help="validate shared JSON CLI defaults")
    config_sub = config_command.add_subparsers(dest="config_command", required=True)
    config_validate = config_sub.add_parser("validate", help="check supported keys without applying defaults")
    config_validate.add_argument("file")
    template = sub.add_parser("template", help="manage reusable local campaign templates")
    template_sub = template.add_subparsers(dest="template_command", required=True)
    template_save = template_sub.add_parser("save"); template_save.add_argument("name"); template_save.add_argument("--actor", required=True); template_save.add_argument("--objective", required=True); template_save.add_argument("--target", default="local-lab"); template_save.add_argument("--platform", default="linux"); template_save.add_argument("--root", default="artifacts/templates")
    template_sub.add_parser("list").add_argument("--root", default="artifacts/templates")
    schedule = sub.add_parser("schedule", help="create local review and retest schedules")
    schedule_create = schedule.add_subparsers(dest="schedule_command", required=True).add_parser("create"); schedule_create.add_argument("name"); schedule_create.add_argument("--template", required=True); schedule_create.add_argument("--cadence-days", required=True, type=int); schedule_create.add_argument("--root", default="artifacts/schedules")
    retention = sub.add_parser("retention", help="preview or explicitly clean expired local campaign artifacts")
    retention_sub = retention.add_subparsers(dest="retention_command", required=True)
    retention_preview_command = retention_sub.add_parser("preview"); retention_preview_command.add_argument("--campaign-root", default="artifacts/campaigns")
    retention_cleanup_command = retention_sub.add_parser("cleanup"); retention_cleanup_command.add_argument("--campaign-root", default="artifacts/campaigns"); retention_cleanup_command.add_argument("--confirm", action="store_true")
    provider = sub.add_parser("provider", parents=[io_parent], help="configure and validate AI provider settings")
    provider_sub = provider.add_subparsers(dest="provider_command", required=True)
    provider_sub.add_parser("status", help="show redacted provider configuration")
    provider_sub.add_parser("validate", help="validate settings without network access")
    provider_sub.add_parser("configure", help="show provider configuration instructions")
    provider_sub.add_parser("diagnose", help="show guided provider troubleshooting")
    profile = provider_sub.add_parser("profile", help="manage non-secret provider profiles")
    profile_sub = profile.add_subparsers(dest="profile_command", required=True)
    profile_sub.add_parser("list")
    profile_sub.add_parser("status", help="show whether the active profile is ready without revealing credentials")
    profile_use = profile_sub.add_parser("use")
    profile_use.add_argument("name")
    profile_save = profile_sub.add_parser("save")
    profile_save.add_argument("name")
    profile_save.add_argument("--provider", default="openai-compatible")
    profile_save.add_argument("--endpoint", required=True)
    profile_save.add_argument("--model", required=True)
    profile_save.add_argument("--credential-env", default="ADVERSARYFLOW_API_KEY")
    profile_remove = profile_sub.add_parser("remove")
    profile_remove.add_argument("name")
    policy = provider_sub.add_parser("policy", help="inspect or update the local hosted-provider allowlist")
    policy_sub = policy.add_subparsers(dest="policy_command", required=True)
    policy_sub.add_parser("status", help="show the non-secret profile allowlist")
    policy_allow = policy_sub.add_parser("allow", help="allow the exact endpoint and model of a saved profile")
    policy_allow.add_argument("name")
    test_provider = provider_sub.add_parser("test", help="send one harmless planning request")
    test_provider.add_argument("--actor", default="APT29")
    test_provider.add_argument("--target", default="local-lab")
    test_provider.add_argument("--objective", default="validate endpoint process visibility")
    test_provider.add_argument("--roe", default="examples/roe.yaml", help="Rules of Engagement used to validate the returned draft")
    test_provider.add_argument("--platform", default="linux")
    test_provider.add_argument("--catalog", default="content/abilities/catalog.json")
    campaign = sub.add_parser("campaign", parents=[io_parent], help="draft, validate, approve, and optionally emulate a campaign")
    campaign.add_argument("--roe", default="examples/roe.yaml")
    campaign.add_argument("--actor", default=None)
    campaign.add_argument("--target", default="local-lab")
    campaign.add_argument("--objective", default=None)
    campaign.add_argument("--platform", default="linux")
    campaign.add_argument("--approver", default=None)
    campaign.add_argument("--approve", action="store_true", help="approve and run the safe local emulation")
    campaign.add_argument("--fallback-offline", action="store_true", help="use the offline planner if the configured provider fails")
    campaign.add_argument("--catalog", default="content/abilities/catalog.json")
    campaign.add_argument("--output", default="artifacts/runs")
    campaign.add_argument("--campaign-root", default="artifacts/campaigns")
    campaign.add_argument("--campaign-id", default=None, help="resume a saved campaign directory")
    campaign.add_argument("--adapter", choices=("local-synthetic", "local-behavioral", "idpt-local"), default="local-synthetic", help="fixed execution adapter used only after approval")
    campaign.add_argument("--sensor-manifest", default=None, help="optional read-only sensor-health snapshot required to pass before execution")
    campaign_sub = campaign.add_subparsers(dest="lifecycle_command")
    list_campaign = campaign_sub.add_parser("list", help="list saved campaigns")
    list_campaign.add_argument("--campaign-root", default="artifacts/campaigns")
    inspect = campaign_sub.add_parser("inspect", help="inspect a saved campaign")
    inspect.add_argument("--campaign-id", required=True)
    inspect.add_argument("--campaign-root", default="artifacts/campaigns")
    reject = campaign_sub.add_parser("reject", help="record a campaign rejection")
    reject.add_argument("--campaign-id", required=True)
    reject.add_argument("--approver", required=True)
    reject.add_argument("--reason", required=True)
    reject.add_argument("--campaign-root", default="artifacts/campaigns")
    cancel = campaign_sub.add_parser("cancel", help="request cancellation of an incomplete campaign")
    cancel.add_argument("--campaign-id", required=True)
    cancel.add_argument("--reason", required=True)
    cancel.add_argument("--campaign-root", default="artifacts/campaigns")
    reset = campaign_sub.add_parser("reset", help="delete a saved campaign")
    reset.add_argument("--campaign-id", required=True)
    reset.add_argument("--confirm", action="store_true")
    reset.add_argument("--campaign-root", default="artifacts/campaigns")
    assess = campaign_sub.add_parser("assess", help="correlate completed behavior with EDR/SIEM telemetry JSONL")
    assess.add_argument("--campaign-id", required=True)
    assess.add_argument("--telemetry-file", required=True)
    assess.add_argument("--window-seconds", type=int, default=300)
    assess.add_argument("--campaign-root", default="artifacts/campaigns")
    retest = campaign_sub.add_parser("retest", help="create an immutable review draft from recorded detection gaps")
    retest.add_argument("--campaign-id", required=True)
    retest.add_argument("--campaign-root", default="artifacts/campaigns")
    telemetry = sub.add_parser("telemetry", parents=[io_parent], help="normalize and validate offline EDR/SIEM exports")
    telemetry_sub = telemetry.add_subparsers(dest="telemetry_command", required=True)
    telemetry_normalize = telemetry_sub.add_parser("normalize")
    telemetry_normalize.add_argument("--source", choices=tuple(sorted(SUPPORTED_SOURCES)), required=True)
    telemetry_normalize.add_argument("--input", required=True)
    telemetry_normalize.add_argument("--output", required=True)
    telemetry_preflight = telemetry_sub.add_parser("preflight")
    telemetry_preflight.add_argument("--run-dir")
    telemetry_preflight.add_argument("--telemetry-file")
    telemetry_preflight.add_argument("--sensor-manifest")
    telemetry_preflight.add_argument("--catalog", default="content/abilities/catalog.json")
    telemetry_preflight.add_argument("--target", default="local-lab")
    telemetry_export = telemetry_sub.add_parser("export")
    telemetry_export.add_argument("--run-dir", required=True)
    telemetry_export.add_argument("--format", choices=("json", "csv"), required=True)
    telemetry_export.add_argument("--output", required=True)
    detection = sub.add_parser("detection", parents=[io_parent], help="export defensive detection-as-code validation mappings")
    detection_sub = detection.add_subparsers(dest="detection_command", required=True)
    detection_export = detection_sub.add_parser("export")
    detection_export.add_argument("--catalog", default="content/abilities/catalog.json")
    detection_export.add_argument("--output", default="artifacts/detection-mappings")
    detection_import = detection_sub.add_parser("import", help="import offline detection rules for local scoring")
    detection_import.add_argument("--input", required=True)
    detection_import.add_argument("--output", default="artifacts/detection-rules")
    detection_score = detection_sub.add_parser("score", help="score imported rules against local campaign evidence")
    detection_score.add_argument("--rules", required=True)
    detection_score.add_argument("--campaign-root", default="artifacts/campaigns")
    coverage = sub.add_parser("coverage", parents=[io_parent], help="show actor-to-detection campaign coverage")
    coverage.add_argument("--campaign-root", default="artifacts/campaigns")
    coverage_sub = coverage.add_subparsers(dest="coverage_command")
    coverage_trends_command = coverage_sub.add_parser("trends", help="show read-only historical coverage trends")
    coverage_trends_command.add_argument("--campaign-root", default="artifacts/campaigns")
    branch = sub.add_parser("branch", help="create a new review draft from a saved campaign")
    branch.add_argument("--campaign-id", required=True); branch.add_argument("--name", required=True); branch.add_argument("--campaign-root", default="artifacts/campaigns")
    catalog = sub.add_parser("catalog", help="author and validate local catalog drafts")
    catalog.add_argument("--source", required=True); catalog.add_argument("--output", required=True); catalog.add_argument("--name", required=True); catalog.add_argument("--version", required=True)
    adapters = sub.add_parser("adapters", help="discover read-only adapter compatibility")
    adapters.add_argument("--catalog", default="content/abilities/catalog.json")
    archive = sub.add_parser("archive", help="search and manage local campaign archive metadata")
    archive_sub = archive.add_subparsers(dest="archive_command", required=True)
    archive_search = archive_sub.add_parser("search", help="search saved campaigns by text or tag")
    archive_search.add_argument("--query", default="")
    archive_search.add_argument("--tag", default="")
    archive_search.add_argument("--campaign-root", default="artifacts/campaigns")
    archive_tag = archive_sub.add_parser("tag", help="replace a campaign's normalized archive tags")
    archive_tag.add_argument("--campaign-id", required=True)
    archive_tag.add_argument("--tags", default="", help="comma-separated tags")
    archive_tag.add_argument("--campaign-root", default="artifacts/campaigns")
    archive_controls = archive_sub.add_parser("controls", help="set campaign owner and retention metadata")
    archive_controls.add_argument("--campaign-id", required=True)
    archive_controls.add_argument("--owner", required=True)
    archive_controls.add_argument("--retention-days", required=True, type=int)
    archive_controls.add_argument("--campaign-root", default="artifacts/campaigns")
    archive_export = archive_sub.add_parser("export", help="write a local Markdown and PDF executive summary")
    archive_export.add_argument("--campaign-id", required=True)
    archive_export.add_argument("--output", default="artifacts/exports")
    archive_export.add_argument("--campaign-root", default="artifacts/campaigns")
    manager = sub.add_parser("manager", parents=[io_parent], help="start the loopback-only guided campaign workspace")
    manager.add_argument("--host", default="127.0.0.1")
    manager.add_argument("--port", type=int, default=8787)
    manager.add_argument("--campaign-root", default="artifacts/campaigns")
    manager.add_argument("--roe", default="examples/roe.yaml", help="Rules of Engagement used to validate browser-created offline drafts")
    manager.add_argument("--catalog", default="content/abilities/catalog.json", help="safe ability catalog used to validate browser-created offline drafts")
    manager.add_argument("--open", action="store_true", help="open the local campaign guide in your default browser")
    args = parser.parse_args()
    if args.command in {None, "interactive"} or (args.interactive and args.command != "guide"):
        interactive_workflow()
        return
    if args.config:
        try:
            config = load_cli_config(args.config)
        except ValueError as exc:
            parser.error(str(exc))
        for key, value in config.items():
            if hasattr(args, key) and key not in {"command", "config", "quiet"}:
                setattr(args, key, value)
    if hasattr(args, "catalog") and not Path(args.catalog).exists() and args.catalog == "content/abilities/catalog.json":
        args.catalog = str(default_catalog_path())
    if hasattr(args, "catalog") and args.catalog == "curated-windows":
        args.catalog = str(curated_windows_catalog_path())
    if hasattr(args, "catalog") and args.catalog == "curated-linux":
        args.catalog = str(curated_linux_catalog_path())
    if hasattr(args, "catalog") and args.catalog == "curated-macos":
        args.catalog = str(curated_macos_catalog_path())
    if hasattr(args, "catalog") and args.catalog == "idpt-windows-collection":
        args.catalog = str(idpt_windows_collection_catalog_path())

    if args.command == "explain":
        if args.code is None:
            payload = {"exit_codes": [{"code": code, "meaning": text} for code, text in sorted(EXIT_CODE_HELP.items())]}
            human = "AdversaryFlow exit codes:\n" + "\n".join(f"  {code}  {text}" for code, text in sorted(EXIT_CODE_HELP.items()))
        else:
            meaning = EXIT_CODE_HELP.get(args.code, "Unknown exit code. AdversaryFlow does not define this value.")
            payload = {"code": args.code, "meaning": meaning}
            human = severity(str(args.code), meaning, "info", enabled=supports_color(no_color=args.no_color))
        respond(args, payload, human)
        return

    if args.command == "validate":
        roe = load_roe(args.roe)
        payload = {"valid": True, "engagement": roe.engagement_name, "dry_run": roe.dry_run}
        human = severity("VALID", f"{roe.engagement_name} · dry-run={roe.dry_run}", "ok", enabled=supports_color(no_color=args.no_color))
        respond(args, payload, human)
        return

    if args.command == "version":
        print(json.dumps({"name": "adversaryflow", "version": __version__}, indent=2))
        return

    if args.command == "why":
        print(json.dumps(_why(args.technique, args.catalog), indent=2))
        return

    if args.command == "explain-last":
        print(json.dumps(_explain_last(args.run_dir, args.output), indent=2))
        return

    if args.command == "config":
        try:
            config = load_cli_config(args.file)
            print(json.dumps({"valid": True, "file": str(Path(args.file)), "keys": sorted(config)}, indent=2))
        except ValueError as exc:
            print(json.dumps({"valid": False, "file": str(Path(args.file)), "error": str(exc)}, indent=2))
            raise SystemExit(1)
        return

    if args.command == "template":
        if args.template_command == "save":
            print(json.dumps(save_campaign_template(args.name, args.actor, args.objective, args.target, args.platform, args.root), indent=2))
        else:
            print(json.dumps(list_campaign_templates(args.root), indent=2))
        return

    if args.command == "schedule":
        print(json.dumps(schedule_retest(args.name, args.template, args.cadence_days, args.root), indent=2))
        return

    if args.command == "retention":
        if args.retention_command == "preview":
            print(json.dumps(retention_preview(args.campaign_root), indent=2))
        else:
            print(json.dumps(cleanup_retention(args.campaign_root, args.confirm), indent=2))
        return

    if args.command == "branch":
        print(json.dumps(branch_campaign(args.campaign_root, args.campaign_id, args.name), indent=2)); return
    if args.command == "catalog":
        print(json.dumps(author_catalog(args.source, args.output, args.name, args.version), indent=2)); return
    if args.command == "adapters":
        print(json.dumps(adapter_compatibility(args.catalog), indent=2)); return

    if args.command == "guide":
        print(campaign_guide(args.actor, args.target, args.objective, args.interactive))
        return

    if args.command == "completion":
        print(completion_script(args.shell), end="")
        return

    if args.command == "intel-sync":
        try:
            progress("Fetching official MITRE ATT&CK STIX bundle", 1, 3)
            bundle = fetch_attack_bundle()
            progress("Looking up CTID technique metadata" if not args.mitre_only else "Skipping CTID lookup (--mitre-only)", 2, 3)
            ctid_ids = () if args.mitre_only else fetch_ctid_technique_ids(args.actor)
            progress("Building synthetic-only coverage", 3, 3)
            coverage = build_enriched_coverage(args.actor, args.platform, bundle, ctid_ids, args.catalog, benign_procedure_catalog())
            result = write_enriched_coverage(coverage, args.output, args.target)
            respond(args, {"success": True, **result})
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            respond(args, {"success": False, "error": str(exc), "boundary": "No commands or payloads are imported."}, exit_code=ExitCode.ERROR)
        return

    if args.command == "adapter":
        abilities = load_catalog(args.catalog)
        readiness = adapter_readiness(abilities, args.name)
        level = "ok" if readiness["compatible"] else "fail"
        human = severity("READY" if readiness["compatible"] else "NOT READY", f"{args.name}: {readiness['detail']}", level, enabled=supports_color(no_color=args.no_color))
        respond(args, readiness, human)
        raise SystemExit(ExitCode.OK if readiness["compatible"] else ExitCode.ERROR)

    if args.command == "telemetry":
        try:
            if args.telemetry_command == "normalize":
                records = normalize_export(args.source, args.input)
                output = write_normalized(records, args.output)
                result = {"success": True, "source": args.source, "record_count": len(records), "output": str(output), "boundary": "Offline export only; no vendor API was queried."}
            else:
                if args.telemetry_command == "preflight" and args.sensor_manifest:
                    abilities = load_catalog(args.catalog)
                    categories = {item.category for ability in abilities for item in ability.expected_telemetry}
                    result = planned_sensor_preflight(categories, args.target, args.sensor_manifest)
                else:
                    if not args.run_dir:
                        raise ValueError("telemetry command requires --run-dir")
                    root = Path(args.run_dir)
                    events = [json.loads(line) for line in (root / "events.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
                    if args.telemetry_command == "preflight" and args.telemetry_file:
                        result = sensor_preflight(events, root.name, load_telemetry_records(args.telemetry_file))
                    elif args.telemetry_command == "preflight":
                        raise ValueError("telemetry preflight requires --sensor-manifest or both --run-dir and --telemetry-file")
                    else:
                        report = json.loads((root / "telemetry-gap-report.json").read_text(encoding="utf-8"))
                        result = {"success": True, "output": str(export_assessment(report, args.output, args.format))}
            respond(args, result)
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            respond(args, {"success": False, "error": str(exc)}, exit_code=ExitCode.ERROR)
        return

    if args.command == "detection":
        if args.detection_command == "export":
            result = write_detection_bundle(load_catalog(args.catalog), args.output)
        elif args.detection_command == "import":
            result = import_detection_rules(args.input, args.output)
        else:
            result = score_detection_rules(args.campaign_root, args.rules)
        respond(args, result)
        return

    if args.command == "coverage":
        if args.coverage_command == "trends":
            respond(args, coverage_trends(args.campaign_root))
        else:
            dashboard = coverage_dashboard(args.campaign_root)
            summary = dashboard.get("summary", {}) if isinstance(dashboard, dict) else {}
            human = severity("COVERAGE", f"{summary.get('campaigns', 0)} campaigns · {summary.get('techniques', 0)} techniques · {summary.get('detections', 0)} detections · {summary.get('gaps', 0)} gaps", "info", enabled=supports_color(no_color=args.no_color))
            respond(args, dashboard, human)
        return

    if args.command == "manager":
        if args.quiet:
            serve_manager(args.host, args.port, args.campaign_root, args.open, args.roe, args.catalog, quiet=True)
        else:
            serve_manager(args.host, args.port, args.campaign_root, args.open, args.roe, args.catalog)
        return

    if args.command == "campaign":
        if args.lifecycle_command == "list":
            campaigns = list_campaigns(args.campaign_root)
            human = _campaign_table(campaigns, enabled=supports_color(no_color=args.no_color))
            respond(args, campaigns, human)
            return
        if args.lifecycle_command == "inspect":
            try:
                respond(args, inspect_campaign(args.campaign_root, args.campaign_id))
            except (OSError, ValueError) as exc:
                respond(args, {"success": False, "error": str(exc)}, exit_code=ExitCode.ERROR)
            return
        if args.lifecycle_command == "reject":
            try:
                path = reject_campaign(args.campaign_root, args.campaign_id, args.approver, args.reason)
                respond(args, {"success": True, "status": "rejected", "record": str(path)})
            except (OSError, KeyError, ValueError) as exc:
                respond(args, {"success": False, "error": str(exc)}, exit_code=ExitCode.ERROR)
            return
        if args.lifecycle_command == "cancel":
            try:
                path = cancel_campaign(args.campaign_root, args.campaign_id, args.reason)
                respond(args, {"success": True, "status": "cancelled", "record": str(path)})
            except (OSError, KeyError, ValueError) as exc:
                respond(args, {"success": False, "error": str(exc)}, exit_code=ExitCode.ERROR)
            return
        if args.lifecycle_command == "reset":
            try:
                reset_campaign(args.campaign_root, args.campaign_id, args.confirm)
                respond(args, {"success": True, "status": "reset", "campaign_id": args.campaign_id})
            except (OSError, ValueError, PermissionError) as exc:
                respond(args, {"success": False, "error": str(exc)}, exit_code=ExitCode.ERROR)
            return
        if args.lifecycle_command == "assess":
            try:
                campaign_record = inspect_campaign(args.campaign_root, args.campaign_id)
                metadata = campaign_record.get("metadata", {})
                if metadata.get("status") != "completed" or not metadata.get("run_dir"):
                    raise ValueError("Only a completed campaign with a run directory can be assessed")
                report = build_gap_report(metadata["run_dir"], args.telemetry_file, args.window_seconds)
                write_campaign_reports(campaign_record["campaign_dir"], metadata["run_dir"])
                respond(args, {"success": True, "campaign_id": args.campaign_id, "assessment": report})
            except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
                respond(args, {"success": False, "error": str(exc)}, exit_code=ExitCode.ERROR)
            return
        if args.lifecycle_command == "retest":
            try:
                result = create_gap_retest(args.campaign_root, args.campaign_id, load_roe(args.roe), load_catalog(args.catalog))
                respond(args, {"success": True, **result})
            except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
                respond(args, {"success": False, "error": str(exc)}, exit_code=ExitCode.ERROR)
            return
        roe = load_roe(args.roe)
        abilities = load_catalog(args.catalog)
        config = load_provider_config()
        if not args.campaign_id and not (args.actor and args.objective):
            args.campaign_id = _pick_campaign(args.campaign_root)
        if args.campaign_id:
            try:
                campaign_dir = Path(args.campaign_root) / args.campaign_id
                draft_result, saved_metadata = load_campaign_draft(campaign_dir)
                integrity = campaign_integrity_hashes(draft_result, roe, abilities)
                verify_campaign_integrity(draft_result, saved_metadata, roe, abilities)
                plan_hash = integrity["plan_hash"]
                validate_ai_draft(draft_result, roe, abilities)
                provider_name = saved_metadata["provider"]
            except (OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
                respond(args, {"success": False, "stage": "resume", "error": f"Could not resume campaign: {exc}"}, exit_code=ExitCode.ERROR)
        else:
            if not args.actor or not args.objective:
                parser.error("campaign requires --actor and --objective when --campaign-id is not supplied")
            dry_run_banner(
                will=["draft a local, RoE-validated plan", "record integrity hashes for later review"],
                will_not=["contact a target", "run a command", "approve or execute anything"],
            )
            request = CampaignRequest(args.actor, args.target, args.objective, args.platform)
            provider_name = config.name
            try:
                provider_metadata = {"provider": config.name, "status": "offline"}
                if config.name == "offline":
                    draft_result = OfflinePlanner().draft(request, abilities)
                elif config.name == "openai-compatible":
                    planner = OpenAICompatiblePlanner(config)
                    draft_result = planner.draft(request, abilities)
                    provider_metadata = planner.last_request_metadata
                    if config.profile_name:
                        provider_metadata = {**provider_metadata, "profile": config.profile_name, "policy_version": policy_summary().get("version")}
                else:
                    raise ProviderError(f"Unsupported provider '{config.name}'.")
                validate_ai_draft(draft_result, roe, abilities)
            except (ProviderError, ValueError) as exc:
                if not args.fallback_offline or config.name == "offline":
                    respond(args, {"success": False, "stage": "draft-validation", "error": str(exc), "recovery": "Review provider configuration or rerun with --fallback-offline."}, exit_code=ExitCode.ERROR)
                draft_result = OfflinePlanner().draft(request, abilities)
                validate_ai_draft(draft_result, roe, abilities)
                provider_metadata = {"provider": config.name, "status": "fallback-offline", "error": str(exc)}
                provider_name = "offline-fallback"
            integrity = campaign_integrity_hashes(draft_result, roe, abilities)
            plan_hash = integrity["plan_hash"]
            campaign_dir = save_campaign_draft(draft_result, plan_hash, provider_name, args.campaign_root, provider_metadata=provider_metadata, roe_hash=integrity["roe_sha256"], catalog_hash=integrity["catalog_sha256"])
        result = {"success": True, "stage": "drafted", "provider": provider_name, "plan_hash": plan_hash, "campaign_id": campaign_dir.name, "campaign_dir": str(campaign_dir), "draft": draft_result.as_dict(), "approval_required": True}
        if args.approve:
            try:
                progress("Verifying draft, RoE, and catalog integrity", 1, 3)
                if args.sensor_manifest:
                    selected = tuple(ability for ability in abilities if ability.id in draft_result.ability_ids)
                    categories = {item.category for ability in selected for item in ability.expected_telemetry}
                    progress("Running read-only sensor preflight", 2, 3)
                    preflight = planned_sensor_preflight(categories, draft_result.target, args.sensor_manifest)
                    if not preflight["ready"]:
                        raise ValueError("Sensor preflight failed; no execution was started")
                    (campaign_dir / "sensor-preflight.json").write_text(json.dumps(preflight, indent=2), encoding="utf-8")
                    result["sensor_preflight"] = preflight
                progress("Running fixed local synthetic emulation", 3, 3)
                result.update(complete_saved_campaign(args.campaign_root, campaign_dir.name, roe, abilities, args.approver or "", args.output, args.adapter))
            except (PermissionError, ValueError) as exc:
                respond(args, {"success": False, "stage": "approval", "error": str(exc), "draft": draft_result.as_dict()}, exit_code=ExitCode.ERROR)
        else:
            result["next"] = "Review the draft, then rerun with --approve --approver <RoE approver>"
        human = _campaign_result_human(result, enabled=supports_color(no_color=args.no_color))
        respond(args, result, human)
        return

    if args.command == "draft":
        roe = load_roe(args.roe)
        abilities = load_catalog(args.catalog)
        dry_run_banner(
            will=["produce a local offline plan for review"],
            will_not=["contact a target", "run a command", "approve or execute anything"],
        )
        request = CampaignRequest(args.actor, args.target, args.objective, args.platform)
        draft_result = OfflinePlanner().draft(request, abilities)
        validate_ai_draft(draft_result, roe, abilities)
        respond(args, {"mode": "offline-ai-fallback", "draft": draft_result.as_dict(), "next": "send to manager approval before emulation"})
        return

    if args.command == "demo":
        roe = load_roe(args.roe)
        abilities = load_catalog(args.catalog)
        dry_run_banner(
            will=["run the fixed local-synthetic example", "write a local telemetry-gap report"],
            will_not=["contact an external target", "accept operator-supplied commands"],
        )
        request = CampaignRequest(args.actor, "local-lab", args.objective, args.platform)
        progress("Drafting and validating the offline plan", 1, 3)
        draft_result = OfflinePlanner().draft(request, abilities)
        validate_ai_draft(draft_result, roe, abilities)
        plan_hash = campaign_integrity_hashes(draft_result, roe, abilities)["plan_hash"]
        progress("Recording auto-approval for the demo", 2, 3)
        approval = approve_draft(draft_result, roe, abilities, args.approver or roe.approver_name, plan_hash)
        progress("Running local synthetic emulation", 3, 3)
        run_dir = run_local_emulation(draft_result, abilities, approval, args.output, args.adapter)
        report = build_gap_report(run_dir)
        respond(args, {"draft": draft_result.as_dict(), "approval": approval.__dict__, "run_dir": str(run_dir), "telemetry_gap_report": report})
        return

    if args.command == "doctor":
        result = run_doctor(args.roe, args.catalog, fix=args.fix)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(_doctor_human(result, enabled=supports_color(no_color=args.no_color)))
        raise SystemExit(ExitCode.OK if result["passed"] else ExitCode.ERROR)

    if args.command == "support-bundle":
        print(create_support_bundle(args.output, args.roe))
        return

    if args.command == "capabilities":
        text = __import__("importlib.resources", fromlist=["files"]).files("adversaryflow.resources").joinpath("capabilities.json").read_text(encoding="utf-8")
        print(text)
        return

    if args.command == "provider":
        config = load_provider_config()
        errors = validate_provider_config(config)
        if args.provider_command == "status":
            respond(args, config.as_dict())
        elif args.provider_command == "configure":
            print(provider_setup_instructions())
        elif args.provider_command == "diagnose":
            respond(args, {"configuration": config.as_dict(), "valid": not errors, "errors": errors, "recovery": [
                "Offline mode requires no key and never sends network requests.",
                "For hosted mode, confirm the endpoint is HTTPS and ends with /v1 when required by the provider.",
                "Use provider validate before provider test; provider test is the only command here that sends a request.",
                "If a hosted request fails, rerun campaign with --fallback-offline to continue a safe local rehearsal.",
            ]})
        elif args.provider_command == "profile":
            try:
                if args.profile_command == "list":
                    respond(args, list_profiles())
                elif args.profile_command == "status":
                    respond(args, activation_summary())
                elif args.profile_command == "use":
                    profile_file = use_profile(args.name)
                    respond(args, {**activation_summary(args.name), "file": str(profile_file)})
                elif args.profile_command == "save":
                    respond(args, {"saved": args.name, "file": str(save_profile(args.name, args.provider, args.endpoint, args.model, args.credential_env))})
                else:
                    remove_profile(args.name)
                    respond(args, {"removed": args.name})
            except (OSError, KeyError, ValueError) as exc:
                respond(args, {"success": False, "error": str(exc)}, exit_code=ExitCode.ERROR)
        elif args.provider_command == "test":
            if config.name != "openai-compatible":
                print("Provider test requires ADVERSARYFLOW_PROVIDER=openai-compatible.")
                raise SystemExit(ExitCode.ERROR)
            try:
                request = CampaignRequest(args.actor, args.target, args.objective, args.platform)
                abilities = load_catalog(args.catalog)
                progress("Sending one harmless planning request to the active provider", 1, 1)
                draft = OpenAICompatiblePlanner(config).draft(request, abilities)
                validate_ai_draft(draft, load_roe(args.roe), abilities)
                respond(args, {"success": True, "stage": "draft-validated", "draft": draft.as_dict()})
            except (ProviderError, ValueError, OSError, json.JSONDecodeError) as exc:
                respond(args, {"success": False, "error": str(exc)}, exit_code=ExitCode.ERROR)
        elif args.provider_command == "policy":
            try:
                if args.policy_command == "status":
                    respond(args, policy_summary())
                else:
                    respond(args, {"allowed": args.name, "file": str(allow_profile(args.name))})
            except (OSError, KeyError, ValueError) as exc:
                respond(args, {"success": False, "error": str(exc)}, exit_code=ExitCode.ERROR)
        else:
            level = "ok" if not errors else "fail"
            human = severity("VALID" if not errors else "INVALID", "; ".join(errors) or "provider configuration is valid", level, enabled=supports_color(no_color=args.no_color))
            respond(args, {"valid": not errors, "configuration": config.as_dict(), "errors": errors}, human)
            raise SystemExit(ExitCode.OK if not errors else ExitCode.ERROR)
        return

    if args.command == "archive":
        try:
            if args.archive_command == "search":
                print(json.dumps({"campaigns": search_campaign_archive(args.campaign_root, args.query, args.tag)}, indent=2))
            elif args.archive_command == "tag":
                tags = [tag.strip() for tag in args.tags.split(",") if tag.strip()]
                print(json.dumps(update_campaign_tags(args.campaign_root, args.campaign_id, tags), indent=2))
            elif args.archive_command == "controls":
                print(json.dumps(update_campaign_archive(args.campaign_root, args.campaign_id, args.owner, args.retention_days), indent=2))
            else:
                print(json.dumps(export_executive_summary(args.campaign_root, args.campaign_id, args.output), indent=2))
        except (OSError, KeyError, ValueError) as exc:
            print(json.dumps({"success": False, "error": str(exc)}, indent=2))
            raise SystemExit(1)
        return

    roe = load_roe(args.roe)
    audit = AuditLog(args.audit)
    audit.record("plan_requested", actor=args.actor, target=args.target, technique=args.technique)
    intelligence_action = "read the local ATT&CK STIX bundle" if args.attack_bundle else "fetch the official ATT&CK STIX bundle"
    dry_run_banner(
        will=[intelligence_action, "produce a dry-run plan for one technique"],
        will_not=["contact a target", "run a command", "create or approve a campaign"],
    )
    progress("Reading local ATT&CK STIX bundle" if args.attack_bundle else "Fetching official MITRE ATT&CK STIX bundle", 1, 1)
    bundle = json.loads(Path(args.attack_bundle).read_text(encoding="utf-8")) if args.attack_bundle else fetch_attack_bundle()
    technique = find_technique(bundle, args.technique)
    if not technique:
        raise SystemExit(f"Technique not found in MITRE ATT&CK source: {args.technique}")
    source = str(Path(args.attack_bundle).resolve()) if args.attack_bundle else "MITRE ATT&CK Enterprise STIX"
    result = build_plan(roe, args.actor, args.target, technique, source)
    respond(args, json.loads(json.dumps({"notice": "DRY RUN ONLY", "plan": result.__dict__}, default=lambda value: value.__dict__)))
