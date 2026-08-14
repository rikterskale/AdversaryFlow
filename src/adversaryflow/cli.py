import argparse
import json
from pathlib import Path

import yaml

from .audit import AuditLog
from .ai import CampaignRequest, OfflinePlanner, validate_ai_draft
from .emulation import default_catalog_path, load_catalog
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
from .intel import fetch_attack_bundle, find_technique
from .models import RulesOfEngagement
from .planner import build_plan


def load_roe(path: str) -> RulesOfEngagement:
    if not Path(path).exists() and path == "examples/roe.yaml":
        path = str(__import__("importlib.resources", fromlist=["files"]).files("adversaryflow.resources").joinpath("roe.yaml"))
    with Path(path).open(encoding="utf-8") as handle:
        return RulesOfEngagement.from_mapping(yaml.safe_load(handle) or {})


def _quote_command(value: str) -> str:
    return '"' + value.replace('"', "") + '"'


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
    parser = argparse.ArgumentParser(prog="adversaryflow", description="Scoped purple-team campaign planning")
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("roe")
    plan = sub.add_parser("plan")
    plan.add_argument("--roe", required=True)
    plan.add_argument("--actor", required=True)
    plan.add_argument("--target", default="local-lab")
    plan.add_argument("--technique", required=True)
    plan.add_argument("--audit", default="artifacts/audit.jsonl")
    draft = sub.add_parser("draft")
    draft.add_argument("--roe", required=True)
    draft.add_argument("--actor", required=True)
    draft.add_argument("--objective", required=True)
    draft.add_argument("--target", default="local-lab")
    draft.add_argument("--platform", default="linux")
    draft.add_argument("--catalog", default="content/abilities/catalog.json")
    demo = sub.add_parser("demo", help="run the complete safe local workflow")
    demo.add_argument("--roe", default="examples/roe.yaml")
    demo.add_argument("--actor", default="APT29")
    demo.add_argument("--objective", default="validate endpoint process visibility")
    demo.add_argument("--approver", default=None)
    demo.add_argument("--catalog", default="content/abilities/catalog.json")
    demo.add_argument("--output", default="artifacts/runs")
    doctor = sub.add_parser("doctor", help="diagnose installation and local runtime")
    doctor.add_argument("--roe", default="examples/roe.yaml")
    doctor.add_argument("--catalog", default="content/abilities/catalog.json")
    doctor.add_argument("--json", action="store_true")
    doctor.add_argument("--fix", action="store_true", help="apply safe local fixes, then diagnose again")
    support = sub.add_parser("support-bundle", help="create a redacted troubleshooting bundle")
    support.add_argument("--output", default="artifacts/support")
    support.add_argument("--roe", default="examples/roe.yaml")
    sub.add_parser("capabilities", help="list advertised capabilities")
    adapter = sub.add_parser("adapter", help="inspect the fixed local execution adapter")
    adapter_sub = adapter.add_subparsers(dest="adapter_command", required=True)
    adapter_status = adapter_sub.add_parser("status", help="show read-only adapter readiness")
    adapter_status.add_argument("--catalog", default="content/abilities/catalog.json")
    guide = sub.add_parser("guide", help="walk through the safe campaign workflow and next steps")
    guide.add_argument("--actor", default="APT29")
    guide.add_argument("--target", default="local-lab")
    guide.add_argument("--objective", default="validate endpoint process visibility")
    guide.add_argument("--interactive", action="store_true", help="prompt for draft-command details without executing a campaign")
    provider = sub.add_parser("provider", help="configure and validate AI provider settings")
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
    campaign = sub.add_parser("campaign", help="draft, validate, approve, and optionally emulate a campaign")
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
    manager = sub.add_parser("manager", help="start the loopback-only guided campaign workspace")
    manager.add_argument("--host", default="127.0.0.1")
    manager.add_argument("--port", type=int, default=8787)
    manager.add_argument("--campaign-root", default="artifacts/campaigns")
    manager.add_argument("--roe", default="examples/roe.yaml", help="Rules of Engagement used to validate browser-created offline drafts")
    manager.add_argument("--catalog", default="content/abilities/catalog.json", help="safe ability catalog used to validate browser-created offline drafts")
    manager.add_argument("--open", action="store_true", help="open the local campaign guide in your default browser")
    args = parser.parse_args()
    if hasattr(args, "catalog") and not Path(args.catalog).exists() and args.catalog == "content/abilities/catalog.json":
        args.catalog = str(default_catalog_path())

    if args.command == "validate":
        roe = load_roe(args.roe)
        print(json.dumps({"valid": True, "engagement": roe.engagement_name, "dry_run": roe.dry_run}, indent=2))
        return

    if args.command == "guide":
        print(campaign_guide(args.actor, args.target, args.objective, args.interactive))
        return

    if args.command == "adapter":
        abilities = load_catalog(args.catalog)
        readiness = adapter_readiness(abilities)
        print(json.dumps(readiness, indent=2))
        raise SystemExit(0 if readiness["compatible"] else 1)

    if args.command == "manager":
        serve_manager(args.host, args.port, args.campaign_root, args.open, args.roe, args.catalog)
        return

    if args.command == "campaign":
        if args.lifecycle_command == "list":
            print(json.dumps(list_campaigns(args.campaign_root), indent=2))
            return
        if args.lifecycle_command == "inspect":
            try:
                print(json.dumps(inspect_campaign(args.campaign_root, args.campaign_id), indent=2))
            except (OSError, ValueError) as exc:
                print(json.dumps({"success": False, "error": str(exc)}, indent=2))
                raise SystemExit(1)
            return
        if args.lifecycle_command == "reject":
            try:
                path = reject_campaign(args.campaign_root, args.campaign_id, args.approver, args.reason)
                print(json.dumps({"success": True, "status": "rejected", "record": str(path)}, indent=2))
            except (OSError, KeyError, ValueError) as exc:
                print(json.dumps({"success": False, "error": str(exc)}, indent=2))
                raise SystemExit(1)
            return
        if args.lifecycle_command == "cancel":
            try:
                path = cancel_campaign(args.campaign_root, args.campaign_id, args.reason)
                print(json.dumps({"success": True, "status": "cancelled", "record": str(path)}, indent=2))
            except (OSError, KeyError, ValueError) as exc:
                print(json.dumps({"success": False, "error": str(exc)}, indent=2))
                raise SystemExit(1)
            return
        if args.lifecycle_command == "reset":
            try:
                reset_campaign(args.campaign_root, args.campaign_id, args.confirm)
                print(json.dumps({"success": True, "status": "reset", "campaign_id": args.campaign_id}, indent=2))
            except (OSError, ValueError, PermissionError) as exc:
                print(json.dumps({"success": False, "error": str(exc)}, indent=2))
                raise SystemExit(1)
            return
        roe = load_roe(args.roe)
        abilities = load_catalog(args.catalog)
        config = load_provider_config()
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
                print(json.dumps({"success": False, "stage": "resume", "error": f"Could not resume campaign: {exc}"}, indent=2))
                raise SystemExit(1)
        else:
            if not args.actor or not args.objective:
                parser.error("campaign requires --actor and --objective when --campaign-id is not supplied")
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
                    print(json.dumps({"success": False, "stage": "draft-validation", "error": str(exc), "recovery": "Review provider configuration or rerun with --fallback-offline."}, indent=2))
                    raise SystemExit(1)
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
                result.update(complete_saved_campaign(args.campaign_root, campaign_dir.name, roe, abilities, args.approver or "", args.output))
            except (PermissionError, ValueError) as exc:
                print(json.dumps({"success": False, "stage": "approval", "error": str(exc), "draft": draft_result.as_dict()}, indent=2))
                raise SystemExit(1)
        else:
            result["next"] = "Review the draft, then rerun with --approve --approver <RoE approver>"
        print(json.dumps(result, indent=2))
        return

    if args.command == "draft":
        roe = load_roe(args.roe)
        abilities = load_catalog(args.catalog)
        request = CampaignRequest(args.actor, args.target, args.objective, args.platform)
        draft_result = OfflinePlanner().draft(request, abilities)
        validate_ai_draft(draft_result, roe, abilities)
        print(json.dumps({"mode": "offline-ai-fallback", "draft": draft_result.as_dict(), "next": "send to manager approval before emulation"}, indent=2))
        return

    if args.command == "demo":
        roe = load_roe(args.roe)
        abilities = load_catalog(args.catalog)
        request = CampaignRequest(args.actor, "local-lab", args.objective, "linux")
        draft_result = OfflinePlanner().draft(request, abilities)
        validate_ai_draft(draft_result, roe, abilities)
        plan_hash = campaign_integrity_hashes(draft_result, roe, abilities)["plan_hash"]
        approval = approve_draft(draft_result, roe, abilities, args.approver or roe.approver_name, plan_hash)
        run_dir = run_local_emulation(draft_result, abilities, approval, args.output)
        report = build_gap_report(run_dir)
        print(json.dumps({"draft": draft_result.as_dict(), "approval": approval.__dict__, "run_dir": str(run_dir), "telemetry_gap_report": report}, indent=2))
        return

    if args.command == "doctor":
        result = run_doctor(args.roe, args.catalog, fix=args.fix)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print("\n".join(f"{'PASS' if item['passed'] else 'FAIL'} {item['name']}: {item['detail']}" for item in result["checks"]))
            if result["fixes_applied"]:
                print(f"FIXED local folders: {', '.join(result['fixes_applied'])}")
            for item in result["guided_fixes"]:
                print(f"NEXT {item['check']}: {item['fix']}")
            provider_readiness = result.get("provider_readiness")
            if provider_readiness:
                print(f"PROVIDER {'READY' if provider_readiness['ready'] else 'NOT READY'}: {provider_readiness['detail']}")
        raise SystemExit(0 if result["passed"] else 1)

    if args.command == "support-bundle":
        print(create_support_bundle(args.output, args.roe))
        return

    if args.command == "capabilities":
        print(Path("capabilities.json").read_text(encoding="utf-8"))
        return

    if args.command == "provider":
        config = load_provider_config()
        errors = validate_provider_config(config)
        if args.provider_command == "status":
            print(json.dumps(config.as_dict(), indent=2))
        elif args.provider_command == "configure":
            print(provider_setup_instructions())
        elif args.provider_command == "diagnose":
            print(json.dumps({"configuration": config.as_dict(), "valid": not errors, "errors": errors, "recovery": [
                "Offline mode requires no key and never sends network requests.",
                "For hosted mode, confirm the endpoint is HTTPS and ends with /v1 when required by the provider.",
                "Use provider validate before provider test; provider test is the only command here that sends a request.",
                "If a hosted request fails, rerun campaign with --fallback-offline to continue a safe local rehearsal.",
            ]}, indent=2))
        elif args.provider_command == "profile":
            try:
                if args.profile_command == "list":
                    print(json.dumps(list_profiles(), indent=2))
                elif args.profile_command == "status":
                    print(json.dumps(activation_summary(), indent=2))
                elif args.profile_command == "use":
                    profile_file = use_profile(args.name)
                    summary = activation_summary(args.name)
                    print(json.dumps({**summary, "file": str(profile_file)}, indent=2))
                elif args.profile_command == "save":
                    print(json.dumps({"saved": args.name, "file": str(save_profile(args.name, args.provider, args.endpoint, args.model, args.credential_env))}, indent=2))
                else:
                    remove_profile(args.name)
                    print(json.dumps({"removed": args.name}, indent=2))
            except (OSError, KeyError, ValueError) as exc:
                print(json.dumps({"success": False, "error": str(exc)}, indent=2))
                raise SystemExit(1)
        elif args.provider_command == "test":
            if config.name != "openai-compatible":
                print("Provider test requires ADVERSARYFLOW_PROVIDER=openai-compatible.")
                raise SystemExit(1)
            try:
                request = CampaignRequest(args.actor, args.target, args.objective, args.platform)
                abilities = load_catalog(args.catalog)
                draft = OpenAICompatiblePlanner(config).draft(request, abilities)
                validate_ai_draft(draft, load_roe(args.roe), abilities)
                print(json.dumps({"success": True, "stage": "draft-validated", "draft": draft.as_dict()}, indent=2))
            except (ProviderError, ValueError, OSError, json.JSONDecodeError) as exc:
                print(json.dumps({"success": False, "error": str(exc)}, indent=2))
                raise SystemExit(1)
        elif args.provider_command == "policy":
            try:
                if args.policy_command == "status":
                    print(json.dumps(policy_summary(), indent=2))
                else:
                    print(json.dumps({"allowed": args.name, "file": str(allow_profile(args.name))}, indent=2))
            except (OSError, KeyError, ValueError) as exc:
                print(json.dumps({"success": False, "error": str(exc)}, indent=2))
                raise SystemExit(1)
        else:
            print(json.dumps({"valid": not errors, "configuration": config.as_dict(), "errors": errors}, indent=2))
            raise SystemExit(0 if not errors else 1)
        return

    roe = load_roe(args.roe)
    audit = AuditLog(args.audit)
    audit.record("plan_requested", actor=args.actor, target=args.target, technique=args.technique)
    bundle = fetch_attack_bundle()
    technique = find_technique(bundle, args.technique)
    if not technique:
        raise SystemExit(f"Technique not found in MITRE ATT&CK source: {args.technique}")
    result = build_plan(roe, args.actor, args.target, technique, "MITRE ATT&CK Enterprise STIX")
    print(json.dumps({"notice": "DRY RUN ONLY", "plan": result.__dict__}, default=lambda value: value.__dict__, indent=2))
