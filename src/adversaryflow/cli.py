import argparse
import json
from pathlib import Path

import yaml

from .audit import AuditLog
from .ai import CampaignRequest, OfflinePlanner, validate_ai_draft
from .emulation import load_catalog
from .workflow import approve_draft, build_gap_report, run_local_emulation
from .doctor import run_doctor
from .support import create_support_bundle
from .intel import fetch_attack_bundle, find_technique
from .models import RulesOfEngagement
from .planner import build_plan


def load_roe(path: str) -> RulesOfEngagement:
    with Path(path).open(encoding="utf-8") as handle:
        return RulesOfEngagement.from_mapping(yaml.safe_load(handle) or {})


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
    support = sub.add_parser("support-bundle", help="create a redacted troubleshooting bundle")
    support.add_argument("--output", default="artifacts/support")
    support.add_argument("--roe", default="examples/roe.yaml")
    sub.add_parser("capabilities", help="list advertised capabilities")
    args = parser.parse_args()

    if args.command == "validate":
        roe = load_roe(args.roe)
        print(json.dumps({"valid": True, "engagement": roe.engagement_name, "dry_run": roe.dry_run}, indent=2))
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
        plan_hash = __import__("hashlib").sha256(json.dumps(draft_result.as_dict(), sort_keys=True).encode()).hexdigest()
        approval = approve_draft(draft_result, roe, abilities, args.approver or roe.approver_name, plan_hash)
        run_dir = run_local_emulation(draft_result, abilities, approval, args.output)
        report = build_gap_report(run_dir)
        print(json.dumps({"draft": draft_result.as_dict(), "approval": approval.__dict__, "run_dir": str(run_dir), "telemetry_gap_report": report}, indent=2))
        return

    if args.command == "doctor":
        result = run_doctor(args.roe, args.catalog)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print("\n".join(f"{'PASS' if item['passed'] else 'FAIL'} {item['name']}: {item['detail']}" for item in result["checks"]))
        raise SystemExit(0 if result["passed"] else 1)

    if args.command == "support-bundle":
        print(create_support_bundle(args.output, args.roe))
        return

    if args.command == "capabilities":
        print(Path("capabilities.json").read_text(encoding="utf-8"))
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
