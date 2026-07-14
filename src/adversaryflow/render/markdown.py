from __future__ import annotations

from adversaryflow.models import ScenarioPack


def render_markdown(pack: ScenarioPack) -> str:
    lines: list[str] = []
    lines.append(f"# {pack.title}")
    lines.append("")
    lines.append(f"- Generated: {pack.generated_at.isoformat()}")
    lines.append(f"- Actor input: {pack.request.actor}")
    lines.append(f"- Exercise mode: {pack.request.mode.value}")
    lines.append(f"- Safety gate: {'PASS' if pack.qa.safety_gate_passed else 'FAIL'}")
    lines.append(
        f"- Factuality gate: {'PASS' if pack.qa.factuality_passed else 'FAIL'} "
        f"({pack.qa.factuality_score:.0%})"
    )
    lines.append(f"- Citation coverage: {pack.qa.citation_coverage:.0%}")
    lines.append(f"- Source validation: {'PASS' if pack.qa.source_validation_passed else 'FAIL'}")
    lines.append(f"- Model calls: {pack.qa.model_call_count}")
    lines.append(f"- Repair calls: {pack.qa.repair_call_count}")
    lines.append("")

    lines.extend(["## Executive Summary", "", pack.executive_summary, ""])

    lines.extend(["## Actor and Grounding Status", ""])
    lines.append(f"- Canonical name: {pack.dossier.identity.canonical_name}")
    lines.append(f"- ATT&CK ID: {pack.dossier.identity.attack_id or 'Unresolved'}")
    lines.append(f"- Identity confidence: {pack.dossier.identity.confidence}")
    lines.append(f"- Grounded techniques: {len(pack.dossier.techniques)}")
    lines.append(f"- Claim graph nodes: {len(pack.citation_graph.claims)}")
    lines.append(f"- Claim graph edges: {len(pack.citation_graph.edges)}")
    if pack.dossier.caveats:
        lines.append("- Caveats:")
        lines.extend(f"  - {item}" for item in pack.dossier.caveats)
    lines.append("")

    if pack.dossier.techniques:
        lines.extend(["## Grounded TTP Dossier", ""])
        lines.append("| Technique | Name | Confidence | Sources |")
        lines.append("|---|---|---|---|")
        for technique in pack.dossier.techniques:
            urls = "<br>".join(str(url) for url in technique.source_urls) or "Pinned ATT&CK"
            lines.append(
                f"| {technique.technique_id} | {technique.name} | {technique.confidence} | {urls} |"
            )
        lines.append("")

    lines.extend(["## Exercise Assumptions", ""])
    lines.extend(f"- {item}" for item in pack.exercise_assumptions)
    lines.append("")

    lines.extend(["## Rules of Engagement Summary", ""])
    lines.append(
        "- Designated test assets: " + ", ".join(pack.request.environment.designated_test_assets)
    )
    lines.append("- No destructive execution: yes")
    lines.append("- No real funds or live transactions: yes")
    lines.append("- Synthetic data required for objective access: yes")
    lines.append("")

    lines.extend(["## Exercise Path", ""])
    for step in pack.attack_path:
        lines.append(f"### {step.sequence}. {step.phase}")
        lines.append("")
        lines.append(f"**Objective:** {step.objective}")
        lines.append("")
        lines.append(f"**ATT&CK:** {', '.join(step.technique_ids) or 'Not actor-mapped in demo'}")
        lines.append("")
        lines.append(f"**Action summary:** {step.action_summary}")
        lines.append("")
        lines.append(f"**Safe equivalent:** {step.safe_equivalent}")
        lines.append("")
        lines.append(f"**Test asset:** {step.designated_test_asset or 'Tabletop only'}")
        lines.append("")
        lines.append(f"**Safety classification:** {step.safety_classification.value}")
        lines.append("")
        lines.append("**Prerequisites**")
        lines.extend(f"- {item}" for item in step.prerequisites)
        lines.append("")
        lines.append("**Expected observables**")
        lines.extend(
            f"- {obs.source}: {obs.observable}"
            + (f" (requires {obs.collection_requirement})" if obs.collection_requirement else "")
            for obs in step.expected_observables
        )
        lines.append("")
        lines.append("**Evidence to capture**")
        lines.extend(f"- {item}" for item in step.evidence_to_capture)
        lines.append("")
        lines.append("**Detection opportunities**")
        lines.extend(f"- {item}" for item in step.detection_opportunities)
        lines.append("")
        lines.append("**Stop conditions**")
        lines.extend(f"- {item}" for item in step.stop_conditions)
        lines.append("")
        lines.append("**Cleanup**")
        lines.extend(f"- {item}" for item in step.cleanup)
        if step.source_urls:
            lines.append("")
            lines.append("**Sources**")
            lines.extend(f"- {url}" for url in step.source_urls)
        lines.append("")

    lines.extend(["## Exercise Injects", ""])
    lines.append("| Time | Audience | Inject | Expected response | Success measure |")
    lines.append("|---|---|---|---|---|")
    for inject in pack.injects:
        lines.append(
            f"| {inject.time_offset} | {inject.audience} | {inject.inject} | "
            f"{inject.expected_response} | {inject.success_measure} |"
        )
    lines.append("")

    lines.extend(["## Metrics", ""])
    lines.extend(f"- {item}" for item in pack.metrics)
    lines.append("")

    lines.extend(["## Claim-Level Citation Graph", ""])
    if not pack.citation_graph.claims:
        lines.append("No actor-specific factual claims were emitted for evaluation.")
    else:
        edge_map: dict[str, list] = {}
        for edge in pack.citation_graph.edges:
            edge_map.setdefault(edge.claim_id, []).append(edge)
        for claim in pack.citation_graph.claims:
            lines.append(f"### {claim.claim_id}")
            lines.append("")
            lines.append(claim.text)
            lines.append("")
            edges = edge_map.get(claim.claim_id, [])
            if not edges:
                lines.append("- **Support:** No validated source edge")
            for edge in edges:
                lines.append(
                    f"- **Support {edge.support_score:.0%}:** {edge.source_url} "
                    f"({edge.support_method})"
                )
                if edge.excerpt:
                    lines.append(f"  - Excerpt: {edge.excerpt}")
            lines.append("")

    lines.extend(["## Factuality Evaluation", ""])
    lines.append(f"- Result: {'PASS' if pack.factuality.passed else 'FAIL'}")
    lines.append(f"- Score: {pack.factuality.score:.0%}")
    lines.append(f"- Citation coverage: {pack.factuality.citation_coverage:.0%}")
    lines.append(f"- Claims evaluated: {pack.factuality.evaluated_claims}")
    lines.append(f"- Claims supported: {pack.factuality.supported_claims}")
    if pack.factuality.findings:
        lines.append("")
        lines.append("| Status | Claim | Reason |")
        lines.append("|---|---|---|")
        for finding in pack.factuality.findings:
            status = "supported" if finding.supported else "unsupported"
            lines.append(f"| {status} | {finding.claim_text} | {finding.reason} |")
    lines.append("")

    lines.extend(["## Source Manifest", ""])
    if not pack.source_manifest:
        lines.append("No live sources were attached to this run.")
    else:
        lines.append("| Status | Title | Domain | Claims | URL | SHA-256 |")
        lines.append("|---|---|---|---|---|---|")
        for source in pack.source_manifest:
            status = (
                "valid" if source.validated else f"invalid: {source.validation_error or 'unknown'}"
            )
            claims = "<br>".join(source.supports_claims)
            lines.append(
                f"| {status} | {source.title} | {source.domain} | {claims} | "
                f"{source.final_url or source.url} | {source.content_sha256 or ''} |"
            )
    lines.append("")

    lines.extend(["## QA and Safety Findings", ""])
    if pack.qa.unsupported_claims:
        lines.append("### Unsupported claims")
        lines.extend(f"- {item}" for item in pack.qa.unsupported_claims)
        lines.append("")
    if pack.qa.blocked_items:
        lines.append("### Blocked items")
        lines.extend(f"- {item}" for item in pack.qa.blocked_items)
        lines.append("")
    if pack.qa.warnings:
        lines.append("### Warnings")
        lines.extend(f"- {item}" for item in pack.qa.warnings)
        lines.append("")
    if not pack.qa.unsupported_claims and not pack.qa.blocked_items and not pack.qa.warnings:
        lines.append("No blocking findings or warnings.")
        lines.append("")

    lines.extend(
        [
            "## Operator Approval Gate",
            "",
            "This document is a planning artifact. Execution requires a human reviewer to confirm "
            "scope, assets, identities, approvals, telemetry readiness, rollback, and exercise timing.",
            "",
        ]
    )
    return "\n".join(lines)
