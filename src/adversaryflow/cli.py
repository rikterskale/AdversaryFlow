from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import typer
from dotenv import load_dotenv
from pydantic import ValidationError
from rich.console import Console

from adversaryflow.config import Settings
from adversaryflow.models import ScenarioRequest
from adversaryflow.pipeline.factuality import FactualityEvaluator
from adversaryflow.pipeline.node_runner import RetryPolicy
from adversaryflow.pipeline.orchestrator import ScenarioOrchestrator
from adversaryflow.providers.demo import DemoLLMProvider
from adversaryflow.providers.openai_compatible import OpenAICompatibleProvider
from adversaryflow.providers.search import BraveSearchProvider, NullSearchProvider
from adversaryflow.render import render_html, render_markdown
from adversaryflow.retrieval.url_validator import URLValidator
from adversaryflow.safety.policy import SafetyPolicy

app = typer.Typer(no_args_is_help=True, help="Build safe, evidence-grounded red team exercises.")
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        from adversaryflow import __version__

        console.print(f"AdversaryFlow {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the installed version and exit.",
    ),
) -> None:
    """AdversaryFlow command-line interface."""
    # The setup task creates this file; existing process environment variables win.
    load_dotenv(dotenv_path=Path.cwd() / ".env", override=False)


def _read_request(path: Path) -> ScenarioRequest:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(
            f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}",
            param_hint="--request",
        ) from exc
    try:
        return ScenarioRequest.model_validate(payload)
    except ValidationError as exc:
        raise typer.BadParameter(_validation_details(exc), param_hint="--request") from exc


def _validation_details(exc: ValidationError) -> str:
    return "; ".join(
        f"{'.'.join(str(item) for item in error['loc'])}: {error['msg']}" for error in exc.errors()
    )


def _load_settings() -> Settings:
    try:
        return Settings()
    except ValueError as exc:
        raise typer.BadParameter(
            f"Invalid value in .env: {exc}. Check numeric timeout, size, retry, and threshold settings.",
            param_hint="configuration",
        ) from exc


def _configuration_issues(settings: Settings, selected_search: str) -> list[str]:
    issues: list[str] = []
    if not settings.llm_base_url:
        issues.append("ADVERSARYFLOW_LLM_BASE_URL is not set")
    if not settings.llm_api_key:
        issues.append("ADVERSARYFLOW_LLM_API_KEY is not set")
    if not settings.llm_model:
        issues.append("ADVERSARYFLOW_LLM_MODEL is not set")
    if selected_search not in {"brave", "null"}:
        issues.append("ADVERSARYFLOW_SEARCH_PROVIDER must be 'brave' or 'null'")
    elif selected_search == "brave" and not settings.brave_api_key:
        issues.append("ADVERSARYFLOW_BRAVE_API_KEY is not set (or select search provider 'null')")
    return issues


@app.command("export-schema")
def export_schema(
    output: Path = typer.Option(
        Path("scenario-request.schema.json"), help="Destination for the JSON Schema"
    ),
    force: bool = typer.Option(False, help="Overwrite an existing file"),
) -> None:
    """Export the complete scenario-request JSON Schema."""
    if output.exists() and not force:
        raise typer.BadParameter(f"{output} already exists; use --force to overwrite")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(ScenarioRequest.model_json_schema(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    console.print(f"[green]Exported request schema[/green] {output}")


@app.command("init")
def initialize_request(
    output: Path = typer.Option(Path("scenario-request.json"), help="New request file"),
    actor: str | None = typer.Option(None, help="Threat actor or exercise label"),
    objective: str | None = typer.Option(None, help="Defensive validation objective"),
    environment: str | None = typer.Option(None, help="Environment name"),
    kind: str = typer.Option("ttp_based", help="ttp_based or ad_hoc"),
    premise: str | None = typer.Option(None, help="Required free-form premise for ad_hoc requests"),
    mode: str = typer.Option("tabletop", help="tabletop, emulation_plan, or controlled_validation"),
    test_asset: str | None = typer.Option(
        None, help="Designated test asset for non-tabletop modes"
    ),
    force: bool = typer.Option(False, help="Overwrite an existing file"),
) -> None:
    """Interactively create a safe starter scenario request."""
    if output.exists() and not force:
        raise typer.BadParameter(f"{output} already exists; use --force to overwrite")
    if mode not in {"tabletop", "emulation_plan", "controlled_validation"}:
        raise typer.BadParameter(
            "mode must be tabletop, emulation_plan, or controlled_validation", param_hint="--mode"
        )
    if kind not in {"ttp_based", "ad_hoc"}:
        raise typer.BadParameter("kind must be ttp_based or ad_hoc", param_hint="--kind")
    actor = actor or typer.prompt("Threat actor or exercise label", default="Ad Hoc Exercise")
    objective = objective or typer.prompt("Defensive validation objective")
    environment = environment or typer.prompt("Environment name", default="Purple Team Lab")
    if kind == "ad_hoc" and not premise:
        premise = typer.prompt("Ad hoc scenario premise")
    if mode != "tabletop" and not test_asset:
        test_asset = typer.prompt("Designated test asset")
    assets = [test_asset] if test_asset else []
    payload = {
        "actor": actor,
        "objective": objective,
        "scenario_kind": kind,
        "mode": mode,
        "environment": {
            "name": environment,
            "platforms": [],
            "identity_systems": [],
            "cloud_services": [],
            "security_tools": [],
            "crown_jewels": [],
            "designated_test_assets": assets,
            "notes": "Replace placeholders with approved exercise details.",
        },
        "roe": {
            "authorized_assets": assets,
            "authorized_users": [],
            "authorized_phishing_recipients": [],
            "prohibited_actions": [
                "Production access",
                "Destructive execution",
                "Access to real sensitive data",
            ],
            "no_real_funds_or_transactions": True,
            "no_destructive_execution": True,
            "real_brand_impersonation_requires_written_consent": True,
            "required_approvals": ["Exercise Director", "System Owner"],
            "exercise_window": "Set an approved exercise window",
        },
        "post_2020_tradecraft_only": True,
        "minimum_source_date": "2020-01-01",
        "max_attack_path_steps": 8,
        "output_audience": ["red_team", "blue_team", "exercise_control"],
    }
    if premise:
        payload["ad_hoc_scenario"] = premise
    try:
        ScenarioRequest.model_validate(payload)
    except ValidationError as exc:
        raise typer.BadParameter(_validation_details(exc), param_hint="request answers") from exc
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    console.print(f"[green]Created request[/green] {output}")
    console.print(f"Next: adversaryflow validate-request --request {output}")


@app.command("validate-request")
def validate_request(
    request: Path = typer.Option(..., exists=True, readable=True, help="Scenario request JSON"),
) -> None:
    """Validate a request without calling models or search services."""
    scenario_request = _read_request(request)
    console.print(
        f"[green]Valid request[/green]: {scenario_request.objective} "
        f"([cyan]{scenario_request.scenario_kind.value}[/cyan])"
    )


@app.command()
def doctor(
    demo: bool = typer.Option(False, help="Check readiness for credential-free demo mode"),
    search_provider: str | None = typer.Option(
        None, help="Override search provider: brave or null"
    ),
    check_network: bool = typer.Option(
        False, help="Make small authenticated requests to verify configured services"
    ),
) -> None:
    """Check local configuration before generating a scenario."""
    settings = _load_settings()
    if demo:
        console.print("[green]Ready[/green] for deterministic demo mode (no credentials required).")
        return
    selected_search = (search_provider or settings.search_provider).casefold()
    issues = _configuration_issues(settings, selected_search)
    if issues:
        console.print("[red]Configuration is incomplete:[/red]")
        for issue in issues:
            console.print(f"  - {issue}")
        console.print("Edit .env, then run this command again. Use --demo to check demo mode.")
        raise typer.Exit(code=1)
    console.print(
        f"[green]Ready[/green] for live generation with model '{settings.llm_model}' "
        f"and search provider '{selected_search}'."
    )
    if not check_network:
        console.print("Use --check-network to verify service connectivity and credentials.")
        return

    failures: list[str] = []
    headers = {"Authorization": f"Bearer {settings.llm_api_key}"}
    try:
        response = httpx.get(
            f"{settings.llm_base_url.rstrip('/')}/models",
            headers=headers,
            timeout=settings.request_timeout_seconds,
        )
        response.raise_for_status()
        console.print("[green]Model endpoint reachable[/green]")
    except httpx.HTTPError as exc:
        failures.append(f"model endpoint: {exc}")
    if selected_search == "brave":
        try:
            response = httpx.get(
                BraveSearchProvider.endpoint,
                headers={"X-Subscription-Token": settings.brave_api_key},
                params={"q": "site:attack.mitre.org ATT&CK", "count": 1},
                timeout=settings.search_timeout_seconds,
            )
            response.raise_for_status()
            console.print("[green]Brave Search reachable[/green]")
        except httpx.HTTPError as exc:
            failures.append(f"Brave Search: {exc}")
    if failures:
        console.print("[red]Connectivity checks failed:[/red]")
        for failure in failures:
            console.print(f"  - {failure}")
        raise typer.Exit(code=1)


@app.command()
def generate(
    request: Path = typer.Option(..., exists=True, readable=True, help="Scenario request JSON"),
    output: Path = typer.Option(Path("reports/scenario.md"), help="Markdown output path"),
    demo: bool = typer.Option(False, help="Use deterministic demo model and disable live search"),
    search_provider: str | None = typer.Option(
        None,
        help="Search provider: brave or null. Defaults to ADVERSARYFLOW_SEARCH_PROVIDER.",
    ),
    attack_bundle: Path | None = typer.Option(
        None,
        help="Optional local Enterprise ATT&CK STIX bundle",
    ),
    output_format: str | None = typer.Option(
        None,
        "--format",
        help="Report format: markdown or html. Defaults from the output extension.",
    ),
) -> None:
    """Generate a safety-constrained red team scenario."""

    async def _run() -> None:
        settings = _load_settings()
        scenario_request = _read_request(request)

        if demo:
            llm = DemoLLMProvider()
            search = NullSearchProvider()
        else:
            selected_search = (search_provider or settings.search_provider).casefold()
            issues = _configuration_issues(settings, selected_search)
            if issues:
                raise typer.BadParameter(
                    "; ".join(issues) + ". Edit .env or run with --demo.",
                    param_hint="configuration",
                )
            llm = OpenAICompatibleProvider(
                base_url=settings.llm_base_url,
                api_key=settings.llm_api_key,
                model=settings.llm_model,
                timeout_seconds=settings.request_timeout_seconds,
            )
            if selected_search == "brave":
                search = BraveSearchProvider(
                    api_key=settings.brave_api_key,
                    timeout_seconds=settings.search_timeout_seconds,
                )
            elif selected_search == "null":
                search = NullSearchProvider()
            else:  # Guarded by _configuration_issues; retained for type narrowing.
                raise typer.BadParameter("search_provider must be 'brave' or 'null'")

        validator = URLValidator(
            allowed_domains=settings.allowed_domains,
            timeout_seconds=settings.url_validation_timeout_seconds,
            max_bytes=settings.max_source_bytes,
        )
        orchestrator = ScenarioOrchestrator(
            llm=llm,
            search=search,
            safety_policy=SafetyPolicy(),
            url_validator=validator,
            attack_bundle_path=attack_bundle,
            retry_policy=RetryPolicy(
                max_attempts=settings.node_max_attempts,
                base_delay_seconds=settings.retry_base_delay_seconds,
            ),
            factuality_evaluator=FactualityEvaluator(threshold=settings.factuality_threshold),
            fail_on_factuality_error=settings.fail_on_factuality_error,
            require_grounded_dossier=(False if demo else settings.require_grounded_dossier),
        )
        pack = await orchestrator.generate(scenario_request)
        selected_format = output_format or (
            "html" if output.suffix.casefold() == ".html" else "markdown"
        )
        if selected_format not in {"markdown", "html"}:
            raise typer.BadParameter("format must be 'markdown' or 'html'", param_hint="--format")
        report = render_html(pack) if selected_format == "html" else render_markdown(pack)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report, encoding="utf-8")
        trace_path = output.with_suffix(".trace.json")
        trace_path.write_text(
            json.dumps(pack.trace, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        console.print(f"[green]Generated[/green] {output}")
        console.print(f"[green]Trace[/green] {trace_path}")
        factuality_status = (
            f"{'PASS' if pack.qa.factuality_passed else 'FAIL'} ({pack.qa.factuality_score:.0%})"
            if pack.factuality.evaluated
            else "N/A (no factual claims evaluated)"
        )
        console.print(
            f"Safety: {'PASS' if pack.qa.safety_gate_passed else 'FAIL'} | "
            f"Claim evidence: {factuality_status} | "
            f"Model calls: {pack.qa.model_call_count} "
            f"(repairs: {pack.qa.repair_call_count})"
        )

    asyncio.run(_run())


if __name__ == "__main__":
    app()
