from __future__ import annotations

import asyncio
import json
from pathlib import Path

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
from adversaryflow.render.markdown import render_markdown
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
        details = "; ".join(
            f"{'.'.join(str(item) for item in error['loc'])}: {error['msg']}"
            for error in exc.errors()
        )
        raise typer.BadParameter(details, param_hint="--request") from exc


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
) -> None:
    """Check local configuration before generating a scenario."""
    settings = Settings()
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
) -> None:
    """Generate a safety-constrained red team scenario."""

    async def _run() -> None:
        settings = Settings()
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
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render_markdown(pack), encoding="utf-8")
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
