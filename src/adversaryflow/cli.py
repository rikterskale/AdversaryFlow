from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer
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

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.callback()
def main() -> None:
    """AdversaryFlow command-line interface."""


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
        payload = json.loads(request.read_text(encoding="utf-8"))
        scenario_request = ScenarioRequest.model_validate(payload)

        if demo:
            llm = DemoLLMProvider()
            search = NullSearchProvider()
        else:
            llm = OpenAICompatibleProvider(
                base_url=settings.llm_base_url,
                api_key=settings.llm_api_key,
                model=settings.llm_model,
                timeout_seconds=settings.request_timeout_seconds,
            )
            selected_search = (search_provider or settings.search_provider).casefold()
            if selected_search == "brave":
                search = BraveSearchProvider(
                    api_key=settings.brave_api_key,
                    timeout_seconds=settings.search_timeout_seconds,
                )
            elif selected_search == "null":
                search = NullSearchProvider()
            else:
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
