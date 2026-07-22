# Contributing to AdversaryFlow

AdversaryFlow accepts changes that improve grounded scenario generation, defensive training value, reproducibility, and safety within explicit Rules of Engagement.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env  # optional for live provider/search configuration
```

Run the local quality gates:

```bash
ruff check src tests
ruff format --check src tests
pytest -q
adversaryflow generate \
  --request examples/apt29_request.json \
  --output reports/apt29_scenario.md \
  --demo
```

## Documentation review checklist

When reviewing documentation, verify that command examples match the Typer CLI, environment variables match `.env.example`, generated report paths are either tracked demo artifacts or intentionally ignored, and safety/grounding descriptions do not imply autonomous execution. If docs mention local ATT&CK data, make clear that `data/enterprise-attack.json` is intentionally untracked.

## Pull-request expectations

Changes to prompts, model schemas, orchestration, retrieval, source allowlists, factuality evaluation, or safety policy must include focused tests and documentation. Do not weaken a deterministic control in favor of model instructions alone.

Never commit credentials, live target details, proprietary evidence, personal data, or an unreviewed execution export. External catalog additions must be first-party or otherwise clearly justified, and must remain subject to HTTPS, hostname, redirect, IP, size, and extraction validation.
