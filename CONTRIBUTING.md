# Contributing to AdversaryFlow

AdversaryFlow accepts changes that improve grounded scenario generation, defensive training value, reproducibility, and safety within explicit Rules of Engagement.

## Development setup

The project ships a stdlib-only task runner (`tasks.py`) that works the same on
Windows, Linux, and macOS. The only prerequisite is Python 3.11+.

```bash
python tasks.py setup   # use python3 on Linux/macOS if that is your interpreter name
```

This creates `.venv`, installs the project with its dev extras, and copies
`.env.example` to `.env` (edit it only for live provider/search configuration).

Run the local quality gates — these are exactly what CI runs on both Windows and
Linux:

```bash
python tasks.py check   # ruff lint + format check, then pytest
python tasks.py demo    # generate the deterministic demo report
```

Individual steps are also available: `python tasks.py lint`, `python tasks.py
format`, and `python tasks.py test`. Unix users who prefer `make` can run the
identical targets (`make check`, `make demo`, …), and the raw `ruff`/`pytest`
commands still work inside an activated virtual environment.

## Documentation review checklist

When reviewing documentation, verify that command examples match the Typer CLI, environment variables match `.env.example`, generated report paths are either tracked demo artifacts or intentionally ignored, and safety/grounding descriptions do not imply autonomous execution. If docs mention local ATT&CK data, make clear that `data/enterprise-attack.json` is intentionally untracked.

## Pull-request expectations

Changes to prompts, model schemas, orchestration, retrieval, source allowlists, factuality evaluation, or safety policy must include focused tests and documentation. Do not weaken a deterministic control in favor of model instructions alone.

Never commit credentials, live target details, proprietary evidence, personal data, or an unreviewed execution export. External catalog additions must be first-party or otherwise clearly justified, and must remain subject to HTTPS, hostname, redirect, IP, size, and extraction validation.
