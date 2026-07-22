# Installation and usage review

Review date: 2026-07-22

## Scope

The review covered packaging metadata, editable and wheel installation, runtime
package contents, project task runners, PowerShell/Bash wrappers, CLI discovery,
demo generation, durable storage, caching, Docker build/run behavior, CI, upgrade
and cleanup semantics, and beginner/expert documentation.

## Paths exercised

| Path | Result | Evidence |
|---|---|---|
| Existing editable development install | Pass | Complete lint, formatting, test, CLI, and demo runs |
| Wheel and source-distribution build | Pass | `python -m build --no-isolation` produced both artifacts |
| Wheel installation | Pass | Installed built wheel into a separate review environment; version, doctor, HTML generation, trace, and durable run passed |
| Docker clean build | Pass | `python:3.12-slim` image downloaded dependencies, built the wheel, and installed the project |
| Docker non-root ephemeral demo | Pass | UID 10001 generated report, trace, and store under `/work` |
| Docker named-volume persistence | Pass | A second container observed the persisted report and `store.json` |
| Docker bind mount without compatible permissions | Expected fail | Reproduced `PermissionError`; documented UID/ACL requirements and added early write preflight |
| Windows CLI | Pass | All commands and generated entry point exercised on Python 3.12 |
| Linux container CLI | Pass | Version, doctor, and generation exercised inside Debian-based Python image |
| Bash setup wrapper | Static/CI coverage | Local Windows host had no WSL distribution; script logic reviewed and Ubuntu CI installs the project |
| macOS native install | Not directly exercised | Uses the same Python/venv path as Linux; detailed commands provided, but no macOS runner is currently configured |
| Live model and Brave credentials | Not exercised | Review intentionally used deterministic demo mode; `doctor --check-network` remains the credentialed preflight |

## Findings and resolutions

### High: local personal settings entered the source distribution

The pre-review source distribution contained `.claude/settings.local.json`.
Hatch build exclusions now remove `.claude`, `.env`, `.adversaryflow`, `.venv`,
and `.test-tmp`. Rebuilt artifacts contained none of the prohibited paths.

### High: Docker sent an unrestricted build context

There was no `.dockerignore`, allowing local Git state, credentials, run stores,
and development artifacts to be sent to the Docker daemon. A restrictive
`.dockerignore` now excludes those paths.

### Medium: container ran as root

The image now creates and runs as UID 10001 with `/work` as its writable working
directory. Named-volume persistence was tested. Bind mounts require compatible
host ownership or an explicit `--user` mapping.

### Medium: disable flags exposed confusing inverse names

Typer generated `--no-no-store` and `--no-no-cache`. The CLI now exposes only
the intended `--no-store` and `--no-cache`; a regression test checks help output.

### Medium: path permissions failed after expensive work began

Output and store writability were not checked until generation or cache writing.
The CLI now preflights both directories before provider calls and reports an
actionable ownership/mount error.

### Medium: repository and installed-package usage were mixed

The old README used repository examples in sections that could be read as generic
package installation instructions. `INSTALLATION.md` now distinguishes repository,
minimal venv, pipx, wheel, offline, and Docker installs; `USAGE.md` states when
examples exist only in the checkout or image.

### Low: Python version and broken virtual environments failed indirectly

`tasks.py` now rejects Python older than 3.11 immediately. Demo wrappers check for
the actual venv interpreter rather than only the `.venv` directory.

### Low: cleanup wording implied durable cache deletion

Task help and documentation now say that development cleanup preserves the
`.adversaryflow` run store and caches.

### Low: package builds were absent from CI

The development dependency set now includes `build`, and CI builds the wheel and
source distribution on Windows and Ubuntu for Python 3.11 and 3.12.

## Artifact inspection

The built wheel contains all Python packages plus both runtime prompt Markdown
files. The source distribution excludes local sensitive state. Runtime dependencies
are declared in `pyproject.toml`, and the `adversaryflow` console entry point maps
to `adversaryflow.cli:app`.

## Remaining coverage recommendations

1. Add a macOS CI job if native macOS support is a release requirement.
2. Add a scheduled Docker build and demo smoke test.
3. Test at least one approved live OpenAI-compatible provider in a protected integration environment.
4. Test Brave Search with a protected credential and recorded allowlist-safe fixtures.
5. Add a release job that inspects distribution file lists and signs artifact hashes.
