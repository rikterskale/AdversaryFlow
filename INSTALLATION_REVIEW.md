# Installation and usage review

## Second pass — 2026-07-22

An independent re-review that executed the documented commands rather than
reading them. Every install method in `INSTALLATION.md` and every command block
in `USAGE.md` was run verbatim and its output compared against what the guide
promises.

### Environment and its one limitation

Linux (Ubuntu 22.04), CPython 3.10.12. No 3.11+ interpreter was obtainable:
python.org and GitHub are network-blocked, apt cannot run as root, and Ubuntu
22.04 ships only 3.10. Docker was unavailable.

The Python 3.11 gate was therefore verified directly — `python3 tasks.py setup`
on 3.10 exits `1` with `AdversaryFlow requires Python 3.11 or newer` and changes
nothing — and everything else was exercised on a throwaway copy with
`requires-python` and the `tasks.py` gate lowered to 3.10, plus a `tomllib` shim
for `tests/test_distribution.py`. No shim touched the repository. Nothing in the
codebase uses 3.11-only syntax or stdlib outside that one test import, so the
substitution is sound for command-surface and documentation testing. It is not a
substitute for a real 3.11/3.12 run, which CI already covers.

### Paths executed

| Path | Result |
|---|---|
| Python version gate on an unsupported interpreter | Pass — exits 1, no side effects |
| Method A: `tasks.py setup` + `demo` from a clean tree | Pass |
| Method A verification block (`--version`, `doctor --demo`, `validate-request`) | Pass, output corrected in the guide |
| Method B: minimal venv, runtime deps only | Pass — `pytest` and `ruff` correctly absent |
| Method C: `pipx install .` and use outside the checkout | Pass |
| Method D: `python -m build`, wheel contents, fresh-env install | Pass |
| Source distribution contents | **Fail — fixed**, see finding 1 |
| Sdist self-sufficiency (unpack → build wheel → install → generate) | Pass |
| Offline wheelhouse build and `--no-index` install | Pass, with a documented pip-bootstrap caveat |
| `USAGE.md` beginner walkthrough, all five steps | Partial — see findings 3 and 5 |
| `init` non-interactive, both documented invocations | Pass |
| `export-schema`, overwrite guard, `--force` | Pass |
| Cache and storage maintenance commands | Pass |
| Hermetic run, `--no-store`, `--no-cache`, `--format` override | `--format` failed late, see finding 2 |
| Output/store writability preflight | Pass — exits 2 before any provider call |
| Documented CI smoke test, verbatim | Pass |
| `ruff check`, `ruff format --check`, `pytest -q` | Pass — 40 tests, clean |
| Live provider and Brave credentials | Not exercised, by design |
| Docker, macOS | Not exercised — unavailable in this environment |

### Findings

**1. High — the source distribution packaged untracked working-directory files.**
`[tool.hatch.build] exclude` was a denylist naming five specific paths. Anything
else in the tree was packaged. Reproduced on a real git checkout: a
`my-request.json`, a `scenario-request.schema.json`, and an `artifacts/scenario.md`
created by following `USAGE.md` were all present inside
`adversaryflow-0.3.0.tar.gz`. This matters more here than in most projects,
because a scenario request enumerates environment names, identity systems,
security tooling, crown jewels, designated test assets, authorized users, and
rules of engagement. The prior review fixed the symptom for `.claude` without
changing the denylist shape.

Fixed by adding `[tool.hatch.build.targets.sdist] include`, an explicit
allowlist. Verified: the same three scratch files are now absent, the sdist
still unpacks and builds a working wheel, and the wheel still carries both
runtime prompt files. `INSTALLATION.md` gained a verification command that lists
anything unexpected in a built sdist.

**2. Medium — `--format` was validated after generation finished.**
`generate --format xml` ran the full 12-node pipeline before rejecting the value.
In demo mode that wastes seconds; against a live provider it is 12 billable
calls thrown away on a typo. Fixed by resolving the renderer before the provider
is constructed. Verified: the same command now fails in 0.37 s, creates no
output directory, and exits 2.

**3. Medium — the beginner walkthrough overwrote its own evidence.**
The trace path is the output path with the extension replaced, so
`reports/tabletop.md` and `reports/tabletop.html` — the two commands step 3 told
readers to run — both wrote `reports/tabletop.trace.json`. Step 4 then asked the
reader to inspect that file as the record of their run. It was the second run's
trace; the first was gone. Confirmed by reading the surviving trace's
`storage.run_id`. The walkthrough now uses distinct output stems and states the
rule, noting that `.adversaryflow/runs/` retains an unclobbered copy either way.
The underlying naming behavior was left alone as a deliberate behavior change
rather than a doc fix.

**4. Medium — `.env.example` shipped a placeholder that defeated `doctor`.**
`ADVERSARYFLOW_LLM_BASE_URL=https://your-provider.example/v1` is non-empty, and
`doctor` only reports empty variables as missing. A user who filled in the key
and model and left the URL alone got `Ready for live generation` while pointed at
a domain that does not resolve. Fixed by blanking the value; `doctor` now lists
the base URL among the missing variables. `USAGE.md` states plainly that `doctor`
checks for emptiness, not validity.

**5. Low — the cache-hit claim was off by one run.**
`USAGE.md` said the "second identical run" makes zero model calls, but step 3
already produces two runs of the same request, so the HTML run reports
`Model calls: 0` before the reader reaches the step demonstrating it. Corrected,
along with the rule that node-cache identity ignores output path and format.

**6. Low — documented node-cache counts were wrong.**
A first draft of this pass's own corrections claimed 24 cache files; measurement
on a clean store gives 12 for a TTP-based request and 7 for an ad hoc one — one
file per resolved model node. Both guides now state the rule rather than a
constant.

**7. Low — `init` contradicts the documented `mode` default.**
The field table gives `emulation_plan`, correct for the schema. The wizard writes
`tabletop` and therefore never prompts for a designated test asset. Both facts
are now stated together in `USAGE.md`.

**8. Low — interpreter selection was undocumented.**
`scripts/setup.sh` honors `PYTHON`, the Makefile documents `make PYTHON=... setup`,
and `INSTALLATION.md` mentioned neither, despite the search order
(3.13 → 3.12 → 3.11 → python3 → python) mattering on multi-version hosts. Added,
along with a note that Ubuntu 22.04's default repositories cannot satisfy the
requirement.

**9. Low — the offline section carried a step that cannot work offline.**
Method B's `pip install --upgrade pip` fails under `--no-index`. The offline
section now says so, and adds hash-recording commands and the fact that
`pydantic-core` and `MarkupSafe` make a wheelhouse OS-, architecture-, and
interpreter-specific.

**10. Low — exit-code guidance was too coarse for automation.**
"Generally exit 2 … otherwise nonzero" hid a useful distinction. All codes were
measured and tabulated: `1` means the command ran and the answer was no, `2`
means it never ran. A missing run ID and a hash mismatch differ this way, which
is exactly the case an integrity pipeline needs to branch on.

**11. Informational — global installs write to the current directory.**
Confirmed with pipx: running `generate` from an arbitrary directory creates
`reports/` and `.adversaryflow/` there and reads `.env` from there. Now noted
under Method C.

### Files changed

`pyproject.toml`, `.env.example`, `src/adversaryflow/cli.py`, `INSTALLATION.md`,
`USAGE.md`, `CHANGELOG.md`. Lint, format, and the 40-test suite pass after the
changes; the corrected walkthrough was re-run verbatim against the edited tree.

### Still uncovered

1. No macOS runner. Native macOS install remains untested.
2. No Docker build or container run in this pass; the previous pass covered it.
3. No live OpenAI-compatible provider or Brave credential test.
4. No artifact signing. The file-list half of this recommendation was
   implemented after the review; see below. Hash signing remains open.

### Follow-up: sdist allowlist enforcement

Finding 1 was a configuration fix with nothing holding it in place. It is now
enforced.

`scripts/check_sdist.py` reads the allowlist from `pyproject.toml` and compares
it against the members of a built tarball. It fails on any unexpected path, and
it fails on a reversion to a denylist rather than silently checking nothing.
Exit codes separate "checked it and it failed" (`1`) from "could not check"
(`2`), so a missing artifact cannot be mistaken for a pass. It is stdlib-only
and runs from `python tasks.py build`, `make build`, or directly.

CI plants two decoy scenario requests — one at the checkout root, one under
`artifacts/` — before running `python -m build`, then runs the check. This is
the part that matters: without a dirty tree, a passing check proves nothing,
because the runner's tree is clean by construction and the old denylist would
have passed too.

Verified four ways on a real build:

| Scenario | Expected | Observed |
|---|---|---|
| Allowlist in place, decoys planted | pass, decoys absent from artifact | exit 0, 80 members, decoys absent |
| Config reverted to the pre-fix denylist | fail loudly | exit 1, "must be built from an explicit allowlist" |
| Allowlist correct but artifact doctored to contain `my-request.json`, `artifacts/scenario.md`, `.env` | fail, naming each path | exit 1, all three listed |
| No artifact, empty `dist/`, or a nonexistent path | cannot check | exit 2 in all three cases |

Six unit tests cover the matching logic without requiring a build, including
prefix-containment (`src` must not authorize `src-scratch`) and each specific
path the review found leaking. A seventh asserts every allowlist entry still
exists, so the list cannot rot into a false sense of coverage. Lint and format
coverage was extended to `scripts/` and `tasks.py`, which were previously
unchecked. Suite is 51 tests, passing.

## First pass — 2026-07-22

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
