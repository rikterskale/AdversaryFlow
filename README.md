# AdversaryFlow

AdversaryFlow is a safety-first purple-team platform for turning current threat-intelligence into reviewable, scoped, defensive campaign simulations.

Supported platforms are Windows, Debian, Ubuntu, and Kali Linux. Supported environments are validated by `adversaryflow doctor`; unsupported platforms fail closed with a remediation message.

## MVP

The first vertical slice provides:

- A machine-readable Rules of Engagement (RoE) file.
- Hard target allowlist enforcement and denylist support.
- Mandatory dry-run planning.
- Human approval records for campaign execution.
- Audit events with redacted inputs and SHA-256 evidence references.
- MITRE ATT&CK STIX ingestion from the official public repository.
- Campaign plans that pair each technique with expected telemetry and validation questions.
- A provider-neutral AI review prompt that keeps planning defensive and novice-friendly.
- Versioned, safe emulation abilities with telemetry expectations, cleanup contracts, and deterministic plan hashes.

The MVP deliberately does not generate exploit payloads, persistence, credential theft, evasion, lateral movement commands, or unrestricted network actions. Execution adapters are simulation-only and must be extended behind the safety interfaces.

AI provider integration is intentionally left behind a small adapter boundary so an organization can choose its approved model, data-handling policy, and retention settings.

The `draft` command uses a deterministic offline fallback. A hosted or local model can implement the `AIPlanner` interface, receive `build_ai_request_prompt(...)`, return `AICampaignDraft`, and then pass through `validate_ai_draft(...)` before any emulation plan is created.

## IDPT-inspired capabilities

AdversaryFlow adopts the reference project's useful control-plane patterns: immutable ability metadata, fixed scenario planning, explicit technique and platform fields, telemetry as a first-class output, cleanup contracts, run-root evidence, and deterministic plan provenance. The initial catalog only permits abstract simulation actions, no arbitrary commands, no remote execution, and no non-loopback network scope.

## Quick start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
adversaryflow validate examples\roe.yaml
adversaryflow plan --roe examples\roe.yaml --actor "APT29" --technique T1059.001
adversaryflow draft --roe examples\roe.yaml --actor "APT29" --objective "validate endpoint process visibility"
adversaryflow demo --roe examples\roe.yaml --actor "APT29" --objective "validate endpoint process visibility"
adversaryflow doctor
adversaryflow support-bundle
adversaryflow capabilities
```

Use `--live` only in a future approved adapter; the current release always produces a dry-run plan.

The local workflow includes an ephemeral loopback sink bound to `127.0.0.1` only. It accepts a fixed synthetic marker, records the request for telemetry validation, and shuts down when the run completes. No external network connection is used.

See [docs/INSTALL.md](docs/INSTALL.md) for Windows, Linux/Kali, and Docker setup. `doctor` is the first troubleshooting command, and `support-bundle` creates a redacted diagnostics archive.

## AI provider management

Offline mode is the default and requires no credentials. To inspect or validate provider configuration:

```powershell
adversaryflow provider status
adversaryflow provider configure
adversaryflow provider validate
```

The supported hosted configuration is an OpenAI-compatible endpoint using `ADVERSARYFLOW_PROVIDER`, `ADVERSARYFLOW_ENDPOINT`, `ADVERSARYFLOW_MODEL`, and `ADVERSARYFLOW_API_KEY`. The API key is read from the process environment only; it is never written to project files or support bundles. Validation is non-networked.

## Product direction

The intended workflow is: source-backed intelligence → novice-friendly campaign plan → manager review → scoped simulation → telemetry capture → gap report and retest plan.
