# Providers and profiles

Offline mode is the default provider. The only hosted mode is `openai-compatible`.

## Configuration

Provider configuration reads these environment variables: `ADVERSARYFLOW_PROVIDER`, `ADVERSARYFLOW_MODEL`, `ADVERSARYFLOW_ENDPOINT`, `ADVERSARYFLOW_API_KEY`, `ADVERSARYFLOW_PROFILE`, and `ADVERSARYFLOW_PROFILE_FILE`. An OpenAI-compatible endpoint must use HTTPS and requires a model and API key.

Profile data is stored by default in `artifacts/providers/profiles.json`. Profiles retain non-secret provider, endpoint, model, and credential-environment-variable metadata; they do not store an API key.

## Safe sequence

1. Run `adversaryflow provider configure` for PowerShell environment-variable instructions.
2. Run `adversaryflow provider validate`; it does not send a request.
3. Run `adversaryflow provider profile status` to see readiness without revealing the credential value.
4. Optionally run `adversaryflow provider test` for one planning request.

Provider request metadata stored with a campaign contains hashes, timing, model, endpoint, and status; it does not retain the API key or raw prompt/response.

See [../CLI_REFERENCE.md](../CLI_REFERENCE.md) for profile commands.
