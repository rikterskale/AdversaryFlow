#!/bin/sh
set -eu

token_file="/run/adversaryflow/api-token"
public_url="${ADVERSARYFLOW_PUBLIC_URL:-http://127.0.0.1:5000}"

if [ -z "${ADVERSARYFLOW_API_TOKEN:-}" ]; then
    ADVERSARYFLOW_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
    export ADVERSARYFLOW_API_TOKEN
    token_note="generated for this container start"
else
    token_note="supplied through ADVERSARYFLOW_API_TOKEN"
fi

umask 077
printf '%s' "$ADVERSARYFLOW_API_TOKEN" > "$token_file"

printf '\n'
printf '%s\n' '============================================================'
printf '%s\n' '  AdversaryFlow container configured successfully'
printf '  URL:       %s\n' "$public_url"
printf '  API token: %s (%s)\n' "$ADVERSARYFLOW_API_TOKEN" "$token_note"
printf '%s\n' '  Next step: open the URL and enter this token when prompted.'
printf '%s\n' '  First start: ATT&CK data downloads into the cache volume.'
printf '%s\n' '  Authorized disposable labs only; see ACCEPTABLE_USE.md.'
printf '%s\n' '============================================================'
printf '\n'

exec adversaryflow "$@"
