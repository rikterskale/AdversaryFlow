#!/bin/sh
set -eu

token_file="/run/adversaryflow/api-token"
cache_dir="${ADVERSARYFLOW_CACHE_DIR:-/var/lib/adversaryflow/cache}"
service_port="${ADVERSARYFLOW_PORT:-5000}"
public_url="${ADVERSARYFLOW_PUBLIC_URL:-http://127.0.0.1:$service_port}"

if [ ! -d "$cache_dir" ] || [ ! -w "$cache_dir" ]; then
    printf 'AdversaryFlow cannot write its cache directory: %s\n' "$cache_dir" >&2
    printf '%s\n' 'Fix the volume ownership or set ADVERSARYFLOW_CACHE_DIR to a writable mounted directory.' >&2
    exit 1
fi

if [ ! -d "${token_file%/*}" ] || [ ! -w "${token_file%/*}" ]; then
    printf 'AdversaryFlow cannot write its runtime token directory: %s\n' "${token_file%/*}" >&2
    printf '%s\n' 'Restore the /run/adversaryflow tmpfs mount with UID/GID 10001.' >&2
    exit 1
fi

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
