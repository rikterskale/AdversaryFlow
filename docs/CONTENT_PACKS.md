# Signed content packs

AdversaryFlow content packs let an operator update reviewed abilities and
detection-rule bindings separately from the application release. Version 1.0
packs are ZIP files containing `manifest.json`, `abilities.json`, and an
optional `detection_bindings.json`. The manifest pins the ATT&CK version and
contains SHA-256 digests for each payload. An Ed25519 signature covers the
canonical manifest, and the installation supplies the trust roots.

The service never extracts a pack or executes its commands. It verifies the
signature, payload digests, ability identity, detection-binding metadata, and
resource limits before using a pack. Only abilities marked `reviewed` can be
signed. A signed ability can be exported to Atomic YAML; its permissions,
fidelity, cleanup, and accepted procedure links still appear in the manifest.
Conflicting abilities or rule bindings fail closed.

## Enable pack verification

Install the optional verification dependency in the application's environment:

~~~powershell
python -m pip install ".[content-packs]"
~~~

Generate a key pair in a protected signing environment. Keep the private key
off the application host:

~~~powershell
python -m backend.content_pack keygen --private-key .\af-content-signing.pem --public-key .\af-content-public.b64
~~~

Set the trusted public key and pack directory in the service environment. The
trust-store value is a JSON object whose values are base64-encoded raw
Ed25519 public keys:

~~~powershell
$env:ADVERSARYFLOW_CONTENT_TRUSTED_KEYS = '{"af-prod-2026":"<base64 public key>"}'
$env:ADVERSARYFLOW_CONTENT_PACK_DIR = 'C:\ProgramData\AdversaryFlow\content-packs'
~~~

The pack directory accepts `.afpack` and `.zip` files. `GET /api/content-packs`
lists only packs whose signatures and payloads verify. A malformed, untrusted,
or conflicting pack makes that request and Atomic export fail closed. Replace
packs by deploying a new version under the same `pack_id`; do not leave two
versions of one pack installed together.

## Create and verify a pack

The JSON source contains `pack_id`, `pack_version`, `attack_version`,
`abilities`, and `detection_bindings`. Ability records use the internal
format-neutral ability fields from
[`adversaryflow-ability.schema.json`](../schemas/adversaryflow-ability.schema.json)
and must set `review_status` to `reviewed`. The signer computes stable ability
IDs and content digests. A detection binding records a provider (`sigma`,
`elastic`, `splunk`, or `kql`), rule ID, title, optional HTTPS URL, the SHA-256
of the reviewed rule content, reviewer, and review time.

~~~powershell
python -m backend.content_pack sign .\content-source.json .\adversaryflow-lab.afpack --private-key .\af-content-signing.pem --key-id af-prod-2026
$env:ADVERSARYFLOW_CONTENT_TRUSTED_KEYS = '{"af-prod-2026":"<base64 public key>"}'
python -m backend.content_pack verify .\adversaryflow-lab.afpack
~~~

Accepted procedure evidence is linked with `procedure_candidate_ids`. When a
plan contains accepted report procedures, an ability without a matching link
is reported as `wrong_shape`. The signed binding metadata is shown in reports
with its reviewer, pack version, signing-key ID, rule digest, and provider.
When no detection bindings are installed, reports do not invent a per-technique
binding gap. Once the active packs provide bindings, unbound planned techniques
are reported as a coverage gap.

## Trust and audit limits

Ed25519 signatures prove that a holder of a configured private key signed the
manifest. They do not prove the rule or ability is effective, safe in every
environment, or independently reviewed. Keep private keys in the organization's
signing system, protect public-key configuration as deployment policy, and
rotate key IDs deliberately. Each saved engagement revision now records the
content-pack-set digest and exact pack IDs, versions, signer keys, and pack
hashes, so later pack updates do not rewrite its recorded content provenance.
