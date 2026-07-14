# Security Policy

## Supported version

Security fixes are applied to the latest release line.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose credentials, bypass source validation, weaken RoE enforcement, permit unsafe output, enable SSRF, or falsify citations. Report it privately through the repository owner's GitHub security-advisory channel after the repository is created.

Include a sanitized description, affected version, minimal reproduction, impact, and a proposed mitigation when available. Do not test against systems you do not own or have explicit authorization to assess.

## Security boundary

AdversaryFlow is a planning and exercise-generation system, not an autonomous intrusion platform. Prompt text is guidance. Deterministic schema validation, retrieval allowlisting, URL/SSRF controls, safety policy, factuality evaluation, output review, and explicit human approval are the security boundary.
