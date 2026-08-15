# Diagnostics and support

`adversaryflow doctor` checks supported platform, Python version, PyYAML, the configured RoE, ability catalog, execution-adapter readiness, loopback binding, and offline mode. Use `--json` for structured output.

`doctor --fix` creates missing local artifact directories only. It does not install software, change system settings, or contact a provider.

`adversaryflow support-bundle` writes a ZIP containing diagnostics and a README. The bundle is designed to exclude secrets and provider credentials.

The ZIP contains `diagnostics.json` and `README.txt`. `diagnostics.json` includes product, Python, platform, and `doctor` output; no provider credential or secret is written. See [../SCHEMAS.md](../SCHEMAS.md) for the complete artifact map.

For step-by-step recovery, see [../TROUBLESHOOTING.md](../TROUBLESHOOTING.md).
