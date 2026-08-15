# Examples

These examples use the packaged defaults. All examples remain within the local simulation boundary except `plan`, which retrieves the MITRE ATT&CK Enterprise STIX bundle over HTTPS while producing a dry-run plan.

## Validate the local setup

```powershell
adversaryflow doctor --json
adversaryflow validate examples/roe.yaml
```

## Plan and draft

```powershell
adversaryflow plan --roe examples/roe.yaml --actor "APT29" --technique T1059.001
adversaryflow draft --roe examples/roe.yaml --actor "APT29" --objective "validate endpoint process visibility"
```

`plan` is dry-run planning; `draft` uses the offline planner and validates the resulting draft against the RoE and catalog.

## Reviewable campaign

```powershell
adversaryflow campaign --actor "APT29" --objective "validate endpoint process visibility"
adversaryflow campaign inspect --campaign-id campaign-...
```

After scope and schedule review, only the approver named in the RoE may authorize local synthetic emulation:

```powershell
adversaryflow campaign --campaign-id campaign-... --approve --approver "manager@example.test"
```

## Recover from a provider failure

```powershell
adversaryflow provider diagnose
adversaryflow campaign --actor "APT29" --objective "validate endpoint process visibility" --fallback-offline
```

## Record a decision

```powershell
adversaryflow campaign reject --campaign-id campaign-... --approver "manager@example.test" --reason "Not scheduled"
adversaryflow campaign cancel --campaign-id campaign-... --reason "Operator requested stop"
```

## Guided workspace

```powershell
adversaryflow guide --interactive
adversaryflow manager --open
```

The manager is loopback-only. It can approve and run a reviewed campaign only through the fixed `local-synthetic` adapter after the named RoE approver enters the exact confirmation; `local-behavioral` and `idpt-local` execution remain CLI-only.
