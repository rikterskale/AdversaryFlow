# Independent telemetry correlation

Exercise receipts are self-reported. AdversaryFlow only calls a run independently
observed when endpoint or SIEM events satisfy the technique's acceptance contract.
All 146 bounded techniques have a contract available in the plan UI and from:

```console
adversaryflow-telemetry criteria T1110
```

Each exercise launches a harmless marker child process whose command line contains
the exact `run_id`, `technique_id`, and scenario. This gives process telemetry a
stable correlation key. A pass requires all of the following:

1. the receipt SHA-256 is valid and its status is `passed`;
2. an independent `endpoint` or `siem` event contains both the run ID and technique ID;
3. the required number of technique-relevant activity events occur on the marker
   host within the receipt start/completion window (with 30 seconds of clock skew).

For example, T1110 requires at least five `authentication_failure` events in
addition to the marker. Seeing only the Python runner or its receipt does not pass.
The result proves observation of the bounded loopback exercise, not password attacks
against real accounts.

## Event input

Correlation accepts a JSON array, an object with an `events` array, or JSON Lines.
Exported SIEM fields can be mapped to this vendor-neutral shape:

```json
{
  "timestamp": "2026-09-04T16:00:00Z",
  "source": "siem",
  "event_id": "auth-1042",
  "host": "lab-host-1",
  "event_type": "authentication_failure",
  "message": "Rejected loopback authentication",
  "count": 5
}
```

The accepted sources are only `endpoint` and `siem`. Required event types and counts
are returned by `criteria`; `count` defaults to one. Provider-specific exports should
retain durable record IDs so successful results return useful `telemetry_refs`.

```console
adversaryflow-telemetry correlate \
  --receipt t1110-receipt.json \
  --telemetry endpoint-events.jsonl \
  --telemetry siem-events.json
```

The command exits zero only when the contract passes.

## Read-only native collection

The bundled collector can capture the receipt window from Windows Event Log,
Linux journal, or macOS unified log:

```console
adversaryflow-telemetry collect --platform auto \
  --receipt t1110-receipt.json --output native-events.json
```

Collection is read-only. Windows queries System, Application, Security, and Sysmon
Operational logs when accessible. Linux queries `journalctl`; macOS queries
`log show`. Process, authentication, network, and file auditing must already be
enabled. Native records are retained as `provider_event` unless a SIEM/exporter maps
them to the acceptance event taxonomy, so a sparse default OS log can legitimately
fail the gate. AdversaryFlow does not treat missing telemetry as success.

Clock synchronization is required. Preserve the receipt, correlation JSON, original
endpoint/SIEM export, and referenced provider record IDs together as the evidence
bundle.
