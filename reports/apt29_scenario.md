# APT29 Safe Red Team Exercise

- Generated: 2026-07-14T15:26:53.260397+00:00
- Actor input: APT29
- Exercise mode: emulation_plan
- Safety gate: PASS
- Factuality gate: PASS (100%)
- Citation coverage: 100%
- Source validation: PASS
- Model calls: 12
- Repair calls: 0

## Executive Summary

This is a safe, threat-informed exercise shell for APT29. Demo mode validates orchestration and policy controls but does not assert live actor TTPs.

## Actor and Grounding Status

- Canonical name: APT29
- ATT&CK ID: Unresolved
- Identity confidence: low
- Grounded techniques: 0
- Claim graph nodes: 0
- Claim graph edges: 0
- Caveats:
  - Demo mode intentionally omits live-grounded actor claims.
  - Connect a local ATT&CK bundle and Brave search for production use.

## Exercise Assumptions

- All actions occur in the approved exercise window.
- Only designated test assets and exercise identities are used.
- Synthetic data replaces production-sensitive data.

## Rules of Engagement Summary

- Designated test assets: LAB-WIN-01
- No destructive execution: yes
- No real funds or live transactions: yes
- Synthetic data required for objective access: yes

## Exercise Path

### 1. Initial Access Validation

**Objective:** Validate an approved initial-access control without targeting real users.

**ATT&CK:** Not actor-mapped in demo

**Action summary:** Use a pre-created exercise identity or benign test artifact to validate the control path.

**Safe equivalent:** Demonstrate access only to the designated test asset and synthetic content.

**Test asset:** LAB-WIN-01

**Safety classification:** controlled_emulation

**Prerequisites**
- Exercise identity
- Approved access path
- Defender telemetry enabled

**Expected observables**
- Identity provider: Authentication and conditional-access decision (requires Exercise account logs retained)

**Evidence to capture**
- Timestamp
- Exercise account
- Control decision
- Relevant alert IDs

**Detection opportunities**
- Unusual exercise-account sign-in
- Policy decision correlation

**Stop conditions**
- Unexpected production impact is observed
- Activity leaves the authorized asset boundary
- Exercise control issues a stop command

**Cleanup**
- Remove test artifacts
- Revoke or reset exercise credentials
- Confirm the asset returned to its baseline state

### 2. Execution / Access Validation

**Objective:** Generate safe endpoint or service telemetry on the designated asset.

**ATT&CK:** Not actor-mapped in demo

**Action summary:** Perform an approved benign action that resembles the selected behavior at the telemetry level.

**Safe equivalent:** Use an inert marker or signed test utility rather than a payload.

**Test asset:** LAB-WIN-01

**Safety classification:** controlled_emulation

**Prerequisites**
- Test utility approved
- Endpoint logging enabled

**Expected observables**
- Endpoint telemetry: Process, parent-child, file, and network events associated with the test action

**Evidence to capture**
- Process tree
- File hash
- Network destination
- Alert disposition

**Detection opportunities**
- Behavioral rule coverage
- Parent-child anomaly detection

**Stop conditions**
- Unexpected production impact is observed
- Activity leaves the authorized asset boundary
- Exercise control issues a stop command

**Cleanup**
- Remove test artifacts
- Revoke or reset exercise credentials
- Confirm the asset returned to its baseline state

### 3. Objective Access

**Objective:** Prove access to a protected business objective without touching real sensitive data.

**ATT&CK:** Not actor-mapped in demo

**Action summary:** Access a synthetic canary record placed in the approved exercise location.

**Safe equivalent:** Capture the canary identifier and access log; do not copy production data.

**Test asset:** LAB-WIN-01

**Safety classification:** controlled_emulation

**Prerequisites**
- Synthetic canary record
- Read-only exercise permission

**Expected observables**
- Data or cloud audit log: Read access to the canary object

**Evidence to capture**
- Canary identifier
- Access event
- Identity
- Alert or case ID

**Detection opportunities**
- Sensitive-object access analytics
- Identity-to-data correlation

**Stop conditions**
- Unexpected production impact is observed
- Activity leaves the authorized asset boundary
- Exercise control issues a stop command

**Cleanup**
- Remove test artifacts
- Revoke or reset exercise credentials
- Confirm the asset returned to its baseline state

### 4. Safe Impact Simulation

**Objective:** Validate impact detection and response without destructive execution.

**ATT&CK:** Not actor-mapped in demo

**Action summary:** Create a reversible impact marker on the designated test asset.

**Safe equivalent:** Write a harmless marker file or toggle an isolated test-only flag, then restore baseline.

**Test asset:** LAB-WIN-01

**Safety classification:** controlled_emulation

**Prerequisites**
- Rollback verified
- Exercise controller present

**Expected observables**
- Endpoint and change monitoring: Creation and removal of the approved impact marker

**Evidence to capture**
- Marker creation
- Alert timing
- Containment decision
- Rollback evidence

**Detection opportunities**
- Impact-stage alerting
- Change-control correlation

**Stop conditions**
- Unexpected production impact is observed
- Activity leaves the authorized asset boundary
- Exercise control issues a stop command

**Cleanup**
- Remove test artifacts
- Revoke or reset exercise credentials
- Confirm the asset returned to its baseline state

## Exercise Injects

| Time | Audience | Inject | Expected response | Success measure |
|---|---|---|---|---|
| T+00:15 | SOC | An authentication anomaly associated with the exercise identity appears. | Triage identity, source, device, and policy context. | Correctly classify the event and preserve evidence within the target time. |
| T+00:45 | Incident Response | Endpoint telemetry indicates a benign but suspicious test action on the designated asset. | Correlate endpoint and identity evidence and decide whether containment is warranted. | Document a defensible containment decision with no impact to production. |
| T+01:30 | Exercise Control | The synthetic objective artifact is accessed and the impact marker is created. | Validate objective detection, initiate cleanup, and capture lessons learned. | All artifacts are removed and telemetry gaps are assigned owners. |

## Metrics

- Time to first high-confidence alert
- Percentage of expected telemetry observed
- Analyst time to correctly map activity to ATT&CK
- Containment decision quality
- Cleanup completion and evidence integrity

## Claim-Level Citation Graph

No actor-specific factual claims were emitted for evaluation.
## Factuality Evaluation

- Result: PASS
- Score: 100%
- Citation coverage: 100%
- Claims evaluated: 0
- Claims supported: 0

## Source Manifest

No live sources were attached to this run.

## QA and Safety Findings

No blocking findings or warnings.

## Operator Approval Gate

This document is a planning artifact. Execution requires a human reviewer to confirm scope, assets, identities, approvals, telemetry readiness, rollback, and exercise timing.
