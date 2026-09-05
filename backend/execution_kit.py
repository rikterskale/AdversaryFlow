"""Generate self-contained, offline execution kits for lab operators.

The web service only serializes artifacts.  Generated runners execute on the
operator's destination machine and never call back to AdversaryFlow.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Tuple

from . import command_catalog

MAX_PLAN_STEPS = 4000
MAX_COMMAND_LENGTH = 10_000
SUPPORTED_PLATFORMS = {"windows", "linux"}
EXERCISE_RUNNER_NAME = "AdversaryFlow-exercises.py"
FIDELITY_VALUES = {"direct", "bounded_synthetic", "lab_proxy"}


class ExecutionKitError(ValueError):
    """The submitted browser plan cannot safely produce an execution kit."""


@dataclass(frozen=True)
class PlanStep:
    sequence: int
    step_id: str
    tactic: str
    tactic_title: str
    technique_id: str
    technique_name: str
    platform: str
    supported: bool
    command_source: str
    fidelity: str
    risk: str
    requires_admin: bool
    requires_network: bool
    prerequisites: Tuple[str, ...]
    side_effects: Tuple[str, ...]
    planned_command: str
    cleanup_command: str
    expected_output: str
    expected_telemetry: str
    timeout_seconds: int


@dataclass(frozen=True)
class ExecutionPlan:
    actor_id: str
    actor_name: str
    data_version: str
    generated: str
    operator: str
    target: str
    platform: str
    steps: Tuple[PlanStep, ...]
    plan_sha256: str


def _string(value: Any, field: str, *, maximum: int = 10_000, required: bool = False) -> str:
    if not isinstance(value, str) or len(value) > maximum or (required and not value.strip()):
        raise ExecutionKitError(f"{field} is invalid")
    if "\x00" in value:
        raise ExecutionKitError(f"{field} contains a null byte")
    return value


def _strings(value: Any, field: str, *, maximum_items: int = 100) -> Tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum_items:
        raise ExecutionKitError(f"{field} is invalid")
    return tuple(_string(item, field, maximum=2_000) for item in value)


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ExecutionKitError(f"{field} must be true or false")
    return value


def _slug(value: str, fallback: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-")
    return (cleaned[:80] or fallback)


def _step_slug(value: str) -> str:
    return _slug(value.lower(), "step")[:40]


def _optional_bool(value: Any, field: str, default: bool = False) -> bool:
    if value is None:
        return default
    return _boolean(value, field)


def _exercise_technique_id(command: Mapping[str, Any]) -> str:
    tokens = str(command.get("command") or "").split()
    if tokens and re.fullmatch(r"T[0-9]{4}(?:\.[0-9]{3})?", tokens[-1]):
        return tokens[-1]
    acceptance = command.get("telemetry_acceptance")
    if isinstance(acceptance, dict):
        technique_id = str(acceptance.get("technique_id") or "")
        if re.fullmatch(r"T[0-9]{4}(?:\.[0-9]{3})?", technique_id):
            return technique_id
    return ""


def kit_exercise_command(command: Mapping[str, Any], platform: str) -> str:
    """Rewrite a bounded exercise so the kit invokes the bundled runner."""
    planned = str(command.get("command") or "")
    if command.get("exercise_kind") != "technique_relevant_bounded":
        return planned
    technique_id = _exercise_technique_id(command)
    if not technique_id:
        return planned
    if platform == "windows":
        return f"python .\\{EXERCISE_RUNNER_NAME} {technique_id}"
    return f"python3 ./{EXERCISE_RUNNER_NAME} {technique_id}"


def _unsupported_command(platform: str, message: str, note: str) -> Dict[str, Any]:
    return {
        "platform": platform,
        "command": message,
        "note": note,
        "cleanup": "",
        "risk": "none",
        "side_effects": [],
        "requires_admin": False,
        "requires_network": False,
        "network_targets": [],
        "prerequisites": [],
        "expected_telemetry": "",
        "expected_output": "",
        "timeout_seconds": 0,
        "rollback": "",
        "cleanup_required": False,
        "acknowledgment_required": False,
        "fidelity": "direct",
        "unsupported": True,
    }


def _apply_scope(command: Dict[str, Any], scope: Mapping[str, Any], platform: str) -> Dict[str, Any]:
    bound = dict(command)
    restrictions = []
    if bound.get("requires_network") and not scope.get("allow_network"):
        restrictions.append("network-active commands are disabled")
    if bound.get("requires_admin") and not scope.get("allow_admin"):
        restrictions.append("administrator commands are disabled")
    if bound.get("risk") == "high" and not scope.get("allow_high_risk"):
        restrictions.append("high-risk commands are disabled")
    if restrictions:
        bound["command"] = f"Restricted by scope: {'; '.join(restrictions)}."
        bound["note"] = "Enable the corresponding safety option in Scope after reviewing the risk."
        bound["unsupported"] = True
        bound["restricted"] = True
        return bound
    bound["command"] = kit_exercise_command(bound, platform)
    bound.pop("unsupported", None)
    bound.pop("restricted", None)
    return bound


def rebind_to_catalog(document: Mapping[str, Any]) -> Dict[str, Any]:
    """Replace client-supplied command text with live catalog records.

    Stage order and technique identity come from the submitted plan. Command
    bodies, safety metadata, and fidelity always come from the catalog so an
    execution kit cannot carry an operator- or attacker-supplied payload.
    """
    if not isinstance(document, dict):
        raise ExecutionKitError("Plan must be a JSON object")
    rebound = json.loads(json.dumps(document))
    scope = rebound.get("scope")
    stages = rebound.get("stages")
    if not isinstance(scope, dict) or not isinstance(stages, list):
        raise ExecutionKitError("Plan metadata is incomplete")
    platform = _string(scope.get("command_platform"), "scope.command_platform", maximum=20, required=True).lower()
    if platform not in SUPPORTED_PLATFORMS:
        raise ExecutionKitError("Execution kits are available for Windows and Linux plans")
    for key in ("allow_network", "allow_admin", "allow_high_risk", "curated_only"):
        if key in scope:
            scope[key] = _boolean(scope[key], f"scope.{key}")
    curated_only = bool(scope.get("curated_only"))

    for stage in stages:
        if not isinstance(stage, dict) or not isinstance(stage.get("techniques"), list):
            raise ExecutionKitError("Plan contains an invalid stage")
        tactic = _string(stage.get("tactic"), "stage.tactic", maximum=120, required=True)
        for technique in stage["techniques"]:
            if not isinstance(technique, dict):
                raise ExecutionKitError("Plan contains an invalid technique")
            technique_id = _string(technique.get("id"), "technique.id", maximum=64, required=True)
            technique_name = _string(technique.get("name"), "technique.name", maximum=500, required=True)
            result = command_catalog.get_commands(technique_id, technique_name, [tactic])
            source = result["source"]
            exact = next((item for item in result["commands"] if item.get("platform") == platform), None)
            if curated_only and source == "fallback":
                exact = None
                note = "Curated tests only is enabled; this technique has no keyed catalog record."
                message = f"No curated {platform} test is available for this technique."
            else:
                note = "Choose another platform or contribute an exact-platform test."
                message = f"No {platform} test is available for this technique."
            bound = (
                _unsupported_command(platform, message, note)
                if exact is None
                else _apply_scope(dict(exact), scope, platform)
            )
            technique["command"] = bound
            technique["command_source"] = "fallback" if source == "fallback" else "curated"
            technique["supported"] = not bool(bound.get("unsupported"))
    return rebound


def _exercise_runner_source() -> bytes:
    return (Path(__file__).resolve().parent / "lab_exercises.py").read_bytes()


def _plan_needs_exercise_runner(plan: ExecutionPlan) -> bool:
    return any(step.supported and EXERCISE_RUNNER_NAME in step.planned_command for step in plan.steps)


def normalize_plan(document: Any) -> ExecutionPlan:
    """Validate the browser's plan export and assign stable occurrence IDs."""
    if not isinstance(document, dict):
        raise ExecutionKitError("Plan must be a JSON object")
    if document.get("schema_version") != "2.0" or document.get("tool") != "AdversaryFlow":
        raise ExecutionKitError("Only AdversaryFlow schema 2.0 plans can produce execution kits")

    actor = document.get("actor")
    scope = document.get("scope")
    context = document.get("execution_context")
    stages = document.get("stages")
    if not isinstance(actor, dict) or not isinstance(scope, dict) or not isinstance(context, dict):
        raise ExecutionKitError("Plan metadata is incomplete")
    if not isinstance(stages, list) or not stages or len(stages) > 32:
        raise ExecutionKitError("Plan must contain between 1 and 32 stages")

    actor_id = _string(actor.get("attack_id"), "actor.attack_id", maximum=64, required=True)
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]{0,63}", actor_id):
        raise ExecutionKitError("actor.attack_id contains unsupported characters")
    actor_name = _string(actor.get("name"), "actor.name", maximum=300, required=True)
    platform = _string(scope.get("command_platform"), "scope.command_platform", maximum=20, required=True).lower()
    if platform not in SUPPORTED_PLATFORMS:
        raise ExecutionKitError("Execution kits are available for Windows and Linux plans")
    operator = _string(context.get("operator", ""), "execution_context.operator", maximum=120)
    target = _string(context.get("target", ""), "execution_context.target", maximum=200)
    data_version = _string(document.get("data_version"), "data_version", maximum=500, required=True)
    generated = _string(document.get("generated"), "generated", maximum=100, required=True)

    rows: List[PlanStep] = []
    for stage in stages:
        if not isinstance(stage, dict) or not isinstance(stage.get("techniques"), list):
            raise ExecutionKitError("Plan contains an invalid stage")
        tactic = _string(stage.get("tactic"), "stage.tactic", maximum=120, required=True)
        tactic_title = _string(stage.get("title"), "stage.title", maximum=200, required=True)
        for technique in stage["techniques"]:
            if len(rows) >= MAX_PLAN_STEPS:
                raise ExecutionKitError(f"Plan exceeds the {MAX_PLAN_STEPS}-step execution-kit limit")
            if not isinstance(technique, dict) or not isinstance(technique.get("command"), dict):
                raise ExecutionKitError("Plan contains an invalid technique")
            command = technique["command"]
            technique_id = _string(technique.get("id"), "technique.id", maximum=64, required=True)
            technique_name = _string(technique.get("name"), "technique.name", maximum=500, required=True)
            command_platform = _string(command.get("platform"), "command.platform", maximum=20, required=True).lower()
            if command_platform != platform:
                raise ExecutionKitError(f"{technique_id} does not contain an exact {platform} command")
            planned_command = _string(command.get("command"), "command.command", maximum=MAX_COMMAND_LENGTH)
            supported = _boolean(technique.get("supported"), "technique.supported")
            if "unsupported" in command:
                supported = supported and not _boolean(command["unsupported"], "command.unsupported")
            if supported and not planned_command.strip():
                raise ExecutionKitError(f"{technique_id} has an empty executable command")
            risk = _string(command.get("risk"), "command.risk", maximum=20, required=True).lower()
            if risk not in {"none", "low", "medium", "high"}:
                raise ExecutionKitError(f"{technique_id} has an invalid risk rating")
            timeout = command.get("timeout_seconds")
            if not isinstance(timeout, int) or isinstance(timeout, bool) or not 0 <= timeout <= 3600:
                raise ExecutionKitError(f"{technique_id} has an invalid timeout")
            sequence = len(rows) + 1
            step_id = f"{sequence:04d}-{_step_slug(tactic)}-{_step_slug(technique_id)}"
            command_source = _string(technique.get("command_source"), "command_source", maximum=20, required=True)
            if command_source not in {"curated", "fallback"}:
                raise ExecutionKitError(f"{technique_id} has an invalid command source")
            fidelity = _string(command.get("fidelity", "direct"), "command.fidelity", maximum=40)
            if fidelity not in FIDELITY_VALUES:
                raise ExecutionKitError(f"{technique_id} has an invalid fidelity class")
            rows.append(PlanStep(
                sequence=sequence,
                step_id=step_id,
                tactic=tactic,
                tactic_title=tactic_title,
                technique_id=technique_id,
                technique_name=technique_name,
                platform=platform,
                supported=supported,
                command_source=command_source,
                fidelity=fidelity,
                risk=risk,
                requires_admin=_boolean(command.get("requires_admin"), "command.requires_admin"),
                requires_network=_boolean(command.get("requires_network"), "command.requires_network"),
                prerequisites=_strings(command.get("prerequisites", []), "command.prerequisites"),
                side_effects=_strings(command.get("side_effects", []), "command.side_effects"),
                planned_command=planned_command,
                cleanup_command=_string(command.get("cleanup", ""), "command.cleanup", maximum=MAX_COMMAND_LENGTH),
                expected_output=_string(command.get("expected_output", ""), "command.expected_output"),
                expected_telemetry=_string(command.get("expected_telemetry", ""), "command.expected_telemetry"),
                timeout_seconds=timeout,
            ))

    if not any(step.supported for step in rows):
        raise ExecutionKitError("Plan has no executable Windows or Linux steps")
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return ExecutionPlan(
        actor_id=actor_id,
        actor_name=actor_name,
        data_version=data_version,
        generated=generated,
        operator=operator,
        target=target,
        platform=platform,
        steps=tuple(rows),
        plan_sha256=hashlib.sha256(canonical).hexdigest(),
    )


def _csv_display(value: Any) -> Any:
    """Prevent downloaded ATT&CK text from becoming a spreadsheet formula."""
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def render_plan_csv(plan: ExecutionPlan) -> bytes:
    output = io.StringIO(newline="")
    columns = (
        "sequence", "step_id", "tactic", "tactic_title", "technique_id", "technique_name",
        "platform", "supported", "command_source", "fidelity", "risk", "requires_admin", "requires_network",
        "prerequisites", "side_effects", "planned_command", "planned_command_sha256", "cleanup_command",
        "expected_output", "expected_telemetry", "timeout_seconds", "plan_sha256",
    )
    writer = csv.DictWriter(output, fieldnames=columns, lineterminator="\r\n")
    writer.writeheader()
    for step in plan.steps:
        row = {
            "sequence": step.sequence,
            "step_id": step.step_id,
            "tactic": step.tactic,
            "tactic_title": step.tactic_title,
            "technique_id": step.technique_id,
            "technique_name": step.technique_name,
            "platform": step.platform,
            "supported": str(step.supported).lower(),
            "command_source": step.command_source,
            "fidelity": step.fidelity,
            "risk": step.risk,
            "requires_admin": str(step.requires_admin).lower(),
            "requires_network": str(step.requires_network).lower(),
            "prerequisites": " | ".join(step.prerequisites),
            "side_effects": " | ".join(step.side_effects),
            "planned_command": step.planned_command,
            "planned_command_sha256": hashlib.sha256(step.planned_command.encode()).hexdigest(),
            "cleanup_command": step.cleanup_command,
            "expected_output": step.expected_output,
            "expected_telemetry": step.expected_telemetry,
            "timeout_seconds": step.timeout_seconds,
            "plan_sha256": plan.plan_sha256,
        }
        writer.writerow({key: _csv_display(value) for key, value in row.items()})
    return ("\ufeff" + output.getvalue()).encode("utf-8")


def _b64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def _bash_array(name: str, values: Iterable[str]) -> str:
    return f"{name}=(\n" + "".join(f"  '{_b64(value)}'\n" for value in values) + ")"


def _bool_text(value: bool) -> str:
    return "true" if value else "false"


def render_bash(plan: ExecutionPlan, csv_name: str, csv_sha256: str) -> str:
    arrays = "\n".join((
        _bash_array("STEP_IDS", (step.step_id for step in plan.steps)),
        _bash_array("TACTICS", (step.tactic_title for step in plan.steps)),
        _bash_array("TECHNIQUE_IDS", (step.technique_id for step in plan.steps)),
        _bash_array("TECHNIQUE_NAMES", (step.technique_name for step in plan.steps)),
        _bash_array("RISKS", (step.risk for step in plan.steps)),
        _bash_array("SUPPORTED", (_bool_text(step.supported) for step in plan.steps)),
        _bash_array("REQUIRES_ADMIN", (_bool_text(step.requires_admin) for step in plan.steps)),
        _bash_array("REQUIRES_NETWORK", (_bool_text(step.requires_network) for step in plan.steps)),
        _bash_array("PREREQUISITES", (" | ".join(step.prerequisites) for step in plan.steps)),
        _bash_array("EFFECTS", (" | ".join(step.side_effects) for step in plan.steps)),
        _bash_array("COMMANDS", (step.planned_command for step in plan.steps)),
        _bash_array("CLEANUPS", (step.cleanup_command for step in plan.steps)),
        _bash_array("EXPECTED_OUTPUT", (step.expected_output for step in plan.steps)),
        _bash_array("EXPECTED_TELEMETRY", (step.expected_telemetry for step in plan.steps)),
        _bash_array("TIMEOUTS", (str(step.timeout_seconds) for step in plan.steps)),
    ))
    template = r'''#!/usr/bin/env bash
set -u

KIT_VERSION="1.0"
PLAN_SHA256="__PLAN_SHA__"
CSV_NAME="__CSV_NAME__"
CSV_SHA256="__CSV_SHA__"
ACTOR_ID_B64="__ACTOR_ID__"
ACTOR_NAME_B64="__ACTOR_NAME__"
DATA_VERSION_B64="__DATA_VERSION__"
DEFAULT_OPERATOR_B64="__OPERATOR__"
DEFAULT_TARGET_B64="__TARGET__"

__ARRAYS__

decode_b64() { printf '%s' "$1" | base64 --decode; }
encode_b64() { printf '%s' "$1" | base64 | tr -d '\n'; }
now_utc() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
sha_file() { sha256sum "$1" | awk '{print $1}'; }
csv_cell() { local value=${1-}; value=${value//\"/\"\"}; printf '"%s"' "$value"; }
append_csv() {
  local first=true value
  for value in "$@"; do
    $first || printf ',' >> "$RESULTS_CSV"
    first=false
    csv_cell "$value" >> "$RESULTS_CSV"
  done
  printf '\r\n' >> "$RESULTS_CSV"
}
event() {
  local kind=$1 step=${2-} detail=${3-}
  printf '{"schema_version":"1.0","timestamp":"%s","run_id":"%s","event":"%s","step_id":"%s","detail_b64":"%s"}\n' \
    "$(now_utc)" "$RUN_ID" "$kind" "$step" "$(encode_b64 "$detail")" >> "$EVENTS"
}
heading() { printf '\n\033[1;36m%s\033[0m\n' "$1"; }
choice() {
  local prompt=$1 allowed=$2 answer
  while true; do
    printf '%s' "$prompt" >&2
    IFS= read -r answer || answer=A
    answer=$(printf '%s' "$answer" | tr '[:lower:]' '[:upper:]')
    case " $allowed " in *" $answer "*) printf '%s' "$answer"; return;; esac
    printf 'Please enter one of the displayed choices.\n' >&2
  done
}
indent_file() {
  local line
  while IFS= read -r line || [ -n "$line" ]; do printf '    %s\n' "$line"; done < "$1"
}
html_escape() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'; }
html_file() { html_escape < "$1"; }
write_checksums() {
  (cd "$RESULTS_DIR" && find . -type f ! -name SHA256SUMS -exec sha256sum '{}' \; | sort > SHA256SUMS)
}
on_interrupt() {
  event "session_interrupted" "" "Operator interrupted execution"
  printf '\n## Session interrupted\n\nInterrupted at %s.\n' "$(now_utc)" >> "$REPORT"
  printf '<h2>Session interrupted</h2><p>Interrupted at %s.</p></main></body></html>\n' "$(now_utc)" >> "$HTML_REPORT"
  write_checksums
  printf '\nExecution interrupted. Evidence retained in:\n%s\n' "$RESULTS_DIR"
  exit 130
}

for required in base64 sha256sum awk date mktemp; do
  command -v "$required" >/dev/null 2>&1 || { printf 'Required standard utility not found: %s\n' "$required" >&2; exit 2; }
done

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
CSV_PATH="$SCRIPT_DIR/$CSV_NAME"
if [ ! -f "$CSV_PATH" ]; then
  printf 'The matching plan CSV is missing: %s\nKeep the CSV and script together.\n' "$CSV_PATH" >&2
  exit 2
fi
ACTUAL_CSV_SHA=$(sha_file "$CSV_PATH")
if [ "$ACTUAL_CSV_SHA" != "$CSV_SHA256" ]; then
  printf 'Plan integrity check failed. The CSV does not match this runner.\nExpected: %s\nActual:   %s\n' "$CSV_SHA256" "$ACTUAL_CSV_SHA" >&2
  exit 2
fi

ACTOR_ID=$(decode_b64 "$ACTOR_ID_B64")
ACTOR_NAME=$(decode_b64 "$ACTOR_NAME_B64")
DATA_VERSION=$(decode_b64 "$DATA_VERSION_B64")
DEFAULT_OPERATOR=$(decode_b64 "$DEFAULT_OPERATOR_B64")
DEFAULT_TARGET=$(decode_b64 "$DEFAULT_TARGET_B64")
RUN_ID=$(date -u '+%Y%m%dT%H%M%SZ')-$$
RESULTS_DIR="$SCRIPT_DIR/AdversaryFlow-results-$RUN_ID"
if ! mkdir -p "$RESULTS_DIR/stdout" "$RESULTS_DIR/stderr" "$RESULTS_DIR/commands"; then
  printf 'Cannot create the evidence directory beside the runner.\n' >&2
  exit 2
fi
chmod 700 "$RESULTS_DIR" 2>/dev/null || true
EVENTS="$RESULTS_DIR/evidence-events.jsonl"
RESULTS_CSV="$RESULTS_DIR/execution-results.csv"
REPORT="$RESULTS_DIR/execution-report.md"
HTML_REPORT="$RESULTS_DIR/execution-report.html"
SUMMARY="$RESULTS_DIR/execution-summary.json"
trap on_interrupt INT TERM

heading "AdversaryFlow portable execution runner"
printf 'Actor:        %s (%s)\nPlatform:     Linux\nPlan steps:   %s\nPlan SHA-256: %s\nData version: %s\n\n' \
  "$ACTOR_NAME" "$ACTOR_ID" "${#STEP_IDS[@]}" "$PLAN_SHA256" "$DATA_VERSION"
printf 'This runner executes one lab step at a time. Nothing runs without approval.\n'
printf 'Every decision, edit, command hash, output hash, and exit code is recorded locally.\n\n'
printf 'Operator [%s]: ' "${DEFAULT_OPERATOR:-not set}"; IFS= read -r OPERATOR || OPERATOR=""
[ -n "$OPERATOR" ] || OPERATOR=$DEFAULT_OPERATOR
printf 'Target [%s]: ' "${DEFAULT_TARGET:-not set}"; IFS= read -r TARGET || TARGET=""
[ -n "$TARGET" ] || TARGET=$DEFAULT_TARGET
STARTED_AT=$(now_utc)
confirm=$(choice 'Start this execution session? [Y]es / [A]bort: ' 'Y A')
if [ "$confirm" != Y ]; then printf 'No commands were executed.\n'; exit 0; fi

printf '"sequence","step_id","technique_id","decision","execution_status","assessment","modified","modification_reason","started_at","completed_at","exit_code","original_command_sha256","effective_command_sha256","stdout_sha256","stderr_sha256","cleanup_status"\r\n' > "$RESULTS_CSV"
cat > "$REPORT" <<EOF
# AdversaryFlow execution report

- **Actor:** $ACTOR_NAME ($ACTOR_ID)
- **Platform:** Linux
- **Operator:** ${OPERATOR:-not recorded}
- **Target:** ${TARGET:-not recorded}
- **Session:** $RUN_ID
- **Started:** $STARTED_AT
- **Plan SHA-256:** \`$PLAN_SHA256\`
- **CSV SHA-256:** \`$CSV_SHA256\`
- **ATT&CK data version:** $DATA_VERSION

EOF
cat > "$HTML_REPORT" <<EOF
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AdversaryFlow execution report</title><style>body{font:15px/1.55 system-ui,sans-serif;margin:0;background:#0b1020;color:#e8edf7}main{max-width:1050px;margin:auto;padding:40px}h1,h2{color:#fff}section{background:#151c31;border:1px solid #2c3654;border-radius:12px;padding:20px;margin:18px 0}code,pre{font:13px/1.5 ui-monospace,monospace}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#090d18;padding:16px;border-radius:8px}.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px}.ok{color:#60d394}.warn{color:#ffca6a}</style></head><body><main>
<h1>AdversaryFlow execution report</h1><div class="meta"><div><b>Actor</b><br>$(printf '%s' "$ACTOR_NAME ($ACTOR_ID)" | html_escape)</div><div><b>Platform</b><br>Linux</div><div><b>Operator</b><br>$(printf '%s' "${OPERATOR:-not recorded}" | html_escape)</div><div><b>Target</b><br>$(printf '%s' "${TARGET:-not recorded}" | html_escape)</div><div><b>Session</b><br>$(printf '%s' "$RUN_ID" | html_escape)</div><div><b>Started</b><br>$STARTED_AT</div></div>
<p><b>Plan SHA-256:</b> <code>$PLAN_SHA256</code><br><b>CSV SHA-256:</b> <code>$CSV_SHA256</code><br><b>ATT&amp;CK data version:</b> $(printf '%s' "$DATA_VERSION" | html_escape)</p>
EOF
event "session_started" "" "operator=$OPERATOR; target=$TARGET; plan_sha256=$PLAN_SHA256"

COMPLETED=0; FAILED=0; SKIPPED=0; ABORTED=false
for index in "${!STEP_IDS[@]}"; do
  seq=$((index + 1))
  step_id=$(decode_b64 "${STEP_IDS[$index]}")
  tactic=$(decode_b64 "${TACTICS[$index]}")
  technique_id=$(decode_b64 "${TECHNIQUE_IDS[$index]}")
  technique_name=$(decode_b64 "${TECHNIQUE_NAMES[$index]}")
  risk=$(decode_b64 "${RISKS[$index]}")
  supported=$(decode_b64 "${SUPPORTED[$index]}")
  requires_admin=$(decode_b64 "${REQUIRES_ADMIN[$index]}")
  requires_network=$(decode_b64 "${REQUIRES_NETWORK[$index]}")
  prerequisites=$(decode_b64 "${PREREQUISITES[$index]}")
  effects=$(decode_b64 "${EFFECTS[$index]}")
  command_text=$(decode_b64 "${COMMANDS[$index]}")
  cleanup_text=$(decode_b64 "${CLEANUPS[$index]}")
  expected_output=$(decode_b64 "${EXPECTED_OUTPUT[$index]}")
  expected_telemetry=$(decode_b64 "${EXPECTED_TELEMETRY[$index]}")
  timeout_seconds=$(decode_b64 "${TIMEOUTS[$index]}")
  original_file="$RESULTS_DIR/commands/$step_id.original.sh"
  effective_file="$RESULTS_DIR/commands/$step_id.executed.sh"
  printf '%s\n' "$command_text" > "$original_file"
  cp "$original_file" "$effective_file"
  original_sha=$(sha_file "$original_file")

  heading "Step $seq of ${#STEP_IDS[@]} — $technique_id $technique_name"
  printf 'Stage: %s\nRisk: %s | Admin: %s | Network: %s\nEffects: %s\nPrerequisites: %s\nExpected output: %s\nExpected telemetry: %s\n\nPlanned command:\n' \
    "$tactic" "$risk" "$requires_admin" "$requires_network" "${effects:-not classified}" \
    "${prerequisites:-none listed}" "${expected_output:-not specified}" "${expected_telemetry:-not specified}"
  indent_file "$effective_file"
  printf '\n'
  if [ "$supported" != true ]; then
    printf 'This step is unsupported on Linux and was recorded as skipped.\n'
    event "step_skipped" "$step_id" "unsupported"
    append_csv "$seq" "$step_id" "$technique_id" "skip" "not_executed" "not_assessed" "false" "unsupported" "" "$(now_utc)" "" "$original_sha" "$original_sha" "" "" "not_applicable"
    printf '## %s. %s — %s\n\n- **Decision:** skipped (unsupported)\n\n' "$seq" "$technique_id" "$technique_name" >> "$REPORT"
    printf '<section><h2>%s. %s — %s</h2><p class="warn"><b>Skipped:</b> unsupported on Linux</p></section>\n' "$seq" "$(printf '%s' "$technique_id" | html_escape)" "$(printf '%s' "$technique_name" | html_escape)" >> "$HTML_REPORT"
    SKIPPED=$((SKIPPED + 1)); continue
  fi

  decision=$(choice '[R]un / [E]dit / [S]kip / [A]bort: ' 'R E S A')
  modified=false; reason=""
  if [ "$decision" = A ]; then
    event "session_aborted" "$step_id" "aborted before step"
    ABORTED=true
    break
  fi
  if [ "$decision" = S ]; then
    reason_text=""
    printf 'Skip reason (optional): '; IFS= read -r reason_text || true
    event "step_skipped" "$step_id" "$reason_text"
    append_csv "$seq" "$step_id" "$technique_id" "skip" "not_executed" "not_assessed" "false" "$reason_text" "" "$(now_utc)" "" "$original_sha" "$original_sha" "" "" "not_applicable"
    printf '## %s. %s — %s\n\n- **Decision:** skipped\n- **Reason:** %s\n\n' "$seq" "$technique_id" "$technique_name" "${reason_text:-not supplied}" >> "$REPORT"
    printf '<section><h2>%s. %s — %s</h2><p class="warn"><b>Skipped.</b> %s</p></section>\n' "$seq" "$(printf '%s' "$technique_id" | html_escape)" "$(printf '%s' "$technique_name" | html_escape)" "$(printf '%s' "${reason_text:-No reason supplied}" | html_escape)" >> "$HTML_REPORT"
    SKIPPED=$((SKIPPED + 1)); continue
  fi
  if [ "$decision" = E ]; then
    editor=${EDITOR:-vi}
    "$editor" "$effective_file"
    while [ -z "$reason" ]; do printf 'Modification reason (required): '; IFS= read -r reason || true; done
    modified=true
    printf '\nEffective command after editing:\n'; indent_file "$effective_file"; printf '\n'
    reapprove=$(choice 'Approve this edited command? [R]un / [S]kip / [A]bort: ' 'R S A')
    if [ "$reapprove" = A ]; then event "session_aborted" "$step_id" "aborted after edit"; ABORTED=true; break; fi
    if [ "$reapprove" = S ]; then
      event "step_skipped" "$step_id" "edited then skipped: $reason"
      effective_sha=$(sha_file "$effective_file")
      append_csv "$seq" "$step_id" "$technique_id" "skip" "not_executed" "not_assessed" "$modified" "$reason" "" "$(now_utc)" "" "$original_sha" "$effective_sha" "" "" "not_applicable"
      SKIPPED=$((SKIPPED + 1)); continue
    fi
  fi

  effective_sha=$(sha_file "$effective_file")
  stdout_file="$RESULTS_DIR/stdout/$step_id.log"
  stderr_file="$RESULTS_DIR/stderr/$step_id.log"
  step_started=$(now_utc)
  event "step_approved" "$step_id" "modified=$modified; reason=$reason; effective_sha256=$effective_sha"
  printf '\nExecuting exactly:\n'; indent_file "$effective_file"; printf '\n'
  set +e
  if command -v timeout >/dev/null 2>&1 && [ "$timeout_seconds" -gt 0 ]; then
    timeout --signal=TERM --kill-after=5 "${timeout_seconds}s" bash -c 'cd "$1" && bash "$2"' bash "$SCRIPT_DIR" "$effective_file" >"$stdout_file" 2>"$stderr_file"
  else
    ( cd "$SCRIPT_DIR" && bash "$effective_file" ) >"$stdout_file" 2>"$stderr_file"
  fi
  exit_code=$?
  set +e
  step_completed=$(now_utc)
  stdout_sha=$(sha_file "$stdout_file"); stderr_sha=$(sha_file "$stderr_file")
  execution_status=completed
  [ "$exit_code" -eq 124 ] && execution_status=timed_out
  [ "$exit_code" -eq 0 ] || FAILED=$((FAILED + 1))
  [ "$exit_code" -ne 0 ] || COMPLETED=$((COMPLETED + 1))
  printf 'Exit code: %s\nstdout: %s\nstderr: %s\n' "$exit_code" "$stdout_file" "$stderr_file"
  assessment_choice=$(choice 'Detection assessment: [Y] passed / [N] failed: ' 'Y N')
  [ "$assessment_choice" = Y ] && assessment=passed || assessment=failed
  cleanup_status=not_applicable
  if [ -n "$cleanup_text" ]; then
    printf '\nCleanup command:\n    %s\n' "$cleanup_text"
    cleanup_choice=$(choice 'Run cleanup now? [Y]es / [N]o: ' 'Y N')
    if [ "$cleanup_choice" = Y ]; then
      cleanup_file="$RESULTS_DIR/commands/$step_id.cleanup.sh"
      printf '%s\n' "$cleanup_text" > "$cleanup_file"
      set +e; ( cd "$SCRIPT_DIR" && bash "$cleanup_file" ) >>"$stdout_file" 2>>"$stderr_file"; cleanup_exit=$?; set +e
      [ "$cleanup_exit" -eq 0 ] && cleanup_status=completed || cleanup_status=failed
      event "cleanup_completed" "$step_id" "status=$cleanup_status; exit_code=$cleanup_exit"
    else cleanup_status=declined; event "cleanup_declined" "$step_id" "operator declined cleanup"; fi
  fi
  event "step_completed" "$step_id" "execution_status=$execution_status; assessment=$assessment; exit_code=$exit_code; stdout_sha256=$stdout_sha; stderr_sha256=$stderr_sha"
  append_csv "$seq" "$step_id" "$technique_id" "run" "$execution_status" "$assessment" "$modified" "$reason" "$step_started" "$step_completed" "$exit_code" "$original_sha" "$effective_sha" "$stdout_sha" "$stderr_sha" "$cleanup_status"
  {
    printf '## %s. %s — %s\n\n' "$seq" "$technique_id" "$technique_name"
    printf -- '- **Decision:** run\n- **Execution:** %s (exit %s)\n- **Detection assessment:** %s\n- **Modified:** %s\n' "$execution_status" "$exit_code" "$assessment" "$modified"
    [ -z "$reason" ] || printf -- '- **Modification reason:** %s\n' "$reason"
    printf -- '- **Started:** %s\n- **Completed:** %s\n- **Effective command SHA-256:** `%s`\n- **stdout SHA-256:** `%s`\n- **stderr SHA-256:** `%s`\n- **Cleanup:** %s\n\n### Executed command\n\n' "$step_started" "$step_completed" "$effective_sha" "$stdout_sha" "$stderr_sha" "$cleanup_status"
    indent_file "$effective_file"
    printf '\n'
  } >> "$REPORT"
  {
    printf '<section><h2>%s. %s — %s</h2><p><b>Execution:</b> %s (exit %s)<br><b>Detection assessment:</b> %s<br><b>Modified:</b> %s<br><b>Cleanup:</b> %s</p>' "$seq" "$(printf '%s' "$technique_id" | html_escape)" "$(printf '%s' "$technique_name" | html_escape)" "$execution_status" "$exit_code" "$assessment" "$modified" "$cleanup_status"
    [ -z "$reason" ] || printf '<p><b>Modification reason:</b> %s</p>' "$(printf '%s' "$reason" | html_escape)"
    printf '<p><b>Started:</b> %s<br><b>Completed:</b> %s<br><b>Effective command SHA-256:</b> <code>%s</code><br><b>stdout SHA-256:</b> <code>%s</code><br><b>stderr SHA-256:</b> <code>%s</code></p><h3>Executed command</h3><pre>' "$step_started" "$step_completed" "$effective_sha" "$stdout_sha" "$stderr_sha"
    html_file "$effective_file"
    printf '</pre></section>\n'
  } >> "$HTML_REPORT"
  next=$(choice 'Proceed to the next step? [N]ext / [A]bort: ' 'N A')
  if [ "$next" = A ]; then event "session_aborted" "$step_id" "aborted after step"; ABORTED=true; break; fi
done

COMPLETED_AT=$(now_utc)
if $ABORTED; then SESSION_STATUS=aborted; else SESSION_STATUS=completed; fi
event "session_completed" "" "status=$SESSION_STATUS; completed=$COMPLETED; failed=$FAILED; skipped=$SKIPPED"
printf '\n## Session summary\n\n- **Status:** %s\n- **Completed successfully:** %s\n- **Command failures/timeouts:** %s\n- **Skipped:** %s\n- **Completed:** %s\n' \
  "$SESSION_STATUS" "$COMPLETED" "$FAILED" "$SKIPPED" "$COMPLETED_AT" >> "$REPORT"
printf '<section><h2>Session summary</h2><p><b>Status:</b> %s<br><b>Completed successfully:</b> %s<br><b>Command failures/timeouts:</b> %s<br><b>Skipped:</b> %s<br><b>Completed:</b> %s</p></section></main></body></html>\n' "$SESSION_STATUS" "$COMPLETED" "$FAILED" "$SKIPPED" "$COMPLETED_AT" >> "$HTML_REPORT"
printf '{"schema_version":"1.0","run_id":"%s","status":"%s","actor_id":"%s","platform":"linux","plan_sha256":"%s","csv_sha256":"%s","started_at":"%s","completed_at":"%s","operator_b64":"%s","target_b64":"%s","completed_steps":%s,"failed_steps":%s,"skipped_steps":%s,"events_file":"evidence-events.jsonl","results_file":"execution-results.csv","report_file":"execution-report.html","markdown_report_file":"execution-report.md"}\n' \
  "$RUN_ID" "$SESSION_STATUS" "$ACTOR_ID" "$PLAN_SHA256" "$CSV_SHA256" "$STARTED_AT" "$COMPLETED_AT" "$(encode_b64 "$OPERATOR")" "$(encode_b64 "$TARGET")" "$COMPLETED" "$FAILED" "$SKIPPED" > "$SUMMARY"
write_checksums
heading "Execution $SESSION_STATUS"
printf 'Report and evidence are ready to hand back:\n%s\n' "$RESULTS_DIR"
'''
    return (template.replace("__PLAN_SHA__", plan.plan_sha256)
            .replace("__CSV_NAME__", csv_name)
            .replace("__CSV_SHA__", csv_sha256)
            .replace("__ACTOR_ID__", _b64(plan.actor_id))
            .replace("__ACTOR_NAME__", _b64(plan.actor_name))
            .replace("__DATA_VERSION__", _b64(plan.data_version))
            .replace("__OPERATOR__", _b64(plan.operator))
            .replace("__TARGET__", _b64(plan.target))
            .replace("__ARRAYS__", arrays))


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def render_powershell(plan: ExecutionPlan, csv_name: str, csv_sha256: str) -> str:
    records = []
    for step in plan.steps:
        values = {
            "StepId": step.step_id, "Tactic": step.tactic_title, "TechniqueId": step.technique_id,
            "TechniqueName": step.technique_name, "Risk": step.risk, "Supported": _bool_text(step.supported),
            "RequiresAdmin": _bool_text(step.requires_admin), "RequiresNetwork": _bool_text(step.requires_network),
            "Prerequisites": " | ".join(step.prerequisites), "Effects": " | ".join(step.side_effects),
            "Command": step.planned_command, "Cleanup": step.cleanup_command, "Fidelity": step.fidelity,
            "ExpectedOutput": step.expected_output, "ExpectedTelemetry": step.expected_telemetry,
            "Timeout": str(step.timeout_seconds),
        }
        fields = "; ".join(f"{key}B64={_ps_quote(_b64(value))}" for key, value in values.items())
        records.append(f"    [pscustomobject]@{{ {fields} }}")
    steps_literal = "@(" + ",\n".join(records) + "\n)"
    template = r'''#requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$KitVersion = '1.0'
$PlanSha256 = '__PLAN_SHA__'
$CsvName = '__CSV_NAME__'
$CsvSha256 = '__CSV_SHA__'
$ActorIdB64 = '__ACTOR_ID__'
$ActorNameB64 = '__ACTOR_NAME__'
$DataVersionB64 = '__DATA_VERSION__'
$DefaultOperatorB64 = '__OPERATOR__'
$DefaultTargetB64 = '__TARGET__'
$Steps = __STEPS__

function ConvertFrom-AfBase64([string]$Value) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Value)) }
function ConvertTo-AfBase64([string]$Value) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Value)) }
function Get-AfTimestamp { [DateTime]::UtcNow.ToString('o') }
function Read-AfChoice([string]$Prompt, [string[]]$Allowed) {
    while ($true) {
        $answer = (Read-Host $Prompt).Trim().ToUpperInvariant()
        if ($Allowed -contains $answer) { return $answer }
        Write-Host "Please enter one of: $($Allowed -join ', ')" -ForegroundColor Yellow
    }
}
function Write-AfEvent([string]$Event, [string]$StepId = '', [string]$Detail = '') {
    [ordered]@{ schema_version='1.0'; timestamp=(Get-AfTimestamp); run_id=$script:RunId; event=$Event; step_id=$StepId; detail_b64=(ConvertTo-AfBase64 $Detail) } |
        ConvertTo-Json -Compress | Add-Content -LiteralPath $script:EventsPath -Encoding UTF8
}
function Write-AfChecksums {
    Get-ChildItem -LiteralPath $script:ResultsDir -File -Recurse |
        Where-Object Name -ne 'SHA256SUMS' |
        Sort-Object FullName |
        ForEach-Object { '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant(), $_.FullName.Substring($script:ResultsDir.Length + 1) } |
        Set-Content -LiteralPath (Join-Path $script:ResultsDir 'SHA256SUMS') -Encoding UTF8
}
function Add-AfReportCode([string]$Path) {
    Get-Content -LiteralPath $Path | ForEach-Object { Add-Content -LiteralPath $script:ReportPath -Value "    $_" -Encoding UTF8 }
}
function ConvertTo-AfHtml([string]$Value) { [Net.WebUtility]::HtmlEncode($Value) }
function Add-AfHtmlCode([string]$Path) {
    $encoded = ConvertTo-AfHtml ([IO.File]::ReadAllText($Path))
    Add-Content -LiteralPath $script:HtmlReportPath -Value "<pre>$encoded</pre>" -Encoding UTF8
}
function Save-AfResults { $script:Results | Export-Csv -LiteralPath $script:ResultsCsv -NoTypeInformation -Encoding UTF8 }

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CsvPath = Join-Path $ScriptDir $CsvName
if (-not (Test-Path -LiteralPath $CsvPath -PathType Leaf)) { throw "The matching plan CSV is missing: $CsvPath. Keep the CSV and runner together." }
$actualCsvSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $CsvPath).Hash.ToLowerInvariant()
if ($actualCsvSha -ne $CsvSha256) { throw "Plan integrity check failed. Expected CSV SHA-256 $CsvSha256, received $actualCsvSha." }

$ActorId = ConvertFrom-AfBase64 $ActorIdB64
$ActorName = ConvertFrom-AfBase64 $ActorNameB64
$DataVersion = ConvertFrom-AfBase64 $DataVersionB64
$DefaultOperator = ConvertFrom-AfBase64 $DefaultOperatorB64
$DefaultTarget = ConvertFrom-AfBase64 $DefaultTargetB64
$RunId = '{0}-{1}' -f ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')), $PID
$ResultsDir = Join-Path $ScriptDir "AdversaryFlow-results-$RunId"
$null = New-Item -ItemType Directory -Force -Path $ResultsDir, (Join-Path $ResultsDir 'stdout'), (Join-Path $ResultsDir 'stderr'), (Join-Path $ResultsDir 'commands')
$EventsPath = Join-Path $ResultsDir 'evidence-events.jsonl'
$ResultsCsv = Join-Path $ResultsDir 'execution-results.csv'
$ReportPath = Join-Path $ResultsDir 'execution-report.md'
$HtmlReportPath = Join-Path $ResultsDir 'execution-report.html'
$SummaryPath = Join-Path $ResultsDir 'execution-summary.json'
$Results = [Collections.Generic.List[object]]::new()

Write-Host "`nAdversaryFlow portable execution runner" -ForegroundColor Cyan
Write-Host "Actor:        $ActorName ($ActorId)"
Write-Host "Platform:     Windows"
Write-Host "Plan steps:   $($Steps.Count)"
Write-Host "Plan SHA-256: $PlanSha256"
Write-Host "Data version: $DataVersion`n"
Write-Host 'This runner executes one lab step at a time. Nothing runs without approval.'
Write-Host 'Every decision, edit, command hash, output hash, and exit code is recorded locally.'
$operatorPrompt = if ($DefaultOperator) { $DefaultOperator } else { 'not set' }
$Operator = Read-Host "Operator [$operatorPrompt]"
if ([string]::IsNullOrWhiteSpace($Operator)) { $Operator = $DefaultOperator }
$targetPrompt = if ($DefaultTarget) { $DefaultTarget } else { 'not set' }
$Target = Read-Host "Target [$targetPrompt]"
if ([string]::IsNullOrWhiteSpace($Target)) { $Target = $DefaultTarget }
$StartedAt = Get-AfTimestamp
if ((Read-AfChoice 'Start this execution session? Y=yes / A=abort' @('Y','A')) -ne 'Y') { Write-Host 'No commands were executed.'; exit 0 }

@"
# AdversaryFlow execution report

- **Actor:** $ActorName ($ActorId)
- **Platform:** Windows
- **Operator:** $(if ($Operator) {$Operator} else {'not recorded'})
- **Target:** $(if ($Target) {$Target} else {'not recorded'})
- **Session:** $RunId
- **Started:** $StartedAt
- **Plan SHA-256:** ``$PlanSha256``
- **CSV SHA-256:** ``$CsvSha256``
- **ATT&CK data version:** $DataVersion

"@ | Set-Content -LiteralPath $ReportPath -Encoding UTF8
$htmlActor = ConvertTo-AfHtml "$ActorName ($ActorId)"
$htmlOperator = ConvertTo-AfHtml $(if ($Operator) { $Operator } else { 'not recorded' })
$htmlTarget = ConvertTo-AfHtml $(if ($Target) { $Target } else { 'not recorded' })
$htmlDataVersion = ConvertTo-AfHtml $DataVersion
@"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AdversaryFlow execution report</title><style>body{font:15px/1.55 system-ui,sans-serif;margin:0;background:#0b1020;color:#e8edf7}main{max-width:1050px;margin:auto;padding:40px}h1,h2{color:#fff}section{background:#151c31;border:1px solid #2c3654;border-radius:12px;padding:20px;margin:18px 0}code,pre{font:13px/1.5 ui-monospace,monospace}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#090d18;padding:16px;border-radius:8px}.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px}.ok{color:#60d394}.warn{color:#ffca6a}</style></head><body><main>
<h1>AdversaryFlow execution report</h1><div class="meta"><div><b>Actor</b><br>$htmlActor</div><div><b>Platform</b><br>Windows</div><div><b>Operator</b><br>$htmlOperator</div><div><b>Target</b><br>$htmlTarget</div><div><b>Session</b><br>$RunId</div><div><b>Started</b><br>$StartedAt</div></div>
<p><b>Plan SHA-256:</b> <code>$PlanSha256</code><br><b>CSV SHA-256:</b> <code>$CsvSha256</code><br><b>ATT&amp;CK data version:</b> $htmlDataVersion</p>
"@ | Set-Content -LiteralPath $HtmlReportPath -Encoding UTF8
Write-AfEvent 'session_started' '' "operator=$Operator; target=$Target; plan_sha256=$PlanSha256"

$completed = 0; $failed = 0; $skipped = 0; $aborted = $false; $interrupted = $false; $runnerError = $null
try {
    for ($index = 0; $index -lt $Steps.Count; $index++) {
        $raw = $Steps[$index]
        $step = @{}
        foreach ($property in $raw.PSObject.Properties) { $step[$property.Name.Substring(0, $property.Name.Length - 3)] = ConvertFrom-AfBase64 $property.Value }
        $sequence = $index + 1
        $stepId = $step.StepId
        $originalFile = Join-Path $ResultsDir "commands\$stepId.original.ps1"
        $effectiveFile = Join-Path $ResultsDir "commands\$stepId.executed.ps1"
        [IO.File]::WriteAllText($originalFile, $step.Command + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
        Copy-Item -LiteralPath $originalFile -Destination $effectiveFile
        $originalSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $originalFile).Hash.ToLowerInvariant()

        Write-Host "`nStep $sequence of $($Steps.Count) — $($step.TechniqueId) $($step.TechniqueName)" -ForegroundColor Cyan
        Write-Host "Stage: $($step.Tactic)"
        Write-Host "Risk: $($step.Risk) | Admin: $($step.RequiresAdmin) | Network: $($step.RequiresNetwork)"
        Write-Host "Effects: $($step.Effects)"
        Write-Host "Prerequisites: $($step.Prerequisites)"
        Write-Host "Expected output: $($step.ExpectedOutput)"
        Write-Host "Expected telemetry: $($step.ExpectedTelemetry)"
        Write-Host "`nPlanned command:"
        Get-Content -LiteralPath $effectiveFile | ForEach-Object { Write-Host "    $_" }
        if ($step.Supported -ne 'true') {
            Write-Host 'This step is unsupported on Windows and was recorded as skipped.' -ForegroundColor Yellow
            Write-AfEvent 'step_skipped' $stepId 'unsupported'
            $Results.Add([pscustomobject]@{ sequence=$sequence; step_id=$stepId; technique_id=$step.TechniqueId; decision='skip'; execution_status='not_executed'; assessment='not_assessed'; modified=$false; modification_reason='unsupported'; started_at=''; completed_at=(Get-AfTimestamp); exit_code=''; original_command_sha256=$originalSha; effective_command_sha256=$originalSha; stdout_sha256=''; stderr_sha256=''; cleanup_status='not_applicable' })
            Add-Content -LiteralPath $HtmlReportPath -Value (('<section><h2>{0}. {1} — {2}</h2><p class="warn"><b>Skipped:</b> unsupported on Windows</p></section>' -f $sequence, (ConvertTo-AfHtml $step.TechniqueId), (ConvertTo-AfHtml $step.TechniqueName))) -Encoding UTF8
            Save-AfResults; $skipped++; continue
        }

        $decision = Read-AfChoice 'R=run / E=edit / S=skip / A=abort' @('R','E','S','A')
        $modified = $false; $reason = ''
        if ($decision -eq 'A') { Write-AfEvent 'session_aborted' $stepId 'aborted before step'; $aborted = $true; break }
        if ($decision -eq 'S') {
            $reason = Read-Host 'Skip reason (optional)'
            Write-AfEvent 'step_skipped' $stepId $reason
            $Results.Add([pscustomobject]@{ sequence=$sequence; step_id=$stepId; technique_id=$step.TechniqueId; decision='skip'; execution_status='not_executed'; assessment='not_assessed'; modified=$false; modification_reason=$reason; started_at=''; completed_at=(Get-AfTimestamp); exit_code=''; original_command_sha256=$originalSha; effective_command_sha256=$originalSha; stdout_sha256=''; stderr_sha256=''; cleanup_status='not_applicable' })
            Save-AfResults; Add-Content -LiteralPath $ReportPath -Value "`n## $sequence. $($step.TechniqueId) — $($step.TechniqueName)`n`n- **Decision:** skipped`n- **Reason:** $reason`n" -Encoding UTF8
            Add-Content -LiteralPath $HtmlReportPath -Value (('<section><h2>{0}. {1} — {2}</h2><p class="warn"><b>Skipped.</b> {3}</p></section>' -f $sequence, (ConvertTo-AfHtml $step.TechniqueId), (ConvertTo-AfHtml $step.TechniqueName), (ConvertTo-AfHtml $reason))) -Encoding UTF8
            $skipped++; continue
        }
        if ($decision -eq 'E') {
            $editor = if ($env:EDITOR) { $env:EDITOR } else { 'notepad.exe' }
            Start-Process -FilePath $editor -ArgumentList $effectiveFile -Wait
            while ([string]::IsNullOrWhiteSpace($reason)) { $reason = Read-Host 'Modification reason (required)' }
            $modified = $true
            Write-Host "`nEffective command after editing:"
            Get-Content -LiteralPath $effectiveFile | ForEach-Object { Write-Host "    $_" }
            $approval = Read-AfChoice 'Approve this edited command? R=run / S=skip / A=abort' @('R','S','A')
            if ($approval -eq 'A') { Write-AfEvent 'session_aborted' $stepId 'aborted after edit'; $aborted = $true; break }
            if ($approval -eq 'S') {
                $effectiveSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $effectiveFile).Hash.ToLowerInvariant()
                Write-AfEvent 'step_skipped' $stepId "edited then skipped: $reason"
                $Results.Add([pscustomobject]@{ sequence=$sequence; step_id=$stepId; technique_id=$step.TechniqueId; decision='skip'; execution_status='not_executed'; assessment='not_assessed'; modified=$true; modification_reason=$reason; started_at=''; completed_at=(Get-AfTimestamp); exit_code=''; original_command_sha256=$originalSha; effective_command_sha256=$effectiveSha; stdout_sha256=''; stderr_sha256=''; cleanup_status='not_applicable' })
                Save-AfResults; $skipped++; continue
            }
        }

        $effectiveSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $effectiveFile).Hash.ToLowerInvariant()
        $stdoutFile = Join-Path $ResultsDir "stdout\$stepId.log"
        $stderrFile = Join-Path $ResultsDir "stderr\$stepId.log"
        $stepStarted = Get-AfTimestamp
        Write-AfEvent 'step_approved' $stepId "modified=$modified; reason=$reason; effective_sha256=$effectiveSha"
        Write-Host "`nExecuting exactly:"
        Get-Content -LiteralPath $effectiveFile | ForEach-Object { Write-Host "    $_" }
        $shellPath = (Get-Process -Id $PID).Path
        $process = Start-Process -FilePath $shellPath -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',"`"$effectiveFile`"") -WorkingDirectory $ScriptDir -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile -PassThru
        $timeoutSeconds = [int]$step.Timeout
        $timedOut = $false
        if ($timeoutSeconds -gt 0 -and -not $process.WaitForExit($timeoutSeconds * 1000)) { $timedOut = $true; Stop-Process -Id $process.Id -Force; $process.WaitForExit() }
        else { $process.WaitForExit() }
        $exitCode = if ($timedOut) { 124 } else { $process.ExitCode }
        $executionStatus = if ($timedOut) { 'timed_out' } else { 'completed' }
        $stepCompleted = Get-AfTimestamp
        $stdoutSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $stdoutFile).Hash.ToLowerInvariant()
        $stderrSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $stderrFile).Hash.ToLowerInvariant()
        if ($exitCode -eq 0) { $completed++ } else { $failed++ }
        Write-Host "Exit code: $exitCode`nstdout: $stdoutFile`nstderr: $stderrFile"
        $assessment = if ((Read-AfChoice 'Detection assessment: Y=passed / N=failed' @('Y','N')) -eq 'Y') { 'passed' } else { 'failed' }
        $cleanupStatus = 'not_applicable'
        if ($step.Cleanup) {
            Write-Host "`nCleanup command:`n    $($step.Cleanup)"
            if ((Read-AfChoice 'Run cleanup now? Y=yes / N=no' @('Y','N')) -eq 'Y') {
                $cleanupFile = Join-Path $ResultsDir "commands\$stepId.cleanup.ps1"
                [IO.File]::WriteAllText($cleanupFile, $step.Cleanup + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
                $cleanupProcess = Start-Process -FilePath $shellPath -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',"`"$cleanupFile`"") -WorkingDirectory $ScriptDir -Wait -PassThru
                $cleanupStatus = if ($cleanupProcess.ExitCode -eq 0) { 'completed' } else { 'failed' }
                Write-AfEvent 'cleanup_completed' $stepId "status=$cleanupStatus; exit_code=$($cleanupProcess.ExitCode)"
            } else { $cleanupStatus = 'declined'; Write-AfEvent 'cleanup_declined' $stepId 'operator declined cleanup' }
        }
        Write-AfEvent 'step_completed' $stepId "execution_status=$executionStatus; assessment=$assessment; exit_code=$exitCode; stdout_sha256=$stdoutSha; stderr_sha256=$stderrSha"
        $Results.Add([pscustomobject]@{ sequence=$sequence; step_id=$stepId; technique_id=$step.TechniqueId; decision='run'; execution_status=$executionStatus; assessment=$assessment; modified=$modified; modification_reason=$reason; started_at=$stepStarted; completed_at=$stepCompleted; exit_code=$exitCode; original_command_sha256=$originalSha; effective_command_sha256=$effectiveSha; stdout_sha256=$stdoutSha; stderr_sha256=$stderrSha; cleanup_status=$cleanupStatus })
        Save-AfResults
        Add-Content -LiteralPath $ReportPath -Value "`n## $sequence. $($step.TechniqueId) — $($step.TechniqueName)`n`n- **Decision:** run`n- **Execution:** $executionStatus (exit $exitCode)`n- **Detection assessment:** $assessment`n- **Modified:** $modified`n- **Modification reason:** $reason`n- **Started:** $stepStarted`n- **Completed:** $stepCompleted`n- **Effective command SHA-256:** ``$effectiveSha```n- **stdout SHA-256:** ``$stdoutSha```n- **stderr SHA-256:** ``$stderrSha```n- **Cleanup:** $cleanupStatus`n`n### Executed command`n" -Encoding UTF8
        Add-AfReportCode $effectiveFile
        $htmlReason = ConvertTo-AfHtml $reason
        $htmlTechniqueId = ConvertTo-AfHtml $step.TechniqueId
        $htmlTechniqueName = ConvertTo-AfHtml $step.TechniqueName
        Add-Content -LiteralPath $HtmlReportPath -Value (('<section><h2>{0}. {1} — {2}</h2><p><b>Execution:</b> {3} (exit {4})<br><b>Detection assessment:</b> {5}<br><b>Modified:</b> {6}<br><b>Modification reason:</b> {7}<br><b>Cleanup:</b> {8}</p><p><b>Started:</b> {9}<br><b>Completed:</b> {10}<br><b>Effective command SHA-256:</b> <code>{11}</code><br><b>stdout SHA-256:</b> <code>{12}</code><br><b>stderr SHA-256:</b> <code>{13}</code></p><h3>Executed command</h3>' -f $sequence,$htmlTechniqueId,$htmlTechniqueName,$executionStatus,$exitCode,$assessment,$modified,$htmlReason,$cleanupStatus,$stepStarted,$stepCompleted,$effectiveSha,$stdoutSha,$stderrSha)) -Encoding UTF8
        Add-AfHtmlCode $effectiveFile
        Add-Content -LiteralPath $HtmlReportPath -Value '</section>' -Encoding UTF8
        if ((Read-AfChoice 'Proceed to the next step? N=next / A=abort' @('N','A')) -eq 'A') { Write-AfEvent 'session_aborted' $stepId 'aborted after step'; $aborted = $true; break }
    }
}
catch [Management.Automation.PipelineStoppedException] {
    $aborted = $true; $interrupted = $true; $runnerError = $_
    Write-AfEvent 'session_interrupted' '' 'PowerShell pipeline stopped'
}
catch {
    $aborted = $true; $runnerError = $_
    Write-AfEvent 'session_error' '' $_.Exception.Message
}
finally {
    $CompletedAt = Get-AfTimestamp
    $SessionStatus = if ($interrupted) { 'interrupted' } elseif ($runnerError) { 'failed' } elseif ($aborted) { 'aborted' } else { 'completed' }
    Write-AfEvent 'session_completed' '' "status=$SessionStatus; completed=$completed; failed=$failed; skipped=$skipped"
    Add-Content -LiteralPath $ReportPath -Value "`n## Session summary`n`n- **Status:** $SessionStatus`n- **Completed successfully:** $completed`n- **Command failures/timeouts:** $failed`n- **Skipped:** $skipped`n- **Completed:** $CompletedAt`n" -Encoding UTF8
    Add-Content -LiteralPath $HtmlReportPath -Value (('<section><h2>Session summary</h2><p><b>Status:</b> {0}<br><b>Completed successfully:</b> {1}<br><b>Command failures/timeouts:</b> {2}<br><b>Skipped:</b> {3}<br><b>Completed:</b> {4}</p></section></main></body></html>' -f $SessionStatus,$completed,$failed,$skipped,$CompletedAt)) -Encoding UTF8
    [ordered]@{ schema_version='1.0'; run_id=$RunId; status=$SessionStatus; actor_id=$ActorId; platform='windows'; plan_sha256=$PlanSha256; csv_sha256=$CsvSha256; started_at=$StartedAt; completed_at=$CompletedAt; operator_b64=(ConvertTo-AfBase64 $Operator); target_b64=(ConvertTo-AfBase64 $Target); completed_steps=$completed; failed_steps=$failed; skipped_steps=$skipped; events_file='evidence-events.jsonl'; results_file='execution-results.csv'; report_file='execution-report.html'; markdown_report_file='execution-report.md' } |
        ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $SummaryPath -Encoding UTF8
    Save-AfResults
    Write-AfChecksums
    Write-Host "`nExecution $SessionStatus" -ForegroundColor Cyan
    Write-Host "Report and evidence are ready to hand back:`n$ResultsDir"
}
if ($runnerError) { Write-Error $runnerError.Exception.Message; exit 1 }
'''
    return (template.replace("__PLAN_SHA__", plan.plan_sha256)
            .replace("__CSV_NAME__", csv_name)
            .replace("__CSV_SHA__", csv_sha256)
            .replace("__ACTOR_ID__", _b64(plan.actor_id))
            .replace("__ACTOR_NAME__", _b64(plan.actor_name))
            .replace("__DATA_VERSION__", _b64(plan.data_version))
            .replace("__OPERATOR__", _b64(plan.operator))
            .replace("__TARGET__", _b64(plan.target))
            .replace("__STEPS__", steps_literal))


def archive_execution_kit(plan: ExecutionPlan) -> tuple[bytes, str]:
    actor_slug = _slug(f"{plan.actor_id}_{plan.actor_name}", "Adversary")
    platform_title = "Windows" if plan.platform == "windows" else "Linux"
    root = f"AdversaryFlow_{actor_slug}_{platform_title}"
    csv_name = f"{actor_slug}-plan.csv"
    script_name = f"{actor_slug}-execute.ps1" if plan.platform == "windows" else f"{actor_slug}-execute.sh"
    csv_bytes = render_plan_csv(plan)
    csv_sha256 = hashlib.sha256(csv_bytes).hexdigest()
    script = (render_powershell(plan, csv_name, csv_sha256) if plan.platform == "windows"
              else render_bash(plan, csv_name, csv_sha256))

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        csv_info = zipfile.ZipInfo(f"{root}/{csv_name}")
        csv_info.external_attr = 0o644 << 16
        archive.writestr(csv_info, csv_bytes)
        script_info = zipfile.ZipInfo(f"{root}/{script_name}")
        script_info.external_attr = (0o755 if plan.platform == "linux" else 0o644) << 16
        archive.writestr(script_info, script.encode("utf-8"))
        if _plan_needs_exercise_runner(plan):
            runner_info = zipfile.ZipInfo(f"{root}/{EXERCISE_RUNNER_NAME}")
            runner_info.external_attr = 0o644 << 16
            archive.writestr(runner_info, _exercise_runner_source())
    return output.getvalue(), f"{root}.zip"


def build_execution_kit(document: Mapping[str, Any]) -> tuple[bytes, str]:
    rebound = rebind_to_catalog(document)
    return archive_execution_kit(normalize_plan(rebound))
