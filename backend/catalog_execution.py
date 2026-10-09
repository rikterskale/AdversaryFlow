"""Executor-specific catalog records; environments are not shell platforms.

These recipes are planning/read-only proxies, not implementations of cloud
compromise, container escape, or external reconnaissance. Nothing runs here.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List

from .command_safety import command_record

PLATFORMS = ("windows", "linux", "macos")

# One provider per block: never silently fall back to a different account.
AZURE = {
    "T1069.003": "az role assignment list --all -o table",
    "T1087.004": "az ad user list -o table",
    "T1526": "az resource list -o table",
    "T1538": "az --help",
    "T1580": "az vm list -o table",
    "T1530": "az storage account list -o table",
    "T1528": "az account get-access-token --query expiresOn -o tsv",
    "T1555.006": "az keyvault list -o table",
    "T1685.002": "az monitor diagnostic-settings list --help",
    "T1550.001": "az account get-access-token --query expiresOn -o tsv",
    "T1059.009": "az account show -o table",
    "T1651": "az vm run-command list --help",
    "T1098.001": "az ad app credential list --help",
    "T1098.003": "az role assignment list --all -o table",
    "T1078.004": "az account show -o table",
    "T1021.007": "az account show -o table",
    "T1578.002": "az vm list -o table",
    "T1578.003": "az vm list -o table",
    "T1537": "az storage account list -o table",
}
DOCKER = {
    "T1204.003": "docker image ls",
    "T1059.013": "docker --version",
    "T1609": "kubectl version --client",
    "T1610": "docker image ls",
    "T1613": "docker ps",
}
DNS = {
    "T1589": "nslookup localhost", "T1590": "nslookup -type=NS localhost",
    "T1590.001": "nslookup -type=SOA localhost", "T1590.005": "nslookup localhost",
    "T1596": "nslookup -type=MX localhost", "T1583.001": "nslookup localhost",
    "T1583.002": "nslookup -type=NS localhost", "T1583.006": "nslookup localhost",
    "T1584.001": "nslookup localhost", "T1584.002": "nslookup -type=NS localhost",
}


def _record(platform: str, command: str, original: Dict[str, Any], environment: str,
            tools: List[str], credentials: List[str] | None = None,
            network: bool = False, targets: List[str] | None = None,
            loopback: bool = False) -> Dict[str, Any]:
    credentials = credentials or []
    role = "planning" if environment == "pre_compromise" else "environment_validation"
    if "Certificate" in command or "openssl req" in command:
        side_effects = ["temporary_certificate_artifacts"]
    elif network:
        side_effects = ["network_activity"]
    elif loopback:
        side_effects = ["loopback_network_activity"]
    else:
        side_effects = ["read_only_or_process_telemetry"]
    return command_record(
        platform, command,
        original["note"] + " Executor-specific lab proxy; not proof of the mapped adversary behavior.",
        risk="medium" if network or "Certificate" in command else "low",
        requires_admin=False, requires_network=network, network_targets=targets or [],
        environment=environment, execution_role=role,
        required_tools=tools, required_credentials=credentials,
        prerequisites=[f"{platform} command environment", "authorized disposable lab", *tools, *credentials],
        fidelity="lab_proxy", acknowledgment_required=network or loopback or "Certificate" in command or "openssl req" in command,
        side_effects=side_effects,
        expected_telemetry="Planning/tool activity only; independently verify any claimed target telemetry.",
        expected_output=original["note"],
    )


def normalize_environment_record(technique_id: str, original: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Replace every non-OS record using an explicitly reviewed recipe."""
    kind = original["platform"]
    if technique_id == "T1537":
        kind = "cloud"
        original = {**original, "note": "Read-only authorized cloud account inventory proxy; does not transfer or upload data."}
    if kind in PLATFORMS:
        return [original]
    if kind not in {"pre", "cloud", "other"}:
        raise ValueError(f"Unknown catalog environment: {kind}")
    result = []
    for platform in PLATFORMS:
        environment = "pre_compromise" if kind == "pre" else "cloud" if kind == "cloud" else "container"
        tools: List[str] = []
        credentials: List[str] = []
        network = False
        loopback = False
        targets: List[str] = []
        if technique_id in AZURE:
            command = AZURE[technique_id]
            tools = ["az"]
            network = "--help" not in command
            if network:
                credentials = ["Azure CLI authenticated to the explicitly authorized tenant/subscription"]
                targets = ["Configured Azure API endpoints"]
        elif technique_id == "T1619":
            command = "aws s3 ls"
            tools, credentials, network, targets = ["aws"], ["AWS credentials for the explicitly authorized account"], True, ["Configured AWS S3 endpoint"]
        elif technique_id in {"T1213.003", "T1593.003"}:
            command, tools = "git --version", ["git"]
        elif technique_id in DOCKER:
            command = DOCKER[technique_id]
            environment = "container"
            tools = [command.split()[0]]
            network = command in {"docker image ls", "docker ps"}
            if network:
                credentials = ["Access to the explicitly authorized Docker daemon/context"]
                targets = ["Configured Docker daemon/context"]
        elif technique_id == "T1611":
            if platform != "linux":
                continue
            command, tools = "head -n 20 /proc/1/cgroup", ["head"]
            credentials = ["Linux container context; this reads cgroup metadata and does not escape"]
        elif technique_id in DNS:
            command, tools, loopback, targets = DNS[technique_id], ["nslookup"], True, ["127.0.0.1"]
        elif technique_id == "T1590.004":
            command = "tracert -h 1 127.0.0.1" if platform == "windows" else "traceroute -m 1 127.0.0.1"
            tools, loopback, targets = [command.split()[0]], True, ["127.0.0.1"]
        elif technique_id == "T1595.001":
            command = "ping -n 1 127.0.0.1" if platform == "windows" else "ping -c 1 127.0.0.1"
            tools, loopback, targets = ["ping"], True, ["127.0.0.1"]
        elif technique_id in {"T1595", "T1595.002"}:
            if platform == "windows":
                command = 'powershell -NoProfile -Command "Test-NetConnection 127.0.0.1 -Port 9 | Select ComputerName,TcpTestSucceeded"'
                tools = ["powershell"]
            else:
                command = "python3 -c \"import socket; s=socket.socket(); s.settimeout(2); print({'loopback_port_9_connect_result': s.connect_ex(('127.0.0.1',9))}); s.close()\""
                tools = ["python3"]
            loopback, targets = True, ["127.0.0.1"]
        elif technique_id in {"T1587.002", "T1587.003"}:
            if platform == "windows":
                certificate_type = "-Type CodeSigning " if technique_id == "T1587.002" else ""
                command = ('powershell -NoProfile -Command "$c=New-SelfSignedCertificate ' + certificate_type
                           + '-Subject CN=AdversaryFlow-Temporary -CertStoreLocation Cert:\\CurrentUser\\My; '
                           + 'try {$c | Select Thumbprint} finally {if ($c) {Remove-Item -LiteralPath $c.PSPath}}"')
                tools = ["powershell"]
            else:
                command = "d=$(mktemp -d) && (trap 'rm -rf -- \"$d\"' EXIT; openssl req -x509 -newkey rsa:2048 -nodes -keyout \"$d/key.pem\" -out \"$d/cert.pem\" -days 1 -subj /CN=AdversaryFlow-Temporary && openssl x509 -in \"$d/cert.pem\" -noout -fingerprint)"
                tools = ["mktemp", "openssl", "rm"]
            original = {**original, "note": "Temporary self-signed certificate proxy; deletes only its own newly created certificate/artifacts. Not a trusted code-signing credential."}
        elif technique_id == "T1588.002":
            command = "where.exe nmap.exe psexec.exe" if platform == "windows" else "command -v nmap; command -v psexec; :"
            tools = ["where.exe"] if platform == "windows" else []
        elif technique_id in {"T1552.005", "T1591", "T1592", "T1592.002", "T1592.004", "T1594"}:
            text = "AdversaryFlow planning proxy: no remote access or adversary behavior is performed."
            command = f"echo {text}" if platform == "windows" else f"printf '%s\\n' '{text}'"
        else:
            raise ValueError(f"Non-OS technique lacks an explicit executor recipe: {technique_id}")
        result.append(_record(platform, command, original, environment, tools, credentials, network, targets, loopback))
    return result


def identify_command(command: Dict[str, Any]) -> Dict[str, Any]:
    """Pin the body and execution requirements; changing either changes identity."""
    executor = command.get("interpreter", "cmd" if command.get("platform") == "windows" else "bash")
    tools = [executor]
    first = str(command.get("command", "")).split(" ", 1)[0].lower()
    if first in {"python", "python3", "powershell", "powershell.exe"} and first not in tools:
        tools.append(first)
    result = {"environment": "endpoint", "execution_role": "endpoint_test",
              "required_tools": tools, "required_credentials": [], **command}
    result.pop("command_id", None)
    digest = hashlib.sha256(json.dumps(result, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {**result, "command_id": digest}


def select_for_scope(commands: List[Dict[str, Any]], platform: str, scope: Dict[str, Any],
                     selected_id: str | None = None) -> Dict[str, Any] | None:
    compatible = [command for command in commands if command["platform"] == platform]
    if selected_id:
        return next((command for command in compatible if command.get("command_id") == selected_id), None)
    def allowed(command: Dict[str, Any]) -> bool:
        return not (command.get("unsupported") or (command["requires_network"] and not scope.get("allow_network"))
                    or (command["requires_admin"] and not scope.get("allow_admin"))
                    or (command["risk"] == "high" and not scope.get("allow_high_risk")))
    return next((command for command in compatible if allowed(command)), compatible[0] if compatible else None)
