import platform
from pathlib import Path


SUPPORTED_PLATFORMS = ("Windows", "Debian", "Ubuntu", "Kali")


def detect_platform() -> str:
    if platform.system() == "Windows":
        return "Windows"
    os_release = Path("/etc/os-release")
    values: dict[str, str] = {}
    if os_release.exists():
        for line in os_release.read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"')
    identifier = values.get("ID", "").lower()
    if identifier == "kali":
        return "Kali"
    if identifier == "ubuntu":
        return "Ubuntu"
    if identifier in {"debian", "raspbian"}:
        return "Debian"
    return platform.system()


def platform_supported() -> bool:
    return detect_platform() in SUPPORTED_PLATFORMS

