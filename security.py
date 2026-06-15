"""
Security model for MCP Gateway — allow-list based permission system.
Every filesystem and shell operation is checked against this module.
"""

import os
import re
import json
import time
from pathlib import Path
from datetime import datetime, timezone

# ── Hard-coded dangerous commands (always blocked, can't be overridden) ──
BLOCKED_COMMAND_PATTERNS = [
    r"^sudo\b", r"^su\b", r"^dd\b", r"^mkfs\b",
    r"^fdisk\b", r"^diskutil\b", r"^shutdown\b", r"^reboot\b",
    r"^halt\b", r"^poweroff\b", r"^init\s",
    r"\brm\s+-rf\b", r"\bchmod\s+777\b",
    r">\s*/dev/sd", r">\s*/dev/nvme", r">\s*/dev/mmcblk",
    r"\bmkfs\.", r"\bfdisk\b", r"\bparted\b",
]

# ── Sensitive paths (never readable or writable) ──
SENSITIVE_PATH_PREFIXES = [
    "~/.ssh", "~/.aws", "~/.gnupg", "~/.gcloud",
    "/etc/", "/root/", "/var/run/", "/var/log/",
    "~/.hermes/.env", "~/.git-credentials",
    ".env", ".secrets",
]

AUDIT_LOG_PATH = "~/.mcp-gateway-audit.log"


def expand_path(path: str) -> Path:
    return Path(path).expanduser().resolve()


def load_config(config_path: str = "config.json") -> dict:
    """Load user config with allow-lists."""
    path = Path(config_path)
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def is_sensitive_path(target: str) -> bool:
    """Check if path matches sensitive patterns (always blocked)."""
    expanded = str(expand_path(target))
    for prefix in SENSITIVE_PATH_PREFIXES:
        pfx = str(expand_path(prefix))
        if expanded == pfx or expanded.startswith(pfx + os.sep):
            return True
    # Also check for symlink escape
    try:
        real = os.path.realpath(expanded)
        for prefix in SENSITIVE_PATH_PREFIXES:
            pfx = str(expand_path(prefix))
            if real == pfx or real.startswith(pfx + os.sep):
                return True
    except OSError:
        pass
    return False


def is_allowed_path(target: str, config: dict, operation: str = "read") -> bool:
    """Check if path is in the allow-list for given operation."""
    if is_sensitive_path(target):
        return False
    expanded = str(expand_path(target))
    allowed_dirs = config.get("allowed_dirs", [])
    for ad in allowed_dirs:
        ad_expanded = str(expand_path(ad))
        if expanded == ad_expanded or expanded.startswith(ad_expanded + os.sep):
            # For write operations, also check if writable is explicitly allowed
            if operation == "write" and not config.get("allow_write", False):
                return False
            return True
    return False


def is_allowed_command(command: str, config: dict) -> tuple[bool, str]:
    """Check if command is allowed. Returns (allowed, reason)."""
    cmd_clean = command.strip()

    # Always block dangerous commands
    for pattern in BLOCKED_COMMAND_PATTERNS:
        if re.search(pattern, cmd_clean, re.IGNORECASE):
            return False, f"Blocked dangerous pattern: {pattern}"

    # Check allow-list
    allowed_commands = config.get("allowed_commands", ["ls", "cat", "head", "tail",
        "grep", "find", "wc", "sort", "uniq", "echo", "date", "pwd", "whoami",
        "git", "python3", "python", "node", "npm", "npx", "pip",
        "curl", "wget", "mkdir", "touch", "cp", "mv",
    ])

    # Extract base command
    base_cmd = cmd_clean.split()[0].split("/")[-1] if cmd_clean.split() else ""

    if base_cmd in allowed_commands:
        return True, ""

    return False, f"Command not in allow-list: {base_cmd}"


def audit_log(action: str, detail: str, status: str, config: dict):
    """Write audit log entry."""
    log_path = expand_path(config.get("audit_log", AUDIT_LOG_PATH))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "detail": detail[:500],
        "status": status,
    }
    with open(log_path, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def generate_token() -> str:
    """Generate a random token for MCP auth."""
    import secrets
    return secrets.token_urlsafe(32)
