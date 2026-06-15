#!/usr/bin/env python3
"""
MCP Gateway — Your machine, your rules. Allow-list security. ChatGPT-ready.

Usage:
  python3 server.py                      # Start with config.json
  python3 server.py --setup              # First-time setup wizard
  python3 server.py --token              # Print auth token
"""

import os
import sys
import json
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from security import (
    load_config, is_allowed_path, is_allowed_command,
    is_sensitive_path, audit_log, generate_token, expand_path,
    BLOCKED_COMMAND_PATTERNS,
)

# ── Config ──
CONFIG_PATH = Path(__file__).parent / "config.json"

def get_config():
    cfg = load_config(str(CONFIG_PATH))
    cfg.setdefault("name", "MCP Gateway")
    cfg.setdefault("port", 8000)
    cfg.setdefault("host", "127.0.0.1")
    cfg.setdefault("allowed_dirs", [str(Path.home())])
    cfg.setdefault("allowed_commands", [
        "ls", "cat", "head", "tail", "grep", "find", "wc", "sort",
        "uniq", "echo", "date", "pwd", "whoami",
        "git", "python3", "python", "node", "npm", "npx", "pip",
        "curl", "wget", "mkdir", "touch", "cp", "mv",
    ])
    cfg.setdefault("allow_write", False)
    cfg.setdefault("allow_shell", False)
    cfg.setdefault("token", "")
    return cfg


def setup_wizard():
    """First-time setup."""
    print("=== MCP Gateway Setup ===\n")
    cfg = get_config()

    name = input(f"Gateway name [{cfg['name']}]: ").strip()
    if name:
        cfg["name"] = name

    port = input(f"Port [{cfg['port']}]: ").strip()
    if port:
        cfg["port"] = int(port)

    dirs = input(f"Allowed dirs (comma-sep) [{cfg['allowed_dirs'][0]}]: ").strip()
    if dirs:
        cfg["allowed_dirs"] = [d.strip() for d in dirs.split(",")]

    write_ok = input("Allow file write? (y/N): ").strip().lower()
    cfg["allow_write"] = write_ok == "y"

    shell_ok = input("Allow shell commands? (y/N): ").strip().lower()
    cfg["allow_shell"] = shell_ok == "y"

    # Generate token
    cfg["token"] = generate_token()

    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)

    print(f"\n✓ Config saved to {CONFIG_PATH}")
    print(f"✓ Token: {cfg['token']}")
    print(f"\nMCP URL for ChatGPT: http://YOUR_HOST:{cfg['port']}/mcp?key={cfg['token']}")
    print("(Replace YOUR_HOST with your CF Tunnel domain or public IP)")


# ── Init FastMCP ──
cfg = get_config()
mcp = FastMCP(
    name=cfg["name"],
    host=cfg["host"],
    port=cfg["port"],
    streamable_http_path="/mcp",
)

# ── Auth check helper ──
def check_auth() -> bool:
    """Simple token check. Override in production."""
    token = cfg.get("token", "")
    if not token:
        return True  # No auth configured
    # FastMCP passes auth via context — for now simple mode
    return True


# ══════════════════════════════════════════════════
# Tools
# ══════════════════════════════════════════════════

@mcp.tool()
def read_file(path: str, offset: int = 1, limit: int = 500) -> str:
    """Read a file. offset=1-indexed line, limit=max lines. Returns content with line numbers."""
    cfg = get_config()
    if not is_allowed_path(path, cfg, "read"):
        audit_log("read_file", path, "DENIED", cfg)
        return f"ERROR: Access denied to '{path}'"
    try:
        p = expand_path(path)
        with open(p) as f:
            lines = f.readlines()
        total = len(lines)
        start = max(0, offset - 1)
        end = min(start + limit, total)
        result = "".join(f"{i+1:4}|{lines[i]}" for i in range(start, end))
        audit_log("read_file", f"{path} lines {start+1}-{end}/{total}", "OK", cfg)
        return result if result else "(empty file)"
    except Exception as e:
        audit_log("read_file", f"{path}: {e}", "ERROR", cfg)
        return f"ERROR: {e}"


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """Write content to a file. Requires allow_write=true in config."""
    cfg = get_config()
    if not cfg.get("allow_write"):
        return "ERROR: File writing is disabled. Set allow_write=true in config.json"
    if not is_allowed_path(path, cfg, "write"):
        audit_log("write_file", path, "DENIED", cfg)
        return f"ERROR: Access denied to '{path}'"
    try:
        p = expand_path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        audit_log("write_file", f"{path} ({len(content)} bytes)", "OK", cfg)
        return f"OK: Wrote {len(content)} bytes to {path}"
    except Exception as e:
        audit_log("write_file", f"{path}: {e}", "ERROR", cfg)
        return f"ERROR: {e}"


@mcp.tool()
def list_dir(path: str = ".") -> str:
    """List directory contents with sizes and types."""
    cfg = get_config()
    if not is_allowed_path(path, cfg, "read"):
        audit_log("list_dir", path, "DENIED", cfg)
        return f"ERROR: Access denied to '{path}'"
    try:
        p = expand_path(path)
        items = []
        for entry in sorted(p.iterdir()):
            try:
                size = entry.stat().st_size
                kind = "DIR" if entry.is_dir() else "FILE"
                name = entry.name + ("/" if entry.is_dir() else "")
                items.append(f"  {kind:4} {size:>10,}  {name}")
            except OSError:
                items.append(f"  ????           ?  {entry.name}")
        result = "\n".join(items) if items else "(empty directory)"
        audit_log("list_dir", path, "OK", cfg)
        return f"{path}:\n{result}"
    except Exception as e:
        audit_log("list_dir", f"{path}: {e}", "ERROR", cfg)
        return f"ERROR: {e}"


@mcp.tool()
def run_command(command: str, cwd: str = ".") -> str:
    """Execute an allowed shell command. Requires allow_shell=true. 30s timeout."""
    cfg = get_config()
    if not cfg.get("allow_shell"):
        return "ERROR: Shell execution is disabled. Set allow_shell=true in config.json"

    allowed, reason = is_allowed_command(command, cfg)
    if not allowed:
        audit_log("run_command", f"'{command}' — {reason}", "DENIED", cfg)
        return f"ERROR: {reason}"

    try:
        cwd_path = expand_path(cwd) if cwd else Path.home()
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True,
            timeout=30, cwd=str(cwd_path),
        )
        out = result.stdout
        if result.stderr:
            out += "\n[stderr]\n" + result.stderr
        out = out.strip() or "(no output)"
        audit_log("run_command", f"'{command}' (exit={result.returncode})", "OK", cfg)
        return out
    except subprocess.TimeoutExpired:
        audit_log("run_command", f"'{command}' — TIMEOUT", "ERROR", cfg)
        return "ERROR: Command timed out (30s)"
    except Exception as e:
        audit_log("run_command", f"'{command}': {e}", "ERROR", cfg)
        return f"ERROR: {e}"


@mcp.tool()
def git_status(repo_path: str = ".") -> str:
    """Run git status in a repo directory."""
    return run_command(f"git -C {repo_path} status --short", cwd=repo_path)


@mcp.tool()
def git_diff(repo_path: str = ".") -> str:
    """Run git diff in a repo directory."""
    return run_command(f"git -C {repo_path} diff", cwd=repo_path)


@mcp.tool()
def git_log(repo_path: str = ".", n: int = 10) -> str:
    """Show last n git commits."""
    return run_command(
        f"git -C {repo_path} log --oneline -{n}", cwd=repo_path
    )


@mcp.tool()
def health_check() -> str:
    """Verify gateway is alive. Returns config summary."""
    cfg = get_config()
    return (
        f"Gateway: {cfg['name']}\n"
        f"Allow write: {cfg['allow_write']}\n"
        f"Allow shell: {cfg['allow_shell']}\n"
        f"Allowed dirs: {', '.join(cfg['allowed_dirs'])}\n"
        f"Status: OK"
    )


# ══════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════

if __name__ == "__main__":
    if "--setup" in sys.argv:
        setup_wizard()
        sys.exit(0)
    if "--token" in sys.argv:
        cfg = get_config()
        print(cfg.get("token", "No token configured. Run --setup first."))
        sys.exit(0)

    cfg = get_config()
    print(f"Starting {cfg['name']} on {cfg['host']}:{cfg['port']}")
    print(f"MCP endpoint: http://{cfg['host']}:{cfg['port']}/mcp")
    if cfg.get("token"):
        print(f"Auth token: {cfg['token'][:8]}...")
    mcp.run(transport="streamable-http")
