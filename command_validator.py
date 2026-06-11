#!/usr/bin/env python3
"""Lightweight shell command validator for AI coding agents."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from typing import Any, Iterable


DANGEROUS_COMMAND_RE = re.compile(
    r"(?is)("
    r"curl\s+[^|]+?\|\s*(?:bash|sh)|"
    r"wget\s+[^|]+?\|\s*(?:bash|sh)|"
    r"rm\s+-rf\s+(?:/|~|\$HOME|\*)|"
    r"cat\s+(?:~?/\.ssh/|~?/\.aws/credentials|~?/\.env)|"
    r"chmod\s+(?:-R\s+)?777|"
    r"sudo\s+.*|"
    r"mkfs(?:\.[a-z0-9]+)?\s+|"
    r"dd\s+if=.*\s+of=/dev/"
    r")"
)

SUSPICIOUS_COMMAND_RE = re.compile(
    r"(?is)("
    r"(?:npm|pnpm|yarn|pip|pip3|uv|cargo|go)\s+.*(?:install|add|get)\s+.*https?://|"
    r"base64\s+-d|"
    r"python3?\s+-c\s+[\"'].*(?:subprocess|socket|requests)|"
    r"openssl\s+.*(?:-nodes|-passout\s+pass:)"
    r")"
)


@dataclass
class Finding:
    severity: str
    rule: str
    message: str


def read_stdin() -> str:
    if sys.stdin.isatty():
        return ""
    return sys.stdin.read()


def collect_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        preferred = ("command", "cmd", "args", "tool_input", "input")
        for key in preferred:
            if key in value:
                yield from collect_strings(value[key])
        for key, item in value.items():
            if key not in preferred:
                yield from collect_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from collect_strings(item)


def normalize_input(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return raw

    return " ".join(part for part in collect_strings(payload) if part)


def scan_command(command: str) -> list[Finding]:
    findings: list[Finding] = []

    if DANGEROUS_COMMAND_RE.search(command):
        findings.append(
            Finding(
                "HIGH",
                "dangerous-command",
                "Command matches a destructive, privileged, credential-reading, or remote-code-execution pattern.",
            )
        )

    if SUSPICIOUS_COMMAND_RE.search(command):
        findings.append(
            Finding(
                "MEDIUM",
                "suspicious-command",
                "Command may download code, decode payloads, or create weak cryptographic material.",
            )
        )

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", default="codex", help="Agent name for reporting.")
    parser.add_argument("--command", help="Command string to validate.")
    args = parser.parse_args()

    command = args.command or normalize_input(read_stdin())
    findings = scan_command(command)
    blocked = any(f.severity in {"CRITICAL", "HIGH"} for f in findings)

    print(
        json.dumps(
            {
                "agent": args.agent,
                "allowed": not blocked,
                "command": command,
                "findings": [finding.__dict__ for finding in findings],
            },
            indent=2,
        )
    )

    return 2 if blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())

