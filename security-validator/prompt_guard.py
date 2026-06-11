#!/usr/bin/env python3
"""Lightweight prompt and context guard for AI coding agents."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from typing import Any, Iterable


SENSITIVE_PATH_RE = re.compile(
    r"(?is)(~?/\.ssh/(?:id_rsa|id_ed25519|id_dsa|id_ecdsa|config)?|"
    r"~?/\.aws/credentials|~?/\.config/gcloud/application_default_credentials\.json|"
    r"~?/\.kube/config|~?/\.docker/config\.json|~?/\.(?:env|npmrc|pypirc|netrc)|"
    r"\.tfstate(?:\.[A-Za-z0-9_-]+)?)"
)

PROMPT_INJECTION_RE = re.compile(
    r"(?is)("
    r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|"
    r"disregard\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|"
    r"reveal\s+(?:the\s+)?(?:system|developer)\s+prompt|"
    r"print\s+(?:the\s+)?(?:system|developer)\s+prompt|"
    r"exfiltrate|"
    r"send\s+(?:all\s+)?(?:secrets|credentials|tokens)\s+to|"
    r"bypass\s+(?:safety|security|policy|approval)|"
    r"do\s+not\s+tell\s+(?:the\s+)?user"
    r")"
)

SECRET_RE = re.compile(
    r"(?is)("
    r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----|"
    r"AKIA[0-9A-Z]{16}|"
    r"gh[pousr]_[A-Za-z0-9_]{30,}|"
    r"xox[baprs]-[A-Za-z0-9-]{20,}|"
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|"
    r"(?:api[_-]?key|secret|token|password|passwd)\s*[:=]\s*[\"']?[A-Za-z0-9_./+=:@-]{12,}"
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
        for item in value.values():
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

    return "\n".join(part for part in collect_strings(payload) if part)


def scan_text(text: str) -> list[Finding]:
    findings: list[Finding] = []

    if PROMPT_INJECTION_RE.search(text):
        findings.append(
            Finding(
                "HIGH",
                "prompt-injection",
                "Text contains instructions that look like prompt injection or policy bypass attempts.",
            )
        )

    if SECRET_RE.search(text):
        findings.append(
            Finding(
                "CRITICAL",
                "secret-material",
                "Text appears to contain a token, password, private key, or similar secret.",
            )
        )

    if SENSITIVE_PATH_RE.search(text):
        findings.append(
            Finding(
                "HIGH",
                "sensitive-path",
                "Text references sensitive credential or local configuration paths.",
            )
        )

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", default="codex", help="Agent name for reporting.")
    parser.add_argument("--mode", choices=("prompt", "context"), default="prompt")
    parser.add_argument("files", nargs="*", help="Optional text files to scan.")
    args = parser.parse_args()

    chunks = [normalize_input(read_stdin())]
    for path in args.files:
        with open(path, "r", encoding="utf-8") as handle:
            chunks.append(handle.read())

    text = "\n".join(chunk for chunk in chunks if chunk)
    findings = scan_text(text)
    blocked = any(f.severity in {"CRITICAL", "HIGH"} for f in findings)

    print(
        json.dumps(
            {
                "agent": args.agent,
                "mode": args.mode,
                "allowed": not blocked,
                "findings": [finding.__dict__ for finding in findings],
            },
            indent=2,
        )
    )

    return 2 if blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())

