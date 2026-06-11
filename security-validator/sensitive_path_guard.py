#!/usr/bin/env python3
"""Lightweight sensitive path guard for AI coding agents."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Iterable


SENSITIVE_PATH_RE = re.compile(
    r"(?is)(^|[\s\"'])("
    r"~?/\.ssh(?:/|$)|"
    r"~?/\.aws/credentials(?:\b|$)|"
    r"~?/\.config/gcloud/application_default_credentials\.json(?:\b|$)|"
    r"~?/\.kube/config(?:\b|$)|"
    r"~?/\.docker/config\.json(?:\b|$)|"
    r"~?/\.(?:env|npmrc|pypirc|netrc)(?:\b|$)|"
    r".*\.tfstate(?:\.[A-Za-z0-9_-]+)?(?:\b|$)"
    r")"
)

SYSTEM_PATH_RE = re.compile(r"(?is)^/(?:etc|private/etc|var/db|usr/bin|bin|sbin|dev)(?:/|$)")


@dataclass
class Finding:
    severity: str
    rule: str
    message: str
    path: str


def read_stdin() -> str:
    if sys.stdin.isatty():
        return ""
    return sys.stdin.read()


def collect_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        preferred = ("path", "file_path", "target", "uri", "tool_input", "input")
        for key in preferred:
            if key in value:
                yield from collect_strings(value[key])
        for key, item in value.items():
            if key not in preferred:
                yield from collect_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from collect_strings(item)


def normalize_input(raw: str) -> list[str]:
    raw = raw.strip()
    if not raw:
        return []

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return [raw]

    return [part for part in collect_strings(payload) if part]


def contains_traversal(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return ".." in PurePosixPath(normalized).parts


def scan_path(path: str) -> list[Finding]:
    findings: list[Finding] = []

    if SENSITIVE_PATH_RE.search(path):
        findings.append(
            Finding(
                "HIGH",
                "sensitive-path",
                "Path targets credentials, local secrets, private keys, or Terraform state.",
                path,
            )
        )

    if SYSTEM_PATH_RE.search(path):
        findings.append(
            Finding(
                "HIGH",
                "system-path",
                "Path targets an operating-system directory that should require explicit approval.",
                path,
            )
        )

    if contains_traversal(path):
        findings.append(
            Finding(
                "MEDIUM",
                "path-traversal",
                "Path contains parent-directory traversal and should be normalized against an allowed base directory.",
                path,
            )
        )

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", default="codex", help="Agent name for reporting.")
    parser.add_argument("--path", action="append", default=[], help="Path to validate. May be repeated.")
    args = parser.parse_args()

    paths = [*args.path, *normalize_input(read_stdin())]
    findings = [finding for path in paths for finding in scan_path(path)]
    blocked = any(f.severity in {"CRITICAL", "HIGH"} for f in findings)

    print(
        json.dumps(
            {
                "agent": args.agent,
                "allowed": not blocked,
                "paths": paths,
                "findings": [finding.__dict__ for finding in findings],
            },
            indent=2,
        )
    )

    return 2 if blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())

