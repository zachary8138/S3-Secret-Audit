from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Pattern:
    name: str
    severity: str
    regex: re.Pattern[str]


def default_filename_indicators() -> list[str]:
    return [
        ".env",
        ".env.local",
        ".env.prod",
        "credentials",
        "aws_access_key_id",
        "config.json",
        "id_rsa",
        "id_ed25519",
        "private_key",
        "service-account",
        "kubeconfig",
        "docker-compose.yml",
        "docker-compose.yaml",
        "settings.py",
        "application.yml",
        "application.yaml",
    ]


def default_secret_patterns() -> list[Pattern]:
    return [
        Pattern(
            name="aws_access_key_id",
            severity="high",
            regex=re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        ),
        Pattern(
            name="aws_secret_access_key_like",
            severity="high",
            regex=re.compile(r"(?i)\baws(.{0,20})?secret(.{0,20})?=\s*['\"]?[A-Za-z0-9/+=]{35,60}['\"]?"),
        ),
        Pattern(
            name="github_token",
            severity="high",
            regex=re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b"),
        ),
        Pattern(
            name="private_key_block",
            severity="critical",
            regex=re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
        ),
        Pattern(
            name="generic_api_key_assignment",
            severity="medium",
            regex=re.compile(r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
        ),
    ]


def iter_matches(text: str, patterns: Iterable[Pattern]) -> Iterable[tuple[Pattern, str]]:
    for p in patterns:
        m = p.regex.search(text)
        if m:
            snippet = text[m.start() : min(len(text), m.start() + 180)]
            yield p, snippet
