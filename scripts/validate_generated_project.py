#!/usr/bin/env python3
"""Validate a Python project produced by the daily-checkin-builder skill.

This is a deterministic structural and security smoke check. YAML parsing
requires the pinned PyYAML dependency from ``requirements-validation.txt``.
It does not contact a live website and never needs runtime credentials.
"""

from __future__ import annotations

import argparse
import ast
import base64
import binascii
import json
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Sequence
from urllib.parse import parse_qsl, urlsplit

try:
    import yaml
except ImportError:  # Reported as a validation finding instead of crashing.
    yaml = None


if yaml is not None:
    class UniqueKeyLoader(yaml.BaseLoader):
        """Parse YAML scalars conservatively and reject duplicate mapping keys."""


    def _construct_unique_mapping(loader, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in mapping:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping


    UniqueKeyLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        _construct_unique_mapping,
    )
else:
    UniqueKeyLoader = None


TEXT_SUFFIXES = {
    ".cfg",
    ".css",
    ".env",
    ".go",
    ".har",
    ".html",
    ".http",
    ".ini",
    ".js",
    ".json",
    ".jsx",
    ".key",
    ".log",
    ".md",
    ".mjs",
    ".pem",
    ".ps1",
    ".py",
    ".rb",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".curl",
    ".xml",
    ".yaml",
    ".yml",
}
SENSITIVE_TEXT_NAMES = {
    ".curlrc", ".dockerconfigjson", ".git-credentials", ".netrc", ".npmrc",
    ".pypirc", ".wgetrc", "credentials", "id_dsa", "id_ecdsa",
    "id_ed25519", "id_rsa",
}
CODE_SUFFIXES = {".go", ".js", ".mjs", ".ps1", ".py", ".rb", ".sh", ".ts"}
IGNORED_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "coverage",
    "dist",
    "node_modules",
    "venv",
}
TODO_RE = re.compile(
    r"(?i)(?:\[\s*todo\b|\btodo\s*:|\bfixme\b|\btbd\b|"
    r"replace\s+this\s+(?:text|section|content)|placeholder\s+file)"
)
SENSITIVE_KEY_RE = re.compile(
    r"(?i)(?:^|[-_])(?:authorization|cookie|set[-_]?cookie|password|passwd|"
    r"access[-_]?key|secret[-_]?access[-_]?key|"
    r"api[-_]?key|client[-_]?secret|access[-_]?token|refresh[-_]?token|"
    r"auth[-_]?token|token|secret|session(?:[-_]?id)?|phone|email|"
    r"device[-_]?id|user[-_]?id|identifier)(?:$|[-_])"
)
ENV_ASSIGNMENT_RE = re.compile(
    r"(?i)^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(.*?)\s*$"
)
CONFIG_ASSIGNMENT_RE = re.compile(
    r"(?i)^\s*([A-Za-z_][A-Za-z0-9_-]*)\s*[:=]\s*(.*?)\s*$"
)
QUOTED_ASSIGNMENT_RE = re.compile(
    r"(?i)[\"']?([A-Za-z_][A-Za-z0-9_-]*)[\"']?\s*[:=]\s*([\"'])(.*?)\2"
)
CURL_HEADER_RE = re.compile(
    r"(?i)(?:-H|--header)(?:\s*=\s*|\s+)\$?([\"'])(authorization|cookie|set-cookie)\s*:\s*(.*?)\1"
)
CURL_COOKIE_RE = re.compile(r"(?i)(?:-b|--cookie)(?:\s*=\s*|\s+)\$?([\"'])(.*?)\1")
RAW_AUTH_HEADER_RE = re.compile(
    r"(?i)[\"']?authorization[\"']?\s*:\s*(?:[frbu]*[\"'])?(?:bearer|basic)\s+([^\s\"'\\,;]+)"
)
CURL_USER_RE = re.compile(
    r"(?i)(?:-u|--user)(?:\s*=\s*|\s+)(?:\$?[\"']([^\"']+)[\"']|([^\s]+))"
)
CURL_DATA_RE = re.compile(
    r"(?i)(?<!\S)(?:-d|--data(?:-raw|-binary|-urlencode)?)(?:\s*=\s*|\s+)(?:\$?[\"']([^\"']*)[\"']|([^\s]+))"
)
RAW_COOKIE_HEADER_RE = re.compile(
    r"(?i)[\"']?(?:cookie|set-cookie)[\"']?\s*:\s*[\"']?([^\"'\\\r\n]+)"
)
SENSITIVE_QUERY_RE = re.compile(
    r"(?i)[?&](?:token|access[_-]?token|refresh[_-]?token|auth[_-]?token|"
    r"api[_-]?key|client[_-]?secret|session[_-]?id|csrf|device[_-]?id|"
    r"user[_-]?id|email|phone|password|passwd|secret|credential|auth|access[_-]?key)=([^&#\s\"']+)"
)
EMAIL_RE = re.compile(
    r"(?i)\b[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9-]+"
    r"(?:\.[A-Z0-9-]+)*\.[A-Z][A-Z0-9-]*\b"
)
LABELLED_PHONE_RE = re.compile(
    r"(?i)(?:phone|mobile|tel|telephone|手机号|手机)\s*(?:[:=：]\s*)?(\+?\d[\d ()-]{7,}\d)"
)
UNLABELLED_PHONE_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:\+[1-9]\d{9,14}|1[3-9]\d{9})(?![A-Za-z0-9])"
)
FREEFORM_SENSITIVE_RE = re.compile(
    r"(?i)\b(authorization|auth|cookie|set[-_]?cookie|password|passwd|api[-_]?key|"
    r"access[-_]?key|secret[-_]?access[-_]?key|"
    r"client[-_]?secret|access[-_]?token|refresh[-_]?token|auth[-_]?token|"
    r"token|secret|session(?:[-_]?id)?|csrf(?:[-_]?token)?|device[-_]?id|"
    r"user[-_]?id|identifier)\s*[:=]\s*(?:([\"'])(.*?)\2|([^\s,;}\]]+))"
)
XML_SENSITIVE_RE = re.compile(
    r"(?is)<(authorization|cookie|password|passwd|api[_-]?key|token|secret|session[_-]?id|user[_-]?id|device[_-]?id|phone|email)>\s*([^<]+?)\s*</\1>"
)
NPM_AUTH_RE = re.compile(
    r"(?i)(?:^|[:/])(?:_authToken|_auth|password)\s*=\s*([^\s#;]+)"
)
NETRC_FIELD_RE = re.compile(r"(?i)\b(?:login|password|account)\s+([^\s]+)")
URL_USERINFO_RE = re.compile(r"(?i)https?://([^:/@\s]+):([^@/\s]+)@")
CURLRC_USER_RE = re.compile(
    r"(?i)^\s*(?:user|-u|--user)\s*(?:=|\s)\s*[\"']?([^\"']+)"
)
ANGLE_PLACEHOLDER_RE = re.compile(
    r"(?i)<(?:redacted|placeholder|masked|removed|not[-_]?set)(?:[-_][A-Za-z0-9]+)*>"
)
CLEAR_PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:[A-Za-z0-9_.-]+=)?(?:placeholder|replace[-_](?:with[-_])?|"
    r"replace[-_]?me|your[-_]|example[-_]|sample[-_]|dummy[-_]|fake[-_]|"
    r"fixture[-_]|sanitized[-_]|test[-_](?:only[-_])?|changeme|not[-_]a[-_]real[-_])"
    r"[A-Za-z0-9_.-]*$"
)
MAX_SCANNED_TEXT_BYTES = 2_000_000
SECRET_SIGNATURES = (
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b")),
    (
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
)
PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----\s+"
    r"[A-Za-z0-9+/=\r\n]{32,}\s+"
    r"-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    re.MULTILINE,
)
CRON_EXPRESSION_RE = re.compile(
    r"(?<!\S)(?:[0-9A-Za-z*?,/\-#L]+\s+){4,5}[0-9A-Za-z*?,/\-#L]+(?!\S)"
)
PINNED_REQUIREMENT_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.-]*==[A-Za-z0-9][A-Za-z0-9_.+!-]*$"
)
REQUIRED_STATUS_NAMES = (
    "SUCCESS",
    "ALREADY_DONE",
    "AUTH_EXPIRED",
    "ACCESS_DENIED",
    "TEMPORARY_ERROR",
    "SITE_CHANGED",
    "CONFIG_ERROR",
    "UNSUPPORTED_SECURITY_CHALLENGE",
)


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    message: str


class Reporter:
    def __init__(self) -> None:
        self.failures = 0

    def check(self, label: str, ok: bool, detail: str = "") -> None:
        status = "PASS" if ok else "FAIL"
        if not ok:
            self.failures += 1
        suffix = f" - {detail}" if detail else ""
        print(f"[{status}] {label}{suffix}")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate a generated daily check-in automation project."
    )
    parser.add_argument("path", type=Path, help="Path to the generated project root")
    parser.add_argument(
        "--mode",
        choices=("template", "generated"),
        default="generated",
        help="Validate reusable scaffold safety or a completed site-specific project",
    )
    return parser.parse_args(argv)


def normalize_root(path: Path) -> Path:
    return path.expanduser().resolve()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig")


def iter_text_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in IGNORED_DIRECTORIES for part in path.parts):
            continue
        if path.stat().st_size > MAX_SCANNED_TEXT_BYTES:
            continue
        if (
            path.suffix.lower() in TEXT_SUFFIXES
            or path.name.startswith(".env")
            or path.name.casefold() in SENSITIVE_TEXT_NAMES
        ):
            yield path


def safe_placeholder(value: str) -> bool:
    candidate = value.strip().strip("`\"'").strip()
    candidate = re.sub(r"^(?:basic|bearer)\s+", "", candidate, flags=re.IGNORECASE)
    lowered = candidate.lower()
    if not candidate:
        return True
    if re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", candidate):
        return True
    if re.fullmatch(r"\$\{\{[^{}]+\}\}", candidate):
        return True
    if ANGLE_PLACEHOLDER_RE.fullmatch(candidate):
        return True
    if re.fullmatch(r"%[A-Za-z_][A-Za-z0-9_]*%", candidate):
        return True
    if re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", candidate):
        return True
    if re.fullmatch(r"CHECKIN_[A-Z0-9_]+", candidate):
        return True
    if re.fullmatch(
        r"(?i)[^@\s]+@[A-Za-z0-9.-]+\.invalid",
        candidate,
    ):
        return True
    if re.fullmatch(r"(?:self|config|settings|env)\.[A-Za-z_][A-Za-z0-9_]*", candidate):
        return True
    if CLEAR_PLACEHOLDER_RE.fullmatch(candidate):
        return True
    if lowered.startswith(("secrets.", "os.environ", "getenv(")):
        return True
    if lowered in {
        "xxx", "xxxx", "authorization", "basic", "bearer", "token", "secret",
        "password", "cookie", "api_key", "apikey", "csrf", "session", "none", "null",
    }:
        return True
    if len(candidate) >= 4 and len(set(candidate.lower())) <= 2:
        return True
    placeholder_tail = re.sub(
        r"(?i)^(?:gh[pousr]_|AKIA|AIza|xox[baprs]-)", "", candidate
    )
    if placeholder_tail and set(placeholder_tail.lower()) <= {"x", "0", "*", "-", "_", "."}:
        return True
    return False


def safe_header_value(name: str, value: str) -> bool:
    if name.casefold() == "authorization":
        return safe_placeholder(value)
    if safe_placeholder(value):
        return True
    safe_cookie_attributes = {"path", "domain", "expires", "max-age", "samesite", "secure", "httponly"}
    for part in value.split(";"):
        candidate = part.strip()
        if not candidate:
            continue
        key, separator, item = candidate.partition("=")
        if key.strip().casefold() in safe_cookie_attributes:
            continue
        if not separator or not safe_placeholder(item):
            return False
    return True


def programmatic_header_reference(value: str) -> bool:
    candidate = value.strip().rstrip(",")
    identifier = candidate.rstrip("})]")
    return bool(
        re.fullmatch(r"\{[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+\}", candidate)
        or identifier in {
            "value", "cookie_value", "cookie_header", "auth_header",
            "authorization_header", "header_value",
        }
    )


def literal_looks_secret(value: str) -> bool:
    candidate = value.strip().rstrip(",").strip("`\"'").strip()
    if safe_placeholder(candidate):
        return False
    if len(candidate) < 8 or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,14}", candidate):
        return False
    classes = sum(
        bool(re.search(pattern, candidate))
        for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")
    )
    return classes >= 2 or len(candidate) >= 20


def embedded_text_is_unsafe(text: str) -> bool:
    if PRIVATE_KEY_BLOCK_RE.search(text):
        return True
    for _, pattern in SECRET_SIGNATURES:
        if any(not safe_placeholder(match.group(0)) for match in pattern.finditer(text)):
            return True
    for match in XML_SENSITIVE_RE.finditer(text):
        if not safe_placeholder(match.group(2)):
            return True
    for line in text.splitlines() or [text]:
        for auth in RAW_AUTH_HEADER_RE.finditer(line):
            if not safe_placeholder(auth.group(1)):
                return True
        for cookie in RAW_COOKIE_HEADER_RE.finditer(line):
            if not safe_header_value("cookie", cookie.group(1)):
                return True
        for query in SENSITIVE_QUERY_RE.finditer(line):
            if not safe_placeholder(query.group(1)):
                return True
        if any(not safe_placeholder(match.group(0)) for match in EMAIL_RE.finditer(line)):
            return True
        if LABELLED_PHONE_RE.search(line):
            return True
        for assignment in FREEFORM_SENSITIVE_RE.finditer(line):
            _, _, quoted_value, bare_value = assignment.groups()
            value = quoted_value if quoted_value is not None else bare_value
            if value is not None and not safe_placeholder(value):
                return True
    return False


def har_node_is_unsafe(node: object, parent: str = "") -> bool:
    if isinstance(node, dict):
        name = node.get("name")
        value = node.get("value")
        named_secret = isinstance(name, str) and SENSITIVE_KEY_RE.search(name)
        cookie_value = parent.casefold() == "cookies"
        if isinstance(value, str) and (named_secret or cookie_value) and not safe_placeholder(value):
            return True
        for key, item in node.items():
            if SENSITIVE_KEY_RE.search(str(key)) and key not in {"name", "value"}:
                if not safe_placeholder(str(item)):
                    return True
            if isinstance(item, str) and embedded_text_is_unsafe(item):
                return True
        text_value = node.get("text")
        if isinstance(text_value, str):
            mime = str(node.get("mimeType", "")).casefold()
            textual = not mime or any(marker in mime for marker in ("json", "text", "xml", "javascript", "x-www-form-urlencoded"))
            raw: bytes
            if str(node.get("encoding", "")).casefold() == "base64":
                try:
                    raw = base64.b64decode(re.sub(r"\s+", "", text_value), validate=True)
                except (ValueError, binascii.Error):
                    return textual
            else:
                raw = text_value.encode("utf-8")
            if len(raw) > MAX_SCANNED_TEXT_BYTES:
                return textual
            try:
                decoded = raw.decode("utf-8")
            except UnicodeDecodeError:
                return textual
            if embedded_text_is_unsafe(decoded):
                return True
            stripped = decoded.lstrip()
            if "json" in mime or stripped.startswith(("{", "[")):
                try:
                    parsed = json.loads(decoded)
                except json.JSONDecodeError:
                    return True
                if har_node_is_unsafe(parsed, "embedded-json"):
                    return True
            if "x-www-form-urlencoded" in mime:
                for key, form_value in parse_qsl(decoded, keep_blank_values=True):
                    if SENSITIVE_KEY_RE.search(key) and not safe_placeholder(form_value):
                        return True
        return any(har_node_is_unsafe(item, str(key)) for key, item in node.items() if key != "text")
    if isinstance(node, list):
        return any(har_node_is_unsafe(item, parent) for item in node)
    return False


def secret_findings(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_text_files(root):
        try:
            text = read_text(path)
        except (OSError, UnicodeError) as exc:
            findings.append(Finding(path, 0, f"cannot safely inspect text: {type(exc).__name__}"))
            continue
        if path.suffix.lower() in {".har", ".json"} or path.name.casefold() == ".dockerconfigjson":
            try:
                structured = json.loads(text)
            except json.JSONDecodeError:
                findings.append(Finding(path, 0, "JSON artifact is malformed and cannot be safely inspected"))
            else:
                if har_node_is_unsafe(structured):
                    findings.append(Finding(path, 0, "JSON artifact contains unsafe or uninspectable sensitive data"))
        cookie_jar = path.suffix.lower() == ".txt" and (
            "cookie" in path.name.casefold()
            or "netscape http cookie file" in text[:512].casefold()
        )
        if cookie_jar:
            for number, line in enumerate(text.splitlines(), start=1):
                if not line or line.lstrip().startswith("#"):
                    continue
                fields = line.split("\t")
                if len(fields) >= 7 and not safe_placeholder(fields[-1]):
                    findings.append(Finding(path, number, "Netscape cookie jar contains a non-placeholder value"))
        for match in XML_SENSITIVE_RE.finditer(text):
            if not safe_placeholder(match.group(2)):
                findings.append(
                    Finding(path, text.count("\n", 0, match.start()) + 1, "XML contains a non-placeholder sensitive value")
                )
        private_key = PRIVATE_KEY_BLOCK_RE.search(text)
        if private_key:
            block = private_key.group(0)
            body = re.sub(r"-----[^\r\n]+-----|\s", "", block)
            placeholder_body = bool(body) and set(body.lower()) <= {"x", "0", "*"}
            if not safe_placeholder(block) and not placeholder_body:
                findings.append(
                    Finding(path, text.count("\n", 0, private_key.start()) + 1, "possible private key")
                )
        for number, line in enumerate(text.splitlines(), start=1):
            if path.name.casefold() == ".npmrc":
                for match in NPM_AUTH_RE.finditer(line):
                    if not safe_placeholder(match.group(1)):
                        findings.append(Finding(path, number, "npm configuration contains a non-placeholder credential"))
            if path.name.casefold() == ".netrc":
                for match in NETRC_FIELD_RE.finditer(line):
                    if not safe_placeholder(match.group(1)):
                        findings.append(Finding(path, number, "netrc contains non-placeholder account data"))
            if path.name.casefold() == ".curlrc":
                match = CURLRC_USER_RE.search(line)
                if match:
                    _, separator, password = match.group(1).partition(":")
                    if separator and not safe_placeholder(password):
                        findings.append(Finding(path, number, "curl configuration contains a non-placeholder password"))
            for match in URL_USERINFO_RE.finditer(line):
                if not safe_placeholder(match.group(2)):
                    findings.append(Finding(path, number, "URL contains a non-placeholder password"))
            for label, pattern in SECRET_SIGNATURES:
                for match in pattern.finditer(line):
                    if not safe_placeholder(match.group(0)):
                        findings.append(Finding(path, number, f"possible {label}"))
            for header in CURL_HEADER_RE.finditer(line):
                _, name, value = header.groups()
                if not safe_header_value(name, value):
                    findings.append(Finding(path, number, f"non-placeholder {name} value in command text"))
            for auth in RAW_AUTH_HEADER_RE.finditer(line):
                if not (
                    path.suffix.lower() in CODE_SUFFIXES
                    and programmatic_header_reference(auth.group(1))
                ) and not safe_placeholder(auth.group(1)):
                    findings.append(Finding(path, number, "non-placeholder authorization value in header text"))
            for cookie_header in RAW_COOKIE_HEADER_RE.finditer(line):
                if not (
                    path.suffix.lower() in CODE_SUFFIXES
                    and programmatic_header_reference(cookie_header.group(1))
                ) and not safe_header_value("cookie", cookie_header.group(1)):
                    findings.append(Finding(path, number, "non-placeholder cookie value in header text"))
            for cookie in CURL_COOKIE_RE.finditer(line):
                if not safe_header_value("cookie", cookie.group(2)):
                    findings.append(Finding(path, number, "non-placeholder cookie value in command text"))
            for user in CURL_USER_RE.finditer(line):
                credential = user.group(1) or user.group(2) or ""
                _, separator, password = credential.partition(":")
                if separator and not safe_placeholder(password):
                    findings.append(Finding(path, number, "non-placeholder password in curl user credentials"))
            for data in CURL_DATA_RE.finditer(line):
                payload = data.group(1) if data.group(1) is not None else (data.group(2) or "")
                if embedded_text_is_unsafe(payload):
                    findings.append(Finding(path, number, "curl request body contains sensitive data"))
            for query in SENSITIVE_QUERY_RE.finditer(line):
                if not safe_placeholder(query.group(1)):
                    findings.append(Finding(path, number, "non-placeholder sensitive URL query value"))
            for email in EMAIL_RE.finditer(line):
                if not safe_placeholder(email.group(0)):
                    findings.append(Finding(path, number, "possible personal email address"))
            if LABELLED_PHONE_RE.search(line):
                findings.append(Finding(path, number, "possible labelled phone number"))
            if UNLABELLED_PHONE_RE.search(line):
                findings.append(Finding(path, number, "possible personal phone number"))
            if path.suffix.lower() not in CODE_SUFFIXES:
                for assignment in FREEFORM_SENSITIVE_RE.finditer(line):
                    key, _, quoted_value, bare_value = assignment.groups()
                    value = quoted_value if quoted_value is not None else bare_value
                    if value is not None and not safe_placeholder(value):
                        findings.append(Finding(path, number, f"literal value assigned to {key}"))
            env_style = path.name.startswith(".env") or path.suffix.lower() in {".sh", ".ps1"}
            config_style = (
                path.suffix.lower() in {".cfg", ".ini", ".toml", ".yaml", ".yml"}
                or path.name.casefold() in SENSITIVE_TEXT_NAMES
            )
            env_match = ENV_ASSIGNMENT_RE.match(line) if env_style else None
            if env_match is None and config_style:
                env_match = CONFIG_ASSIGNMENT_RE.match(line)
            if env_match:
                key, value = env_match.groups()
                value = re.split(r"\s+#", value, maxsplit=1)[0]
                unsafe_value = not safe_placeholder(value)
                if SENSITIVE_KEY_RE.search(key) and unsafe_value:
                    findings.append(Finding(path, number, f"literal value assigned to {key}"))
            for quoted in QUOTED_ASSIGNMENT_RE.finditer(line):
                key, _, value = quoted.groups()
                value_is_safe = (
                    safe_header_value("cookie", value)
                    if key.casefold() in {"cookie", "set-cookie", "set_cookie"}
                    else safe_placeholder(value)
                )
                if SENSITIVE_KEY_RE.search(key) and not value_is_safe:
                    findings.append(Finding(path, number, f"literal value assigned to {key}"))
    return list(dict.fromkeys(findings))


def format_findings(root: Path, findings: Iterable[Finding]) -> str:
    rendered: list[str] = []
    for finding in findings:
        try:
            name = finding.path.relative_to(root).as_posix()
        except ValueError:
            name = str(finding.path)
        location = f"{name}:{finding.line}" if finding.line else name
        rendered.append(f"{location}: {finding.message}")
    return "; ".join(rendered)


def nonempty_file(path: Path) -> bool:
    return path.is_file() and path.stat().st_size > 0


def requirement_findings(root: Path) -> list[Finding]:
    path = root / "requirements.txt"
    if not nonempty_file(path):
        return [Finding(path, 0, "requirements.txt is missing or empty")]
    try:
        lines = read_text(path).splitlines()
    except (OSError, UnicodeError) as exc:
        return [Finding(path, 0, f"requirements cannot be inspected: {type(exc).__name__}")]
    findings: list[Finding] = []
    requirement_count = 0
    for number, line in enumerate(lines, start=1):
        candidate = line.strip()
        if not candidate or candidate.startswith("#"):
            continue
        requirement_count += 1
        if not PINNED_REQUIREMENT_RE.fullmatch(candidate):
            findings.append(
                Finding(path, number, "dependency must be a package name pinned with one exact == version")
            )
    if not requirement_count:
        findings.append(Finding(path, 0, "requirements.txt has no pinned dependencies"))
    return findings


def syntax_findings(root: Path) -> list[Finding]:
    """Parse supported source and configuration formats without executing code."""

    findings: list[Finding] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in IGNORED_DIRECTORIES for part in path.parts):
            continue
        try:
            if path.suffix.lower() == ".py":
                ast.parse(read_text(path), filename=str(path))
            elif path.suffix.lower() == ".toml":
                tomllib.loads(read_text(path))
            elif path.suffix.lower() == ".json":
                json.loads(read_text(path))
            elif path.suffix.lower() in {".yaml", ".yml"}:
                if yaml is None:
                    findings.append(
                        Finding(
                            path,
                            0,
                            "PyYAML is required; install requirements-validation.txt",
                        )
                    )
                else:
                    document = yaml.load(read_text(path), Loader=UniqueKeyLoader)
                    if not isinstance(document, dict):
                        findings.append(Finding(path, 0, "YAML document root must be a mapping"))
        except SyntaxError as exc:
            findings.append(Finding(path, exc.lineno or 0, f"invalid Python syntax: {exc.msg}"))
        except tomllib.TOMLDecodeError as exc:
            findings.append(Finding(path, 0, f"invalid TOML: {exc}"))
        except json.JSONDecodeError as exc:
            findings.append(Finding(path, exc.lineno, f"invalid JSON: {exc.msg}"))
        except (OSError, UnicodeError) as exc:
            findings.append(Finding(path, 0, f"cannot parse file: {type(exc).__name__}"))
        except Exception as exc:
            if yaml is not None and isinstance(exc, yaml.YAMLError):
                mark = getattr(exc, "problem_mark", None)
                findings.append(
                    Finding(path, (mark.line + 1) if mark else 0, f"invalid YAML: {exc}")
                )
            else:
                raise
    return findings


def site_contract_findings(root: Path, mode: str) -> list[Finding]:
    path = root / "docs" / "site-contract.json"
    if not nonempty_file(path):
        return [Finding(path, 0, "docs/site-contract.json is missing or empty")]
    try:
        contract = json.loads(read_text(path))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [Finding(path, 0, f"site contract cannot be parsed: {type(exc).__name__}")]
    expected = (
        {"analysis_status": "template", "implementation_status": "scaffold"}
        if mode == "template"
        else {"analysis_status": "verified", "implementation_status": "site_specific"}
    )
    findings: list[Finding] = []
    if not isinstance(contract, dict):
        return [Finding(path, 0, "site contract root must be an object")]
    if contract.get("schema_version") != 1:
        findings.append(Finding(path, 0, "site contract schema_version must be 1"))
    for key, value in expected.items():
        if contract.get(key) != value:
            findings.append(Finding(path, 0, f"site contract {key} must be {value!r} in {mode} mode"))
    if contract.get("live_test_enabled") is not False:
        findings.append(Finding(path, 0, "site contract live_test_enabled must be false"))
    allowed = {"schema_version", "analysis_status", "implementation_status", "live_test_enabled"}
    if set(contract) != allowed:
        findings.append(Finding(path, 0, "site contract contains unsupported or missing keys"))
    return findings


def generated_scaffold_findings(root: Path) -> list[Finding]:
    """Reject known bundled scaffold residue outside offline tests and fixtures."""

    markers = (
        "checkin.example.invalid",
        "Baseline contract (not site evidence)",
        "sanitized-placeholder",
    )
    findings: list[Finding] = []
    for path in iter_text_files(root):
        relative = path.relative_to(root)
        if any(part.casefold() in {"tests", "test", "fixtures"} for part in relative.parts):
            continue
        try:
            text = read_text(path)
        except (OSError, UnicodeError):
            continue
        for marker in markers:
            if marker.casefold() in text.casefold():
                findings.append(Finding(path, 0, f"generated project retains scaffold marker {marker!r}"))
    return findings


def site_analysis_findings(root: Path) -> list[Finding]:
    path = root / "docs" / "site-analysis.md"
    if not nonempty_file(path):
        return [Finding(path, 0, "docs/site-analysis.md is missing or empty")]
    try:
        text = read_text(path)
    except (OSError, UnicodeError) as exc:
        return [Finding(path, 0, f"site analysis cannot be read: {type(exc).__name__}")]
    lowered = text.casefold()
    required_groups = {
        "authorization scope": ("authorization", "授权"),
        "evidence source": ("evidence", "证据"),
        "request contract": ("request contract", "请求契约", "请求流程"),
        "state evidence": ("state evidence", "状态证据", "状态判定"),
        "open assumptions": ("assumption", "假设", "待确认"),
        "CSRF evidence": ("csrf",),
        "success evidence": ("success", "成功"),
        "already-done evidence": ("already", "已签到"),
        "authentication-expiry evidence": ("authentication expired", "auth_expired", "认证过期"),
        "temporary-error evidence": ("temporary", "临时"),
        "site-change evidence": ("site changed", "site_changed", "网站变化"),
    }
    findings: list[Finding] = []
    for label, alternatives in required_groups.items():
        if not any(term.casefold() in lowered for term in alternatives):
            findings.append(Finding(path, 0, f"site analysis lacks {label}"))
    if TODO_RE.search(text):
        findings.append(Finding(path, 0, "site analysis contains an unfinished TODO"))
    return findings


def readme_contract_findings(root: Path) -> list[Finding]:
    path = root / "README.md"
    if not nonempty_file(path):
        return [Finding(path, 0, "README.md is missing or empty")]
    try:
        text = read_text(path)
    except (OSError, UnicodeError) as exc:
        return [Finding(path, 0, f"README cannot be read: {type(exc).__name__}")]
    lowered = text.casefold()
    required_groups = {
        "authorization boundary": ("authorized", "授权"),
        "site analysis": ("docs/site-analysis.md",),
        "local run": ("local", "本地"),
        "GitHub deployment": ("github actions",),
        "QingLong deployment": ("qinglong", "青龙"),
        "multi-account configuration": ("checkin_accounts", "multi-account", "多账号"),
        "secret handling": ("secret", "credential", "凭据", "秘密"),
        "offline tests": ("offline", "mock", "离线"),
    }
    findings: list[Finding] = []
    for label, alternatives in required_groups.items():
        if not any(term.casefold() in lowered for term in alternatives):
            findings.append(Finding(path, 0, f"README lacks {label}"))
    for status in REQUIRED_STATUS_NAMES:
        if status.casefold() not in lowered:
            findings.append(Finding(path, 0, f"README lacks state {status}"))
    return findings


def runtime_contract_findings(root: Path) -> list[Finding]:
    """Require substantive authentication/state logic and reject guessed endpoints."""

    source_files = [
        path
        for path in iter_text_files(root)
        if path.suffix.lower() in CODE_SUFFIXES
        and not any(part.casefold() in {"tests", "test", "fixtures", "docs"} for part in path.relative_to(root).parts)
    ]
    combined = "\n".join(read_text(path) for path in source_files)
    lowered = combined.casefold()
    findings: list[Finding] = []
    required_groups = {
        "source-controlled fixed site contract": ("site_config", "base_url"),
        "Cookie authentication": ("cookie",),
        "Bearer authentication": ("bearer", "authorization"),
        "CSRF handling": ("csrf",),
        "multi-account configuration": ("checkin_accounts", "accounts"),
        "bounded retries": ("max_retries", "retry"),
        "redaction": ("redact", "mask", "sanitize"),
    }
    for label, alternatives in required_groups.items():
        if not any(term in lowered for term in alternatives):
            findings.append(Finding(root, 0, f"runtime lacks {label}"))
    for status in REQUIRED_STATUS_NAMES:
        if status.casefold() not in lowered:
            findings.append(Finding(root, 0, f"runtime lacks state {status}"))
    site_config_path = root / "src" / "checkin" / "site_config.py"
    if not nonempty_file(site_config_path):
        findings.append(Finding(site_config_path, 0, "runtime lacks src/checkin/site_config.py for fixed site values"))
    fixed_value_outside_contract = re.compile(
        r"(?m)^\s*(?:status_path_value|checkin_path_value)\s*=\s*[\"']/"
    )
    for path in source_files:
        if path.name == "site_config.py":
            continue
        text = read_text(path)
        match = fixed_value_outside_contract.search(text)
        if match:
            findings.append(
                Finding(
                    path,
                    text.count("\n", 0, match.start()) + 1,
                    "runtime supplies an invented default endpoint path",
                )
            )
    guessed_endpoint = re.compile(
        r"(?is)(?:env|environ|os\.environ)\.get\(\s*[\"']"
        r"CHECKIN_(?:STATUS|ACTION)_PATH[\"']\s*,\s*[\"']/"
    )
    for path in source_files:
        text = read_text(path)
        match = guessed_endpoint.search(text)
        if match:
            findings.append(
                Finding(
                    path,
                    text.count("\n", 0, match.start()) + 1,
                    "runtime supplies an invented default endpoint path",
                )
            )
    return findings


def test_contract_findings(root: Path, tests: Iterable[Path]) -> list[Finding]:
    test_paths = list(tests)
    text = "\n".join(read_text(path) for path in test_paths)
    lowered = text.casefold()
    findings: list[Finding] = []
    for status in REQUIRED_STATUS_NAMES:
        # A response fixture, test name, or comment containing e.g.
        # ``auth_expired`` is not evidence that the expected result is tested.
        # Require an explicit domain-state expectation/reference instead.
        expected_state = re.compile(
            rf"\bCheckinStatus\s*\.\s*{re.escape(status)}\b",
            re.IGNORECASE,
        )
        if not expected_state.search(text):
            findings.append(Finding(root / "tests", 0, f"tests lack state assertion for {status}"))
    required_groups = {
        "Cookie and Bearer authentication": ("cookie", "bearer"),
        "CSRF": ("csrf",),
        "multi-account isolation": ("multi_account", "two_accounts", "multiple account", "多账号"),
        "timeout": ("timeout",),
        "429 handling": ("429",),
        "5xx handling": ("503", "5xx"),
        "POST duplicate prevention": ("ambiguous_post", "post_is_never_repeated", "防重复"),
        "redaction": ("redact", "mask", "遮盖"),
        "network deny guard": ("deny_live_network", "socket audit", "disablenetconnect"),
    }
    for label, alternatives in required_groups.items():
        if label == "Cookie and Bearer authentication":
            ok = all(term in lowered for term in alternatives)
        else:
            ok = any(term in lowered for term in alternatives)
        if not ok:
            findings.append(Finding(root / "tests", 0, f"tests lack {label}"))

    url_re = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
    tests_root = root / "tests"
    if tests_root.is_dir():
        for path in sorted(tests_root.rglob("*")):
            if not path.is_file() or path.stat().st_size > MAX_SCANNED_TEXT_BYTES:
                continue
            if path.suffix.lower() not in TEXT_SUFFIXES and path.name.casefold() not in SENSITIVE_TEXT_NAMES:
                continue
            try:
                file_text = read_text(path)
            except (OSError, UnicodeError):
                continue
            for number, line in enumerate(file_text.splitlines(), start=1):
                for match in url_re.finditer(line):
                    try:
                        host = urlsplit(match.group(0).rstrip(".,);]")).hostname
                    except ValueError:
                        host = None
                    if host and host not in {"localhost", "127.0.0.1", "::1"} and not host.endswith(".invalid"):
                        findings.append(Finding(path, number, "test data contains a non-reserved network URL"))
    return list(dict.fromkeys(findings))


def test_files(root: Path) -> list[Path]:
    tests = root / "tests"
    if not tests.is_dir():
        return []
    patterns = (
        re.compile(r"^test.*\.py$", re.IGNORECASE),
        re.compile(r"^.*_test\.py$", re.IGNORECASE),
        re.compile(r"^.*\.(?:test|spec)\.(?:js|jsx|ts|tsx)$", re.IGNORECASE),
        re.compile(r"^.*_test\.go$", re.IGNORECASE),
        re.compile(r"^.*_spec\.rb$", re.IGNORECASE),
    )
    recognized: list[Path] = []
    for path in tests.rglob("*"):
        if (
            not path.is_file()
            or path.stat().st_size == 0
            or not any(pattern.match(path.name) for pattern in patterns)
        ):
            continue
        try:
            text = read_text(path)
        except (OSError, UnicodeError):
            continue
        suffix = path.suffix.lower()
        has_test = (
            (suffix == ".py" and bool(re.search(r"(?m)^\s*(?:async\s+)?def\s+test_|^\s*class\s+\w*Test\w*", text)))
            or (suffix in {".js", ".jsx", ".ts", ".tsx"} and bool(re.search(r"\b(?:test|it|describe)\s*\(", text)))
            or (suffix == ".go" and bool(re.search(r"(?m)^func\s+Test\w+\s*\(", text)))
            or (suffix == ".rb" and bool(re.search(r"\b(?:describe|it|test)\b", text)))
        )
        if has_test:
            recognized.append(path)
    return recognized


def offline_test_findings(root: Path, tests: Iterable[Path]) -> list[Finding]:
    """Fail closed when automated tests can reach a live network."""

    findings: list[Finding] = []
    direct_network = re.compile(
        r"(?i)(?:urllib\.request\.urlopen\s*\(|requests\.(?:get|post|put|patch|delete|request)\s*\(|"
        r"httpx\.(?:get|post|put|patch|delete|request|Client|AsyncClient)\s*\(|"
        r"aiohttp\.ClientSession\s*\(|urllib3\.(?:PoolManager|request)\s*\(|"
        r"urllib\.request\.(?:Request|build_opener|urlopen)\s*\(|"
        r"http\.client\.HTTPS?Connection\s*\(|socket\.(?:socket|create_connection|getaddrinfo|gethostbyname)\s*\(|"
        r"(?:subprocess\.(?:Popen|run|call|check_call|check_output)|os\.(?:system|popen|spawn\w*)|webbrowser\.open)\s*\(|"
        r"(?:globalThis\.)?fetch\s*\(|axios\.(?:get|post|request)\s*\(|"
        r"(?:node:)?https?\.(?:get|request)\s*\(|"
        r"http\.(?:Get|Post|NewRequest)\s*\(|Net::HTTP|"
        r"StdlibTransport\s*\(|\b(?:curl|wget)\s+https?://|Invoke-WebRequest\b|Invoke-RestMethod\b)"
    )
    banned_import = re.compile(
        r"(?ix)^\s*(?:"
        r"from\s+(?:urllib(?:\.request)?|requests|httpx|aiohttp|urllib3|http\.client|"
        r"_socket|subprocess|ctypes|ftplib|smtplib)\s+import\b|"
        r"import\s+(?:urllib(?:\.request)?|requests|httpx|aiohttp|urllib3|http\.client|"
        r"_socket|subprocess|ctypes|ftplib|smtplib)\b|"
        r"from\s+os\s+import\s+(?:system|popen|spawn\w*)\b|"
        r".*(?:require\s*\(|from\s+)[\"'](?:axios|node:https?|https?|node:child_process|child_process)[\"']"
        r")"
    )
    url_re = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
    test_root = root / "tests"
    all_test_sources = [
        path
        for path in test_root.rglob("*")
        if path.is_file() and path.suffix.lower() in CODE_SUFFIXES
    ] if test_root.is_dir() else []
    evidence = "\n".join(
        read_text(path) for path in all_test_sources
        if path.stat().st_size <= MAX_SCANNED_TEXT_BYTES
    )
    python_tests = any(path.suffix.lower() == ".py" for path in tests)
    offline_runner = test_root / "run_offline.py"
    if python_tests:
        try:
            runner_text = read_text(offline_runner)
        except (OSError, UnicodeError) as exc:
            findings.append(Finding(offline_runner, 0, f"offline runner cannot be inspected: {type(exc).__name__}"))
        else:
            runner_contract = (
                re.search(r"(?m)^\s*socket\.create_connection\s*=\s*deny_live_network\s*$", runner_text)
                and "sys.addaudithook" in runner_text
                and 'event.startswith("socket.")' in runner_text
                and "unittest.defaultTestLoader.discover" in runner_text
            )
            if not runner_contract:
                findings.append(Finding(offline_runner, 0, "offline runner lacks the required pre-discovery socket audit guard"))
    if python_tests and not re.search(
        r"(?im)^\s*socket\.(?:socket|create_connection)\s*=\s*(?:deny|disable|guard)[A-Za-z0-9_]*\s*$",
        evidence,
    ):
        findings.append(Finding(test_root, 0, "Python tests lack a global socket-deny guard"))
    if any(path.suffix.lower() in {".js", ".jsx", ".ts", ".tsx"} for path in tests) and not re.search(
        r"(?i)(?:nock\.disableNetConnect\s*\(|disableNetConnect\s*\(|MockAgent\b)",
        evidence,
    ):
        findings.append(Finding(test_root, 0, "Node tests lack a global network-deny guard"))
    for path in all_test_sources:
        try:
            text = read_text(path)
        except (OSError, UnicodeError):
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if direct_network.search(line):
                findings.append(Finding(path, number, "test contains a direct live-network primitive"))
            if banned_import.search(line):
                findings.append(Finding(path, number, "test imports a live-network or subprocess capability"))
            if re.search(r"(?i)\bLIVE_TEST\b\s*[:=]", line):
                findings.append(Finding(path, number, "offline tests must not define LIVE_TEST"))
            for match in url_re.finditer(line):
                try:
                    host = urlsplit(match.group(0).rstrip(".,);]")).hostname
                except ValueError:
                    findings.append(Finding(path, number, "test contains a malformed network URL"))
                    continue
                if host and host not in {"localhost", "127.0.0.1", "::1"} and not host.endswith(".invalid"):
                    findings.append(Finding(path, number, "test contains a non-reserved network URL"))
    return list(dict.fromkeys(findings))


def workflow_files(root: Path) -> list[Path]:
    workflows = root / ".github" / "workflows"
    if not workflows.is_dir():
        return []
    return sorted(
        path
        for path in workflows.iterdir()
        if path.is_file() and path.suffix.lower() in {".yml", ".yaml"} and path.stat().st_size > 0
    )


def qinglong_files(root: Path) -> list[Path]:
    found: list[Path] = []
    exact_names = {"deploy_qinglong.md", "qinglong.md", "ql.md"}
    for path in iter_text_files(root):
        lowered_parts = [part.lower() for part in path.relative_to(root).parts]
        if path.name.lower() in exact_names or any("qinglong" in part for part in lowered_parts):
            found.append(path)
    return found


def without_yaml_comments(text: str) -> str:
    lines: list[str] = []
    for line in text.splitlines():
        single_quoted = False
        double_quoted = False
        escaped = False
        end = len(line)
        index = 0
        while index < len(line):
            character = line[index]
            if double_quoted:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    double_quoted = False
            elif single_quoted:
                if character == "'":
                    if index + 1 < len(line) and line[index + 1] == "'":
                        index += 1
                    else:
                        single_quoted = False
            elif character == '"':
                double_quoted = True
            elif character == "'":
                single_quoted = True
            elif character == "#" and (index == 0 or line[index - 1].isspace()):
                end = index
                break
            index += 1
        lines.append(line[:end].rstrip())
    return "\n".join(lines)


def indentation(line: str) -> int:
    prefix = line[: len(line) - len(line.lstrip(" \t"))]
    return len(prefix.replace("\t", "    "))


def direct_mapping_entries(lines: Iterable[str]) -> list[tuple[str, str]]:
    """Return direct mapping keys and inline values from a YAML block or step."""

    found: list[tuple[int, str, str]] = []
    pattern = re.compile(
        r"^(\s*)(-\s*)?([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(.*?)\s*$"
    )
    for line in lines:
        match = pattern.match(line)
        if not match:
            continue
        effective_indent = indentation(match.group(1)) + (2 if match.group(2) else 0)
        found.append((effective_indent, match.group(3).casefold(), match.group(4).strip()))
    if not found:
        return []
    direct_indent = min(item[0] for item in found)
    return [(key, value) for level, key, value in found if level == direct_indent]


def mapping_blocks(text: str, key: str) -> list[tuple[int, str, list[str]]]:
    """Return ``(indent, inline_value, children)`` for simple YAML mappings."""

    lines = without_yaml_comments(text).splitlines()
    pattern = re.compile(
        rf"^(\s*)[\"']?{re.escape(key)}[\"']?\s*:\s*(.*?)\s*$",
        re.IGNORECASE,
    )
    blocks: list[tuple[int, str, list[str]]] = []
    for index, line in enumerate(lines):
        match = pattern.match(line)
        if not match:
            continue
        base_indent = indentation(line)
        children: list[str] = []
        for following in lines[index + 1 :]:
            if not following.strip():
                children.append(following)
                continue
            if indentation(following) <= base_indent:
                break
            children.append(following)
        blocks.append((base_indent, match.group(2).strip(), children))
    return blocks


def top_level_children(text: str, key: str) -> list[str]:
    for indent, inline, children in mapping_blocks(text, key):
        if indent == 0 and not inline:
            return children
    return []


def has_cron_expression(text: str) -> bool:
    searchable = text.replace("`", " ").replace('"', " ").replace("'", " ")
    for match in CRON_EXPRESSION_RE.finditer(searchable):
        expression = match.group(0)
        fields = expression.split()
        if len(fields) in {5, 6} and "*" in expression and re.search(r"\d", expression):
            return True
    return False


def workflow_has_schedule(text: str) -> bool:
    on_children = top_level_children(text, "on")
    if not on_children:
        return False
    on_text = "\n".join(on_children)
    for _, inline, children in mapping_blocks(on_text, "schedule"):
        schedule_text = "\n".join([inline, *children])
        cron_values = re.findall(r"(?m)^\s*-?\s*cron\s*:\s*(.*?)\s*$", schedule_text)
        if any(has_cron_expression(value) for value in cron_values):
            return True
    return False


def workflow_has_manual_trigger(text: str) -> bool:
    on_children = top_level_children(text, "on")
    return bool(
        on_children
        and re.search(r"(?mi)^\s+workflow_dispatch\s*:", "\n".join(on_children))
    )


def workflow_has_iana_timezone(text: str) -> bool:
    """Require every cron schedule item to carry its own literal IANA timezone."""

    on_children = top_level_children(text, "on")
    if not on_children:
        return False
    schedule_items = 0
    for _, inline, children in mapping_blocks("\n".join(on_children), "schedule"):
        if inline or not children:
            continue
        starts = [
            index
            for index, line in enumerate(children)
            if re.match(r"^\s*-\s*cron\s*:", line, re.IGNORECASE)
        ]
        for position, start in enumerate(starts):
            end = starts[position + 1] if position + 1 < len(starts) else len(children)
            item = "\n".join(children[start:end])
            cron_match = re.search(r"(?mi)^\s*-\s*cron\s*:\s*(.*?)\s*$", item)
            timezone_match = re.search(
                r"(?mi)^\s+timezone\s*:\s*[\"']?"
                r"([A-Za-z][A-Za-z0-9_+.-]*/[A-Za-z0-9_+./-]+)[\"']?\s*$",
                item,
            )
            if not cron_match or not has_cron_expression(cron_match.group(1)) or not timezone_match:
                return False
            schedule_items += 1
    return schedule_items > 0


def workflow_has_concurrency(text: str) -> bool:
    for indent, inline, children in mapping_blocks(text, "concurrency"):
        if indent != 0:
            continue
        if inline:
            return inline not in {"{}", "null", "~"}
        block = "\n".join(children)
        has_group = bool(re.search(r"(?mi)^\s+group\s*:\s*\S.+$", block))
        has_cancel_policy = bool(
            re.search(r"(?mi)^\s+cancel-in-progress\s*:\s*(?:true|false|\$\{\{.+\}\})\s*$", block)
        )
        return has_group and has_cancel_policy
    return False


def workflow_has_timeout(text: str) -> bool:
    jobs_children = top_level_children(text, "jobs")
    if not jobs_children:
        return False
    return bool(
        re.search(
            r"(?mi)^\s{4,}timeout-minutes\s*:\s*[1-9][0-9]*\s*$",
            "\n".join(jobs_children),
        )
    )


def workflow_steps(text: str) -> list[str]:
    steps: list[str] = []
    for _, inline, children in mapping_blocks(text, "steps"):
        if inline or not children:
            continue
        starts = [
            index
            for index, line in enumerate(children)
            if re.match(
                r"^\s*-\s+[\"']?(?:name|id|uses|run|if)[\"']?\s*:",
                line,
                re.IGNORECASE,
            )
        ]
        for position, start in enumerate(starts):
            end = starts[position + 1] if position + 1 < len(starts) else len(children)
            steps.append("\n".join(children[start:end]))
    return steps


def step_run_text(step: str) -> str:
    """Extract only a step's shell program, excluding its env/metadata."""

    lines = without_yaml_comments(step).splitlines()
    pattern = re.compile(
        r"^(\s*)(-\s*)?[\"']?run[\"']?\s*:\s*(.*?)\s*$",
        re.IGNORECASE,
    )
    for index, line in enumerate(lines):
        match = pattern.match(line)
        if not match:
            continue
        key_indent = indentation(match.group(1)) + (2 if match.group(2) else 0)
        inline = match.group(3).strip()
        if inline and not re.fullmatch(r"[|>][0-9+-]*", inline):
            return inline
        body: list[str] = []
        for following in lines[index + 1 :]:
            if not following.strip():
                body.append(following)
                continue
            if indentation(following) <= key_indent:
                break
            body.append(following)
        return "\n".join(body)
    return ""


def workflow_tests_before_checkin(text: str) -> bool:
    steps = workflow_steps(text)
    test_re = re.compile(
        r"\s*(?:python3?|py\s+-3)\s+tests/run_offline\.py\s*",
        re.IGNORECASE,
    )
    checkin_re = re.compile(
        r"(?i)(?:check[- ]?in|checkin|签到|\bpython(?:3)?\s+(?:-m\s+checkin\b|run\.py\b))"
    )
    entry_re = re.compile(
        r"\s*(?:python3?|py\s+-3)\s+(?:-m\s+checkin(?:\.main)?|run\.py)\s*",
        re.IGNORECASE,
    )
    test_positions = [
        index for index, step in enumerate(steps)
        if test_re.fullmatch(step_run_text(step))
    ]
    checkin_positions = [
        index for index, step in enumerate(steps)
        if entry_re.fullmatch(step_run_text(step))
    ]
    return bool(test_positions and checkin_positions and min(test_positions) < min(checkin_positions))


def workflow_safety_findings(path: Path, text: str) -> list[Finding]:
    """Check security properties while allowing safe workflow variation."""

    findings: list[Finding] = []
    visible = without_yaml_comments(text)
    top_entries = direct_mapping_entries(visible.splitlines())
    top_keys = [key for key, _ in top_entries]
    required_top = {"on", "permissions", "concurrency", "jobs"}
    allowed_top = required_top | {"name", "run-name", "env"}
    if not required_top.issubset(top_keys):
        findings.append(Finding(path, 0, "workflow lacks on, permissions, concurrency, or jobs"))
    if set(top_keys) - allowed_top or any(top_keys.count(key) > 1 for key in set(top_keys)):
        findings.append(Finding(path, 0, "workflow has duplicate or unsupported top-level keys"))

    dangerous_mapping = re.compile(
        r"(?mi)^\s*(?:container|services|defaults|shell|working-directory)\s*:"
    )
    dangerous_environment = re.compile(
        r"(?m)^\s*(?:BASH_ENV|ENV|SHELLOPTS|PYTHONSTARTUP|PYTHONPATH|NODE_OPTIONS|"
        r"LD_PRELOAD|DYLD_INSERT_LIBRARIES)\s*:"
    )
    if dangerous_mapping.search(visible):
        findings.append(Finding(path, 0, "workflow contains an execution-context override"))
    if dangerous_environment.search(visible):
        findings.append(Finding(path, 0, "workflow contains a dangerous process-control environment variable"))

    on_children = top_level_children(text, "on")
    event_lines = [line for line in on_children if line.strip()]
    if event_lines:
        event_indent = min(indentation(line) for line in event_lines)
        events = {
            match.group(1).casefold()
            for line in event_lines
            if indentation(line) == event_indent
            for match in [re.match(r"^\s*[\"']?([A-Za-z_][A-Za-z0-9_-]*)[\"']?\s*:", line)]
            if match
        }
        if events - {"schedule", "workflow_dispatch"}:
            findings.append(Finding(path, 0, "check-in workflow has a non-approved remote trigger"))
    if re.search(r"(?mi)^\s+[\"']?inputs[\"']?\s*:", "\n".join(on_children)):
        findings.append(Finding(path, 0, "workflow_dispatch inputs are not permitted"))
    if re.search(r"(?im)^\s*[\"']?LIVE_TEST[\"']?\s*:", visible):
        findings.append(Finding(path, 0, "workflow must not define LIVE_TEST"))

    unsafe_expression = re.compile(
        r"\$\{\{(?:(?!\}\}).)*(?:\binputs\s*(?:\.|\[)|"
        r"\bgithub\s*(?:\.\s*event\b|\[\s*[\"']event[\"']\s*\])|"
        r"\bgithub\s*\.\s*(?:ref|head_ref|base_ref)\b)",
        re.IGNORECASE | re.DOTALL,
    )
    secret_expression = re.compile(
        r"\$\{\{(?:(?!\}\}).)*\bsecrets\s*(?:\.|\[)",
        re.IGNORECASE | re.DOTALL,
    )
    shell_hazard = re.compile(
        r"(?im)(?:^\s*(?:env|printenv)(?:\s|$)|\bset\s+-x\b|\bGITHUB_(?:ENV|OUTPUT)\b)"
    )
    entry_re = re.compile(
        r"\s*(?:py\s+-3|python3?)\s+(?:-m\s+checkin(?:\.main)?|run\.py)\s*",
        re.IGNORECASE,
    )
    for step in workflow_steps(text):
        run_text = step_run_text(step)
        step_fields = direct_mapping_entries(step.splitlines())
        step_keys = [key for key, _ in step_fields]
        if any(step_keys.count(key) != 1 for key in set(step_keys)):
            findings.append(Finding(path, 0, "workflow step contains a duplicate mapping key"))
        if run_text and unsafe_expression.search(run_text):
            findings.append(Finding(path, 0, "dispatch or branch expression is interpolated into a run step"))
        if run_text and secret_expression.search(run_text):
            findings.append(Finding(path, 0, "secret expression is interpolated directly into a run step"))
        if run_text and shell_hazard.search(run_text):
            findings.append(Finding(path, 0, "run step contains a credential-exposure primitive"))
        if secret_expression.search(step) and not entry_re.fullmatch(run_text):
            findings.append(Finding(path, 0, "only the shared check-in entry step may receive secrets"))
        if entry_re.fullmatch(run_text):
            env_blocks = mapping_blocks(step, "env")
            if len(env_blocks) != 1 or env_blocks[0][1]:
                findings.append(Finding(path, 0, "check-in step must use one block-style env mapping"))
                continue
            env_keys = {key for key, _ in direct_mapping_entries(env_blocks[0][2])}
            auth_options = {"checkin_accounts", "checkin_token", "checkin_cookie", "checkin_api_key"}
            fixed_site_keys = {"checkin_base_url", "checkin_status_path", "checkin_action_path", "checkin_user_agent"}
            if not (env_keys & auth_options):
                findings.append(Finding(path, 0, "check-in step lacks authentication environment values"))
            if env_keys & fixed_site_keys:
                findings.append(Finding(path, 0, "check-in step must not inject fixed site values through environment variables"))

    secret_reference = re.compile(r"\$\{\{(?:(?!\}\}).)*\bsecrets\s*(?:\.|\[)", re.IGNORECASE)
    allowed_secret = re.compile(
        r"^(\s*)[\"']?(CHECKIN_[A-Z0-9_]+)[\"']?\s*:\s*"
        r"\$\{\{\s*secrets\.(CHECKIN_[A-Z0-9_]+)\s*\}\}\s*$"
    )
    for number, line in enumerate(visible.splitlines(), start=1):
        if not secret_reference.search(line):
            continue
        allowed = allowed_secret.match(line)
        if not allowed or indentation(line) < 10 or allowed.group(2) != allowed.group(3):
            findings.append(Finding(path, number, "secret reference is outside an exact step-level CHECKIN_* env mapping"))
    return findings


def workflow_action_pin_findings(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for number, line in enumerate(without_yaml_comments(text).splitlines(), start=1):
        match = re.match(
            r"^\s*(?:-\s*)?[\"']?uses[\"']?\s*:\s*[\"']?([^\s\"']+)[\"']?\s*$",
            line,
            re.IGNORECASE,
        )
        if not match:
            continue
        action = match.group(1)
        if action.startswith("./"):
            findings.append(Finding(path, number, "local actions are not permitted without recursive audit"))
            continue
        if action.startswith("docker://"):
            findings.append(Finding(path, number, "Docker actions are not in the default allowlist"))
            continue
        ref_match = re.match(r"^[^@\s]+@([0-9a-fA-F]{40})$", action)
        if not ref_match:
            findings.append(Finding(path, number, f"action is not pinned to a full commit SHA: {action}"))
    for step in workflow_steps(text):
        action_match = re.search(
            r"(?mi)^\s*(?:-\s*)?[\"']?uses[\"']?\s*:\s*[\"']?([^\s\"']+)[\"']?\s*$",
            step,
        )
        if not action_match:
            continue
        repository = action_match.group(1).split("@", 1)[0].casefold()
        with_blocks = mapping_blocks(step, "with")
        entries = direct_mapping_entries(with_blocks[0][2]) if len(with_blocks) == 1 and not with_blocks[0][1] else []
        normalized = {key: value.strip("\"'") for key, value in entries}
        if repository == "actions/checkout":
            if normalized.get("persist-credentials", "true").casefold() != "false":
                findings.append(Finding(path, 0, "checkout must set persist-credentials: false"))
        elif repository == "actions/setup-python":
            version = normalized.get("python-version", "")
            if not re.fullmatch(r"3\.(?:1[1-9]|[2-9][0-9])", version):
                findings.append(Finding(path, 0, "setup-python must select Python 3.11 or newer"))
    return findings


def workflow_permission_issue(text: str) -> str:
    blocks = mapping_blocks(text, "permissions")
    if len(blocks) != 1:
        return "workflow must have exactly one top-level permissions block"
    indent, inline, children = blocks[0]
    if indent != 0:
        return "permissions must be declared only at workflow scope"
    if inline:
        return "permissions must use a block containing only contents: read"
    entries = [line.strip() for line in children if line.strip()]
    if len(entries) != 1 or not re.fullmatch(
        r"[\"']?contents[\"']?\s*:\s*[\"']?read[\"']?",
        entries[0],
        re.IGNORECASE,
    ):
        return "permissions block must contain only contents: read"
    return ""


def qinglong_has_schedule(files: Iterable[Path]) -> bool:
    for path in files:
        try:
            text = read_text(path)
        except (OSError, UnicodeError):
            continue
        if re.search(r"(?i)\bcron\b|定时", text) and has_cron_expression(text):
            return True
    return False


def local_entry_evidence(root: Path) -> list[Path]:
    evidence: list[Path] = []
    for path in iter_text_files(root):
        relative = path.relative_to(root)
        if any(part.casefold() in {"tests", "test", "fixtures", "docs"} for part in relative.parts):
            continue
        if path.name.casefold().startswith(("test_", "validate_")):
            continue
        if path.suffix.lower() not in CODE_SUFFIXES and path.name not in {"pyproject.toml", "package.json"}:
            continue
        try:
            text = read_text(path)
        except (OSError, UnicodeError):
            continue
        if (
            re.search(r"if\s+__name__\s*==\s*[\"']__main__[\"']", text)
            or re.search(r"(?m)^\s*\[project\.scripts\]\s*$", text)
            or (path.name == "package.json" and re.search(r'"(?:start|checkin)"\s*:', text))
            or re.search(r"(?m)^#!.*\b(?:python|node|sh|bash)\b", text)
        ):
            evidence.append(path)
    return evidence


def qinglong_manual_command(files: Iterable[Path]) -> bool:
    command_re = re.compile(
        r"(?im)(?:^|[`>\s])(?:py\s+-3|python3?|node|bash|sh)\s+"
        r"(?:-m\s+)?[^\s`]+"
    )
    for path in files:
        try:
            if command_re.search(read_text(path)):
                return True
        except (OSError, UnicodeError):
            continue
    return False


def qinglong_contract_findings(root: Path, files: Iterable[Path]) -> list[Finding]:
    paths = list(files)
    if not paths:
        return []
    findings: list[Finding] = []
    chunks: list[str] = []
    for path in paths:
        try:
            chunks.append(read_text(path))
        except (OSError, UnicodeError) as exc:
            findings.append(Finding(path, 0, f"QingLong documentation cannot be read: {type(exc).__name__}"))
    text = "\n".join(chunks)
    lowered = text.casefold()
    shared_entry = re.compile(
        r"(?im)(?:python3?|py\s+-3)\s+(?:run\.py|-m\s+checkin\.main)\b"
    )
    task_command = re.compile(
        r"(?im)\bcd\s+[^\r\n`]+\s+&&\s+(?:python3?|py\s+-3)\s+(?:run\.py|-m\s+checkin\.main)\b"
    )
    dependency_install = re.compile(
        r"(?im)(?:python3?|py\s+-3)\s+-m\s+pip\s+install\b[^\r\n]*-r\s+requirements\.txt"
    )
    required = {
        "shared Python business entry": bool(shared_entry.search(text)),
        "direct task command with project directory": bool(task_command.search(text)),
        "five-field cron": qinglong_has_schedule(paths),
        "pinned dependency installation": bool(dependency_install.search(text)),
        "offline test command": "tests/run_offline.py" in text,
        "IANA timezone configuration": "checkin_timezone" in lowered and bool(re.search(r"[A-Za-z]+/[A-Za-z0-9_+./-]+", text)),
        "single/multi-account environment variables": any(
                name in lowered
                for name in ("checkin_accounts", "checkin_cookie", "checkin_token", "checkin_api_key")
            ),
        "source-controlled verified site contract": "site_config.py" in lowered,
        "dependency and environment troubleshooting": "troubleshoot" in lowered or "排障" in lowered,
        "disable instructions": "disable" in lowered or "禁用" in lowered,
    }
    for label, ok in required.items():
        if not ok:
            findings.append(Finding(paths[0], 0, f"QingLong deployment lacks {label}"))
    for status in REQUIRED_STATUS_NAMES:
        if status.casefold() not in lowered:
            findings.append(Finding(paths[0], 0, f"QingLong troubleshooting lacks state {status}"))
    return findings


def redaction_evidence(root: Path, tests: Iterable[Path]) -> tuple[list[Path], list[Path]]:
    implementation: list[Path] = []
    test_evidence: list[Path] = []
    action_re = re.compile(r"(?i)\b(?:redact(?:ion|ed)?|mask(?:ing|ed)?|saniti[sz]e|scrub)\w*\b")
    field_re = re.compile(
        r"(?i)authorization|cookie|set[-_]?cookie|password|api[-_ ]?key|token|secret"
    )

    test_set = {path.resolve() for path in tests}
    for path in iter_text_files(root):
        if path.suffix.lower() not in CODE_SUFFIXES:
            continue
        try:
            text = read_text(path)
        except (OSError, UnicodeError):
            continue
        if action_re.search(text) and field_re.search(text):
            if path.resolve() in test_set or "tests" in path.relative_to(root).parts:
                test_evidence.append(path)
            else:
                implementation.append(path)
    return implementation, test_evidence


def nonzero_exit_evidence(root: Path) -> list[Path]:
    evidence: list[Path] = []
    direct_nonzero = re.compile(
        r"(?ix)(?:"
        r"sys\.exit\(\s*[1-9][0-9]*\s*\)|"
        r"raise\s+SystemExit\(\s*[1-9][0-9]*\s*\)|"
        r"process\.exit(?:Code\s*=|\()\s*[1-9][0-9]*|"
        r"os\.Exit\(\s*[1-9][0-9]*\s*\)|"
        r"(?m:^\s*exit\s+[1-9][0-9]*\s*$)"
        r")"
    )
    delegated_exit = re.compile(
        r"(?i)(?:sys\.exit|SystemExit|process\.exit)\s*\(\s*[A-Za-z_]\w*\s*\("
    )
    nonzero_result = re.compile(
        r"(?ix)(?:"
        r"\breturn\s+(?:[1-9][0-9]*|[^\n]+\belse\s+[1-9][0-9]*)|"
        r"\b(?:exit_?code|status_?code|failure_?code)\s*=\s*[1-9][0-9]*|"
        r"\bEXIT_FAILURE\b"
        r")"
    )

    for path in iter_text_files(root):
        if path.suffix.lower() not in CODE_SUFFIXES:
            continue
        try:
            text = read_text(path)
        except (OSError, UnicodeError):
            continue
        if direct_nonzero.search(text) or (delegated_exit.search(text) and nonzero_result.search(text)):
            evidence.append(path)
    return evidence


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    root = normalize_root(args.path)
    reporter = Reporter()

    if not root.is_dir():
        reporter.check("project directory", False, f"not a directory: {root}")
        print("\nValidation failed (1 check failed).")
        return 1
    reporter.check("project directory", True, str(root))
    reporter.check("validation mode", True, args.mode)

    readme = root / "README.md"
    readme_ok = nonempty_file(readme)
    readme_detail = "README.md is missing or empty" if not readme_ok else ""
    if readme_ok:
        try:
            if TODO_RE.search(read_text(readme)):
                readme_ok = False
                readme_detail = "README.md contains an unfinished TODO"
        except (OSError, UnicodeError) as exc:
            readme_ok = False
            readme_detail = f"cannot read UTF-8 text: {exc}"
    reporter.check("README", readme_ok, readme_detail)

    readme_findings = readme_contract_findings(root)
    reporter.check(
        "README operational contract",
        not readme_findings,
        format_findings(root, readme_findings),
    )

    analysis_findings = site_analysis_findings(root)
    reporter.check(
        "site-analysis evidence contract",
        not analysis_findings,
        format_findings(root, analysis_findings),
    )

    contract_findings = site_contract_findings(root, args.mode)
    reporter.check(
        "machine-readable site contract",
        not contract_findings,
        format_findings(root, contract_findings),
    )

    scaffold_findings = generated_scaffold_findings(root) if args.mode == "generated" else []
    reporter.check(
        "no generated-project scaffold residue",
        not scaffold_findings,
        "not applicable (template mode)" if args.mode == "template" else format_findings(root, scaffold_findings),
    )

    env_example = root / ".env.example"
    env_ok = nonempty_file(env_example)
    env_detail = ".env.example is missing or empty" if not env_ok else ""
    if env_ok:
        unsafe_env: list[str] = []
        assignment_count = 0
        try:
            for number, line in enumerate(read_text(env_example).splitlines(), start=1):
                if re.match(r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*=", line):
                    assignment_count += 1
                match = ENV_ASSIGNMENT_RE.match(line)
                value = re.split(r"\s+#", match.group(2), maxsplit=1)[0] if match else ""
                if match and SENSITIVE_KEY_RE.search(match.group(1)) and not safe_placeholder(value):
                    unsafe_env.append(f"line {number} ({match.group(1)})")
        except (OSError, UnicodeError) as exc:
            env_ok = False
            env_detail = f"cannot read UTF-8 text: {exc}"
        if unsafe_env:
            env_ok = False
            env_detail = "literal sensitive values at " + ", ".join(unsafe_env)
        elif env_ok and assignment_count == 0:
            env_ok = False
            env_detail = ".env.example contains no environment-variable assignments"
    reporter.check("safe .env.example", env_ok, env_detail)

    dependency_findings = requirement_findings(root)
    reporter.check(
        "pinned dependency requirements",
        not dependency_findings,
        format_findings(root, dependency_findings),
    )

    parse_findings = syntax_findings(root)
    reporter.check(
        "Python, TOML, JSON, and YAML syntax",
        not parse_findings,
        format_findings(root, parse_findings),
    )

    runtime_findings = runtime_contract_findings(root)
    reporter.check(
        "runtime authentication and state contract",
        not runtime_findings,
        format_findings(root, runtime_findings),
    )

    oversized = [
        path
        for path in root.rglob("*")
        if path.is_file()
        and not any(part in IGNORED_DIRECTORIES for part in path.parts)
        and (
            path.suffix.lower() in TEXT_SUFFIXES
            or path.name.startswith(".env")
            or path.name.casefold() in SENSITIVE_TEXT_NAMES
        )
        and path.stat().st_size > MAX_SCANNED_TEXT_BYTES
    ]
    reporter.check(
        "no unscanned oversized text artifacts",
        not oversized,
        (
            "cannot safely scan: " + ", ".join(path.relative_to(root).as_posix() for path in oversized)
            if oversized
            else ""
        ),
    )

    tests = test_files(root)
    reporter.check(
        "automated tests",
        bool(tests),
        f"{len(tests)} test file(s)" if tests else "tests directory has no recognized non-empty tests",
    )
    offline_findings = offline_test_findings(root, tests)
    reporter.check(
        "offline tests do not contact live services",
        not offline_findings,
        format_findings(root, offline_findings),
    )
    required_test_findings = test_contract_findings(root, tests)
    reporter.check(
        "required offline test scenarios",
        not required_test_findings,
        format_findings(root, required_test_findings),
    )

    workflows = workflow_files(root)
    qinglong = qinglong_files(root)
    deployment_ok = bool(workflows or qinglong)
    deployment_detail = (
        f"GitHub workflows={len(workflows)}, Qinglong files={len(qinglong)}"
        if deployment_ok
        else "no GitHub Actions workflow or Qinglong deployment file"
    )
    reporter.check("deployment configuration", deployment_ok, deployment_detail)

    workflow_texts: list[tuple[Path, str]] = []
    for workflow in workflows:
        try:
            workflow_texts.append((workflow, read_text(workflow)))
        except (OSError, UnicodeError):
            workflow_texts.append((workflow, ""))
    checkin_workflow_texts = [
        (path, text)
        for path, text in workflow_texts
        if workflow_has_schedule(text)
        or re.search(r"(?i)check[- ]?in|checkin|签到", path.name + "\n" + text)
    ]

    github_scheduled = any(workflow_has_schedule(text) for _, text in workflow_texts)
    qinglong_scheduled = qinglong_has_schedule(qinglong)
    schedule_ok = (
        deployment_ok
        and (not workflows or github_scheduled)
        and (not qinglong or qinglong_scheduled)
    )
    reporter.check(
        "scheduled execution",
        schedule_ok,
        f"GitHub={github_scheduled}, Qinglong={qinglong_scheduled}",
    )

    entry_files = local_entry_evidence(root)
    workflow_manual = any(workflow_has_manual_trigger(text) for _, text in workflow_texts)
    qinglong_manual = qinglong_manual_command(qinglong)
    manual_ok = (
        bool(entry_files)
        and (not workflows or workflow_manual)
        and (not qinglong or qinglong_manual)
    )
    manual_details = (
        f"local entry={bool(entry_files)}, workflow_dispatch={workflow_manual}, "
        f"Qinglong command={qinglong_manual}"
    )
    reporter.check("manual run entry", manual_ok, manual_details)

    qinglong_findings = qinglong_contract_findings(root, qinglong)
    reporter.check(
        "QingLong deployment contract",
        not qinglong_findings,
        (
            "not applicable (GitHub-only project)"
            if not qinglong
            else format_findings(root, qinglong_findings)
        ),
    )

    permission_findings: list[Finding] = []
    for workflow, text in workflow_texts:
        issue = workflow_permission_issue(text)
        if issue:
            permission_findings.append(Finding(workflow, 0, issue))
    permissions_ok = not workflows or not permission_findings
    permissions_detail = (
        "not applicable (Qinglong-only project)"
        if not workflows
        else format_findings(root, permission_findings)
    )
    reporter.check("GitHub minimum permissions", permissions_ok, permissions_detail)

    def workflow_contract_findings(predicate, message: str) -> list[Finding]:
        if not workflows:
            return []
        if not checkin_workflow_texts:
            return [Finding(workflows[0], 0, "no check-in workflow could be identified")]
        return [
            Finding(path, 0, message)
            for path, text in checkin_workflow_texts
            if not predicate(text)
        ]

    structure_findings = workflow_contract_findings(
        lambda text: bool(
            top_level_children(text, "on")
            and top_level_children(text, "jobs")
            and workflow_steps(text)
        ),
        "missing correctly indented top-level on/jobs or job steps structure",
    )
    reporter.check(
        "GitHub workflow critical structure",
        not structure_findings,
        (
            "not applicable (Qinglong-only project)"
            if not workflows
            else format_findings(root, structure_findings)
        ),
    )

    timezone_findings = workflow_contract_findings(
        workflow_has_iana_timezone,
        "each cron schedule item must include its own literal IANA Area/Location timezone",
    )
    reporter.check(
        "GitHub workflow IANA timezone",
        not timezone_findings,
        (
            "not applicable (Qinglong-only project)"
            if not workflows
            else format_findings(root, timezone_findings)
        ),
    )

    concurrency_findings = workflow_contract_findings(
        workflow_has_concurrency,
        "missing top-level concurrency group and cancel-in-progress policy",
    )
    reporter.check(
        "GitHub workflow concurrency",
        not concurrency_findings,
        (
            "not applicable (Qinglong-only project)"
            if not workflows
            else format_findings(root, concurrency_findings)
        ),
    )

    timeout_findings = workflow_contract_findings(
        workflow_has_timeout,
        "missing a positive job-level timeout-minutes",
    )
    reporter.check(
        "GitHub workflow timeout",
        not timeout_findings,
        (
            "not applicable (Qinglong-only project)"
            if not workflows
            else format_findings(root, timeout_findings)
        ),
    )

    order_findings = workflow_contract_findings(
        workflow_tests_before_checkin,
        "offline test step is missing or does not precede the check-in step",
    )
    reporter.check(
        "GitHub tests before check-in",
        not order_findings,
        (
            "not applicable (Qinglong-only project)"
            if not workflows
            else format_findings(root, order_findings)
        ),
    )

    action_pin_findings: list[Finding] = []
    for workflow, text in workflow_texts:
        action_pin_findings.extend(workflow_action_pin_findings(workflow, text))
    reporter.check(
        "GitHub Actions pinned to full SHAs",
        not action_pin_findings,
        (
            "not applicable (Qinglong-only project)"
            if not workflows
            else format_findings(root, action_pin_findings)
        ),
    )

    workflow_safety: list[Finding] = []
    for workflow, text in workflow_texts:
        workflow_safety.extend(workflow_safety_findings(workflow, text))
    reporter.check(
        "GitHub remote-trigger and shell safety",
        not workflow_safety,
        (
            "not applicable (Qinglong-only project)"
            if not workflows
            else format_findings(root, workflow_safety)
        ),
    )

    secrets = secret_findings(root)
    reporter.check(
        "no hard-coded secrets",
        not secrets,
        format_findings(root, secrets),
    )

    redaction_code, redaction_tests = redaction_evidence(root, tests)
    redaction_ok = bool(redaction_code and redaction_tests)
    reporter.check(
        "log redaction implementation and test evidence",
        redaction_ok,
        f"implementation files={len(redaction_code)}, test files={len(redaction_tests)}",
    )

    exit_evidence = nonzero_exit_evidence(root)
    reporter.check(
        "non-zero failure exit contract",
        bool(exit_evidence),
        (
            "evidence: " + ", ".join(path.relative_to(root).as_posix() for path in exit_evidence)
            if exit_evidence
            else "no explicit non-zero failure exit path found"
        ),
    )

    if reporter.failures:
        noun = "check" if reporter.failures == 1 else "checks"
        print(f"\nValidation failed ({reporter.failures} {noun} failed).")
        return 1
    print("\nValidation passed (all checks passed).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
