#!/usr/bin/env python3
"""Validate the repository-level daily-checkin-builder Codex skill.

The validator intentionally uses only the Python standard library so it can be
run on Windows with ``py -3`` as well as with ``python3`` on other platforms.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Sequence
from urllib.parse import parse_qsl, unquote


EXPECTED_NAME = "daily-checkin-builder"
REQUIRED_REFERENCES = (
    "references/intake.md",
    "references/cookie-acquisition.md",
    "references/site-analysis.md",
    "references/camofox-human-handoff.md",
    "references/implementation-contract.md",
    "references/github-actions.md",
    "references/qinglong.md",
    "references/security.md",
    "references/testing.md",
)
REQUIRED_AGENT_FILE = "agents/openai.yaml"
TEMPLATE_DIRECTORY = "assets/templates"
BUNDLED_PROJECTS = (
    ("assets/templates/python-checkin", "template"),
    ("examples/fictional-checkin", "generated"),
)
TRIGGER_VALIDATOR = "scripts/validate_trigger_metadata.py"
VALIDATOR_SELF_TEST = "scripts/test_validators.py"

MARKDOWN_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
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
CURL_USER_RE = re.compile(
    r"(?i)(?:-u|--user)(?:\s*=\s*|\s+)(?:\$?[\"']([^\"']+)[\"']|([^\s]+))"
)
CURL_DATA_RE = re.compile(
    r"(?i)(?<!\S)(?:-d|--data(?:-raw|-binary|-urlencode)?)(?:\s*=\s*|\s+)(?:\$?[\"']([^\"']*)[\"']|([^\s]+))"
)
RAW_AUTH_HEADER_RE = re.compile(
    r"(?i)[\"']?authorization[\"']?\s*:\s*(?:[frbu]*[\"'])?(?:bearer|basic)\s+([^\s\"'\\,;]+)"
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

# These signatures are sufficiently specific to be useful even when a value is
# not assigned to an obviously sensitive variable.
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

TEXT_SUFFIXES = {
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
    ".log",
    ".md",
    ".mjs",
    ".pem",
    ".key",
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
        description="Validate the daily-checkin-builder skill folder."
    )
    parser.add_argument(
        "path",
        type=Path,
        help="Path to the skill folder (or directly to its SKILL.md)",
    )
    return parser.parse_args(argv)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig")


def normalize_root(path: Path) -> Path:
    candidate = path.expanduser()
    if candidate.is_file() and candidate.name == "SKILL.md":
        candidate = candidate.parent
    return candidate.resolve()


def parse_front_matter(text: str) -> tuple[dict[str, str], list[str]]:
    """Parse the deliberately small YAML subset allowed for skill metadata."""

    errors: list[str] = []
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, ["SKILL.md must start with a YAML '---' delimiter"]

    try:
        closing = next(i for i in range(1, len(lines)) if lines[i].strip() == "---")
    except StopIteration:
        return {}, ["YAML front matter is missing its closing '---' delimiter"]

    metadata: dict[str, str] = {}
    raw = lines[1:closing]
    index = 0
    while index < len(raw):
        line = raw[index]
        if not line.strip() or line.lstrip().startswith("#"):
            index += 1
            continue
        if line[:1].isspace():
            errors.append(f"unexpected indentation on front-matter line {index + 2}")
            index += 1
            continue

        match = re.match(r"^([A-Za-z][A-Za-z0-9_-]*)\s*:\s*(.*)$", line)
        if not match:
            errors.append(f"invalid YAML mapping on front-matter line {index + 2}")
            index += 1
            continue

        key, value = match.group(1), match.group(2).strip()
        if key in metadata:
            errors.append(f"duplicate front-matter key: {key}")

        if value in {"|", ">", "|-", ">-", "|+", ">+"}:
            block: list[str] = []
            index += 1
            while index < len(raw) and (not raw[index].strip() or raw[index][:1].isspace()):
                block.append(raw[index].strip())
                index += 1
            separator = "\n" if value.startswith("|") else " "
            metadata[key] = separator.join(part for part in block if part).strip()
            continue

        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            quote = value[0]
            value = value[1:-1]
            if quote == "'":
                value = value.replace("''", "'")
            else:
                value = value.replace(r'\"', '"').replace(r"\\", "\\")
        metadata[key] = value.strip()
        index += 1

    if closing == len(lines) - 1:
        errors.append("SKILL.md has no instruction body after front matter")
    return metadata, errors


def is_external_link(target: str) -> bool:
    lowered = target.lower()
    return (
        not target
        or target.startswith("#")
        or lowered.startswith(("http://", "https://", "mailto:", "data:", "tel:"))
    )


def link_target(raw_target: str) -> str:
    target = raw_target.strip()
    if target.startswith("<") and ">" in target:
        target = target[1 : target.index(">")]
    else:
        # Optional Markdown titles follow the target after whitespace.
        target = re.split(r"\s+[\"']", target, maxsplit=1)[0]
    return unquote(target.split("#", 1)[0].split("?", 1)[0]).strip()


def internal_links(root: Path) -> tuple[list[Finding], set[Path]]:
    findings: list[Finding] = []
    skill_targets: set[Path] = set()
    for markdown in sorted(root.rglob("*.md")):
        try:
            text = read_text(markdown)
        except (OSError, UnicodeError) as exc:
            findings.append(Finding(markdown, 0, f"cannot read Markdown: {exc}"))
            continue

        # Links inside fenced code are examples, not navigational links.
        visible = re.sub(r"```.*?```|~~~.*?~~~", "", text, flags=re.DOTALL)
        for match in MARKDOWN_LINK_RE.finditer(visible):
            target = link_target(match.group(1))
            if is_external_link(target):
                continue
            if not target:
                continue
            destination = (markdown.parent / target).resolve()
            line = visible.count("\n", 0, match.start()) + 1
            try:
                destination.relative_to(root)
            except ValueError:
                findings.append(Finding(markdown, line, f"link escapes skill folder: {target}"))
                continue
            if not destination.exists():
                findings.append(Finding(markdown, line, f"missing link target: {target}"))
            if markdown.name == "SKILL.md":
                skill_targets.add(destination)
    return findings, skill_targets


def iter_text_files(root: Path) -> Iterable[Path]:
    ignored_dirs = {".git", "__pycache__", ".pytest_cache", ".mypy_cache"}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in ignored_dirs for part in path.parts):
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
    # Obvious-secret validation intentionally favors precision. Short or plain
    # words are too ambiguous to report as leaked credentials.
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
            if len(raw) > 2_000_000:
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
    # A line may match both the signature and assignment checks. Keep output concise.
    return list(dict.fromkeys(findings))


def relative_findings(root: Path, findings: Iterable[Finding]) -> str:
    rendered: list[str] = []
    for finding in findings:
        try:
            name = finding.path.relative_to(root).as_posix()
        except ValueError:
            name = str(finding.path)
        location = f"{name}:{finding.line}" if finding.line else name
        rendered.append(f"{location}: {finding.message}")
    return "; ".join(rendered)


def validate_bundled_project(root: Path, relative: str, mode: str) -> tuple[bool, str]:
    validator = Path(__file__).resolve().with_name("validate_generated_project.py")
    project = root / relative
    if not validator.is_file() or not project.is_dir():
        return False, f"missing validator or bundled project: {relative}"
    try:
        child_env = {
            key: os.environ[key]
            for key in ("COMSPEC", "PATH", "PATHEXT", "SYSTEMROOT", "TEMP", "TMP", "WINDIR")
            if key in os.environ
        }
        child_env["PYTHONIOENCODING"] = "utf-8"
        completed = subprocess.run(
            [sys.executable, str(validator), str(project), "--mode", mode],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env=child_env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"could not run generated-project validator: {type(exc).__name__}"
    if completed.returncode == 0:
        return True, relative
    output = " ".join(
        line.strip()
        for line in (completed.stdout + "\n" + completed.stderr).splitlines()
        if line.strip()
    )
    return False, (output[-800:] or f"validator exited {completed.returncode}")


def validate_trigger_metadata(root: Path) -> tuple[bool, str]:
    validator = root / TRIGGER_VALIDATOR
    if not validator.is_file():
        return False, f"missing validator: {TRIGGER_VALIDATOR}"
    try:
        child_env = {
            key: os.environ[key]
            for key in ("COMSPEC", "PATH", "PATHEXT", "SYSTEMROOT", "TEMP", "TMP", "WINDIR")
            if key in os.environ
        }
        child_env["PYTHONIOENCODING"] = "utf-8"
        completed = subprocess.run(
            [sys.executable, str(validator), str(root)],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
            env=child_env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"could not run trigger validator: {type(exc).__name__}"
    if completed.returncode == 0:
        final_line = next(
            (line.strip() for line in reversed(completed.stdout.splitlines()) if line.strip()),
            "trigger cases passed",
        )
        return True, final_line
    output = " ".join(
        line.strip()
        for line in (completed.stdout + "\n" + completed.stderr).splitlines()
        if line.strip()
    )
    return False, (output[-1200:] or f"validator exited {completed.returncode}")


def validate_validator_mutations(root: Path) -> tuple[bool, str]:
    validator = root / VALIDATOR_SELF_TEST
    if not validator.is_file():
        return False, f"missing validator self-test: {VALIDATOR_SELF_TEST}"
    try:
        child_env = {
            key: os.environ[key]
            for key in ("COMSPEC", "PATH", "PATHEXT", "SYSTEMROOT", "TEMP", "TMP", "WINDIR")
            if key in os.environ
        }
        child_env["PYTHONIOENCODING"] = "utf-8"
        completed = subprocess.run(
            [sys.executable, str(validator)],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
            env=child_env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"could not run validator self-test: {type(exc).__name__}"
    if completed.returncode == 0:
        final_line = next(
            (line.strip() for line in reversed(completed.stdout.splitlines()) if line.strip()),
            "validator mutations passed",
        )
        return True, final_line
    output = " ".join(
        line.strip()
        for line in (completed.stdout + "\n" + completed.stderr).splitlines()
        if line.strip()
    )
    return False, (output[-1600:] or f"validator self-test exited {completed.returncode}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    root = normalize_root(args.path)
    reporter = Reporter()

    if not root.is_dir():
        reporter.check("skill directory", False, f"not a directory: {root}")
        print("\nValidation failed (1 check failed).")
        return 1
    reporter.check("skill directory", True, str(root))

    skill_file = root / "SKILL.md"
    if not skill_file.is_file():
        reporter.check("SKILL.md", False, "file is missing")
        print(f"\nValidation failed ({reporter.failures} check failed).")
        return 1

    try:
        skill_text = read_text(skill_file)
    except (OSError, UnicodeError) as exc:
        reporter.check("SKILL.md", False, f"cannot read UTF-8 text: {exc}")
        print(f"\nValidation failed ({reporter.failures} check failed).")
        return 1

    metadata, yaml_errors = parse_front_matter(skill_text)
    keys_ok = set(metadata) == {"name", "description"}
    yaml_detail_parts = list(yaml_errors)
    if not keys_ok:
        yaml_detail_parts.append(
            "front matter must contain only name and description "
            f"(found: {', '.join(sorted(metadata)) or 'none'})"
        )
    reporter.check(
        "YAML front matter",
        not yaml_errors and keys_ok,
        "; ".join(yaml_detail_parts),
    )

    actual_name = metadata.get("name", "")
    reporter.check(
        "skill name",
        actual_name == EXPECTED_NAME,
        f"expected {EXPECTED_NAME!r}, found {actual_name!r}",
    )

    description = metadata.get("description", "").strip()
    description_ok = bool(description) and not TODO_RE.search(description)
    reporter.check(
        "trigger description",
        description_ok,
        "description is empty or still contains a TODO" if not description_ok else "",
    )
    lowered_description = description.casefold()
    domain_terms = (
        "daily check-in",
        "daily checkin",
        "check-in automation",
        "签到",
    )
    applicable_cues = (
        "use when",
        "when the user",
        "use for",
        "applies to",
        "经授权",
        "for authorized",
        "authorized daily",
        "适用",
        "用于",
        "当用户",
    )
    forbidden_terms = (
        "do not use",
        "not for",
        "must not",
        "prohibit",
        "forbid",
        "refuse",
        "unauthorized",
        "without authorization",
        "bypass",
        "禁止",
        "不得",
        "不适用",
        "未经授权",
        "绕过",
        "拒绝",
    )
    has_applicable = (
        any(term in lowered_description for term in domain_terms)
        and any(term in lowered_description for term in applicable_cues)
    )
    has_forbidden = any(term in lowered_description for term in forbidden_terms)
    reporter.check(
        "description applicability and prohibition semantics",
        has_applicable and has_forbidden,
        f"applicability={has_applicable}, prohibition={has_forbidden}",
    )

    missing_refs = [item for item in REQUIRED_REFERENCES if not (root / item).is_file()]
    empty_refs = [
        item
        for item in REQUIRED_REFERENCES
        if (root / item).is_file() and (root / item).stat().st_size == 0
    ]
    refs_ok = not missing_refs and not empty_refs
    ref_detail: list[str] = []
    if missing_refs:
        ref_detail.append("missing: " + ", ".join(missing_refs))
    if empty_refs:
        ref_detail.append("empty: " + ", ".join(empty_refs))
    reporter.check("required reference files", refs_ok, "; ".join(ref_detail))

    handoff_path = root / "references/camofox-human-handoff.md"
    handoff_terms = (
        "$camofox-browser",
        "当前说明",
        "noVNC",
        "临时敏感",
        "等待用户明确确认",
        "UNSUPPORTED_SECURITY_CHALLENGE",
        "不得启用代理轮换",
    )
    missing_handoff_terms: list[str] = []
    try:
        handoff_text = read_text(handoff_path) if handoff_path.is_file() else ""
        missing_handoff_terms.extend(term for term in handoff_terms if term not in handoff_text)
        for term in ("$camofox-browser", "noVNC", "references/camofox-human-handoff.md"):
            if term not in skill_text:
                missing_handoff_terms.append(f"SKILL.md:{term}")
    except (OSError, UnicodeError) as exc:
        missing_handoff_terms.append(f"cannot read handoff reference: {exc}")
    reporter.check(
        "CamoFox human-handoff contract",
        not missing_handoff_terms,
        "missing: " + ", ".join(missing_handoff_terms) if missing_handoff_terms else "",
    )

    cookie_path = root / "references/cookie-acquisition.md"
    cookie_terms = (
        "docs/cookie-setup.md",
        "interactive_login",
        "network",
        "console",
        "not_applicable",
        "Set-Cookie",
        "HttpOnly",
        "青龙",
        "标准输入",
        "不是交付给所有网站共用",
    )
    missing_cookie_terms: list[str] = []
    try:
        cookie_text = read_text(cookie_path) if cookie_path.is_file() else ""
        missing_cookie_terms.extend(term for term in cookie_terms if term not in cookie_text)
        if "references/cookie-acquisition.md" not in skill_text:
            missing_cookie_terms.append("SKILL.md:references/cookie-acquisition.md")
    except (OSError, UnicodeError) as exc:
        missing_cookie_terms.append(f"cannot read cookie acquisition reference: {exc}")
    reporter.check(
        "Cookie acquisition contract",
        not missing_cookie_terms,
        "missing: " + ", ".join(missing_cookie_terms) if missing_cookie_terms else "",
    )

    agent_file = root / REQUIRED_AGENT_FILE
    agent_ok = agent_file.is_file() and agent_file.stat().st_size > 0
    agent_detail = ""
    if agent_ok:
        try:
            agent_text = read_text(agent_file)
            required_agent_keys = ("display_name:", "short_description:", "default_prompt:")
            missing_agent_keys = [key[:-1] for key in required_agent_keys if key not in agent_text]
            if missing_agent_keys or f"${EXPECTED_NAME}" not in agent_text:
                agent_ok = False
                agent_detail = "missing interface metadata or skill invocation"
        except (OSError, UnicodeError) as exc:
            agent_ok = False
            agent_detail = f"cannot read UTF-8 text: {exc}"
    else:
        agent_detail = "agents/openai.yaml is missing or empty"
    reporter.check("agents/openai.yaml", agent_ok, agent_detail)

    template_dir = root / TEMPLATE_DIRECTORY
    template_files = (
        [path for path in template_dir.rglob("*") if path.is_file()]
        if template_dir.is_dir()
        else []
    )
    substantive_templates = [
        path for path in template_files if path.name != ".gitkeep" and path.stat().st_size > 0
    ]
    reporter.check(
        "reusable templates",
        bool(substantive_templates),
        "assets/templates is missing or has no substantive files"
        if not substantive_templates
        else f"{len(substantive_templates)} substantive file(s)",
    )

    todo_findings: list[Finding] = []
    for path in iter_text_files(root):
        try:
            text = read_text(path)
        except (OSError, UnicodeError) as exc:
            todo_findings.append(Finding(path, 0, f"cannot read UTF-8 text: {exc}"))
            continue
        match = TODO_RE.search(text)
        if match:
            todo_findings.append(
                Finding(path, text.count("\n", 0, match.start()) + 1, "unfinished TODO placeholder")
            )
    reporter.check(
        "no unfinished placeholders",
        not todo_findings,
        relative_findings(root, todo_findings),
    )

    link_findings, skill_targets = internal_links(root)
    reporter.check(
        "internal Markdown links",
        not link_findings,
        relative_findings(root, link_findings),
    )
    unlinked_refs = [
        item for item in REQUIRED_REFERENCES if (root / item).resolve() not in skill_targets
    ]
    reporter.check(
        "SKILL.md reference navigation",
        not unlinked_refs,
        "not linked from SKILL.md: " + ", ".join(unlinked_refs) if unlinked_refs else "",
    )

    routing_ok, routing_detail = validate_trigger_metadata(root)
    reporter.check("trigger metadata heuristic", routing_ok, routing_detail)

    mutations_ok, mutations_detail = validate_validator_mutations(root)
    reporter.check("validator negative mutations", mutations_ok, mutations_detail)

    for relative, mode in BUNDLED_PROJECTS:
        bundled_ok, bundled_detail = validate_bundled_project(root, relative, mode)
        reporter.check(
            f"bundled project contract ({Path(relative).name}, {mode})",
            bundled_ok,
            bundled_detail,
        )

    secrets = secret_findings(root)
    reporter.check(
        "no obvious embedded secrets",
        not secrets,
        relative_findings(root, secrets),
    )

    if reporter.failures:
        noun = "check" if reporter.failures == 1 else "checks"
        print(f"\nValidation failed ({reporter.failures} {noun} failed).")
        return 1
    print("\nValidation passed (all checks passed).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
