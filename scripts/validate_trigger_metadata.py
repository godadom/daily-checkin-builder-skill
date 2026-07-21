#!/usr/bin/env python3
"""Execute deterministic positive, refusal, and non-trigger metadata checks."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RoutingCase:
    case_id: str
    prompt: str
    expected: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Heuristically validate daily-checkin-builder trigger metadata cases.")
    parser.add_argument("path", type=Path, help="Skill root")
    return parser.parse_args()


def frontmatter_description(skill_text: str) -> str:
    match = re.search(r'(?ms)^---\s*\n.*?^description:\s*(["\'])(.*?)\1\s*\n---\s*$', skill_text)
    return match.group(2).strip() if match else ""


def parse_cases(markdown: str) -> list[RoutingCase]:
    cases: list[RoutingCase] = []
    for line in markdown.splitlines():
        if not re.match(r"^\|\s*[PN]\d+\s*\|", line):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 3:
            raise ValueError(f"routing row must have exactly three columns: {line}")
        case_id, prompt, expected_text = cells
        prompt = prompt.strip("“”\"")
        lowered = expected_text.casefold()
        if lowered.startswith("invoke"):
            expected = "INVOKE"
        elif lowered.startswith("refuse"):
            expected = "REFUSE"
        elif lowered.startswith("do not invoke"):
            expected = "DO_NOT_INVOKE"
        else:
            raise ValueError(f"unknown expected routing for {case_id}: {expected_text}")
        cases.append(RoutingCase(case_id, prompt, expected))
    return cases


def route_prompt(prompt: str) -> str:
    """Apply a deterministic heuristic to regression-check trigger metadata."""

    lowered = prompt.casefold()
    prohibited = (
        "bypass", "farm rewards", "other users' session", "other users’ session",
        "mass-register", "credential theft", "steal cookie", "绕过", "刷奖励",
        "批量注册", "窃取", "撞库",
    )
    if any(term in lowered for term in prohibited):
        return "REFUSE"

    checkin_terms = ("check-in", "checkin", "daily claim", "每日签到", "签到", "签到接口", "签到脚本")
    supported_work = (
        "sanitized", "cURL", "har", "cookie", "csrf", "token", "script",
        "automation", "automate", "github actions", "qinglong", "repair",
        "convert", "build", "camofox", "noVNC", "接口", "脚本", "自动化",
        "修复", "青龙", "脱敏",
    )
    ordinary_only = (
        "summarize", "summary", "redesign", "ordinary ui", "public webpage",
        "news page", "price monitor", "generic ci", "generic api", "网页总结",
        "普通网页", "ui 开发", "通用 ci", "通用 api",
    )
    if any(term in lowered for term in ordinary_only) and not any(
        term in lowered for term in ("automation", "automate", "script", "cookie", "csrf", "har", "cURL", "签到接口", "签到脚本")
    ):
        return "DO_NOT_INVOKE"
    if any(term in lowered for term in checkin_terms) and any(term.casefold() in lowered for term in supported_work):
        return "INVOKE"
    return "DO_NOT_INVOKE"


def description_findings(description: str) -> list[str]:
    requirements = {
        "authorization": ("授权",),
        "check-in scope": ("签到",),
        "sanitization": ("脱敏",),
        "evidence inputs": ("har", "copy as curl", "请求头", "接口响应", "已有脚本"),
        "Python generation": ("python 3",),
        "deployment": ("github actions", "青龙", "本地"),
        "existing Node repair": ("提供 node.js", "已有 node.js"),
        "no new Node projects": ("不从零生成 node.js",),
        "ordinary web exclusions": ("普通网页分析", "网页总结"),
        "generic work exclusions": ("通用 api", "通用 ci"),
        "security refusal": ("未授权", "凭据窃取", "安全挑战绕过"),
    }
    lowered = description.casefold()
    findings: list[str] = []
    for label, alternatives in requirements.items():
        if not any(term.casefold() in lowered for term in alternatives):
            findings.append(f"{label} missing: {' or '.join(alternatives)}")
    return findings


def main() -> int:
    root = parse_args().path.resolve()
    try:
        skill_text = (root / "SKILL.md").read_text(encoding="utf-8-sig")
        routing_text = (root / "examples" / "trigger-routing.md").read_text(encoding="utf-8-sig")
        cases = parse_cases(routing_text)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"[FAIL] trigger routing inputs - {exc}")
        return 1

    failures = description_findings(frontmatter_description(skill_text))
    if len(cases) < 10:
        failures.append("routing corpus must contain at least 10 cases")
    if not any(case.expected == "INVOKE" for case in cases):
        failures.append("routing corpus has no positive cases")
    if not any(case.expected == "REFUSE" for case in cases):
        failures.append("routing corpus has no refusal cases")
    if not any(case.expected == "DO_NOT_INVOKE" for case in cases):
        failures.append("routing corpus has no non-trigger cases")

    for case in cases:
        actual = route_prompt(case.prompt)
        status = "PASS" if actual == case.expected else "FAIL"
        print(f"[{status}] {case.case_id}: expected={case.expected} actual={actual}")
        if actual != case.expected:
            failures.append(f"{case.case_id} expected {case.expected}, got {actual}")

    for finding in failures:
        print(f"[FAIL] {finding}")
    if failures:
        print(f"\nTrigger metadata validation failed ({len(failures)} issue(s)).")
        return 1
    print(f"\nTrigger metadata validation passed ({len(cases)} cases).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
