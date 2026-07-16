#!/usr/bin/env python3
"""Negative mutation tests for the generated-project validator.

Each case edits only a temporary copy of the bundled Python template. The
validator must reject every mutation with the expected content-level finding.
No network access or credentials are used.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "assets" / "templates" / "python-checkin"
VALIDATOR = ROOT / "scripts" / "validate_generated_project.py"


def child_environment() -> dict[str, str]:
    env = {
        key: os.environ[key]
        for key in ("COMSPEC", "PATH", "PATHEXT", "SYSTEMROOT", "TEMP", "TMP", "WINDIR")
        if key in os.environ
    }
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def run_validator(project: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VALIDATOR), str(project)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=child_environment(),
    )


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise AssertionError(f"expected exactly one mutation target in {path}: {old!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def remove_site_analysis(project: Path) -> None:
    (project / "docs" / "site-analysis.md").unlink()


def remove_schedule_timezone(project: Path) -> None:
    workflow = project / ".github" / "workflows" / "daily-checkin.yml"
    replace_once(workflow, '      timezone: "Asia/Shanghai"\n', "")


def add_guessed_endpoint(project: Path) -> None:
    config = project / "src" / "checkin" / "config.py"
    replace_once(
        config,
        'env.get("CHECKIN_STATUS_PATH", "").strip()',
        'env.get("CHECKIN_STATUS_PATH", "/api/guessed-status").strip()',
    )


def break_python_syntax(project: Path) -> None:
    config = project / "src" / "checkin" / "config.py"
    with config.open("a", encoding="utf-8", newline="") as handle:
        handle.write("\ndef invalid_syntax(:\n")


def erase_qinglong_substance(project: Path) -> None:
    deployment = project / "DEPLOY_QINGLONG.md"
    deployment.write_text(
        "# QingLong\n\nTask: `python3 run.py`\n\nCron: `17 7 * * *`\n",
        encoding="utf-8",
    )


def remove_auth_expired_test(project: Path) -> None:
    test_file = project / "tests" / "test_checkin.py"
    text = test_file.read_text(encoding="utf-8")
    if "AUTH_EXPIRED" not in text:
        raise AssertionError("AUTH_EXPIRED test evidence is missing before mutation")
    test_file.write_text(text.replace("AUTH_EXPIRED", "AUTH_REMOVED"), encoding="utf-8")


def main() -> int:
    if not TEMPLATE.is_dir() or not VALIDATOR.is_file():
        print("[FAIL] validator fixtures are missing", file=sys.stderr)
        return 1

    cases: tuple[tuple[str, Callable[[Path], None], str], ...] = (
        ("missing site analysis", remove_site_analysis, "docs/site-analysis.md is missing or empty"),
        (
            "missing per-schedule timezone",
            remove_schedule_timezone,
            "each cron schedule item must include its own literal IANA Area/Location timezone",
        ),
        ("guessed runtime endpoint", add_guessed_endpoint, "runtime supplies an invented default endpoint path"),
        ("invalid Python syntax", break_python_syntax, "invalid Python"),
        ("hollow QingLong guide", erase_qinglong_substance, "QingLong deployment lacks"),
        ("missing auth-expired test", remove_auth_expired_test, "tests lack state assertion for AUTH_EXPIRED"),
    )

    failures = 0
    with tempfile.TemporaryDirectory(prefix="daily-checkin-validator-tests-") as temp:
        temp_root = Path(temp)
        baseline = temp_root / "baseline"
        shutil.copytree(TEMPLATE, baseline)
        baseline_result = run_validator(baseline)
        if baseline_result.returncode != 0:
            print("[FAIL] baseline template was rejected", file=sys.stderr)
            print(baseline_result.stdout, file=sys.stderr)
            print(baseline_result.stderr, file=sys.stderr)
            return 1
        print("[PASS] baseline template accepted")

        for index, (name, mutate, expected) in enumerate(cases, start=1):
            project = temp_root / f"mutation-{index}"
            shutil.copytree(TEMPLATE, project)
            mutate(project)
            result = run_validator(project)
            output = result.stdout + "\n" + result.stderr
            passed = result.returncode != 0 and expected in output
            if passed:
                print(f"[PASS] {name}: rejected with content finding")
            else:
                failures += 1
                print(
                    f"[FAIL] {name}: returncode={result.returncode}, expected={expected!r}",
                    file=sys.stderr,
                )
                print(output[-2000:], file=sys.stderr)

    if failures:
        print(f"\nValidator mutation tests failed ({failures} case(s)).", file=sys.stderr)
        return 1
    print(f"\nValidator mutation tests passed ({len(cases)} rejected mutations).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
