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
EXAMPLE = ROOT / "examples" / "fictional-checkin"
VALIDATOR = ROOT / "scripts" / "validate_generated_project.py"


def child_environment() -> dict[str, str]:
    env = {
        key: os.environ[key]
        for key in ("COMSPEC", "PATH", "PATHEXT", "SYSTEMROOT", "TEMP", "TMP", "WINDIR")
        if key in os.environ
    }
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def run_validator(project: Path, mode: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VALIDATOR), str(project), "--mode", mode],
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


def remove_cookie_setup(project: Path) -> None:
    (project / "docs" / "cookie-setup.md").unlink()


def replace_cookie_setup_with_generic_f12(project: Path) -> None:
    (project / "docs" / "cookie-setup.md").write_text(
        "# Cookie setup\n\n"
        "- Acquisition mode: `network`\n"
        "- Site and scope: target site\n"
        "- Evidence source: unspecified\n\n"
        "## Exact operator steps\n\nOpen F12 and inspect Network.\n\n"
        "## Output and transformation\n\nCopy a Cookie string.\n\n"
        "## Secret destination\n\nPut it in an environment variable.\n\n"
        "## Expiration and renewal\n\nRepeat when expired.\n",
        encoding="utf-8",
    )


def remove_schedule_timezone(project: Path) -> None:
    workflow = project / ".github" / "workflows" / "daily-checkin.yml"
    replace_once(workflow, '      timezone: "Asia/Shanghai"\n', "")


def inject_fixed_site_value_into_workflow(project: Path) -> None:
    workflow = project / ".github" / "workflows" / "daily-checkin.yml"
    replace_once(
        workflow,
        "          CHECKIN_ACCOUNTS: ${{ secrets.CHECKIN_ACCOUNTS }}\n",
        "          CHECKIN_BASE_URL: https://example.invalid\n"
        "          CHECKIN_ACCOUNTS: ${{ secrets.CHECKIN_ACCOUNTS }}\n",
    )


def add_guessed_endpoint(project: Path) -> None:
    config = project / "src" / "checkin" / "config.py"
    replace_once(
        config,
        "status_path_value = site_config.STATUS_PATH.strip()",
        'status_path_value = "/api/guessed-status"',
    )


def break_python_syntax(project: Path) -> None:
    config = project / "src" / "checkin" / "config.py"
    with config.open("a", encoding="utf-8", newline="") as handle:
        handle.write("\ndef invalid_syntax(:\n")


def break_yaml_syntax(project: Path) -> None:
    workflow = project / ".github" / "workflows" / "daily-checkin.yml"
    with workflow.open("a", encoding="utf-8", newline="") as handle:
        handle.write("\ninvalid: [unclosed\n")


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


def add_safe_workflow_variation(project: Path) -> None:
    workflow = project / ".github" / "workflows" / "daily-checkin.yml"
    replace_once(workflow, 'python-version: "3.12"', 'python-version: "3.13"')
    replace_once(
        workflow,
        "      - name: Run offline tests\n",
        "      - name: Compile Python sources\n"
        "        run: python -m compileall -q src\n"
        "      - name: Run offline tests\n",
    )


def main() -> int:
    if not TEMPLATE.is_dir() or not EXAMPLE.is_dir() or not VALIDATOR.is_file():
        print("[FAIL] validator fixtures are missing", file=sys.stderr)
        return 1

    cases: tuple[tuple[str, Callable[[Path], None], str], ...] = (
        ("missing site analysis", remove_site_analysis, "docs/site-analysis.md is missing or empty"),
        ("missing site-specific Cookie setup", remove_cookie_setup, "docs/cookie-setup.md is missing or empty"),
        (
            "missing per-schedule timezone",
            remove_schedule_timezone,
            "each cron schedule item must include its own literal IANA Area/Location timezone",
        ),
        (
            "fixed site value injected through workflow environment",
            inject_fixed_site_value_into_workflow,
            "must not inject fixed site values through environment variables",
        ),
        ("guessed runtime endpoint", add_guessed_endpoint, "runtime supplies an invented default endpoint path"),
        ("invalid Python syntax", break_python_syntax, "invalid Python"),
        ("invalid YAML syntax", break_yaml_syntax, "invalid YAML"),
        ("hollow QingLong guide", erase_qinglong_substance, "QingLong deployment lacks"),
        ("missing auth-expired test", remove_auth_expired_test, "tests lack state assertion for AUTH_EXPIRED"),
    )

    failures = 0
    with tempfile.TemporaryDirectory(prefix="daily-checkin-validator-tests-") as temp:
        temp_root = Path(temp)
        baseline = temp_root / "baseline"
        shutil.copytree(TEMPLATE, baseline)
        baseline_result = run_validator(baseline, "template")
        if baseline_result.returncode != 0:
            print("[FAIL] baseline template was rejected", file=sys.stderr)
            print(baseline_result.stdout, file=sys.stderr)
            print(baseline_result.stderr, file=sys.stderr)
            return 1
        print("[PASS] baseline template accepted")

        varied = temp_root / "safe-workflow-variation"
        shutil.copytree(TEMPLATE, varied)
        add_safe_workflow_variation(varied)
        varied_result = run_validator(varied, "template")
        if varied_result.returncode != 0:
            print("[FAIL] safe workflow variation was rejected", file=sys.stderr)
            print(varied_result.stdout, file=sys.stderr)
            return 1
        print("[PASS] safe workflow variation accepted")

        generated_baseline = run_validator(baseline, "generated")
        if generated_baseline.returncode == 0 or "site contract analysis_status" not in generated_baseline.stdout:
            print("[FAIL] generated mode accepted the scaffold template", file=sys.stderr)
            print(generated_baseline.stdout, file=sys.stderr)
            return 1
        print("[PASS] generated mode rejected the scaffold template")

        generated_example = run_validator(EXAMPLE, "generated")
        if generated_example.returncode != 0:
            print("[FAIL] site-specific fictional example was rejected", file=sys.stderr)
            print(generated_example.stdout, file=sys.stderr)
            return 1
        print("[PASS] site-specific fictional example accepted")

        generic_cookie = temp_root / "generic-cookie-setup"
        shutil.copytree(EXAMPLE, generic_cookie)
        replace_cookie_setup_with_generic_f12(generic_cookie)
        generic_cookie_result = run_validator(generic_cookie, "generated")
        generic_cookie_output = generic_cookie_result.stdout + "\n" + generic_cookie_result.stderr
        if (
            generic_cookie_result.returncode == 0
            or "Network Cookie setup lacks request method/path" not in generic_cookie_output
        ):
            print("[FAIL] generated mode accepted a generic F12 Cookie guide", file=sys.stderr)
            print(generic_cookie_output[-2000:], file=sys.stderr)
            return 1
        print("[PASS] generic F12 Cookie guide rejected with content finding")

        for index, (name, mutate, expected) in enumerate(cases, start=1):
            project = temp_root / f"mutation-{index}"
            shutil.copytree(TEMPLATE, project)
            mutate(project)
            result = run_validator(project, "template")
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
    print(f"\nValidator mutation tests passed ({len(cases) + 1} rejected mutations).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
