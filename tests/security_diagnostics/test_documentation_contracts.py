from __future__ import annotations

import inspect
import subprocess
import sys
from pathlib import Path

from traceseed import TraceSeedConfig, guard


ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "README.md"


def test_documented_guard_keyword_exists_in_public_signature():
    text = README.read_text(encoding="utf-8")
    if "with guard(" in text and "metadata={" in text:
        assert "metadata" in inspect.signature(guard).parameters


def test_documented_configuration_fields_exist():
    text = README.read_text(encoding="utf-8")
    available = set(TraceSeedConfig.__dataclass_fields__)
    for field_name in ("capture_arguments", "capture_threads"):
        if f"{field_name}=" in text:
            assert field_name in available, f"README documents unknown config field {field_name!r}"


def test_documented_replay_authorization_flag_exists_in_cli_help():
    text = README.read_text(encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "traceseed", "replay", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    help_text = result.stdout + result.stderr
    if "--allow-code-execution" in text:
        assert "--allow-code-execution" in help_text
    if "traceseed replay" in text and " --allow" in text:
        assert "--allow" in help_text


def test_readme_security_test_claim_has_runnable_ci_workflow():
    text = README.read_text(encoding="utf-8")
    if "regression tests" not in text:
        return
    workflows = list((ROOT / ".github" / "workflows").glob("*.yml")) + list(
        (ROOT / ".github" / "workflows").glob("*.yaml")
    )
    assert workflows
    workflow_text = "\n".join(path.read_text(encoding="utf-8") for path in workflows)
    assert "pytest" in workflow_text
