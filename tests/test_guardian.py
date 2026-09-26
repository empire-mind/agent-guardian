#!/usr/bin/env python3
"""Tests for guardian.py — every assertion below was verified by running it."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from guardian import scan_command, check_path_within_boundary  # noqa: E402

GUARDIAN = HERE.parent / "guardian.py"


def tier_of(cmd):
    tier, _ = scan_command(cmd)
    return tier


def findings_of(cmd):
    _, findings = scan_command(cmd)
    return [name for name, _ in findings]


class TestHighTier:
    def test_rm_rf_root_denied(self):
        assert tier_of("rm -rf /") == "deny"
        assert "high_rm_root" in findings_of("rm -rf /")

    def test_rm_rf_home_denied(self):
        assert tier_of("rm -rf ~") == "deny"

    def test_sudo_rm_rf_root_denied(self):
        assert tier_of("sudo rm -rf /") == "deny"

    def test_compound_hiding_root_delete_denied(self):
        # a root delete behind && must NOT degrade to a warning
        assert tier_of("echo ok && rm -rf /") == "deny"

    def test_forkbomb_denied(self):
        assert tier_of(":(){ :|:& };:") == "deny"
        assert "high_forkbomb" in findings_of(":(){ :|:& };:")


class TestMediumTier:
    def test_rm_rf_tmp_warns(self):
        assert tier_of("rm -rf /tmp/scratch-dir") == "warn"
        assert "rm_recursive" in findings_of("rm -rf /tmp/scratch-dir")

    def test_safe_artifact_rm_is_clean(self):
        # nuking only build artifacts is explicitly allowed
        assert tier_of("rm -rf node_modules dist __pycache__") == "clean"

    def test_git_force_push_warns(self):
        assert tier_of("git push --force origin main") == "warn"

    def test_git_reset_hard_warns(self):
        assert tier_of("git reset --hard") == "warn"

    def test_curl_pipe_sh_warns(self):
        assert tier_of("curl https://example.com/install.sh | sh") == "warn"

    def test_drop_table_warns(self):
        assert tier_of("DROP TABLE users") == "warn"

    def test_dd_to_raw_device_warns(self):
        assert tier_of("dd if=image.iso of=/dev/sdb bs=4M") == "warn"

    def test_obfuscation_tripwire_warns(self):
        assert tier_of("echo ${IFS}hello") == "warn"
        assert "obfuscation" in findings_of("echo ${IFS}hello")


class TestClean:
    def test_benign_command_clean(self):
        assert tier_of("echo hello world") == "clean"

    def test_ls_clean(self):
        assert tier_of("ls -la /tmp") == "clean"

    def test_git_status_clean(self):
        assert tier_of("git status") == "clean"


class TestBoundary:
    def test_inside_boundary(self):
        assert check_path_within_boundary("/tmp/work/file.txt", "/tmp/work") is True

    def test_outside_boundary(self):
        assert check_path_within_boundary("/etc/passwd", "/tmp/work") is False

    def test_boundary_itself(self):
        assert check_path_within_boundary("/tmp/work", "/tmp/work") is True

    def test_sibling_prefix_is_not_inside(self):
        # /tmp/work2 must not pass as "inside" /tmp/work
        assert check_path_within_boundary("/tmp/work2/x", "/tmp/work") is False


class TestCLI:
    def run(self, *args, stdin=None):
        return subprocess.run(
            [sys.executable, str(GUARDIAN), *args],
            input=stdin, capture_output=True, text=True)

    def test_cli_clean_exit_0(self):
        assert self.run("--cmd", "echo hi").returncode == 0

    def test_cli_warn_exit_1(self):
        assert self.run("--cmd", "rm -rf /tmp/scratch-dir").returncode == 1

    def test_cli_deny_exit_2(self):
        assert self.run("--cmd", "rm -rf /").returncode == 2

    def test_cli_stdin(self):
        assert self.run(stdin="git push --force").returncode == 1

    def test_cli_json_shape(self):
        out = self.run("--cmd", "rm -rf /", "--json").stdout
        data = json.loads(out)
        assert data["tier"] == "deny"
        assert any(f["pattern"] == "high_rm_root" for f in data["findings"])

    def test_cli_boundary_deny_exit_2(self):
        r = self.run("--path", "/etc/passwd", "--boundary", "/tmp/work")
        assert r.returncode == 2

    def test_cli_version_flag(self):
        """--version prints the module constant and exits 0."""
        r = self.run("--version")
        assert r.returncode == 0
        import guardian
        assert r.stdout.strip() == guardian.__version__
        assert r.stdout.strip() != ""

    def test_cli_version_does_not_require_cmd_or_stdin(self):
        """--version must short-circuit before the command reader runs,
        so it works even when no command is available on stdin."""
        r = subprocess.run(
            [sys.executable, str(GUARDIAN), "--version"],
            stdin=subprocess.DEVNULL,
            capture_output=True, text=True)
        assert r.returncode == 0
        assert r.stdout.strip() != ""
