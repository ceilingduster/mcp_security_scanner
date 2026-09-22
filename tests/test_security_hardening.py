import tempfile
import unittest
from pathlib import Path
from unittest import mock

import server
from src import scanner as scanner_module
from src import ai_review
from src.ai_review import collect_review_candidates
from src.analyzers import _sanitize_build_log
from src.models import ScanConfig
from src.scanner import Scanner
from src.subprocess_utils import run_safe


class ScannerSecurityTests(unittest.TestCase):
    def test_allowed_remote_repo_urls(self):
        self.assertTrue(scanner_module._is_allowed_remote_repo_url("https://github.com/owner/repo"))
        self.assertTrue(scanner_module._is_allowed_remote_repo_url("https://github.com/owner/repo.git"))
        self.assertFalse(scanner_module._is_allowed_remote_repo_url("http://github.com/owner/repo"))
        self.assertFalse(scanner_module._is_allowed_remote_repo_url("https://github.com/owner/repo/tree/main"))
        self.assertFalse(scanner_module._is_allowed_remote_repo_url("https://127.0.0.1/repo"))

    def test_scan_blocks_disallowed_remote_url(self):
        scanner = Scanner(ScanConfig(skip_ai=True, cleanup_repos=True))
        result = scanner.scan("https://evil.example.com/owner/repo")
        self.assertFalse(result.clone_success)
        self.assertIn("Disallowed repository URL", result.error)

    def test_scan_rejects_unsafe_repository_name(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_dir = Path(tmpdir) / "project"
            repo_dir.mkdir()
            (repo_dir / "README.md").write_text("# demo")
            scanner = Scanner(ScanConfig(skip_ai=True, cleanup_repos=True))
            result = scanner.scan(str(repo_dir), name="..")
            self.assertFalse(result.clone_success)
            self.assertIn("Invalid repository name", result.error)

    def test_scan_rejects_subdir_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_dir = Path(tmpdir) / "project"
            repo_dir.mkdir()
            (repo_dir / "README.md").write_text("# demo")
            scanner = Scanner(ScanConfig(skip_ai=True, cleanup_repos=True))
            result = scanner.scan(str(repo_dir), subdir="../../etc")
            self.assertFalse(result.clone_success)
            self.assertIn("Invalid subdir", result.error)

    def test_scan_blocks_local_paths_when_disabled(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_dir = Path(tmpdir) / "project"
            repo_dir.mkdir()
            scanner = Scanner(ScanConfig(skip_ai=True, cleanup_repos=True, allow_local_paths=False))
            result = scanner.scan(str(repo_dir))
            self.assertFalse(result.clone_success)
            self.assertIn("Local repository paths are disabled", result.error)

    def test_build_step_is_skipped_by_default(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_dir = Path(tmpdir) / "project"
            repo_dir.mkdir()
            (repo_dir / "README.md").write_text("# demo")
            (repo_dir / "requirements.txt").write_text("requests==2.31.0")

            scanner = Scanner(ScanConfig(skip_ai=True, cleanup_repos=True))
            with (
                mock.patch("src.scanner.run_bandit", return_value={"high": 0, "medium": 0, "low": 0, "findings": []}),
                mock.patch("src.scanner.detect_secrets", return_value=[]),
                mock.patch("src.scanner.detect_tests", return_value=(True, "unittest")),
                mock.patch("src.scanner.try_build", side_effect=AssertionError("try_build should not be called")),
            ):
                result = scanner.scan(str(repo_dir))

            self.assertTrue(result.clone_success)
            self.assertFalse(result.build_attempted)
            self.assertFalse(result.build_success)
            self.assertIn("skipped", result.build_skipped_reason.lower())


class ReportPathSecurityTests(unittest.TestCase):
    def test_get_report_does_not_traverse_outside_reports_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            reports_dir = Path(tmpdir) / "reports"
            reports_dir.mkdir()
            safe_dir = reports_dir / "owner_repo"
            safe_dir.mkdir()
            (safe_dir / "SECURITY.md").write_text("safe report")

            outside = Path(tmpdir) / "outside.md"
            outside.write_text("sensitive data")

            with mock.patch.object(server, "REPORTS_DIR", reports_dir):
                traversal_response = server.get_report("../../outside")
                self.assertNotIn("sensitive data", traversal_response)
                self.assertIn("Available reports", traversal_response)
                safe_response = server.get_report("owner/repo")
                self.assertEqual("safe report", safe_response)

    def test_server_defaults_local_paths_to_disabled(self):
        with mock.patch.dict("os.environ", {}, clear=False):
            scanner = server._build_scanner()
            self.assertFalse(scanner.config.allow_local_paths)


class BuildLogSanitizationTests(unittest.TestCase):
    def test_build_log_redaction(self):
        dirty = "token=\"sk-abcdefghijklmnopqrstuvwxyz123456\"\napi_key='super-secret-value'"
        cleaned = _sanitize_build_log(dirty)
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz123456", cleaned)
        self.assertNotIn("super-secret-value", cleaned)
        self.assertIn("[REDACTED]", cleaned)


class SubprocessHardeningTests(unittest.TestCase):
    def test_run_safe_rejects_unapproved_executable(self):
        with self.assertRaises(ValueError):
            run_safe(["python", "--version"])

    def test_run_safe_uses_absolute_executable_path(self):
        with (
            mock.patch("src.subprocess_utils.shutil.which", return_value="/usr/bin/git"),
            mock.patch("src.subprocess_utils.subprocess.run") as mock_run,
        ):
            mock_run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
            run_safe(["git", "--version"], timeout=5)
            called_args = mock_run.call_args.kwargs["args"] if "args" in mock_run.call_args.kwargs else mock_run.call_args.args[0]
            self.assertEqual("/usr/bin/git", called_args[0])


class AIReviewCoverageTests(unittest.TestCase):
    def test_collect_review_candidates_prioritizes_source_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            docs = root / "docs"
            src = root / "src"
            docs.mkdir()
            src.mkdir()
            for i in range(40):
                (docs / f"note_{i}.txt").write_text("notes")
            (src / "server.py").write_text("print('hi')")
            (root / "package.json").write_text("{}")

            files = collect_review_candidates(root, max_files=200)
            self.assertIn("src/server.py", files)
            self.assertIn("package.json", files)
            self.assertNotIn("docs/note_1.txt", files)


class ClaudeCliBackendTests(unittest.TestCase):
    def _completed(self, stdout, returncode=0, stderr=""):
        return mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)

    def test_parse_json_result(self):
        out = '{"type":"result","subtype":"success","is_error":false,"result":"# Report","total_cost_usd":0.42,"num_turns":7,"duration_ms":1234}'
        report, meta = ai_review.parse_claude_cli_output(out)
        self.assertEqual("# Report", report)
        self.assertFalse(meta["is_error"])
        self.assertAlmostEqual(0.42, meta["cost_usd"])
        self.assertEqual(7, meta["num_turns"])

    def test_parse_plain_text_fallback(self):
        report, meta = ai_review.parse_claude_cli_output("just text")
        self.assertEqual("just text", report)
        self.assertEqual({}, meta)

    def test_command_is_read_only_and_ignores_repo_settings(self):
        with mock.patch.object(ai_review, "_claude_help", return_value="--tools --strict-mcp-config --setting-sources --max-turns --max-budget-usd --no-session-persistence"):
            cmd = ai_review.build_claude_cli_command("claude", "sonnet", max_turns=12, max_budget_usd=1.5, subdir="src/x")
        self.assertEqual("claude", cmd[0])
        self.assertIn("-p", cmd)
        self.assertEqual("json", cmd[cmd.index("--output-format") + 1])
        self.assertEqual(ai_review.CLAUDE_CLI_READ_ONLY_TOOLS, cmd[cmd.index("--tools") + 1])
        self.assertEqual(ai_review.CLAUDE_CLI_READ_ONLY_TOOLS, cmd[cmd.index("--allowedTools") + 1])
        self.assertIn("Bash", cmd[cmd.index("--disallowedTools") + 1])
        self.assertEqual("user", cmd[cmd.index("--setting-sources") + 1])
        self.assertIn("--strict-mcp-config", cmd)
        self.assertEqual("12", cmd[cmd.index("--max-turns") + 1])
        self.assertEqual("1.5", cmd[cmd.index("--max-budget-usd") + 1])
        self.assertIn("src/x", cmd[cmd.index("--append-system-prompt") + 1])

    def test_command_skips_flags_the_cli_lacks(self):
        with mock.patch.object(ai_review, "_claude_help", return_value=""):
            cmd = ai_review.build_claude_cli_command("claude", "sonnet", max_turns=12, max_budget_usd=1.5)
        for flag in ("--tools", "--max-turns", "--max-budget-usd", "--setting-sources", "--strict-mcp-config"):
            self.assertNotIn(flag, cmd)
        self.assertIn("--allowedTools", cmd)

    def test_run_review_success(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "server.py").write_text("print('hi')")
            out = '{"type":"result","is_error":false,"result":"# Findings - none","total_cost_usd":0.1,"num_turns":3}'
            with (
                mock.patch.object(ai_review.shutil, "which", return_value="/usr/bin/claude"),
                mock.patch.object(ai_review, "_claude_help", return_value=""),
                mock.patch.object(ai_review, "run_safe", return_value=self._completed(out)) as mock_run,
            ):
                report, meta = ai_review.run_ai_review_claude_cli("claude", "sonnet", root, root, "demo", [], ai_timeout=5)
            self.assertTrue(report.startswith("# Findings"))
            self.assertEqual(3, meta["num_turns"])
            kwargs = mock_run.call_args.kwargs
            self.assertEqual(root, kwargs["cwd"])
            self.assertIn("security code review", kwargs["input"])
            self.assertNotIn("CLAUDECODE", kwargs["env"])

    def test_run_review_reports_cli_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            out = '{"type":"result","is_error":true,"result":"API Error: 400 bad model"}'
            with (
                mock.patch.object(ai_review.shutil, "which", return_value="/usr/bin/claude"),
                mock.patch.object(ai_review, "_claude_help", return_value=""),
                mock.patch.object(ai_review, "run_safe", return_value=self._completed(out, returncode=1)),
            ):
                report, _ = ai_review.run_ai_review_claude_cli("claude", "sonnet", root, root, "demo", [], ai_timeout=5)
            self.assertTrue(report.startswith("AI review failed"))
            self.assertIn("bad model", report)

    def test_run_review_missing_binary(self):
        with mock.patch.object(ai_review.shutil, "which", return_value=None):
            report, _ = ai_review.run_ai_review_claude_cli("claude", "sonnet", Path("."), Path("."), "demo", [])
        self.assertIn("not found on PATH", report)

    def test_scanner_uses_cli_backend_without_api_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_dir = Path(tmpdir) / "project"
            repo_dir.mkdir()
            (repo_dir / "README.md").write_text("# demo")
            scanner = Scanner(ScanConfig(ai_backend="claude-cli", model="sonnet", cleanup_repos=True,
                                         reports_dir=str(Path(tmpdir) / "reports"), work_dir=str(Path(tmpdir) / "repos")))
            self.assertIsNone(scanner._client)
            with (
                mock.patch("src.scanner.run_bandit", return_value={"high": 0, "medium": 0, "low": 0, "findings": []}),
                mock.patch("src.scanner.detect_secrets", return_value=[]),
                mock.patch("src.scanner.detect_tests", return_value=(True, "pytest")),
                mock.patch("src.scanner.run_ai_review_claude_cli", return_value=("# AI report", {"cost_usd": 0.2, "num_turns": 4})) as mock_cli,
            ):
                result = scanner.scan(str(repo_dir))
            self.assertTrue(result.clone_success)
            self.assertEqual("claude-cli", result.ai_backend)
            self.assertEqual("# AI report", result.ai_review)
            self.assertEqual(4, result.ai_turns)
            self.assertAlmostEqual(0.2, result.ai_cost_usd)
            self.assertEqual("sonnet", mock_cli.call_args.kwargs["model"])
            self.assertIn("AI Security Review", result.report_path.read_text())

    def test_scanner_rejects_unknown_backend(self):
        with self.assertRaises(ValueError):
            Scanner(ScanConfig(ai_backend="bogus"))


if __name__ == "__main__":
    unittest.main()
