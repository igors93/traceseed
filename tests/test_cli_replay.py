import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from traceseed import TraceSeedConfig, capture_exception
from traceseed.cli import main
from traceseed.errors import ReplayError
from traceseed.models import CallableInfo
from traceseed.replay import ReplayRunner
from traceseed.serialization import SafeSerializer
from traceseed.storage import ArchiveStorage


class CliReplayTests(unittest.TestCase):
    def create_package(self, directory, *, replay=False, args=(1, 0), kwargs=None):
        config = TraceSeedConfig(output_directory=directory)
        storage = ArchiveStorage(config, SafeSerializer(config))
        try:
            raise ZeroDivisionError("division by zero")
        except ZeroDivisionError as error:
            return capture_exception(
                error,
                operation="divide",
                callable_info=CallableInfo("tests.replay_targets", "divide", replay),
                replay_arguments=args if replay else None,
                replay_keyword_arguments=kwargs or {} if replay else None,
                config=config,
                storage=storage,
                strict=True,
            )

    def test_show_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.create_package(tmp)
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["show", result.location])
            self.assertEqual(code, 0)
            self.assertIn("ZeroDivisionError", output.getvalue())

    def test_show_json_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.create_package(tmp)
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["show", result.location, "--json"])
            self.assertEqual(code, 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["operation"], "divide")

    def test_verify_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.create_package(tmp)
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["verify", result.location])
            self.assertEqual(code, 0)
            self.assertIn("OK:", output.getvalue())

    def test_list_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.create_package(tmp)
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["list", tmp])
            self.assertEqual(code, 0)
            self.assertIn(Path(result.location).name, output.getvalue())

    def test_list_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["list", tmp])
            self.assertEqual(code, 0)
            self.assertIn("No .tseed", output.getvalue())

    def test_compare_same_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self.create_package(tmp)
            second = self.create_package(tmp)
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["compare", first.location, second.location])
            self.assertEqual(code, 0)
            self.assertIn("Same fingerprint: yes", output.getvalue())

    def test_invalid_package_returns_error_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.tseed"
            path.write_text("bad")
            error = io.StringIO()
            with redirect_stderr(error):
                code = main(["show", str(path)])
            self.assertEqual(code, 1)
            self.assertIn("traceseed:", error.getvalue())

    def test_replay_requires_explicit_permission(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.create_package(tmp, replay=True)
            with self.assertRaises(ReplayError):
                ReplayRunner().run(result.location)

    def test_replay_reproduces_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.create_package(tmp, replay=True)
            with self.assertRaises(ZeroDivisionError):
                ReplayRunner().run(result.location, allow_code_execution=True)

    def test_replay_successful_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = TraceSeedConfig(output_directory=tmp)
            storage = ArchiveStorage(config, SafeSerializer(config))
            error = RuntimeError("captured for replay")
            result = capture_exception(
                error,
                operation="add",
                callable_info=CallableInfo("tests.replay_targets", "add", True),
                replay_arguments=(2,),
                replay_keyword_arguments={"b": 3},
                config=config,
                storage=storage,
                strict=True,
            )
            self.assertEqual(ReplayRunner().run(result.location, allow_code_execution=True), 5)

    def test_replay_missing_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.create_package(tmp, replay=False)
            with self.assertRaises(ReplayError):
                ReplayRunner().inspect(result.location)

    def test_cli_replay_without_flag_returns_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.create_package(tmp, replay=True)
            error = io.StringIO()
            with redirect_stderr(error):
                code = main(["replay", result.location])
            self.assertEqual(code, 2)
            self.assertIn("executes application code", error.getvalue())

    def test_version(self):
        output = io.StringIO()
        with self.assertRaises(SystemExit) as raised, redirect_stdout(output):
            main(["--version"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn("0.1.0", output.getvalue())
