import asyncio
import io
import os
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr
from pathlib import Path

from traceseed import (
    TraceSeedConfig,
    MemoryStorage,
    breadcrumb,
    capture,
    capture_exception,
    clear_context,
    context,
    get_last_capture,
    guard,
    install,
    register_codec,
    register_collector,
    reset_config,
    uninstall,
    unregister_codec,
    unregister_collector,
)
from traceseed.collectors import CollectorRegistry
from traceseed.engine import CaptureEngine
from traceseed.models import CaptureContext


class FailingStorage:
    name = "broken"
    def save(self, record, extra=None):
        raise OSError("disk unavailable")


class CustomCollector:
    name = "custom"
    def collect(self, exception, context, config):
        return {"custom_value": 42}


class BrokenCollector:
    name = "broken"
    def collect(self, exception, context, config):
        raise RuntimeError("collector failed")


class CaptureTests(unittest.TestCase):
    def setUp(self):
        clear_context()
        reset_config()
        uninstall()
        unregister_collector("custom")
        unregister_collector("broken")
        unregister_codec("box")

    def tearDown(self):
        clear_context()
        reset_config()
        uninstall()
        unregister_collector("custom")
        unregister_collector("broken")
        unregister_codec("box")

    def test_capture_decorator_reraises_original(self):
        storage = MemoryStorage()

        @capture(storage=storage)
        def fail():
            raise ValueError("boom")

        with self.assertRaisesRegex(ValueError, "boom"):
            fail()
        self.assertEqual(len(storage.records), 1)

    def test_capture_decorator_preserves_metadata(self):
        @capture
        def sample(a, b=2):
            "doc"
            return a + b

        self.assertEqual(sample.__name__, "sample")
        self.assertEqual(sample.__doc__, "doc")
        self.assertEqual(sample(1), 3)

    def test_capture_arguments(self):
        storage = MemoryStorage()

        @capture(storage=storage)
        def fail(a, b=2):
            raise RuntimeError("x")

        with self.assertRaises(RuntimeError):
            fail(1, b=3)
        self.assertEqual(storage.records[0].arguments, {"a": 1, "b": 3})

    def test_sensitive_arguments_are_redacted(self):
        storage = MemoryStorage()

        @capture(storage=storage)
        def fail(username, password):
            raise RuntimeError("x")

        with self.assertRaises(RuntimeError):
            fail("igor", "super-secret")
        self.assertEqual(storage.records[0].arguments["password"], "[REDACTED]")

    def test_metadata_and_context_are_merged(self):
        storage = MemoryStorage()
        with context(request_id="req-1"):
            try:
                raise ValueError("x")
            except ValueError as error:
                capture_exception(error, metadata={"tenant": "a"}, storage=storage)
        self.assertEqual(storage.records[0].metadata, {"request_id": "req-1", "tenant": "a"})

    def test_breadcrumbs_are_captured(self):
        storage = MemoryStorage()
        breadcrumb("db", "loaded", row=2)
        try:
            raise ValueError("x")
        except ValueError as error:
            capture_exception(error, storage=storage)
        self.assertEqual(storage.records[0].breadcrumbs[0].message, "loaded")

    def test_capture_locals_disabled_by_default(self):
        storage = MemoryStorage()
        try:
            local_secret = "x"
            raise ValueError("x")
        except ValueError as error:
            capture_exception(error, storage=storage)
        self.assertTrue(all(frame.locals == {} for frame in storage.records[0].frames))

    def test_capture_locals_when_enabled(self):
        storage = MemoryStorage()
        config = TraceSeedConfig(capture_locals=True)
        try:
            local_value = 123
            raise ValueError("x")
        except ValueError as error:
            capture_exception(error, storage=storage, config=config)
        self.assertTrue(any(frame.locals.get("local_value") == 123 for frame in storage.records[0].frames))

    def test_guard_reraises(self):
        storage = MemoryStorage()
        with self.assertRaises(ZeroDivisionError):
            with guard("division", storage=storage):
                1 / 0
        self.assertEqual(storage.records[0].operation, "division")

    def test_guard_can_suppress(self):
        storage = MemoryStorage()
        config = TraceSeedConfig(re_raise=False)
        with guard("division", storage=storage, config=config):
            1 / 0
        self.assertEqual(len(storage.records), 1)

    def test_decorator_can_suppress(self):
        storage = MemoryStorage()
        config = TraceSeedConfig(re_raise=False)

        @capture(storage=storage, config=config)
        def fail():
            raise RuntimeError("x")

        self.assertIsNone(fail())
        self.assertEqual(len(storage.records), 1)

    def test_on_captured_callback(self):
        storage = MemoryStorage()
        seen = []

        @capture(storage=storage, on_captured=seen.append)
        def fail():
            raise RuntimeError("x")

        with self.assertRaises(RuntimeError):
            fail()
        self.assertEqual(seen[0].record.incident_id, storage.records[0].incident_id)

    def test_async_capture(self):
        storage = MemoryStorage()

        @capture(storage=storage)
        async def fail():
            await asyncio.sleep(0)
            raise RuntimeError("async")

        with self.assertRaises(RuntimeError):
            asyncio.run(fail())
        self.assertEqual(len(storage.records), 1)

    def test_successful_async_function_is_not_captured(self):
        storage = MemoryStorage()

        @capture(storage=storage)
        async def ok():
            return 3

        self.assertEqual(asyncio.run(ok()), 3)
        self.assertEqual(storage.records, [])

    def test_successful_sync_function_is_not_captured(self):
        storage = MemoryStorage()

        @capture(storage=storage)
        def ok():
            return 3

        self.assertEqual(ok(), 3)
        self.assertEqual(storage.records, [])

    def test_capture_exception_rejects_non_exception(self):
        with self.assertRaises(TypeError):
            capture_exception("wrong")


    def test_keyboard_interrupt_is_not_captured_or_suppressed(self):
        storage = MemoryStorage()
        config = TraceSeedConfig(re_raise=False)

        @capture(storage=storage, config=config)
        def interrupt():
            raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            interrupt()
        self.assertEqual(storage.records, [])

    def test_system_exit_is_not_captured_or_suppressed(self):
        storage = MemoryStorage()
        config = TraceSeedConfig(re_raise=False)

        @capture(storage=storage, config=config)
        def exit_now():
            raise SystemExit(2)

        with self.assertRaises(SystemExit):
            exit_now()
        self.assertEqual(storage.records, [])

    def test_internal_storage_error_does_not_escape_by_default(self):
        stream = io.StringIO()
        with redirect_stderr(stream):
            try:
                raise ValueError("original")
            except ValueError as error:
                result = capture_exception(error, storage=FailingStorage())
        self.assertIsNone(result)
        self.assertIn("disk unavailable", stream.getvalue())

    def test_internal_storage_error_escapes_in_strict_mode(self):
        try:
            raise ValueError("original")
        except ValueError as error:
            with self.assertRaises(OSError):
                capture_exception(error, storage=FailingStorage(), strict=True)

    def test_get_last_capture(self):
        storage = MemoryStorage()
        try:
            raise ValueError("x")
        except ValueError as error:
            result = capture_exception(error, storage=storage)
        self.assertIs(get_last_capture(), result)

    def test_custom_collector_registration(self):
        register_collector(CustomCollector())
        storage = MemoryStorage()
        try:
            raise ValueError("x")
        except ValueError as error:
            capture_exception(error, storage=storage)
        self.assertEqual(storage.records[0].extensions["custom_value"], 42)

    def test_duplicate_collector_registration_rejected(self):
        register_collector(CustomCollector())
        with self.assertRaises(ValueError):
            register_collector(CustomCollector())

    def test_broken_collector_is_recorded_not_raised(self):
        registry = CollectorRegistry([])
        registry.register(BrokenCollector())
        storage = MemoryStorage()
        engine = CaptureEngine(TraceSeedConfig(), collectors=registry, storage=storage)
        try:
            raise ValueError("x")
        except ValueError as error:
            result = engine.capture(error, CaptureContext())
        self.assertEqual(result.record.collector_errors[0]["collector"], "broken")
        self.assertEqual(result.record.exception.type_name, "ValueError")

    def test_exception_cause_is_captured(self):
        storage = MemoryStorage()
        try:
            try:
                raise KeyError("missing")
            except KeyError as inner:
                raise ValueError("outer") from inner
        except ValueError as error:
            capture_exception(error, storage=storage)
        self.assertEqual(storage.records[0].exception.cause.type_name, "KeyError")

    def test_exception_notes_are_captured(self):
        storage = MemoryStorage()
        error = ValueError("x")
        error.add_note("important")
        capture_exception(error, storage=storage)
        self.assertEqual(storage.records[0].exception.notes, ("important",))

    def test_exception_group_children_are_captured(self):
        storage = MemoryStorage()
        error = ExceptionGroup("group", [ValueError("a"), TypeError("b")])
        capture_exception(error, storage=storage)
        children = storage.records[0].exception.children
        self.assertEqual([child.type_name for child in children], ["ValueError", "TypeError"])

    def test_operation_defaults_to_function_qualname(self):
        storage = MemoryStorage()

        @capture(storage=storage)
        def fail():
            raise RuntimeError("x")

        with self.assertRaises(RuntimeError):
            fail()
        self.assertTrue(storage.records[0].operation.endswith("fail"))

    def test_replayable_local_function_is_marked_non_replayable(self):
        storage = MemoryStorage()

        @capture(storage=storage, replayable=True)
        def fail(value):
            raise RuntimeError(value)

        with self.assertRaises(RuntimeError):
            fail("x")
        self.assertFalse(storage.records[0].callable_info.replayable)



    def test_replay_payload_redacts_nested_sensitive_values(self):
        storage = MemoryStorage()
        try:
            raise RuntimeError("x")
        except RuntimeError as error:
            result = capture_exception(
                error,
                callable_info=__import__("traceseed.models", fromlist=["CallableInfo"]).CallableInfo(
                    "tests.replay_targets", "add", True
                ),
                replay_arguments=({"password": "secret", "value": 2},),
                replay_keyword_arguments={},
                storage=storage,
            )
        payload = str(storage.extras[0]["replay"])
        self.assertNotIn("secret", payload)
        self.assertIn("[REDACTED]", payload)

    def test_registered_codec_enables_replay_serialization(self):
        class Box:
            def __init__(self, value):
                self.value = value

        class BoxCodec:
            type_name = "box"
            def can_encode(self, value): return isinstance(value, Box)
            def encode(self, value, serializer): return value.value
            def decode(self, value, serializer): return Box(value)

        register_codec(BoxCodec())
        storage = MemoryStorage()
        try:
            raise RuntimeError("x")
        except RuntimeError as error:
            result = capture_exception(
                error,
                callable_info=__import__("traceseed.models", fromlist=["CallableInfo"]).CallableInfo(
                    "tests.replay_targets", "add", True
                ),
                replay_arguments=(Box(3),),
                replay_keyword_arguments={},
                storage=storage,
            )
        self.assertTrue(result.record.callable_info.replayable)
        encoded = storage.extras[0]["replay"]["arguments"]
        self.assertIn("box", str(encoded))

    def test_install_and_uninstall_restore_hooks(self):
        old_sys = sys.excepthook
        old_thread = threading.excepthook
        install()
        self.assertIsNot(sys.excepthook, old_sys)
        uninstall()
        self.assertIs(sys.excepthook, old_sys)
        self.assertIs(threading.excepthook, old_thread)

    def test_install_is_idempotent(self):
        install()
        hook = sys.excepthook
        install()
        self.assertIs(sys.excepthook, hook)
