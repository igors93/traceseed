from __future__ import annotations

import threading

import pytest

from traceseed import (
    CallableInfo,
    MemoryStorage,
    TraceSeedConfig,
    breadcrumb,
    capture_exception,
    clear_context,
)

from ._helpers import make_exception_chain, walk_exception_info


SECRET = "Bearer diagnostic-secret-token"


@pytest.fixture(autouse=True)
def _clear_trace_context():
    clear_context()
    yield
    clear_context()


def _capture(error: BaseException, *, config: TraceSeedConfig | None = None):
    storage = MemoryStorage()
    result = capture_exception(error, config=config, storage=storage, strict=True)
    assert result is not None
    assert storage.records
    return result.record, storage


def test_deep_exception_chain_is_sanitized_at_every_level():
    error = make_exception_chain(18, deepest_message=SECRET)
    record, _ = _capture(error, config=TraceSeedConfig(max_exception_depth=20))

    all_text = "\n".join(
        text
        for item in walk_exception_info(record.exception)
        for text in (item.message, item.representation, *item.notes)
    )
    assert "diagnostic-secret-token" not in all_text
    assert "[REDACTED]" in all_text


def test_deep_exception_notes_are_sanitized_at_every_level():
    error = make_exception_chain(18, deepest_message="deep failure")
    deepest = error
    while deepest.__cause__ is not None:
        deepest = deepest.__cause__
    deepest.add_note(SECRET)

    record, _ = _capture(error, config=TraceSeedConfig(max_exception_depth=20))
    all_notes = [note for item in walk_exception_info(record.exception) for note in item.notes]
    assert not any("diagnostic-secret-token" in note for note in all_notes)


@pytest.mark.parametrize(
    "field_name",
    [
        "password_hash",
        "password_value",
        "api_key_prod",
        "authorization_header",
        "access_token_cache",
    ],
)
def test_sensitive_field_prefixes_are_redacted(field_name: str):
    storage = MemoryStorage()

    def fail(**kwargs):
        raise RuntimeError("failure")

    try:
        fail(**{field_name: "plain-secret"})
    except RuntimeError as error:
        capture_exception(
            error,
            metadata={field_name: "plain-secret"},
            storage=storage,
            strict=True,
        )

    assert storage.records[0].metadata[field_name] == "[REDACTED]"


def test_opted_in_argv_is_sanitized_before_persistence(monkeypatch):
    monkeypatch.setattr(
        "traceseed.collectors.sys.argv",
        ["application", "--authorization", SECRET],
    )
    record, _ = _capture(
        RuntimeError("failure"),
        config=TraceSeedConfig(capture_argv=True),
    )
    assert "diagnostic-secret-token" not in repr(record.runtime.argv)


def test_cwd_is_sanitized_before_persistence(monkeypatch):
    monkeypatch.setattr(
        "traceseed.collectors.os.getcwd",
        lambda: f"/srv/{SECRET}/project",
    )
    record, _ = _capture(
        RuntimeError("failure"),
        config=TraceSeedConfig(capture_cwd=True),
    )
    assert "diagnostic-secret-token" not in record.runtime.cwd


def test_thread_name_is_sanitized_before_persistence():
    thread = threading.current_thread()
    previous_name = thread.name
    thread.name = SECRET
    try:
        record, _ = _capture(RuntimeError("failure"))
    finally:
        thread.name = previous_name
    assert "diagnostic-secret-token" not in record.runtime.thread_name


def test_frame_filename_is_sanitized_before_persistence():
    namespace: dict[str, object] = {"__name__": "diagnostic_dynamic_module"}
    code = compile(
        "def fail():\n    raise RuntimeError('failure')\n",
        SECRET,
        "exec",
    )
    exec(code, namespace)

    try:
        namespace["fail"]()  # type: ignore[index,operator]
    except RuntimeError as error:
        record, _ = _capture(error)

    assert record.frames
    assert all("diagnostic-secret-token" not in frame.filename for frame in record.frames)


def test_frame_module_is_sanitized_before_persistence():
    namespace: dict[str, object] = {"__name__": SECRET}
    exec("def fail():\n    raise RuntimeError('failure')\n", namespace)

    try:
        namespace["fail"]()  # type: ignore[index,operator]
    except RuntimeError as error:
        record, _ = _capture(error)

    assert all(
        frame.module is None or "diagnostic-secret-token" not in frame.module
        for frame in record.frames
    )


def test_breadcrumb_category_is_sanitized_before_persistence():
    breadcrumb(SECRET, "safe message")
    record, _ = _capture(RuntimeError("failure"))
    assert record.breadcrumbs
    assert "diagnostic-secret-token" not in record.breadcrumbs[0].category


def test_callable_info_is_sanitized_before_persistence():
    storage = MemoryStorage()
    info = CallableInfo(
        module=SECRET,
        qualname=f"service.{SECRET}",
        replayable=False,
        reason=SECRET,
    )
    result = capture_exception(
        RuntimeError("failure"),
        callable_info=info,
        storage=storage,
        strict=True,
    )
    assert result is not None
    assert "diagnostic-secret-token" not in repr(result.record.callable_info)


def test_exception_type_metadata_cannot_bypass_sanitization():
    secret_exception = type(
        "DiagnosticSecretError",
        (RuntimeError,),
        {"__module__": SECRET},
    )
    record, _ = _capture(secret_exception("failure"))
    assert "diagnostic-secret-token" not in record.exception.module


def test_collector_name_is_sanitized_when_collector_fails():
    from traceseed.collectors import CollectorRegistry
    from traceseed.engine import CaptureEngine
    from traceseed.models import CaptureContext

    class FailingCollector:
        name = SECRET

        def collect(self, exception, context, config):
            raise RuntimeError("collector failed")

    registry = CollectorRegistry([FailingCollector()])
    storage = MemoryStorage()
    result = CaptureEngine(
        TraceSeedConfig(),
        collectors=registry,
        storage=storage,
    ).capture(RuntimeError("failure"), CaptureContext())

    assert result.capture_error is None
    assert result.record.collector_errors
    assert "diagnostic-secret-token" not in result.record.collector_errors[0]["collector"]
