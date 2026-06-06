# Contributing

## Principles

- **Zero runtime dependencies.** The standard library is sufficient at runtime; no external packages should be added.
- **Dev tooling:** pytest, Ruff, and mypy are the only required development dependencies.
- **Keep the public API small.** New features should justify their surface area.
- **The original exception is always preserved.** Internal failures must never replace or shadow it.
- **Security and sanitization before convenience.** Sensitive data must be redacted before any persistence.
- **Every bug fix must include a regression test.**

---

## Running checks

```bash
python -m ruff format --check .   # formatting
python -m ruff check .             # linting
python -m mypy src                 # type checking
python -m pytest                   # full test suite
```

For faster iteration:

```bash
python -m pytest -q
python -m pytest --maxfail=1
python -m pytest tests/test_capture.py
```

---

## Writing tests

Use `pytest` or `unittest`. Keep tests independent of network, external clocks, and services.

- For temporary files, use `tmp_path` (pytest) or `tempfile.TemporaryDirectory`.
- Do not leave `.tseed` files behind after tests.
- Do not mock internal components unless testing the failure boundary explicitly.
- For archive or manifest tests, construct the ZIP directly with `zipfile.ZipFile`.

---

## Security checklist

Before submitting a change:

1. Code compiles under Python 3.11+.
2. `ruff format --check`, `ruff check`, `mypy src`, and `pytest` all pass without errors.
3. No runtime dependency is introduced.
4. Sensitive data is not persisted before sanitization.
5. Failures in the new component do not hide the original exception.
6. New config fields include boundary validation in `TraceSeedConfig.__post_init__`.
7. Documentation is updated to reflect the change.

---

## Adding a collector

Implement the collector protocol:

```python
class MyCollector:
    name = "my_collector"

    def collect(self, exception, context, config):
        return {"key": "value"}
```

Register it with `register_collector(MyCollector())`. Use a stable `name` — it becomes a key in the stored record.

A failing collector is recorded in `collector_errors` and must not block the others.

---

## Adding a storage backend

```python
from traceseed.storage import StoredFailure

class MyStorage:
    name = "my-storage"

    def save(self, record, extra=None):
        identifier = persist(record, extra)
        return StoredFailure(
            location=f"my-storage://{identifier}",
            storage_name=self.name,
        )
```

`save` must be synchronous in 0.1. For async I/O, delegate to a queue controlled by the application.

---

## Format compatibility

- Do not change the meaning of existing fields without incrementing `format_version`.
- New files can be added to a package while maintaining backward-readable support for older ones.
- Fingerprint canonical representations must carry a version field to allow algorithm evolution.
