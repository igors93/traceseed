# TraceSeed Architecture

## Goals

1. **Small, predictable public API.**
2. **Internal failures never hide the original exception.** A global failure boundary in `CaptureEngine.capture()` catches any unexpected error and returns a safe `CaptureResult` with a `capture_error` field.
3. **Sensitive data is removed before persistence.** Sanitization happens inside the engine, before the storage layer is called.
4. **Collectors, serializers, and storage backends are replaceable** without modifying the engine.
5. **The `.tseed` format is versioned and auditable.** SHA-256 hashes detect accidental corruption; they do not authenticate origin.
6. **Fingerprints are machine-portable.** The canonical representation uses `frame.module` (e.g. `"app.services"`) instead of absolute file paths, so the same failure on different machines produces the same fingerprint.

---

## Capture flow

```text
@capture / guard / capture_exception
                 │
                 ▼
          CaptureContext          (in-memory, per-call)
                 │
                 ▼
          CaptureEngine
          ├─ collectors           (independent; errors recorded, not raised)
          ├─ redactor             (sanitizes before anything is written)
          ├─ fingerprinter        (uses already-sanitized data)
          ├─ serializer           (safe JSON encoding)
          └─ storage              (atomic write)
                 │
                 ▼
          FailureRecord           (immutable dataclass)
                 │
                 ▼
       .tseed / directory / memory
```

---

## Public API (`api.py`)

The public surface is intentionally small:

| Symbol | Purpose |
|---|---|
| `capture` | decorator |
| `guard` | context manager |
| `capture_exception` | manual capture |
| `register_collector` | add a custom collector |
| `install` / `uninstall` | sys.excepthook hooks |
| `install_asyncio` / `uninstall_asyncio` | asyncio loop hooks |

Each entry point builds a `CaptureContext` and delegates to the engine. Asyncio hooks use a `WeakKeyDictionary` keyed on the actual loop object to prevent id()-collision after GC and avoid leaking closed loops.

---

## Engine (`engine.py`)

`CaptureEngine` is an orchestrator. It contains no collection or I/O details. Its sequence:

1. Run each collector in isolation; record failures in `collector_errors`.
2. Sanitize exception info, frames, arguments, context, and breadcrumbs.
3. Generate the fingerprint from already-sanitized data.
4. Evaluate whether arguments allow safe replay (no redacted/truncated/unresolvable values).
5. Build an immutable `FailureRecord`.
6. Persist via the `Storage` protocol.

The entire `_capture_impl()` call is wrapped in a `try/except` at the `capture()` level. Any unexpected internal error is caught and returned as `CaptureResult(capture_error="traceseed internal error: …")` rather than raised.

---

## Collectors (`collectors/`)

Each collector implements:

```python
name: str

def collect(exception, context, config) -> dict:
    ...
```

Built-in collectors:

| Collector | Data |
|---|---|
| `ExceptionCollector` | type, message, notes, chained exceptions |
| `TracebackCollector` | formatted traceback text |
| `RuntimeCollector` | Python version, platform, `sys.argv` (opt-in), cwd |
| `ContextCollector` | contextvars context and breadcrumbs |
| `ThreadCollector` | active thread info |

A failing collector is recorded and does not interrupt the others. `build_exception_info()` protects against cycles (via a `frozenset` of seen ids), depth overflow, broken `str()`/`repr()`, and non-string `__notes__`.

---

## Sanitization (`redaction.py`)

`Redactor` processes data recursively with four protections:

- Sensitive field names (exact and prefix match).
- Regular expressions (bearer tokens, card-like numbers).
- Depth and collection-size limits.
- Circular reference detection.

Sanitization runs before any call to storage. `source_line` from frames is also sanitized. `sys.argv` is only captured when `capture_argv=True` (default: `False`).

---

## Serialization (`serialization.py`)

`SafeSerializer` converts data to a typed JSON tree. It never uses `pickle`.

Reconstructable types: primitives, bytes, collections, dates, `Decimal`, `UUID`, `Path`, enums, and dataclasses. Enums and dataclasses require import authorization at decode time.

Arbitrary objects produce `unresolved` records for diagnostics and automatically disable replay for that invocation.

---

## Fingerprinting (`fingerprint.py`)

The fingerprint is SHA-256 over a canonical representation:

- Exception class and normalized message.
- Final N frames (limited).
- Immediate cause type.

Variable values (numbers, UUIDs, long tokens, hex addresses) are normalized before hashing. The canonical representation carries `algorithm_version: 2`. Frames use `frame.module` as the primary identifier; when module is unavailable, the last three path components are used as a fallback.

---

## Storage backends

### `ArchiveStorage`

Creates a ZIP file with the `.tseed` extension. Every diagnostic file receives a SHA-256 entry in the manifest. Writes use a temporary file and `os.replace` for atomicity.

ZIP loading applies safety checks in strict order before reading any content:

1. Entry count limit.
2. Name validation (no absolute paths, traversal, or empty names).
3. Duplicate detection.
4. Type rejection (directories, encrypted entries, symlinks).
5. Per-file size check (from metadata, before extraction).
6. Total size check.
7. Manifest size check.
8. Content read with a byte limit to detect misleading headers.

### `DirectoryStorage`

Creates the same structure unpacked into a directory, useful for inspection during development.

### `MemoryStorage`

Holds `FailureRecord` in memory. Intended for tests and integrations.

---

## Manifest validation

`verify_files()` is the single authority for manifest checks:

- `format_version` must be a real `int`, not a `bool` (Python subtype).
- `files` and `hashes` keys must match exactly.
- Files declared in `files` must all be present in the archive.
- No extra files may appear in the archive beyond those declared.
- SHA-256 hashes are verified for every declared file.

---

## Replay (`replay/`)

Replay is deliberately separated from capture:

1. The package must contain `replay.json` with `{"replayable": true, …}`.
2. The package must have integrity hashes, including a hash for `replay.json`.
3. The user must authorize execution explicitly (`--allow-code-execution`).
4. The module and callable are imported.
5. Arguments are reconstructed by the serializer.
6. The function is called.

If any argument was redacted, truncated, exceeded depth, contained a circular reference, or was unresolvable, `replay.json` is written as `{"replayable": false, "reason": "…"}` and the runner raises `ReplayError` without importing any module.

Replay is assisted reproduction, not a sandbox.

---

## Compatibility

The initial release requires Python 3.11+ for `ExceptionGroup` support and modern typing syntax. The runtime core does not depend on `tomllib` or any third-party package.
