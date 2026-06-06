# Changelog

## 0.1.0 — 2026-06-06

Initial release.

### Core API

- `@capture` decorator, `guard()` context manager, and `capture_exception()` for manual capture.
- Synchronous and asynchronous support.
- Context and breadcrumbs via `contextvars`, isolated across async tasks.
- Modular collectors: exception info, traceback, runtime, context, and threads.

### Sanitization

- Deep redaction of secrets by field name, regex, and custom function.
- Built-in patterns: bearer tokens, card-like numbers, common sensitive key names.
- `source_line` from stack frames is sanitized before storage.
- `capture_argv` defaults to `False` — `sys.argv` is not captured unless explicitly enabled.

### Serialization

- Safe JSON encoding with no `pickle`.
- Reconstructable types: primitives, bytes, collections, dates, `Decimal`, `UUID`, `Path`, enums, dataclasses.
- Unresolvable objects produce diagnostic `unresolved` records.

### Fingerprinting

- SHA-256 over a canonical representation of exception class, normalized message, final frames, and immediate cause.
- Normalizes variable values: numbers, UUIDs, long tokens, hex addresses.
- `algorithm_version: 2` — frames use `frame.module` (e.g. `"app.services"`) instead of absolute file paths for cross-machine stability.

### Storage

- `ArchiveStorage` — `.tseed` ZIP with manifest and SHA-256 hashes; atomic writes via `os.replace`.
- `DirectoryStorage` — unpacked structure for development inspection.
- `MemoryStorage` — in-memory backend for tests and integrations.

### Package integrity

- Metadata-first ZIP validation: entry count, name checks, type rejection, per-file size, total size, compression ratio — all checked before content is read.
- `format_version` bool-subtype check (`True`/`False` explicitly rejected).
- `files` and `hashes` in the manifest must match exactly.
- Absolute paths and path traversal sequences rejected at load time.

### Replay

- Assisted replay via `replay.json` with explicit `--allow-code-execution` authorization.
- Replay disabled automatically when any argument was redacted, truncated, exceeded depth, or was unresolvable — stored as `{"replayable": false, "reason": "…"}`.
- Replay blocked when `replay.json` has no integrity hash in the manifest.
- Raw `replay_arguments` are never written to `FailureRecord` or any persisted file.

### Failure isolation

- Global failure boundary in `CaptureEngine.capture()` — internal errors return `capture_error` rather than raising.
- Collector failures recorded in `collector_errors`, never propagated.
- `strict=False` (default): errors printed to stderr, caller continues.
- `strict=True`: `StorageError` on storage failure, `CallbackError` on callback failure.

### Asyncio hooks

- `install_asyncio()` uses `WeakKeyDictionary` — idempotent, no handler stacking, closed loops garbage-collected cleanly.

### CLI

- `traceseed show` — display a package.
- `traceseed verify` — check integrity hashes.
- `traceseed list` — list packages in a directory.
- `traceseed compare` — diff two packages by fingerprint.
- `traceseed replay` — assisted replay with explicit authorization.

### Testing

- Over 330 automated tests.
- Covers: package corruption, ZIP bomb protection, exception cycles, broken `repr()`, async concurrency, global hooks, collector failures, replay security, manifest validation, config boundary checks, and cross-machine fingerprint stability.
