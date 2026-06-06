# Security

## Threat model

Diagnostic packages may contain function arguments, local variables, file paths, error messages, business data, and execution context. This project assumes all of that may be sensitive.

The goals are:

1. No secret leaves the process unredacted.
2. A malformed or adversarial package cannot crash the host process or escape a directory.
3. Internal library failures do not replace the original exception.
4. Replay cannot happen silently or without explicit user consent.

---

## Protections in place

### Sanitization

- Field names are checked against a built-in list of sensitive keys (`password`, `token`, `secret`, `api_key`, `authorization`, `card`, `cpf`, and others).
- Regular expressions detect bearer tokens and card-like numbers in string values.
- Redaction happens recursively through dicts, lists, and nested structures.
- `source_line` from stack frames is sanitized before storage.
- `sys.argv` is **not captured by default** (`capture_argv=False`). It must be explicitly enabled, as argv frequently contains credentials and paths.

### Serialization

- `pickle` is never used.
- Arbitrary objects that cannot be safely encoded become `unresolved` records — they are described but not reconstructed.
- Redacted values become a `[REDACTED]` sentinel that is detectable by the replay engine.

### Package integrity

- Every file in a `.tseed` package receives a SHA-256 hash in the manifest.
- ZIP loading performs metadata-first safety checks before any content is extracted: entry count, file names, entry types (no directories, symlinks, or encrypted entries), per-file size, total size, and compression ratio.
- Absolute paths and path traversal sequences (`..`) in ZIP entries are rejected.
- `format_version` must be a real integer — `True` and `False` (Python `bool` subtypes) are explicitly rejected.
- The `files` and `hashes` fields in the manifest must match exactly; any discrepancy raises `InvalidPackageError`.

### Replay safety

- Replay requires `{"replayable": true}` in `replay.json`.
- Replay is blocked when `replay.json` has no integrity hash in the manifest.
- Replay is blocked when `include_package_hashes=False`.
- If any argument was redacted, truncated, exceeded the depth limit, contained a circular reference, or could not be resolved, `replay.json` contains `{"replayable": false}` and the runner refuses to execute.
- `--allow-code-execution` must be passed explicitly on the CLI.

### Failure isolation

- A global failure boundary in `CaptureEngine.capture()` ensures that any unexpected internal error is caught and returned as a `capture_error` field rather than raised.
- Collector failures are recorded in `collector_errors` and do not interrupt the capture pipeline.
- In `strict=False` mode (default), capture errors are printed to stderr and the caller continues normally.
- In `strict=True` mode, storage failures raise `StorageError` and callback failures raise `CallbackError`.

### Asyncio hooks

- `install_asyncio()` uses a `WeakKeyDictionary` keyed on the actual loop object. This prevents id()-collision after garbage collection and avoids leaking closed loops.
- Installing the hook twice on the same loop is idempotent — the handler is not stacked.
- The previous handler is always restored on `uninstall_asyncio()`.

---

## Recommendations

- Add domain-specific field names to `redact_fields` (e.g. national IDs, session keys, medical record numbers).
- Do not enable `capture_locals` without evaluating the data exposed in your call stack.
- Do not enable `capture_argv` unless you have verified that your application does not pass secrets via command-line arguments.
- Restrict filesystem permissions on the output directory.
- Define a retention and secure deletion policy for `.tseed` packages.
- Verify a package with `traceseed verify` before sharing it.
- Never replay a package from an untrusted source.

---

## Replay is not a sandbox

`--allow-code-execution` imports Python modules and executes the callable specified in `replay.json`. SHA-256 hashes verify integrity against the manifest, but they do not prove the authenticity of the origin. A malicious actor can construct a valid manifest pointing to arbitrary code.

Treat replay packages with the same caution you would apply to arbitrary code from that source.

---

## Reporting vulnerabilities

Do not publish secrets or real production packages in issues. Create a minimal reproduction with synthetic data that demonstrates the problem without exposing sensitive information.
