# TraceSeed security diagnostics

Target reviewed: commit `f1c171de0956af44cb07fedf034f035735cf5367`.

This directory contains security and reliability regression tests for the fixes in this patch.

## Run

```bash
python -m pytest tests/security_diagnostics -q
```

For full tracebacks and individual test names:

```bash
python -m pytest tests/security_diagnostics -vv --tb=long
```

The suite contains 76 test functions and approximately 128 collected cases after
parameterization. It covers:

- sanitization of exception chains, runtime data, frames, breadcrumbs, and callable metadata;
- preservation of the original exception when TraceSeed initialization fails;
- asyncio cancellation semantics;
- replay generation, schema validation, size limits, malformed serialized values, and codecs;
- ZIP path handling, manifest consistency, integrity checks, and filename collisions;
- DirectoryStorage symlink, file-count, and size boundaries;
- CLI integrity verification and controlled handling of malformed JSON;
- collector isolation and extension-key collisions;
- configuration type and regular-expression validation;
- consistency between README examples and the public API/CLI;
- baseline protections that should already pass, including explicit replay authorization,
  tamper detection, default argv privacy, package hashes, and private file permissions.

Tests are deliberately **not** marked `xfail`: a failure identifies an invariant that is
not currently satisfied. Some tests permit more than one secure implementation, such as
rejecting an unsafe configuration immediately or supporting it consistently end to end.
