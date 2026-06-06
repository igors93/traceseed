# TraceSeed

**Turn Python failures into verifiable, reproducible diagnostic packages.**

TraceSeed is a modular library with **zero runtime dependencies**. It captures an exception, collects useful context, removes sensitive information, generates a stable fingerprint, and saves a `.tseed` package with integrity hashes.

> **Status:** initial release `0.1.0`, ready for study, controlled use, and further development. Replay is assisted and should only be used with trusted packages.

---

## Features

- **Small API:** `@capture`, `guard()`, and `capture_exception()`.
- Synchronous and asynchronous support.
- Chained exceptions, notes, and `ExceptionGroup`.
- Arguments, locals, traceback, runtime info, threads, and breadcrumbs.
- Deep sanitization by field name, regex, and custom function.
- Stable fingerprinting that normalizes IDs, numbers, UUIDs, long tokens, and hex addresses.
- `.tseed` packages in ZIP format with a manifest and SHA-256 hashes.
- Atomic writes to prevent incomplete packages.
- File, directory, and in-memory storage backends.
- Extensible collectors and serializers.
- CLI for viewing, verifying, listing, comparing, and replaying packages.
- Global hooks for `sys`, `threading`, and `asyncio`.
- Over 330 regression tests, with lint and static type checking.

---

## Requirements

- Python 3.11 or higher.
- No external runtime dependencies.

---

## Quick start (no install)

From the project root:

```bash
PYTHONPATH=src python examples/basic.py
PYTHONPATH=src python -m traceseed --version
```

On Windows PowerShell:

```powershell
$env:PYTHONPATH = "src"
python examples/basic.py
```

---

## Installation

```bash
python -m pip install .
```

No runtime dependencies are declared.

---

## Basic example

```python
from traceseed import capture


@capture(operation="process-payment")
def process_payment(order_id: int, token: str) -> None:
    raise ValueError(f"payment rejected for order {order_id}")


process_payment(123, token="secret-token")
```

The original exception is re-raised. A package is created under `.traceseeds/`:

```text
.traceseeds/
└── process-payment-traceseed-9c41...-2ac39f10.tseed
```

The token is redacted before persistence.

---

## Context manager

```python
from traceseed import guard

with guard("import-customers", metadata={"file": "customers.csv"}):
    import_customers()
```

---

## Manual capture

```python
from traceseed import capture_exception

try:
    execute_job()
except Exception as error:
    result = capture_exception(
        error,
        operation="background-job",
        metadata={"job_id": 42},
    )
    raise
```

By default, an internal TraceSeed failure never replaces the original exception. Use `strict=True` in tests or admin tools to surface capture errors explicitly.

---

## Configuration

```python
from pathlib import Path
from traceseed import TraceSeedConfig, configure

configure(
    TraceSeedConfig(
        output_directory=Path("var/traceseeds"),
        capture_arguments=True,
        capture_locals=True,
        capture_argv=False,        # disabled by default — argv may contain secrets
        capture_threads=False,
        max_depth=6,
        max_collection_items=80,
        max_operation_length=256,
        max_exception_depth=20,
        max_exception_children=32,
    ).with_redact_fields({"cpf", "session_id"})
)
```

### Security-relevant defaults

| Field | Default | Notes |
|---|---|---|
| `capture_argv` | `False` | `sys.argv` may contain secrets; opt in explicitly |
| `capture_cwd` | `True` | working directory is low-risk; disable if needed |
| `max_exception_depth` | `20` | limits chained-exception recursion |
| `max_exception_children` | `32` | limits `ExceptionGroup` children |
| `max_operation_length` | `256` | operation name is truncated to this length |
| `max_replay_payload_size` | `1 MB` | replay payloads larger than this are rejected |

---

## Context and breadcrumbs

```python
from traceseed import breadcrumb, context

with context(request_id="req-123", tenant="company-a"):
    breadcrumb("database", "customer loaded", customer_id=42)
    breadcrumb("payment", "gateway request sent")
    process_payment()
```

Context uses `contextvars` and stays isolated across async tasks.

---

## Logs as breadcrumbs

```python
import logging
from traceseed import BreadcrumbHandler

handler = BreadcrumbHandler()
logging.getLogger().addHandler(handler)
```

---

## Storage backends

```python
from traceseed import TraceSeedConfig
from traceseed.serialization import SafeSerializer
from traceseed.storage import ArchiveStorage, DirectoryStorage, MemoryStorage

config = TraceSeedConfig()
serializer = SafeSerializer(config)

archive = ArchiveStorage(config, serializer)   # .tseed ZIP files
directory = DirectoryStorage(config, serializer)  # unpacked directory
memory = MemoryStorage()                       # in-memory, useful in tests
```

Pass a storage per capture:

```python
@capture(storage=memory)
def operation():
    ...
```

A custom storage only needs to implement:

```python
class MyStorage:
    name = "my-storage"

    def save(self, record, extra=None):
        ...
```

---

## Custom collectors

```python
from traceseed import register_collector


class TenantCollector:
    name = "tenant"

    def collect(self, exception, context, config):
        return {"tenant_runtime": read_current_tenant()}


register_collector(TenantCollector())
```

A failing collector is recorded in `collector_errors` and does not block the others.

---

## Assisted replay

```python
@capture(operation="calculate-tax", replayable=True)
def calculate_tax(amount, rate):
    return amount * rate
```

Replay is generated only when the callable is importable and all arguments are reconstructable. If any argument was redacted or could not be serialized, `replay.json` contains `{"replayable": false}` and the runner refuses to execute.

```bash
traceseed replay failure.tseed --allow-code-execution
```

> **Warning:** replay imports modules and executes application code. Never replay a package received from an untrusted source.

---

## CLI

```bash
traceseed show error.tseed
traceseed show error.tseed --json
traceseed verify error.tseed
traceseed list .traceseeds
traceseed compare first.tseed second.tseed
traceseed replay error.tseed --allow-code-execution
```

Without installation:

```bash
PYTHONPATH=src python -m traceseed show error.tseed
```

---

## Development

TraceSeed has **zero runtime dependencies**. Development, testing, linting, and type checking use pytest, Ruff, and mypy.

```bash
python -m ruff format --check .
python -m ruff check .
python -m mypy src
python -m pytest
```

The test suite covers over 330 scenarios, including package corruption, ZIP bomb protection, exception cycles, broken `repr()`, async concurrency, global hooks, collector failures, and replay.

---

## Project layout

```text
src/traceseed/
├── api.py              public API and hooks
├── engine.py           capture orchestration
├── config.py           immutable configuration
├── context.py          context and breadcrumbs
├── fingerprint.py      stable failure grouping
├── redaction.py        secret removal
├── serialization.py    safe JSON codec
├── collectors/         independent data collectors
├── storage/            file, directory, and memory backends
├── replay/             assisted reproduction
└── cli.py              administrative commands
```

See also:

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/SECURITY.md](docs/SECURITY.md)
- [docs/EXTENDING.md](docs/EXTENDING.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)

---

## Known limitations

- Replay does not automatically recreate databases, network, external files, or global state.
- Arbitrary objects are represented for diagnostic purposes but are not automatically reconstructed.
- Replay isolation is not a security sandbox.
- Capturing locals may record sensitive data — maintain proper sanitization and limits.

---

## License

MIT.
