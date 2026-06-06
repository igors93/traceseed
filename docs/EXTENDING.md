# Extending TraceSeed

## Custom collector

A collector is any object with a `name` attribute and a `collect` method:

```python
class RequestCollector:
    name = "request"

    def collect(self, exception, context, config):
        return {
            "request": {
                "method": current_method(),
                "path": current_path(),
                "user_id": current_user_id(),
            }
        }
```

Register it globally:

```python
from traceseed import register_collector

register_collector(RequestCollector())
```

### Rules

- Use a **stable name**. It becomes a key in the stored record and is part of the public format.
- Pass `replace=True` to replace a previously registered collector with the same name.
- A collector that raises is recorded in `collector_errors` and **must not block the others**.
- Do not perform I/O that can fail or block indefinitely inside `collect`.

---

## Custom storage backend

```python
from traceseed.storage import StoredFailure


class DatabaseStorage:
    name = "database"

    def save(self, record, extra=None):
        identifier = insert_record(record, extra)
        return StoredFailure(
            location=f"database://{identifier}",
            storage_name=self.name,
        )
```

### Rules

- `save` must be **synchronous** in version 0.1. For async I/O, delegate to a queue or thread pool controlled by the application.
- If `save` raises, the exception propagates as a `StorageError` in `strict=True` mode, or is printed to stderr and swallowed in `strict=False` mode.
- Return a `StoredFailure` with a meaningful `location` to allow later retrieval.

Pass the storage per capture:

```python
from traceseed import capture_exception

capture_exception(exc, storage=DatabaseStorage())
```

Or set it as the default via `configure()`.

---

## Custom codec

A codec extends the serializer to handle types that are not natively supported:

```python
class MoneyCodec:
    type_name = "money"

    def can_encode(self, value):
        return isinstance(value, Money)

    def encode(self, value, serializer):
        return {
            "amount": str(value.amount),
            "currency": value.currency,
        }

    def decode(self, value, serializer):
        return Money(value["amount"], value["currency"])
```

Register it on the serializer:

```python
from traceseed.serialization import SafeSerializer
from traceseed import TraceSeedConfig

config = TraceSeedConfig()
serializer = SafeSerializer(config)
serializer.register_codec(MoneyCodec())
```

### Rules

- `encode` must return only JSON-compatible structures (dicts, lists, strings, numbers, booleans, `None`).
- `type_name` must be unique across all registered codecs.
- Codecs that can encode a value also participate in replay reconstruction via `decode`.
- A codec that raises in `encode` causes the value to be recorded as `codec_error`, which disables replay for that invocation.

---

## Custom redaction rule

Add field names or patterns at configuration time:

```python
from traceseed import TraceSeedConfig

config = (
    TraceSeedConfig()
    .with_redact_fields({"national_id", "health_record_number", "pin"})
    .with_redact_pattern(r"\b\d{3}-\d{2}-\d{4}\b")  # SSN pattern
)
```

Or provide a callable for full control:

```python
config = config.with_redact_func(
    lambda key, value: "[CUSTOM_REDACTED]" if is_pii(value) else value
)
```

---

## Format compatibility

When evolving the `.tseed` format:

- Do **not** change the meaning of existing fields without incrementing `format_version`.
- New files can be added to a package while old readers skip unknown entries gracefully.
- Fingerprint canonical representations carry `algorithm_version`; increment it when the hashing logic changes in a way that would produce different values for the same failure.
- The `files` and `hashes` lists in the manifest must always match exactly — add any new file to both.
