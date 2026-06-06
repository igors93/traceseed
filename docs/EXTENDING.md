# Estendendo o TraceSeed

## Novo coletor

```python
class RequestCollector:
    name = "request"

    def collect(self, exception, context, config):
        return {
            "request_data": {
                "method": current_method(),
                "path": current_path(),
            }
        }
```

Registro:

```python
from traceseed import register_collector
register_collector(RequestCollector())
```

Use nomes estáveis. `replace=True` substitui um coletor customizado com o mesmo nome.

## Novo storage

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

O método `save` deve ser síncrono na versão 0.1. Para I/O assíncrono, use um adaptador que delegue a uma fila controlada pela aplicação.

## Codec customizado

```python
class MoneyCodec:
    type_name = "money"

    def can_encode(self, value):
        return isinstance(value, Money)

    def encode(self, value, serializer):
        return {"amount": str(value.amount), "currency": value.currency}

    def decode(self, value, serializer):
        return Money(value["amount"], value["currency"])
```

```python
serializer.register_codec(MoneyCodec())
```

Um codec deve produzir somente estruturas que o JSON suporte.

## Compatibilidade de formato

- Não altere o significado de campos existentes sem aumentar `format_version`.
- Novos arquivos podem ser acrescentados a um pacote mantendo a leitura dos antigos.
- Fingerprints precisam manter um campo de versão canônica para permitir evolução.
