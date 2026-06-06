# TraceSeed

**Transforme falhas Python em pacotes diagnósticos verificáveis e, quando possível, reproduzíveis.**

TraceSeed é uma biblioteca modular com **zero dependências em runtime**. Ela captura uma exceção, coleta o contexto útil, remove informações sensíveis, gera uma fingerprint estável e salva um pacote `.fprint` com hashes de integridade.

> Estado: versão inicial `0.1.0`, pronta para estudo, evolução e uso controlado. O replay é assistido e deve ser usado somente com pacotes confiáveis.

## Principais recursos

- API pequena: `@capture`, `guard()` e `capture_exception()`.
- Funções síncronas e assíncronas.
- Exceções encadeadas, notas e `ExceptionGroup`.
- Argumentos, locals opcionais, traceback, runtime, threads e breadcrumbs.
- Sanitização por nome de campo, regex e função personalizada.
- Fingerprint que normaliza IDs, números, UUIDs, tokens longos e endereços hexadecimais.
- Pacotes `.fprint` em ZIP com manifesto e SHA-256.
- Escrita atômica para evitar pacotes incompletos.
- Storages em arquivo, diretório e memória.
- Coletores e serializers extensíveis.
- CLI para visualizar, verificar, listar, comparar e reproduzir.
- Hooks para `sys`, `threading` e `asyncio`.
- 145 testes feitos somente com `unittest`.

## Requisitos

- Python 3.11 ou superior.
- Nenhuma dependência externa em runtime.

## Uso direto, sem instalação

Na raiz do projeto:

```bash
PYTHONPATH=src python examples/basic.py
PYTHONPATH=src python -m traceseed --version
```

No Windows PowerShell:

```powershell
$env:PYTHONPATH = "src"
python examples/basic.py
```

## Instalação local sem baixar dependências

O instalador incluído usa somente a biblioteca padrão:

```bash
python install_local.py
```

Para remover:

```bash
python uninstall_local.py
```

Também é possível instalar com ferramentas de build Python comuns:

```bash
python -m pip install .
```

A biblioteca não declara dependências de runtime. Esse método pode usar o backend de build configurado no `pyproject.toml`.

## Primeiro exemplo

```python
from traceseed import capture


@capture(operation="process-payment")
def process_payment(order_id: int, token: str) -> None:
    raise ValueError(f"payment rejected for order {order_id}")


process_payment(123, token="secret-token")
```

O erro original continua sendo lançado e um pacote será criado em `.traceseeds/`:

```text
.traceseeds/
└── process-payment-fp_9c41...-2ac39f10.fprint
```

O token é removido antes da persistência.

## Context manager

```python
from traceseed import guard

with guard("import-customers", metadata={"file": "customers.csv"}):
    import_customers()
```

## Captura manual

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

Por padrão, uma falha interna do TraceSeed não substitui a exceção original. Em testes ou ferramentas administrativas, use `strict=True` para receber erros de captura.

## Configuração

```python
from pathlib import Path
from traceseed import TraceSeedConfig, configure

configure(
    TraceSeedConfig(
        output_directory=Path("var/traceseeds"),
        capture_arguments=True,
        capture_locals=True,
        capture_threads=False,
        max_depth=6,
        max_collection_items=80,
    ).with_redact_fields({"cpf", "session_id"})
)
```

## Contexto e breadcrumbs

```python
from traceseed import breadcrumb, context

with context(request_id="req-123", tenant="company-a"):
    breadcrumb("database", "customer loaded", customer_id=42)
    breadcrumb("payment", "gateway request sent")
    process_payment()
```

O contexto usa `contextvars`, portanto permanece isolado entre tasks assíncronas.

## Logs como breadcrumbs

```python
import logging
from traceseed import BreadcrumbHandler

handler = BreadcrumbHandler()
logging.getLogger().addHandler(handler)
```

## Storages

```python
from traceseed import TraceSeedConfig
from traceseed.serialization import SafeSerializer
from traceseed.storage import ArchiveStorage, DirectoryStorage, MemoryStorage

config = TraceSeedConfig()
serializer = SafeSerializer(config)

archive = ArchiveStorage(config, serializer)
directory = DirectoryStorage(config, serializer)
memory = MemoryStorage()
```

O storage pode ser informado por captura:

```python
@capture(storage=memory)
def operation():
    ...
```

Um storage customizado precisa implementar:

```python
class MyStorage:
    name = "my-storage"

    def save(self, record, extra=None):
        ...
```

## Coletores customizados

```python
from traceseed import register_collector


class TenantCollector:
    name = "tenant"

    def collect(self, exception, context, config):
        return {"tenant_runtime": read_current_tenant()}


register_collector(TenantCollector())
```

Coletores defeituosos são registrados em `collector_errors` e não impedem os outros coletores.

## Replay assistido

```python
@capture(operation="calculate-tax", replayable=True)
def calculate_tax(amount, rate):
    return amount * rate
```

O replay só é gerado quando o callable é importável e todos os argumentos são reconstruíveis.

```bash
traceseed replay failure.fprint --allow-code-execution
```

**Atenção:** replay importa módulos e executa código da aplicação. Nunca reproduza um pacote recebido de fonte não confiável.

## CLI

```bash
traceseed show error.fprint
traceseed show error.fprint --json
traceseed verify error.fprint
traceseed list .traceseeds
traceseed compare first.fprint second.fprint
traceseed replay error.fprint --allow-code-execution
```

Sem instalação:

```bash
PYTHONPATH=src python -m traceseed show error.fprint
```

## Testes

```bash
python run_tests.py
```

Ou:

```bash
PYTHONPATH=src:. python -m unittest discover -s tests -v
```

A suíte cobre 145 cenários, incluindo corrupção de pacotes, dados circulares, `repr()` defeituoso, concorrência assíncrona, hooks globais, falhas dos coletores e reprodução.

## Estrutura

```text
src/traceseed/
├── api.py              API pública e hooks
├── engine.py           orquestração da captura
├── config.py           configuração imutável
├── context.py          contexto e breadcrumbs
├── fingerprint.py      agrupamento estável
├── redaction.py        remoção de segredos
├── serialization.py    codec JSON seguro
├── collectors/         coletores independentes
├── storage/            arquivo, diretório e memória
├── replay/             reprodução assistida
└── cli.py              comandos administrativos
```

Leia também:

- `docs/ARCHITECTURE.md`
- `docs/SECURITY.md`
- `docs/EXTENDING.md`
- `CONTRIBUTING.md`

## Limites conhecidos

- Replay não recria automaticamente bancos de dados, rede, arquivos externos ou estado global.
- Objetos arbitrários são representados para diagnóstico, mas não são reconstruídos automaticamente.
- O isolamento do replay não é um sandbox de segurança.
- Capturar locals pode registrar dados sensíveis; mantenha sanitização e limites adequados.

## Licença

MIT.
