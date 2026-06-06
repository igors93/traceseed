# Arquitetura do TraceSeed

## Objetivos

1. API pública pequena e previsível.
2. Falhas internas nunca escondem a exceção original.
3. Dados sensíveis são removidos antes da persistência.
4. Componentes de coleta, serialização e armazenamento podem ser substituídos.
5. O formato `.tseed` é verificável e versionado.
6. A biblioteca padrão do Python é suficiente em runtime e nos testes.

## Fluxo

```text
@capture / guard / capture_exception
                 │
                 ▼
          CaptureContext
                 │
                 ▼
          CaptureEngine
          ├─ collectors
          ├─ redactor
          ├─ fingerprinter
          ├─ serializer
          └─ storage
                 │
                 ▼
          FailureRecord
                 │
                 ▼
       .tseed / diretório / memória
```

## API pública

`api.py` mantém a superfície de uso pequena:

- `capture`
- `guard`
- `capture_exception`
- `register_collector`
- `install`, `uninstall`, `install_asyncio`

Ela cria um `CaptureContext` e entrega a operação ao engine.

## Engine

O `CaptureEngine` é um orquestrador. Ele não contém detalhes específicos de coleta ou I/O. Sua sequência é:

1. Executar coletores isoladamente.
2. Registrar falhas individuais de coletores.
3. Sanitizar exceção, frames, argumentos, contexto e breadcrumbs.
4. Gerar a fingerprint com dados já sanitizados.
5. Avaliar se os argumentos permitem replay.
6. Criar um `FailureRecord` imutável.
7. Persistir pelo protocolo `Storage`.

## Coletores

Cada coletor implementa:

```python
name: str

def collect(exception, context, config) -> dict:
    ...
```

Os coletores nativos são independentes:

- `ExceptionCollector`
- `TracebackCollector`
- `RuntimeCollector`
- `ContextCollector`
- `ThreadCollector`

Uma falha em um coletor não interrompe os demais.

## Sanitização

`Redactor` processa dados recursivamente e possui quatro proteções:

- nomes de campos sensíveis;
- expressões regulares;
- limites de profundidade e tamanho;
- detecção de referências circulares.

A sanitização acontece antes de qualquer chamada ao storage.

## Serialização

`SafeSerializer` converte dados para uma árvore JSON tipada. Ele não usa `pickle`.

Tipos reconstruíveis incluem primitivos, bytes, coleções, datas, `Decimal`, `UUID`, `Path`, enums e dataclasses. Enums e dataclasses exigem autorização de importação no decode.

Objetos arbitrários viram registros `unresolved` para diagnóstico e bloqueiam replay automático.

## Fingerprint

A fingerprint usa SHA-256 sobre uma representação canônica composta por:

- classe da exceção;
- mensagem normalizada;
- frames finais limitados;
- causa imediata.

Valores variáveis como números, UUIDs, tokens longos e endereços hexadecimais são normalizados. O algoritmo possui versão no formato canônico.

## Armazenamento

### ArchiveStorage

Cria um ZIP com extensão `.tseed`. Todos os arquivos diagnósticos recebem SHA-256 no manifesto. A gravação usa arquivo temporário e `os.replace`.

### DirectoryStorage

Cria a mesma estrutura em um diretório, facilitando inspeção durante desenvolvimento.

### MemoryStorage

Mantém `FailureRecord` em memória para testes e integrações.

## Replay

O replay é deliberadamente separado da captura:

1. O pacote precisa conter `replay.json`.
2. O usuário precisa autorizar execução explicitamente.
3. O módulo e o callable são importados.
4. Argumentos são reconstruídos pelo serializer.
5. A função é executada.

Isso é reprodução assistida, não sandbox.

## Compatibilidade

A versão inicial exige Python 3.11 por usar recursos como `ExceptionGroup`, typing moderno e `tomllib` disponível no ecossistema padrão, embora o núcleo não dependa de `tomllib`.
