# Contribuindo

## Princípios

- Runtime somente com biblioteca padrão. Zero dependências externas em runtime.
- Para desenvolvimento, testes, lint e tipagem: pytest, Ruff e mypy.
- API pública pequena.
- Exceção original sempre preservada.
- Segurança e sanitização antes de conveniência.
- Cada correção de bug deve incluir teste de regressão.

## Executar testes

```bash
python -m ruff format --check .
python -m ruff check .
python -m mypy src
python -m pytest
```

Para execução mais rápida:

```bash
python -m pytest -q
python -m pytest --maxfail=1
```

## Adicionar testes

Use `pytest` ou `unittest` e mantenha testes independentes de rede, relógio externo e serviços. Para arquivos, use `tmp_path` (pytest) ou `tempfile.TemporaryDirectory`. Não deixe arquivos `.tseed` após os testes.

## Checklist

1. O código compila em Python 3.11+.
2. `ruff format --check`, `ruff check`, `mypy src` e `pytest` passam sem erros.
3. O recurso não adiciona dependência de runtime.
4. Dados sensíveis não são persistidos antes de sanitização.
5. Falhas do novo componente não escondem a exceção original.
6. A documentação foi atualizada.
