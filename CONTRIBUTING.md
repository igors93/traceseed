# Contribuindo

## Princípios

- Runtime somente com biblioteca padrão.
- API pública pequena.
- Exceção original sempre preservada.
- Segurança e sanitização antes de conveniência.
- Cada correção de bug deve incluir teste de regressão.

## Executar testes

```bash
python run_tests.py
```

## Adicionar testes

Use `unittest` e mantenha testes independentes de rede, relógio externo e serviços. Para arquivos, use `tempfile.TemporaryDirectory`.

## Checklist

1. O código compila em Python 3.11+.
2. Todos os testes passam.
3. O recurso não adiciona dependência de runtime.
4. Dados sensíveis não são persistidos antes de sanitização.
5. Falhas do novo componente não escondem a exceção original.
6. A documentação foi atualizada.
