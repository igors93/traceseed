# Segurança

## Modelo de ameaça

Pacotes de diagnóstico podem conter argumentos, locals, caminhos, mensagens, dados de negócio e contexto de execução. O projeto assume que esses dados podem ser sensíveis.

## Proteções existentes

- Sanitização antes da persistência.
- Lista padrão de nomes sensíveis.
- Redação de bearer tokens e números semelhantes a cartões.
- Limites de profundidade, tamanho de strings e coleções.
- Detecção de ciclos.
- Nenhum uso de `pickle`.
- Hashes SHA-256 dos arquivos do pacote.
- Rejeição de caminhos ZIP com traversal.
- Replay bloqueado sem autorização explícita.
- Falhas internas não substituem a exceção original.

## Recomendações

- Adicione nomes de campos específicos do domínio, como CPF, chaves de sessão e dados médicos.
- Não ative `capture_locals` sem avaliar o risco.
- Restrinja acesso ao diretório de saída.
- Defina retenção e descarte seguro dos pacotes.
- Verifique o pacote antes de compartilhar.
- Nunca execute replay de fonte não confiável.

## Replay não é sandbox

`--allow-code-execution` importa módulos e executa o código indicado no pacote. Hashes garantem integridade em relação ao manifesto, não autenticidade da origem. Uma origem maliciosa pode construir seu próprio manifesto válido.

## Relato de vulnerabilidades

Não publique segredos ou pacotes reais em issues. Crie uma reprodução mínima com dados fictícios.
