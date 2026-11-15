# Como Contribuir com `praxis-authz-enforcement-core`

Contribuições para `praxis-authz-enforcement-core` devem preservar a ordem estrita das 15 etapas do PEP, o comportamento *fail-closed* e o desacoplamento total de Spring Boot e Hibernate ORM.

## Baseline de Desenvolvimento

- **Java:** 21 (`[21,)` imposto pelo `maven-enforcer-plugin`)
- **Apache Maven:** `3.9.0` ou superior

Execute a verificação completa e confirme a árvore de dependências de runtime (somente `praxis-authz-contracts` e Jackson `2.18.2`):

```powershell
mvn -B clean verify
mvn -B dependency:tree -Dscope=runtime
```

## Regras Arquiteturais de Contribuição (`BND-OWN-002`)

1. **Zero Spring Boot / Zero Hibernate ORM:** Este módulo usa apenas contratos de [`praxis-authz-contracts`](https://github.com/codexrodrigues/praxis-authz-contracts), Jackson `2.18.2`, API padrão `jakarta.persistence` (compile-only/bridge) e SLF4J. Toda auto-configuração Spring pertence a [`praxis-authz-starter`](https://github.com/codexrodrigues/praxis-authz-starter).
2. **Sem Atalhos no Pipeline `STEP_01`–`STEP_15`:** Nunca antecipe hidratação de entidades nem execução de regras de negócio (`STEP_12`) antes da validação de escrita (`STEP_11`), e nunca entregue resultados sem aplicar `DetachedDtoMaskingProcessor` (`STEP_15`).
3. **Respeito Estrito a Kleene 3VL no Pushdown JPA:** Alterações em `JpaDataScopeAdapter` exigem provas explícitas com campos `NULL`, relacionamentos opcionais (`EXISTS`/`NOT EXISTS`), negações compostas em NNF (De Morgan) e preservação obrigatória do `hardScope` via `AND`.
4. **Exceções Estruturadas e Fail-Closed:** Falhas de execução ou cabeçalhos falsificados nunca podem degradar para autorização permissiva nem expor valores brutos de campos sensíveis.
5. **Idioma e Clareza:** Padronize guias, JavaDocs e melhorias de documentação em **PT-BR** claro e didático, mantendo os nomes técnicos exatos da API.

## Governança e Releases

- Nunca comite segredos, chaves GPG, tokens ou segredos HMAC reais;
- Siga [RELEASING.md](RELEASING.md), [AGENTS.md](AGENTS.md) e [ACTIONS-RELEASE-POLICY.md](ACTIONS-RELEASE-POLICY.md).
