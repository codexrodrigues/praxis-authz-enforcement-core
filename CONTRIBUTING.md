# Como Contribuir com `praxis-authz-enforcement-core`

Contribuições para `praxis-authz-enforcement-core` devem preservar a ordem estrita das 15 etapas do PEP, o comportamento *fail-closed* e o desacoplamento total de Spring Boot e Hibernate ORM.

## Regras Arquiteturais de Contribuição

1. **Zero Spring Boot / Zero Hibernate ORM (`BND-OWN-002`):** Este módulo usa apenas contratos de `praxis-authz-contracts`, Jackson, SLF4J e `jakarta.persistence` API padrão. Toda auto-configuração Spring deve permanecer em [`praxis-authz-starter`](https://github.com/codexrodrigues/praxis-authz-starter).
2. **Sem Atalhos no Pipeline `STEP_01`–`STEP_15`:** Nunca antecipe hidratação de entidades nem execução de regras de negócio (`STEP_12`) antes da validação de escrita (`STEP_11`), e nunca entregue resultados sem aplicar `DetachedDtoMaskingProcessor` (`STEP_14`).
3. **Respeito Estrito a Kleene 3VL no Pushdown JPA:** Alterações em `JpaDataScopeAdapter` exigem provas explícitas com campos `NULL`, relacionamentos opcionais e negações compostas (`NOT`).
4. **Exceções Estruturadas e Fail-Closed:** Erros de provedor ou falhas internas de execução nunca podem resultar em autorização permissiva nem vazar valores brutos de campos sigilosos nas mensagens de erro.
5. **Idioma e Clareza:** Padronize guias, comentários novos de documentação e relatórios de PR em PT-BR didático com termos técnicos exatos.

## Verificação Local Obrigatória

```powershell
mvn -B clean verify
```

Leia também [AGENTS.md](AGENTS.md) e [ACTIONS-RELEASE-POLICY.md](ACTIONS-RELEASE-POLICY.md).
