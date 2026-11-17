# Histórico de Alterações (Changelog)

Todas as mudanças relevantes de `praxis-authz-enforcement-core` são documentadas neste arquivo.

O formato segue o padrão [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), e este projeto adere ao [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Alterado
- `FieldWriteAuthorizer`: suporte completo aos modos neutros de `DualScopeDelegationSpec` (`ORIGIN_DESTINATION_SPLIT`, `ORIGIN_ONLY_WRITE`, `READ_ONLY_DESTINATION`) preservando compatibilidade com os aliases legados, além de parâmetros e Javadocs neutralizados em `FieldWriteAuthorizer` e `EnforcementPipelineExecutor`.
- `UntrustedRequestHeaderGuard`: adiciona o cabeçalho `"x-delegated-destination-org-ids"` mapeado para `"subject.delegatedDestinationOrgIds"`, mantendo compatibilidade retroativa com `"x-delegated-cessionario-org-ids"`.

## [0.1.0-beta.1] - 2026-11-15

### Adicionado
- Publicação beta inicial no Maven Central de `io.github.codexrodrigues:praxis-authz-enforcement-core:0.1.0-beta.1`.
- Orquestrador PEP determinístico de 15 etapas (`EnforcementPipelineExecutor`, `HostDecisionNormalizationEngine`, `executeTargetPipeline(...)` e `executeSearchPipeline(...)`) operando sem Spring Boot ou Hibernate ORM.
- Subsistemas de contexto e anti-spoofing (`UntrustedRequestHeaderGuard`, `ContextCompositionCoordinator` em 4 estágios `EXTRACT -> ENRICH -> DERIVE -> FREEZE`, `ScopedExecutionContextHolder` com limpeza via `try-with-resources`).
- Proteção pré-hidratação de escrita e consulta (`DtoWriteIntentExtractor`, `FieldWriteAuthorizer`, `DualScopeDelegationSpec`, `FieldUseQueryGuard` para `FILTER`, `SORT`, `GROUP`, `AGGREGATE` e `JOIN`).
- Compilador JPQL Kleene 3VL (`JpaDataScopeAdapter`, `CompiledDataScopeCriterion.composedWhereClause()`) com Forma Normal Negativa (De Morgan), subqueries correlacionadas `EXISTS`/`NOT EXISTS`, escape de `LIKE ... ESCAPE '\'` e conjunção obrigatória com `hardScope`.
- Processador desconectado de mascaramento (`DetachedDtoMaskingProcessor.projectAndMask(...)`) garantindo dominância de `FIELD_USE(VALUE)=DENY` sobre o lattice de 7 estratégias.
- Coordenador de barreiras de obrigações (`ObligationBarrierCoordinator`, `TransactionalAuditOutboxPort`) e empacotamento Maven com regras `requireReleaseDeps` e bloqueio de `org.springframework.boot:*` e `org.hibernate.orm:*`.
