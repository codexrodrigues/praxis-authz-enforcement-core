# Praxis Authz Enforcement Core

Deterministic 15-step authorization enforcement runtime for the Praxis Authorization Decision Platform, built strictly on `praxis-authz-contracts` without Spring Boot or Hibernate ORM runtime dependencies.

## Highlights

- **15-Step Pipeline:** `EnforcementPipelineExecutor` and `HostDecisionNormalizationEngine` normalize allow/deny, `DataScopePlan`, field-use, write-intent, masking, and obligation outcomes fail-closed.
- **Pre-Hydration Write Governance:** `DtoWriteIntentExtractor` and `FieldWriteAuthorizer` inspect canonical `WriteIntent` payloads before persistence.
- **Query & Scope Enforcement:** `FieldUseQueryGuard` prevents inference on restricted filter/sort/group/aggregate fields, while `JpaDataScopeAdapter` compiles Kleene 3VL-safe JPQL predicates with explicit null guards and correlated `EXISTS` / `NOT EXISTS` subqueries.
- **Post-Read Protection & Obligations:** `DetachedDtoMaskingProcessor` applies fail-closed DTO field masking and conflict detection, and `ObligationBarrierCoordinator` coordinates transactional audit outbox barriers.

## Maven Coordinates

```xml
<dependency>
    <groupId>io.github.codexrodrigues</groupId>
    <artifactId>praxis-authz-enforcement-core</artifactId>
    <version>0.1.0-beta.1</version>
</dependency>
```

## License

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
