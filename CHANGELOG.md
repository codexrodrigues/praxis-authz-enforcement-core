# Changelog

All notable changes to `praxis-authz-enforcement-core` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-beta.1] - 2026-11-15

### Added
- Initial Maven Central beta publication of `io.github.codexrodrigues:praxis-authz-enforcement-core:0.1.0-beta.1`.
- Complete 15-step authorization enforcement runtime (`EnforcementPipelineExecutor`, `HostDecisionNormalizationEngine`, `AuthorizationProviderPort`) implementing `executeTargetPipeline(...)` and `executeSearchPipeline(...)`.
- Zero-trust header guard (`UntrustedRequestHeaderGuard`) and 4-stage context composition coordinator (`ContextCompositionCoordinator`, `ScopedExecutionContextHolder`).
- Pre-hydration `DtoWriteIntentExtractor` and `DualScopeDelegationSpec`-aware `FieldWriteAuthorizer`.
- Inference-channel guard (`FieldUseQueryGuard`) across `FILTER`, `SORT`, `GROUP`, `AGGREGATE`, and `JOIN`.
- Kleene 3VL-safe `JpaDataScopeAdapter` with De Morgan NNF pushdown, correlated `EXISTS`/`NOT EXISTS` subqueries, escaped `LIKE` predicates, case-insensitive `LOWER(...)` alignment, and mandatory `AND` composition with host `hardScope`.
- Non-mutating `DetachedDtoMaskingProcessor` and barrier-scoped `ObligationBarrierCoordinator`.
- Reproducible Maven release build with `flatten-maven-plugin` (`oss`), GPG signing, and Maven Enforcer rules banning Spring Boot and Hibernate ORM runtime dependencies.
