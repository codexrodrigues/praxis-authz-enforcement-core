# Contributing to Praxis Authz Enforcement Core

Thank you for contributing to `praxis-authz-enforcement-core`.

## Development Baseline

- **Java:** 21+ (`[21,)` enforced by `maven-enforcer-plugin`)
- **Maven:** 3.9.0 or newer

Run full local verification before submitting changes:

```powershell
mvn -B clean verify
```

Verify that Spring Boot and Hibernate ORM remain absent from the runtime dependency tree:

```powershell
mvn -B dependency:tree -Dscope=runtime
```

## Module Boundary & Enforcer Rules

`praxis-authz-enforcement-core` owns the pure Java PEP enforcement pipeline and persistence-neutral adapters built over `praxis-authz-contracts`:

- **Never** add dependencies on `org.springframework.boot:*`, `org.hibernate.orm:*`, Jakarta Servlet, or OPA HTTP SDKs (`maven-enforcer-plugin` enforces the `org.springframework.boot` and `org.hibernate.orm` ban);
- Keep Rego v1 compilation, OPA bundle assembly, and OPA HTTP clients in `praxis-authz-opa`;
- Keep Spring Boot auto-configuration, MVC filters, JPA Criteria translators, and `praxis-metadata-starter` host bridges in `praxis-authz-starter`.

## Security & Contract Discipline

- Never allow `DataScopeOutcome.ALL` to remove or bypass host `hardScope`;
- Never mutate source/managed JPA entities during DTO projection masking;
- Never silently ignore unmapped JSON wire paths during `WriteIntent` extraction;
- Update Javadoc, `README.md`, and `CHANGELOG.md` whenever pipeline behavior changes, and follow [RELEASING.md](RELEASING.md) for releases.
