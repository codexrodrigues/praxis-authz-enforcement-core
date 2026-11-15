# AGENTS.md — Praxis Authz Enforcement Core

## Escopo e Herança

- Aplica-se a todo o repositório `praxis-authz-enforcement-core`.
- Herda as diretrizes do `AGENTS.md` da raiz do monorepo Praxis (`praxis-plataform`), adicionando as regras locais deste módulo.

## Fronteira Canônica

- Este artefato implementa a execução determinística do PEP em 15 etapas (`STEP_01..STEP_15`) da trilha `decisionKind = AUTHORIZATION`.
- Depende exclusivamente de `praxis-authz-contracts` e Jackson (`jackson-annotations`, `jackson-databind`, `jackson-datatype-jsr310`).
- **Proibido** introduzir dependências de `org.springframework.boot:*` ou `org.hibernate.orm:*` (`maven-enforcer-plugin` falha o build caso apareçam na árvore runtime).
- Compiladores Rego v1 e clientes OPA pertencem a `praxis-authz-opa`; auto-configuração Spring, filtros HTTP e integração com `praxis-metadata-starter` pertencem a `praxis-authz-starter`.

## Invariantes Obrigatórias de Código

- Preservar o encadeamento `STEP_11` (pre-mutation access + `FIELD_WRITE` + custódia dual) estritamente antes de `STEP_12` (`hydrate*` + `PraxisRulesEngine`).
- Nunca mutar DTOs/entidades originais em `DetachedDtoMaskingProcessor`.
- Sempre compor `hardScope` via `AND` em `JpaDataScopeAdapter` e manter semântica Kleene 3VL intacta.
- O repositório deve permanecer buildável de forma autônoma contra dependências publicadas no Maven Central.

## Validação e Economia de GitHub Actions

- Use Java 21 e Maven 3.9+ com `mvn -B clean verify`.
- Não use `mvn install` local como evidência final de release nem execute `mvn deploy` localmente.
- Consulte [ACTIONS-RELEASE-POLICY.md](ACTIONS-RELEASE-POLICY.md) e [RELEASING.md](RELEASING.md) antes de qualquer dispatch ou tag.
