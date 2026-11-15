# Guia de Release (`praxis-authz-enforcement-core`)

Este repositório segue a [Política de Releases e GitHub Actions](ACTIONS-RELEASE-POLICY.md) para garantir que cada artefato publicado no Maven Central permaneça sincronizado com `praxis-authz-contracts`.

## Pré-requisitos do Ambiente

- **Java:** `[21,)` com target Java 21
- **Apache Maven:** `3.9.0` ou superior
- **GPG & Central Portal:** segredos `CENTRAL_TOKEN_USER`, `CENTRAL_TOKEN_PASS`, `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`, `GPG_KEY_ID` e `RELEASE_PAT` configurados no repositório para execução em CI

## Ordem de Publicação Multi-Repositório

`praxis-authz-enforcement-core` ocupa o **Nível 1** da cadeia de build:

1. `praxis-authz-contracts` *(deve estar previamente disponível no Maven Central na versão exata declarada)*
2. **`praxis-authz-enforcement-core`** e `praxis-authz-opa` *(Nível 1)*
3. `praxis-authz-starter` *(aguarda todos os módulos anteriores)*

O `maven-enforcer-plugin` aplica `requireReleaseDeps`, impedindo o release caso exista dependência `-SNAPSHOT`.

## Verificação Local Pré-Release

Antes de acionar a release via workflow:

```powershell
mvn -B clean verify
```

Confirme que:
- Todas as verificações de conformidade e testes JPA/pipeline passaram;
- Não há dependências `-SNAPSHOT` nem acoplamento proibido a `org.springframework.boot:*` ou `org.hibernate.orm:*`;
- O `CHANGELOG.md` documenta a versão exata da tag a ser publicada.

## Fluxo Oficial no GitHub Actions

- `ci.yml` executa **somente** por `workflow_dispatch`;
- `release.yml` executa via `workflow_dispatch` ou tag `v*` aprovada, publicando o artefato assinado no Sonatype Central Portal via `central-publishing-maven-plugin`.
