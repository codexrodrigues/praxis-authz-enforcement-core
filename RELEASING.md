# Guia de Release — Praxis Authz Enforcement Core

## Linha Pública

A linha pública ativa é `0.1.0-beta.*` sob a coordenada `io.github.codexrodrigues:praxis-authz-enforcement-core` (release atual publicada: `0.1.0-beta.1`). Correções compatíveis seguem nesta linha enquanto módulos downstream e hosts validam o runtime PEP.

Este repositório segue a [Política de Releases e GitHub Actions](ACTIONS-RELEASE-POLICY.md).

## Ordem Sequencial de Publicação Multi-Repositório (4 Etapas)

Como os módulos downstream vinculam `<praxis-authz.version>${project.version}</praxis-authz.version>` e o `release.yml` valida os arquivos `.pom` upstream no `repo1.maven.org` antes de criar a tag, execute as releases **estritamente em ordem sequencial**:

1. `codexrodrigues/praxis-authz-contracts` *(deve retornar `HTTP 200` no Maven Central antes deste módulo)*
2. **`codexrodrigues/praxis-authz-enforcement-core`** *(este repositório — publica após `contracts`)*
3. `codexrodrigues/praxis-authz-opa` *(valida `praxis-authz-contracts` e `praxis-authz-enforcement-core` no Maven Central)*
4. `codexrodrigues/praxis-authz-starter` *(valida todos os três módulos anteriores no Maven Central)*

Todos os quatro módulos de uma onda coordenada devem publicar exatamente a mesma string SemVer. O `maven-enforcer-plugin` aplica ainda `requireReleaseDeps`, impedindo qualquer dependência `-SNAPSHOT`.

## Segredos Obrigatórios no Repositório

- `CENTRAL_TOKEN_USER`
- `CENTRAL_TOKEN_PASS`
- `GPG_PRIVATE_KEY` (bloco ASCII-armored com a linha em branco obrigatória pela RFC 4880 imediatamente após `-----BEGIN PGP PRIVATE KEY BLOCK-----`, ou exportação binária codificada em base64)
- `GPG_PASSPHRASE`
- `GPG_KEY_ID` (opcional)
- `RELEASE_PAT`, com permissão `contents: write` para enviar commits e tags para `main`

`RELEASE_PAT` é obrigatório porque tags enviadas via `GITHUB_TOKEN` não disparam o workflow separado com gatilho `push: tags: v*`.

## Fluxo Oficial de Release

1. Confirme que `praxis-authz-contracts` na mesma versão já está acessível no Maven Central (`repo1.maven.org`), que o working tree está limpo e a validação local passa com JDK 21 (`[21,)`) e Maven `3.9.0+`:

   ```powershell
   mvn -B clean verify
   ```

2. No GitHub Actions, execute **Release Praxis Authz Enforcement Core** (`workflow_dispatch`) em `main` com `create_tag=true` informando `version` ou `bump`/`preid`.
3. O job `create_tag` verifica a presença do `.pom` upstream em `repo1.maven.org`, persiste a versão no `pom.xml`, cria a tag anotada `v<semver>` e envia `HEAD:main` e a tag atomicamente.
4. O job `publish` valida ancestralidade da tag, importa a chave GPG, impõe fronteiras de módulo (`maven-enforcer-plugin`), roda os testes, gera o POM achatado (`flatten-maven-plugin`, modo `oss`), assina `.pom`/`.jar`/`-sources.jar`/`-javadoc.jar`, publica via `central-publishing-maven-plugin` e aguarda `HTTP 200` do `.pom` em `repo1.maven.org`.
5. Somente inicie `praxis-authz-opa` após o probe deste workflow no Maven Central concluir com sucesso.
6. Após a publicação, caso desenvolva alterações inéditas localmente com `mvn install`, avance antes `<version>` para o próximo `-SNAPSHOT` para não sobrescrever o artefato de release em `~/.m2`.
7. Valide as coordenadas publicadas usando um repositório local temporário isolado e vazio contra `repo1.maven.org`:

   ```powershell
   mvn -B -Dmaven.repo.local=<temp-dir> dependency:tree
   ```

Nunca crie tags de release manualmente, não execute `mvn deploy` localmente nem contorne gates reprovados.
