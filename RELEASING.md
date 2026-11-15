# Releasing — Praxis Authz Enforcement Core

## Public line

The active public line is `0.1.0-beta.*` under coordinate `io.github.codexrodrigues:praxis-authz-enforcement-core` (current published release: `0.1.0-beta.1`). Compatible corrections remain on this line while downstream modules and hosts validate the enforcement pipeline. A stable `1.0.0` or new major requires a governed compatibility and migration plan.

## Multi-repository release order

This module sets `<praxis-authz.version>${project.version}</praxis-authz.version>` in `pom.xml`, and `release.yml` requires the matching `praxis-authz-contracts:<version>` `.pom` to return `HTTP 200` on `repo1.maven.org` before tagging:

1. `codexrodrigues/praxis-authz-contracts` (must be published first)
2. `codexrodrigues/praxis-authz-enforcement-core` (this repository)
3. `codexrodrigues/praxis-authz-opa`
4. `codexrodrigues/praxis-authz-starter`

## Required repository secrets

- `CENTRAL_TOKEN_USER`
- `CENTRAL_TOKEN_PASS`
- `GPG_PRIVATE_KEY` (ASCII-armored private key block with the mandatory RFC 4880 blank line immediately after `-----BEGIN PGP PRIVATE KEY BLOCK-----`, or base64-encoded binary key export)
- `GPG_PASSPHRASE`
- `GPG_KEY_ID` (optional)
- `RELEASE_PAT`, with `contents: write` permission to push commits and tags on `main`

`RELEASE_PAT` is required because tags pushed by `GITHUB_TOKEN` do not trigger the separate `push: tags: v*` publication workflow.

## Release flow

1. Confirm `io.github.codexrodrigues:praxis-authz-contracts:<version>` is already live (`HTTP 200`) on `repo1.maven.org`.
2. Confirm the intended commit is on remote `main` and local validation passes with JDK 21:

   ```powershell
   mvn -B clean verify
   ```

3. In GitHub Actions, run **Release Praxis Authz Enforcement Core** (`workflow_dispatch`) on `main` with `create_tag=true` and either an explicit `version` matching `praxis-authz-contracts` or `bump`/`preid`.
4. The `create_tag` job verifies `praxis-authz-contracts:<version>` on Maven Central, persists the resolved version in `pom.xml`, creates the annotated `v<semver>` tag, and pushes `HEAD:main` and the tag atomically.
5. The `publish` job verifies tag ancestry on `main`, imports the GPG key, enforces module boundaries (`requireReleaseDeps` and banned Spring/Hibernate/OPA dependencies), runs tests, flattens the published POM (`oss` mode), signs `.pom`/`.jar`/`-sources.jar`/`-javadoc.jar`, publishes via `central-publishing-maven-plugin`, and polls `repo1.maven.org` until the `.pom` returns `HTTP 200`.
6. Only start `praxis-authz-opa` after the Maven Central availability probe in this workflow succeeds.
7. Before running `mvn install` locally for new unreleased work, bump `<version>` to the next `-SNAPSHOT` (e.g. `0.1.0-beta.2-SNAPSHOT`) so local builds do not overwrite published release artifacts in `~/.m2`.
8. Validate published coordinates with an isolated empty local repository (`mvn -B -Dmaven.repo.local=<temp-dir> dependency:tree`) against `repo1.maven.org`; a local Maven install is not release evidence.

Do not create release tags manually, run `mvn deploy` locally, or bypass a failed CI/release gate.
