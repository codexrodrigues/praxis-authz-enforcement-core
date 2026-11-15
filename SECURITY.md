# Política de Segurança (`praxis-authz-enforcement-core`)

`praxis-authz-enforcement-core` implementa o pipeline PEP de 15 etapas, guarda anti-spoofing de headers HTTP, análise pré-hidratação de `WriteIntent`, validação de `FIELD_USE`, compilação JPQL Kleene 3VL e mascaramento em projeções desconectadas para a **Praxis Authorization Decision Platform**. Defeitos com impacto de segurança devem ser tratados de forma responsável e privada.

## Reportando uma Vulnerabilidade

**Não** abra issues públicas no GitHub contendo payloads de exploração, dados reais de clientes, segredos HMAC ou detalhes de contorno antes de a correção ser publicada.

Comunique vulnerabilidades em canal privado via **GitHub Security Advisories** (`codexrodrigues/praxis-authz-enforcement-core`), informando:

- Versão, tag ou commit afetado;
- Subsistema envolvido (`context`, `writeintent`, `fielduse`, `jpa`, `masking`, `obligation` ou `pipeline`);
- Passos mínimos de reprodução sem credenciais ou registros reais;
- Impacto de segurança observado (ex.: spoofing de `x-authz-*`, bypass de `FIELD_WRITE` ou `AUTHZ_UNMAPPED_WRITE_WIRE_PATH`, falha em `EXISTS`/`NOT EXISTS` no pushdown JPQL, vazamento de valor sem máscara ou quebra de barreira `ObligationBarrierCoordinator`).

## Invariantes de Segurança por Design

- **Guarda Anti-Spoofing (`UntrustedRequestHeaderGuard`):** Rejeita headers `x-authz-*`, `x-praxis-authz-*`, `x-bypass-*` e `x-workflow-*` vindos de origem não confiável antes do PDP;
- **Ordem Imutável Pré-Hidratação (`STEP_11` antes de `STEP_12`):** `DtoWriteIntentExtractor` e `FieldWriteAuthorizer` validam `SET`/`CLEAR_EXPLICIT_NULL`/`REMOVE` e custódia `DualScopeDelegationSpec` antes que o serviço hidrate a entidade ou acione `PraxisRulesEngine`;
- **Semântica JPQL Segura com `hardScope`:** `JpaDataScopeAdapter` aplica NNF (De Morgan) e jamais remove o `hardScope` do host mesmo em `DataScopeOutcome.ALL`;
- **Mascaramento Desconectado (`STEP_15`):** `DetachedDtoMaskingProcessor` atua somente em projeções desconectadas sem risco de *dirty-checking* JPA, mantendo `FIELD_USE(VALUE)=DENY` dominante.

## Higiene de Credenciais e Releases

- Nunca comite tokens Maven Central, PATs, chaves GPG ou segredos HMAC reais;
- Releases oficiais aguardam `praxis-authz-contracts` e ocorrem exclusivamente em CI conforme [RELEASING.md](RELEASING.md).
