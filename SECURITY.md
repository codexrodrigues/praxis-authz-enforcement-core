# Security Policy

`praxis-authz-enforcement-core` implements the 15-step Policy Enforcement Point (`STEP_01..STEP_15`) responsible for header anti-spoofing, pre-hydration write authorization, query side-channel prevention, SQL data-scope pushdown, obligation barriers, and detached DTO masking.

## Reporting a Vulnerability

Do **not** open public issues with exploit payloads, credential material, or confidential tenant data.

Report vulnerabilities privately to the maintainer through GitHub Security Advisories (`codexrodrigues/praxis-authz-enforcement-core`) and provide:

- Affected version or commit;
- Affected component (`UntrustedRequestHeaderGuard`, `JpaDataScopeAdapter`, `DtoWriteIntentExtractor`, `DetachedDtoMaskingProcessor`, `EnforcementPipelineExecutor`, etc.);
- Steps to reproduce without real credentials or secrets;
- Security impact assessment (e.g., tenant scope bypass, `LIKE` wildcard injection, Kleene 3VL false match, or unmasked disclosure).

## Fail-Closed Security Guarantees

- **Header Anti-Spoofing (`P01`, `P42`, `P61`):** `UntrustedRequestHeaderGuard` rejects `x-authz-*`, `x-praxis-authz-*`, `x-bypass-*`, and `x-workflow-*` unconditionally and permits organization headers only to narrow already `PRESENT` server-side `subject.*` facts;
- **Pre-Hydration Write Custody (`P13`, `P14`, `P45`):** `DtoWriteIntentExtractor` fails closed on unmapped keys (`AUTHZ_UNMAPPED_WRITE_WIRE_PATH`), and `FieldWriteAuthorizer` checks `STEP_11` before business rules/persistence run;
- **Mandatory Hard Scope & De Morgan NNF (`P05`, `P06`, `P24`):** `JpaDataScopeAdapter` always composes host `hardScope` via `AND`, escapes `LIKE` literals, and handles Kleene `UNKNOWN` safely;
- **Obligation Barrier Revocation (`P21`, `P22`):** Any unfulfilled or conflicting obligation converts `PERMIT` to `DENY`.

## Credential Hygiene

Never commit HMAC secrets, GPG keys, PATs, or Maven Central tokens. Releases are signed exclusively inside GitHub Actions using protected secrets (see [RELEASING.md](RELEASING.md)).
