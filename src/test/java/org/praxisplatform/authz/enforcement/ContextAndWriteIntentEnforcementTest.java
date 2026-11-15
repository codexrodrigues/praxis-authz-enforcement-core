package org.praxisplatform.authz.enforcement;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode;
import org.praxisplatform.authz.contracts.binding.TransactionCardinality;
import org.praxisplatform.authz.contracts.binding.WriteChangeKind;
import org.praxisplatform.authz.contracts.binding.WriteFieldChange;
import org.praxisplatform.authz.contracts.binding.WriteIntent;
import org.praxisplatform.authz.contracts.context.ContextCompositionProfile;
import org.praxisplatform.authz.contracts.context.ContextEvaluationPhase;
import org.praxisplatform.authz.contracts.context.EvaluationContextSnapshot;
import org.praxisplatform.authz.contracts.context.FactCardinality;
import org.praxisplatform.authz.contracts.context.FactContract;
import org.praxisplatform.authz.contracts.context.FactDescriptor;
import org.praxisplatform.authz.contracts.context.FactPresenceModel;
import org.praxisplatform.authz.contracts.context.FactResolutionStage;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.context.FactSlotNamespace;
import org.praxisplatform.authz.contracts.context.FactUnavailableCause;
import org.praxisplatform.authz.contracts.context.FactValueType;
import org.praxisplatform.authz.contracts.context.ResolvedFactValue;
import org.praxisplatform.authz.contracts.context.TemporalContext;
import org.praxisplatform.authz.contracts.digest.CanonicalDigestCalculator;
import org.praxisplatform.authz.contracts.digest.DigestDomainKind;
import org.praxisplatform.authz.contracts.policy.DualScopeDelegationSpec;
import org.praxisplatform.authz.enforcement.context.ContextCompositionCoordinator;
import org.praxisplatform.authz.enforcement.context.ScopedExecutionContextHolder;
import org.praxisplatform.authz.enforcement.context.TrustedFactSource;
import org.praxisplatform.authz.enforcement.context.UntrustedHeaderSpoofingException;
import org.praxisplatform.authz.enforcement.context.UntrustedRequestHeaderGuard;
import org.praxisplatform.authz.enforcement.writeintent.DtoWriteIntentExtractor;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteAuthorizer;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteViolationException;

/**
 * Conformance tests for {@code CC04} runtime context composition, {@code P01/P02/P04/P42} guards,
 * and {@code CC06} pre-hydration {@link WriteIntent} extraction and {@link DualScopeDelegationSpec}
 * custody enforcement ({@code P16}, {@code P17}).
 */
class ContextAndWriteIntentEnforcementTest {

    @Test
    void p01_p42_untrustedRequestHeadersCannotSpoofTenantRoleOrWorkflowStage() {
        Map<String, ResolvedFactValue> authFacts = Map.of(
                "subject.tenantId", ResolvedFactValue.present("subject.tenantId", "gov-sp"),
                "subject.organizationUnitIds", ResolvedFactValue.present("subject.organizationUnitIds", Set.of(101L, 102L))
        );

        // Matching header within authoritative grant is accepted
        UntrustedRequestHeaderGuard.assertNoAuthoritySpoofingHeaders(
                Map.of("X-Tenant-Id", "gov-sp", "X-Org-Id", "101"),
                authFacts
        );

        // P01: Header attempting to switch tenant to gov-rj -> rejected fail-closed
        assertThrows(UntrustedHeaderSpoofingException.class, () ->
                UntrustedRequestHeaderGuard.assertNoAuthoritySpoofingHeaders(
                        Map.of("X-Tenant-Id", "gov-rj"),
                        authFacts
                )
        );

        // P01: Header attempting to claim ungranted org 999 -> rejected fail-closed
        assertThrows(UntrustedHeaderSpoofingException.class, () ->
                UntrustedRequestHeaderGuard.assertNoAuthoritySpoofingHeaders(
                        Map.of("X-Org-Id", "999"),
                        authFacts
                )
        );

        // P42: Header attempting to inject workflow stage -> rejected fail-closed even if stage is in facts!
        Map<String, ResolvedFactValue> authFactsWithStage = Map.of(
                "subject.tenantId", ResolvedFactValue.present("subject.tenantId", "gov-sp"),
                "subject.organizationUnitIds", ResolvedFactValue.present("subject.organizationUnitIds", Set.of(101L, 102L)),
                "transition.workflowStage", ResolvedFactValue.present("transition.workflowStage", "HOMOLOGADO")
        );
        assertThrows(UntrustedHeaderSpoofingException.class, () ->
                UntrustedRequestHeaderGuard.assertNoAuthoritySpoofingHeaders(
                        Map.of("X-Workflow-Stage", "HOMOLOGADO"),
                        authFactsWithStage
                )
        );

        // P2-R01: Comma-separated multi-value header where one token is outside grant -> rejected fail-closed!
        UntrustedRequestHeaderGuard.assertNoAuthoritySpoofingHeaders(
                Map.of("X-Org-Id", "101, 102"),
                authFacts
        );
        assertThrows(UntrustedHeaderSpoofingException.class, () ->
                UntrustedRequestHeaderGuard.assertNoAuthoritySpoofingHeaders(
                        Map.of("X-Org-Id", "101, 999"),
                        authFacts
                )
        );

        // P2-R01: Unrecognized x-authz-* or x-bypass-* prefix header -> rejected fail-closed!
        assertThrows(UntrustedHeaderSpoofingException.class, () ->
                UntrustedRequestHeaderGuard.assertNoAuthoritySpoofingHeaders(
                        Map.of("X-Authz-Override-Mode", "ALLOW"),
                        authFacts
                )
        );
    }

    @Test
    void p02_p04_contextCoordinatorDistinguishesSixStatesAndScopedHolderCleansUpOnException() {
        FactDescriptor subjectId = new FactDescriptor(
                "subject.principalId",
                FactSlotNamespace.SUBJECT,
                FactValueType.STRING,
                FactCardinality.SCALAR,
                FactPresenceModel.ALWAYS_PRESENT,
                null,
                null,
                FactResolutionStage.EXTRACT,
                Set.of(ContextEvaluationPhase.ADMISSION, ContextEvaluationPhase.TARGET),
                false,
                "INTERNAL",
                "OPERATIONAL",
                Set.of(),
                "HUMAN_RESOURCES_ADMINISTRATION",
                null
        );
        FactDescriptor enrichedOrg = new FactDescriptor(
                "subject.delegatedCessionarioOrgIds",
                FactSlotNamespace.SUBJECT,
                FactValueType.INT64,
                FactCardinality.SET,
                FactPresenceModel.MAY_BE_ABSENT,
                null,
                null,
                FactResolutionStage.ENRICH,
                Set.of(ContextEvaluationPhase.ADMISSION, ContextEvaluationPhase.TARGET),
                false,
                "INTERNAL",
                "OPERATIONAL",
                Set.of(),
                "HUMAN_RESOURCES_ADMINISTRATION",
                null
        );
        FactDescriptor optionalObs = new FactDescriptor(
                "resource.observacao",
                FactSlotNamespace.RESOURCE,
                FactValueType.STRING,
                FactCardinality.SCALAR,
                FactPresenceModel.MAY_BE_ABSENT,
                "ergon.afastamentos.observacao",
                null,
                FactResolutionStage.EXTRACT,
                Set.of(ContextEvaluationPhase.TARGET),
                true,
                "INTERNAL",
                "OPERATIONAL",
                Set.of(),
                "HUMAN_RESOURCES_ADMINISTRATION",
                null
        );

        String fcDigest = CanonicalDigestCalculator.computeDigest(DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, "fc");
        FactContract contract = new FactContract(
                FactContract.SCHEMA_VERSION_V1,
                "fc-afastamentos",
                "1.0.0",
                fcDigest,
                "human-resources.afastamentos",
                Map.of(
                        subjectId.factPath(), subjectId,
                        enrichedOrg.factPath(), enrichedOrg,
                        optionalObs.factPath(), optionalObs
                )
        );
        ContextCompositionProfile profile = new ContextCompositionProfile(
                ContextCompositionProfile.SCHEMA_VERSION_V1,
                "prof-target",
                "resource-operation/human-resources.afastamentos/findById",
                ContextEvaluationPhase.TARGET,
                contract.factContractId(),
                contract.factContractDigest(),
                Set.of("subject.principalId", "subject.delegatedCessionarioOrgIds"),
                Set.of("resource.observacao"),
                200L,
                true
        );

        TrustedFactSource extractSource = new TrustedFactSource() {
            @Override
            public FactResolutionStage stage() {
                return FactResolutionStage.EXTRACT;
            }

            @Override
            public Map<String, ResolvedFactValue> resolveFacts(
                    ContextEvaluationPhase phase,
                    Map<String, FactDescriptor> descriptorsToResolve,
                    Map<String, ResolvedFactValue> alreadyResolved
            ) {
                return Map.of("subject.principalId", ResolvedFactValue.present("subject.principalId", "usr-A"));
            }
        };

        // Failing enricher throws RuntimeException -> P04 requires UNAVAILABLE(SOURCE_ERROR), never ABSENT!
        TrustedFactSource failingEnrichSource = new TrustedFactSource() {
            @Override
            public FactResolutionStage stage() {
                return FactResolutionStage.ENRICH;
            }

            @Override
            public Map<String, ResolvedFactValue> resolveFacts(
                    ContextEvaluationPhase phase,
                    Map<String, FactDescriptor> descriptorsToResolve,
                    Map<String, ResolvedFactValue> alreadyResolved
            ) {
                throw new IllegalStateException("Oracle connection pool timeout");
            }
        };

        ContextCompositionCoordinator coordinator = new ContextCompositionCoordinator(
                List.of(extractSource, failingEnrichSource));
        EvaluationContextSnapshot snap = coordinator.composeSnapshot(
                contract,
                profile,
                new TemporalContext(Instant.now(), ZoneId.of("UTC")),
                Set.of()
        );

        assertEquals(FactResolutionStatus.PRESENT, snap.findFact("subject.principalId").orElseThrow().status());
        assertEquals(FactResolutionStatus.UNAVAILABLE, snap.findFact("subject.delegatedCessionarioOrgIds").orElseThrow().status());
        assertEquals(
                FactUnavailableCause.SOURCE_TIMEOUT,
                snap.findFact("subject.delegatedCessionarioOrgIds").orElseThrow().unavailableCause()
        );
        assertEquals(FactResolutionStatus.ABSENT, snap.findFact("resource.observacao").orElseThrow().status());

        // P02: ScopedExecutionContextHolder cleans up even when an exception unwinds the stack
        assertTrue(ScopedExecutionContextHolder.current().isEmpty());
        assertThrows(RuntimeException.class, () -> {
            try (ScopedExecutionContextHolder.ScopeToken ignored = ScopedExecutionContextHolder.open(snap)) {
                assertEquals("usr-A", ScopedExecutionContextHolder.current().orElseThrow()
                        .findFact("subject.principalId").orElseThrow().value());
                throw new RuntimeException("Simulated worker failure");
            }
        });
        assertTrue(ScopedExecutionContextHolder.current().isEmpty());
    }

    @Test
    void p16_p17_dtoWriteIntentExtractorPreservesFalsyValuesAndDualScopeEnforcesCustody() {
        DtoWriteIntentExtractor extractor = new DtoWriteIntentExtractor();
        Map<String, String> wireMap = Map.of(
                "/substitutoMatricula", "ergon.afastamentos.substituto_matricula",
                "/observacao", "ergon.afastamentos.observacao",
                "/diasDesconto", "ergon.afastamentos.dias_desconto",
                "/remunerado", "ergon.afastamentos.remunerado",
                "/dataInicio", "ergon.afastamentos.data_inicio"
        );

        // Note: /dataInicio is omitted in this PATCH payload; /observacao is explicit null;
        // /diasDesconto is 0; /remunerado is false; /substitutoMatricula is ""
        String rawPatchJson = """
                {
                  "substitutoMatricula": "",
                  "observacao": null,
                  "diasDesconto": 0,
                  "remunerado": false
                }
                """;

        WriteIntent intent = extractor.extractFromJson(
                "UPDATE_PARTIAL",
                true,
                BatchAuthorizationMode.REJECT_ALL,
                TransactionCardinality.SINGLE_ITEM,
                rawPatchJson,
                wireMap
        );

        assertEquals(4, intent.changes().size());
        assertFalse(intent.modifiedAttributeIds().contains("ergon.afastamentos.data_inicio"));

        Map<String, WriteFieldChange> byAttr = intent.changes().stream()
                .collect(java.util.stream.Collectors.toMap(WriteFieldChange::attributeId, c -> c));
        assertEquals(WriteChangeKind.SET, byAttr.get("ergon.afastamentos.substituto_matricula").changeKind());
        assertEquals("", byAttr.get("ergon.afastamentos.substituto_matricula").declaredValueProjection());
        assertEquals(WriteChangeKind.CLEAR_EXPLICIT_NULL, byAttr.get("ergon.afastamentos.observacao").changeKind());
        assertEquals(WriteChangeKind.SET, byAttr.get("ergon.afastamentos.dias_desconto").changeKind());
        assertEquals(0, byAttr.get("ergon.afastamentos.dias_desconto").declaredValueProjection());
        assertEquals(WriteChangeKind.SET, byAttr.get("ergon.afastamentos.remunerado").changeKind());
        assertEquals(false, byAttr.get("ergon.afastamentos.remunerado").declaredValueProjection());

        // P17 (R-07): DualScopeDelegationSpec custody enforcement
        DualScopeDelegationSpec dualScope = new DualScopeDelegationSpec(
                "CEDENTE_CESSIONARIO_SPLIT",
                "resource.lotacaoSetorId",
                "resource.orgaoCessionarioId",
                Set.of("ergon.afastamentos.data_inicio", "ergon.afastamentos.remunerado"),
                Set.of("ergon.afastamentos.substituto_matricula", "ergon.afastamentos.observacao")
        );

        FieldWriteAuthorizer authorizer = new FieldWriteAuthorizer();
        WriteIntent cessionarioValidPatch = extractor.extractFromJson(
                "UPDATE_PARTIAL",
                true,
                BatchAuthorizationMode.REJECT_ALL,
                TransactionCardinality.SINGLE_ITEM,
                "{\"substitutoMatricula\": \"MAT-20499\", \"observacao\": null}",
                wireMap
        );
        // Cessionario can modify substituto_matricula and observacao
        authorizer.enforceDualScopeCustody(cessionarioValidPatch, dualScope, false, true);

        // Cessionario attempting to modify cedente-owned data_inicio or remunerado -> rejected!
        assertThrows(FieldWriteViolationException.class, () ->
                authorizer.enforceDualScopeCustody(intent, dualScope, false, true)
        );

        // P2-R4: Caller matching neither cedente nor cessionario custody is rejected fail-closed!
        assertThrows(FieldWriteViolationException.class, () ->
                authorizer.enforceDualScopeCustody(cessionarioValidPatch, dualScope, false, false)
        );

        // P2-R4: Mode READ_ONLY_CESSIONARIO forbids mutations by a caller holding only cessionario custody!
        DualScopeDelegationSpec readOnlyCessionarioSpec = new DualScopeDelegationSpec(
                "READ_ONLY_CESSIONARIO",
                "resource.lotacaoSetorId",
                "resource.orgaoCessionarioId",
                Set.of("ergon.afastamentos.data_inicio", "ergon.afastamentos.remunerado"),
                Set.of("ergon.afastamentos.substituto_matricula")
        );
        assertThrows(FieldWriteViolationException.class, () ->
                authorizer.enforceDualScopeCustody(cessionarioValidPatch, readOnlyCessionarioSpec, false, true)
        );

        // P2-R03 (P13 / P45): Unmapped business wire field in JSON payload is rejected fail-closed!
        assertThrows(FieldWriteViolationException.class, () ->
                extractor.extractFromJson(
                        "UPDATE_PARTIAL",
                        true,
                        BatchAuthorizationMode.REJECT_ALL,
                        TransactionCardinality.SINGLE_ITEM,
                        "{\"substitutoMatricula\": \"MAT-20499\", \"salarioOculto\": 99999}",
                        wireMap
                )
        );

        // P5-R2 (P13 / P14): Full-replacement PUT (partialPatch == false) emits WriteChangeKind.REMOVE for omitted mapped fields!
        WriteIntent fullPutIntent = extractor.extractFromJson(
                "UPDATE",
                false,
                BatchAuthorizationMode.REJECT_ALL,
                TransactionCardinality.SINGLE_ITEM,
                "{\"substitutoMatricula\": \"MAT-20499\", \"observacao\": \"OK\"}",
                wireMap
        );
        Map<String, WriteFieldChange> putByAttr = fullPutIntent.changes().stream()
                .collect(java.util.stream.Collectors.toMap(WriteFieldChange::attributeId, c -> c));
        assertEquals(WriteChangeKind.REMOVE, putByAttr.get("ergon.afastamentos.data_inicio").changeKind());
        assertEquals(WriteChangeKind.REMOVE, putByAttr.get("ergon.afastamentos.remunerado").changeKind());
        // Cessionario attempting a full PUT that omits cedente-owned fields (which would clear them!) is denied!
        assertThrows(FieldWriteViolationException.class, () ->
                authorizer.enforceDualScopeCustody(fullPutIntent, dualScope, false, true)
        );
    }
}
