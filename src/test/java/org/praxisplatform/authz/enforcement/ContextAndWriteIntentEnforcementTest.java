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
    @SuppressWarnings("deprecation")
    void p01_p42_untrustedRequestHeadersCannotSpoofTenantRoleOrWorkflowStage() {
        Map<String, ResolvedFactValue> authFacts = Map.of(
                "subject.tenantId", ResolvedFactValue.present("subject.tenantId", "tenant-alpha"),
                "subject.organizationUnitIds", ResolvedFactValue.present("subject.organizationUnitIds", Set.of(101L, 102L)),
                "subject.delegatedDestinationOrgIds", ResolvedFactValue.present("subject.delegatedDestinationOrgIds", Set.of(201L, 202L)),
                "subject.delegatedCessionarioOrgIds", ResolvedFactValue.present("subject.delegatedCessionarioOrgIds", Set.of(301L))
        );

        // Matching headers within authoritative grant are accepted
        UntrustedRequestHeaderGuard.assertNoAuthoritySpoofingHeaders(
                Map.of(
                        "X-Tenant-Id", "tenant-alpha",
                        "X-Org-Id", "101",
                        "X-Delegated-Destination-Org-Ids", "201, 202",
                        "X-Delegated-Cessionario-Org-Ids", "301"
                ),
                authFacts
        );

        // P01: Header attempting to switch tenant to tenant-beta -> rejected fail-closed
        assertThrows(UntrustedHeaderSpoofingException.class, () ->
                UntrustedRequestHeaderGuard.assertNoAuthoritySpoofingHeaders(
                        Map.of("X-Tenant-Id", "tenant-beta"),
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

        // P01: Neutral delegated destination header outside grant -> rejected fail-closed
        assertThrows(UntrustedHeaderSpoofingException.class, () ->
                UntrustedRequestHeaderGuard.assertNoAuthoritySpoofingHeaders(
                        Map.of("X-Delegated-Destination-Org-Ids", "201, 999"),
                        authFacts
                )
        );

        // P01: Legacy delegated org header outside grant -> still rejected fail-closed
        assertThrows(UntrustedHeaderSpoofingException.class, () ->
                UntrustedRequestHeaderGuard.assertNoAuthoritySpoofingHeaders(
                        Map.of("X-Delegated-Cessionario-Org-Ids", "999"),
                        authFacts
                )
        );

        // P42: Header attempting to inject workflow stage -> rejected fail-closed even if stage is in facts!
        Map<String, ResolvedFactValue> authFactsWithStage = Map.of(
                "subject.tenantId", ResolvedFactValue.present("subject.tenantId", "tenant-alpha"),
                "subject.organizationUnitIds", ResolvedFactValue.present("subject.organizationUnitIds", Set.of(101L, 102L)),
                "transition.workflowStage", ResolvedFactValue.present("transition.workflowStage", "APPROVED")
        );
        assertThrows(UntrustedHeaderSpoofingException.class, () ->
                UntrustedRequestHeaderGuard.assertNoAuthoritySpoofingHeaders(
                        Map.of("X-Workflow-Stage", "APPROVED"),
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
                "subject.delegatedDestinationOrgIds",
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
        FactDescriptor optionalNotes = new FactDescriptor(
                "resource.notes",
                FactSlotNamespace.RESOURCE,
                FactValueType.STRING,
                FactCardinality.SCALAR,
                FactPresenceModel.MAY_BE_ABSENT,
                "hr.leave_requests.notes",
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
                "fc-leave-requests",
                "1.0.0",
                fcDigest,
                "human-resources.leave-requests",
                Map.of(
                        subjectId.factPath(), subjectId,
                        enrichedOrg.factPath(), enrichedOrg,
                        optionalNotes.factPath(), optionalNotes
                )
        );
        ContextCompositionProfile profile = new ContextCompositionProfile(
                ContextCompositionProfile.SCHEMA_VERSION_V1,
                "prof-target",
                "resource-operation/human-resources.leave-requests/findById",
                ContextEvaluationPhase.TARGET,
                contract.factContractId(),
                contract.factContractDigest(),
                Set.of("subject.principalId", "subject.delegatedDestinationOrgIds"),
                Set.of("resource.notes"),
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

        // Failing enricher throws RuntimeException -> P04 requires UNAVAILABLE(SOURCE_ERROR/TIMEOUT), never ABSENT!
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
                throw new IllegalStateException("Directory lookup pool timeout");
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
        assertEquals(FactResolutionStatus.UNAVAILABLE, snap.findFact("subject.delegatedDestinationOrgIds").orElseThrow().status());
        assertEquals(
                FactUnavailableCause.SOURCE_TIMEOUT,
                snap.findFact("subject.delegatedDestinationOrgIds").orElseThrow().unavailableCause()
        );
        assertEquals(FactResolutionStatus.ABSENT, snap.findFact("resource.notes").orElseThrow().status());

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
    @SuppressWarnings("deprecation")
    void p16_p17_dtoWriteIntentExtractorPreservesFalsyValuesAndDualScopeEnforcesCustody() {
        DtoWriteIntentExtractor extractor = new DtoWriteIntentExtractor();
        Map<String, String> wireMap = Map.of(
                "/substituteCode", "hr.leave_requests.substitute_code",
                "/notes", "hr.leave_requests.notes",
                "/discountDays", "hr.leave_requests.discount_days",
                "/paid", "hr.leave_requests.paid",
                "/startDate", "hr.leave_requests.start_date"
        );

        // Note: /startDate is omitted in this PATCH payload; /notes is explicit null;
        // /discountDays is 0; /paid is false; /substituteCode is ""
        String rawPatchJson = """
                {
                  "substituteCode": "",
                  "notes": null,
                  "discountDays": 0,
                  "paid": false
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
        assertFalse(intent.modifiedAttributeIds().contains("hr.leave_requests.start_date"));

        Map<String, WriteFieldChange> byAttr = intent.changes().stream()
                .collect(java.util.stream.Collectors.toMap(WriteFieldChange::attributeId, c -> c));
        assertEquals(WriteChangeKind.SET, byAttr.get("hr.leave_requests.substitute_code").changeKind());
        assertEquals("", byAttr.get("hr.leave_requests.substitute_code").declaredValueProjection());
        assertEquals(WriteChangeKind.CLEAR_EXPLICIT_NULL, byAttr.get("hr.leave_requests.notes").changeKind());
        assertEquals(WriteChangeKind.SET, byAttr.get("hr.leave_requests.discount_days").changeKind());
        assertEquals(0, byAttr.get("hr.leave_requests.discount_days").declaredValueProjection());
        assertEquals(WriteChangeKind.SET, byAttr.get("hr.leave_requests.paid").changeKind());
        assertEquals(false, byAttr.get("hr.leave_requests.paid").declaredValueProjection());

        // P17 (R-07): Neutral DualScopeDelegationSpec custody enforcement
        DualScopeDelegationSpec dualScope = DualScopeDelegationSpec.ofOriginAndDestination(
                DualScopeDelegationSpec.ORIGIN_DESTINATION_SPLIT,
                "resource.originOrgId",
                "resource.destinationOrgId",
                Set.of("hr.leave_requests.start_date", "hr.leave_requests.paid"),
                Set.of("hr.leave_requests.substitute_code", "hr.leave_requests.notes")
        );

        FieldWriteAuthorizer authorizer = new FieldWriteAuthorizer();
        WriteIntent destinationValidPatch = extractor.extractFromJson(
                "UPDATE_PARTIAL",
                true,
                BatchAuthorizationMode.REJECT_ALL,
                TransactionCardinality.SINGLE_ITEM,
                "{\"substituteCode\": \"EMP-20499\", \"notes\": null}",
                wireMap
        );
        WriteIntent originValidPatch = extractor.extractFromJson(
                "UPDATE_PARTIAL",
                true,
                BatchAuthorizationMode.REJECT_ALL,
                TransactionCardinality.SINGLE_ITEM,
                "{\"startDate\": \"2026-11-20\", \"paid\": false}",
                wireMap
        );

        // Destination can modify substitute_code and notes
        authorizer.enforceDualScopeCustody(destinationValidPatch, dualScope, false, true);
        // Origin can modify start_date and paid
        authorizer.enforceDualScopeCustody(originValidPatch, dualScope, true, false);

        // Destination attempting to modify origin-owned start_date or paid (via ungranted paid/discountDays) -> rejected!
        assertThrows(FieldWriteViolationException.class, () ->
                authorizer.enforceDualScopeCustody(intent, dualScope, false, true)
        );

        // P2-R4: Caller matching neither origin nor destination custody is rejected fail-closed!
        assertThrows(FieldWriteViolationException.class, () ->
                authorizer.enforceDualScopeCustody(destinationValidPatch, dualScope, false, false)
        );

        // P2-R4: Modes ORIGIN_ONLY_WRITE and READ_ONLY_DESTINATION forbid mutations by a caller holding only destination custody!
        DualScopeDelegationSpec originOnlySpec = DualScopeDelegationSpec.ofOriginAndDestination(
                DualScopeDelegationSpec.ORIGIN_ONLY_WRITE,
                "resource.originOrgId",
                "resource.destinationOrgId",
                Set.of("hr.leave_requests.start_date", "hr.leave_requests.paid"),
                Set.of("hr.leave_requests.substitute_code")
        );
        authorizer.enforceDualScopeCustody(originValidPatch, originOnlySpec, true, false);
        assertThrows(FieldWriteViolationException.class, () ->
                authorizer.enforceDualScopeCustody(destinationValidPatch, originOnlySpec, false, true)
        );

        DualScopeDelegationSpec readOnlyDestinationSpec = DualScopeDelegationSpec.ofOriginAndDestination(
                DualScopeDelegationSpec.READ_ONLY_DESTINATION,
                "resource.originOrgId",
                "resource.destinationOrgId",
                Set.of("hr.leave_requests.start_date", "hr.leave_requests.paid"),
                Set.of("hr.leave_requests.substitute_code")
        );
        assertThrows(FieldWriteViolationException.class, () ->
                authorizer.enforceDualScopeCustody(destinationValidPatch, readOnlyDestinationSpec, false, true)
        );

        // Backward compatibility: legacy split mode aliases still enforce identically
        DualScopeDelegationSpec legacySplitSpec = new DualScopeDelegationSpec(
                DualScopeDelegationSpec.CEDENTE_CESSIONARIO_SPLIT,
                "resource.originOrgId",
                "resource.destinationOrgId",
                Set.of("hr.leave_requests.start_date", "hr.leave_requests.paid"),
                Set.of("hr.leave_requests.substitute_code", "hr.leave_requests.notes")
        );
        authorizer.enforceDualScopeCustody(destinationValidPatch, legacySplitSpec, false, true);
        DualScopeDelegationSpec legacyReadOnlySpec = new DualScopeDelegationSpec(
                DualScopeDelegationSpec.READ_ONLY_CESSIONARIO,
                "resource.originOrgId",
                "resource.destinationOrgId",
                Set.of("hr.leave_requests.start_date", "hr.leave_requests.paid"),
                Set.of("hr.leave_requests.substitute_code")
        );
        assertThrows(FieldWriteViolationException.class, () ->
                authorizer.enforceDualScopeCustody(destinationValidPatch, legacyReadOnlySpec, false, true)
        );

        // P2-R03 (P13 / P45): Unmapped business wire field in JSON payload is rejected fail-closed!
        assertThrows(FieldWriteViolationException.class, () ->
                extractor.extractFromJson(
                        "UPDATE_PARTIAL",
                        true,
                        BatchAuthorizationMode.REJECT_ALL,
                        TransactionCardinality.SINGLE_ITEM,
                        "{\"substituteCode\": \"EMP-20499\", \"hiddenSalary\": 99999}",
                        wireMap
                )
        );

        // P5-R2 (P13 / P14): Full-replacement PUT (partialPatch == false) emits WriteChangeKind.REMOVE for omitted mapped fields!
        WriteIntent fullPutIntent = extractor.extractFromJson(
                "UPDATE",
                false,
                BatchAuthorizationMode.REJECT_ALL,
                TransactionCardinality.SINGLE_ITEM,
                "{\"substituteCode\": \"EMP-20499\", \"notes\": \"OK\"}",
                wireMap
        );
        Map<String, WriteFieldChange> putByAttr = fullPutIntent.changes().stream()
                .collect(java.util.stream.Collectors.toMap(WriteFieldChange::attributeId, c -> c));
        assertEquals(WriteChangeKind.REMOVE, putByAttr.get("hr.leave_requests.start_date").changeKind());
        assertEquals(WriteChangeKind.REMOVE, putByAttr.get("hr.leave_requests.paid").changeKind());
        // Destination attempting a full PUT that omits origin-owned fields (which would clear them!) is denied!
        assertThrows(FieldWriteViolationException.class, () ->
                authorizer.enforceDualScopeCustody(fullPutIntent, dualScope, false, true)
        );
    }
}
