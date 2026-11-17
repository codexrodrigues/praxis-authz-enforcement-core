package org.praxisplatform.authz.enforcement;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.time.ZoneId;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.contracts.authority.EffectiveAuthorityBinding;
import org.praxisplatform.authz.contracts.authority.ExecutionDispositionMode;
import org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode;
import org.praxisplatform.authz.contracts.binding.EnforcementPipelineStep;
import org.praxisplatform.authz.contracts.binding.HostEnforcementPhase;
import org.praxisplatform.authz.contracts.binding.ReadinessEvidenceOverlay;
import org.praxisplatform.authz.contracts.binding.ReadinessStage;
import org.praxisplatform.authz.contracts.binding.RuntimeEnforcementBinding;
import org.praxisplatform.authz.contracts.binding.TransactionCardinality;
import org.praxisplatform.authz.contracts.binding.WriteChangeKind;
import org.praxisplatform.authz.contracts.binding.WriteFieldChange;
import org.praxisplatform.authz.contracts.binding.WriteIntent;
import org.praxisplatform.authz.contracts.context.ContextCompositionProfile;
import org.praxisplatform.authz.contracts.context.ContextEvaluationPhase;
import org.praxisplatform.authz.contracts.context.FactCardinality;
import org.praxisplatform.authz.contracts.context.FactContract;
import org.praxisplatform.authz.contracts.context.FactDescriptor;
import org.praxisplatform.authz.contracts.context.FactPresenceModel;
import org.praxisplatform.authz.contracts.context.FactResolutionStage;
import org.praxisplatform.authz.contracts.context.FactSlotNamespace;
import org.praxisplatform.authz.contracts.context.FactValueType;
import org.praxisplatform.authz.contracts.context.ProviderInputProjection;
import org.praxisplatform.authz.contracts.context.ResolvedFactValue;
import org.praxisplatform.authz.contracts.context.TemporalContext;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointIdentity;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointRef;
import org.praxisplatform.authz.contracts.decisionpoint.EnforcementCapability;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.decisionpoint.PointAuthorityMode;
import org.praxisplatform.authz.contracts.digest.CanonicalDigestCalculator;
import org.praxisplatform.authz.contracts.digest.DigestDomainKind;
import org.praxisplatform.authz.contracts.envelope.ContributionAuthority;
import org.praxisplatform.authz.contracts.envelope.EnforcementDisposition;
import org.praxisplatform.authz.contracts.envelope.FieldWriteEffectDirective;
import org.praxisplatform.authz.contracts.envelope.GateOutcome;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;
import org.praxisplatform.authz.contracts.envelope.ObligationDirective;
import org.praxisplatform.authz.contracts.envelope.PolicyUnitContributionTrace;
import org.praxisplatform.authz.contracts.envelope.ProviderEvaluationEnvelope;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;
import org.praxisplatform.authz.contracts.obligation.DefaultObligationHandlerRegistry;
import org.praxisplatform.authz.enforcement.context.ContextCompositionCoordinator;
import org.praxisplatform.authz.enforcement.context.TrustedFactSource;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseQueryGuard;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingResult;
import org.praxisplatform.authz.enforcement.masking.DtoFieldSchemaMetadata;
import org.praxisplatform.authz.enforcement.masking.MaskingConflictException;
import org.praxisplatform.authz.enforcement.obligation.InMemoryTransactionalAuditOutbox;
import org.praxisplatform.authz.enforcement.obligation.ObligationBarrierCoordinator;
import org.praxisplatform.authz.enforcement.pipeline.AuthorizationProviderPort;
import org.praxisplatform.authz.enforcement.pipeline.EnforcementPipelineExecutor;
import org.praxisplatform.authz.enforcement.pipeline.HostDecisionNormalizationEngine;
import org.praxisplatform.authz.enforcement.pipeline.NormalizedEnforcementOutcome;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteAuthorizer;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteViolationException;

/**
 * Conformance tests for {@code CC09} {@link DetachedDtoMaskingProcessor} ({@code P15}, {@code P40}),
 * {@code CC10} {@link ObligationBarrierCoordinator} ({@code P22}, {@code ENF-OBL-003}), and the
 * 15-step {@link EnforcementPipelineExecutor} ({@code R-11}).
 */
class MaskingObligationAnd15StepPipelineTest {

    @Test
    void p15_p40_detachedDtoMaskingProcessorNeverMutatesSourceAndRespectsFieldUseDenyPrecedence() {
        DetachedDtoMaskingProcessor processor = new DetachedDtoMaskingProcessor();

        Map<String, Object> managedEntityOrDto = new LinkedHashMap<>();
        managedEntityOrDto.put("id", 42L);
        managedEntityOrDto.put("medicalCode", "J11.0");
        managedEntityOrDto.put("employeeTaxId", "123.456.789-01");
        managedEntityOrDto.put("medicalNotes", "Detailed medical assessment notes");

        List<DtoFieldSchemaMetadata> schemas = List.of(
                new DtoFieldSchemaMetadata("medicalCode", "hr.leave_requests.medical_code", FactValueType.STRING, false),
                new DtoFieldSchemaMetadata("employeeTaxId", "hr.employees.tax_id", FactValueType.STRING, false),
                new DtoFieldSchemaMetadata("medicalNotes", "hr.leave_requests.medical_notes", FactValueType.STRING, true)
        );

        DetachedDtoMaskingResult result = processor.projectAndMask(
                managedEntityOrDto,
                schemas,
                Set.of("hr.leave_requests.medical_notes"), // FIELD_USE(VALUE)=DENY -> omitted completely!
                List.of(
                        new MaskDirective("hr.leave_requests.medical_code", "REDACT_CONSTANT", Map.of("replacement", "***RESTRICTED-CODE***")),
                        new MaskDirective("hr.employees.tax_id", "CPF_CNPJ_PARTIAL", Map.of()),
                        new MaskDirective("hr.leave_requests.medical_notes", "PARTIAL_MASK", Map.of("visiblePrefix", 2, "visibleSuffix", 2))
                )
        );

        // Source map/entity is untouched (P15 / P40: no dirty-checking corruption!)
        assertEquals("J11.0", managedEntityOrDto.get("medicalCode"));
        assertEquals("123.456.789-01", managedEntityOrDto.get("employeeTaxId"));
        assertEquals("Detailed medical assessment notes", managedEntityOrDto.get("medicalNotes"));

        // Detached projection has masked/omitted values
        assertEquals("***RESTRICTED-CODE***", result.detachedProjection().get("medicalCode"));
        assertEquals("***.***.***-01", result.detachedProjection().get("employeeTaxId"));
        assertFalse(result.detachedProjection().containsKey("medicalNotes"));
        assertEquals("OMIT_BY_FIELD_USE_DENY", result.appliedStrategiesByAttributeId().get("hr.leave_requests.medical_notes"));

        // NULLIFY on non-nullable medicalCode must throw MaskingConflictException (ENF-MSK-005)
        assertThrows(MaskingConflictException.class, () ->
                processor.projectAndMask(
                        managedEntityOrDto,
                        schemas,
                        Set.of(),
                        List.of(new MaskDirective("hr.leave_requests.medical_code", "NULLIFY", Map.of()))
                )
        );

        // P2-R06 (P12 / P25 / P36): Nested map & collection masking + per-row page masking without cross-row leakage
        Map<String, Object> nestedRecord = new LinkedHashMap<>();
        nestedRecord.put("id", 99L);
        nestedRecord.put("employee", new LinkedHashMap<>(Map.of("taxId", "111.222.333-44", "name", "Maria")));
        nestedRecord.put("dependents", List.of(
                new LinkedHashMap<>(Map.of("name", "Dependent 1", "taxId", "555.666.777-88"))
        ));
        List<DtoFieldSchemaMetadata> nestedSchemas = List.of(
                new DtoFieldSchemaMetadata("employee.taxId", "hr.employees.tax_id", FactValueType.STRING, false),
                new DtoFieldSchemaMetadata("dependents[].taxId", "hr.dependents.tax_id", FactValueType.STRING, false)
        );
        DetachedDtoMaskingResult nestedMasked = processor.projectAndMask(
                nestedRecord,
                nestedSchemas,
                Set.of("hr.dependents.tax_id"),
                List.of(new MaskDirective("hr.employees.tax_id", "CPF_CNPJ_PARTIAL", Map.of()))
        );
        @SuppressWarnings("unchecked")
        Map<String, Object> maskedEmployee = (Map<String, Object>) nestedMasked.detachedProjection().get("employee");
        assertEquals("***.***.***-44", maskedEmployee.get("taxId"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> maskedDeps = (List<Map<String, Object>>) nestedMasked.detachedProjection().get("dependents");
        assertFalse(maskedDeps.get(0).containsKey("taxId"));

        // P23 (P2-R05): Monotonic step guard rejects out-of-order pipeline steps fail-closed
        assertThrows(IllegalStateException.class, () -> {
            List<EnforcementPipelineStep> steps = new java.util.ArrayList<>();
            EnforcementPipelineExecutor.recordStep(steps, EnforcementPipelineStep.STEP_07_INJECT_DATA_SCOPE_PLAN);
            EnforcementPipelineExecutor.recordStep(steps, EnforcementPipelineStep.STEP_03_GUARD_QUERY_FIELD_USE);
        });
    }

    @Test
    void r11_p22_pipelineEnforcesStep11BeforeStep12AndRevokesPermitWhenAuditOutboxFails() {
        String digest = CanonicalDigestCalculator.computeDigest(DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, "dp");
        DecisionPointIdentity dpId = DecisionPointIdentity.resourceOperation(
                "workforce-service", "human-resources.leave-requests", "assignSubstitute");
        RuntimeEnforcementBinding binding = new RuntimeEnforcementBinding(
                RuntimeEnforcementBinding.SCHEMA_VERSION_V1,
                "bind-patch",
                new DecisionPointRef(dpId.pointKey(), dpId.pointKind(), dpId.serviceKey(), dpId.resourceKey(), dpId.operationOrActionKey(), digest),
                EvaluationMode.TARGET,
                EnforcementCapability.FIELD_WRITE,
                Set.of(FieldUseCategory.VALUE),
                HostEnforcementPhase.PRE_MUTATION,
                "OPA_REGO_V1",
                PointAuthorityMode.AUTHORITATIVE,
                "praxis.enforcement-profile.spring-jpa/v1",
                "DefaultPatchHandler/v1",
                "praxis.authz-host-contract/v1",
                BatchAuthorizationMode.REJECT_ALL,
                TransactionCardinality.SINGLE_ITEM,
                digest,
                new ReadinessEvidenceOverlay(
                        Set.of(
                                ReadinessStage.STRUCTURAL_READY,
                                ReadinessStage.POLICY_READY,
                                ReadinessStage.PROVIDER_READY,
                                ReadinessStage.ENFORCEMENT_READY),
                        "rev-1",
                        digest,
                        Instant.now()
                )
        );
        EffectiveAuthorityBinding authorityBinding = new EffectiveAuthorityBinding(
                "AUTHORITATIVE",
                ExecutionDispositionMode.AUTHORITATIVE_EXECUTION,
                PointAuthorityMode.AUTHORITATIVE
        );

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
        FactContract factContract = new FactContract(
                FactContract.SCHEMA_VERSION_V1,
                "fc-1",
                "1.0.0",
                digest,
                "human-resources.leave-requests",
                Map.of("subject.principalId", subjectId)
        );
        ContextCompositionProfile profile = new ContextCompositionProfile(
                ContextCompositionProfile.SCHEMA_VERSION_V1,
                "prof-1",
                dpId.pointKey(),
                ContextEvaluationPhase.TARGET,
                factContract.factContractId(),
                factContract.factContractDigest(),
                Set.of("subject.principalId"),
                Set.of(),
                200L,
                true
        );
        ContextCompositionCoordinator contextCoordinator = new ContextCompositionCoordinator(List.of(
                new TrustedFactSource() {
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
                        return Map.of("subject.principalId", ResolvedFactValue.present("subject.principalId", "usr-9910"));
                    }
                }
        ));

        InMemoryTransactionalAuditOutbox outbox = new InMemoryTransactionalAuditOutbox();
        ObligationBarrierCoordinator obligationCoordinator = new ObligationBarrierCoordinator(
                new DefaultObligationHandlerRegistry(),
                outbox
        );

        AuthorizationProviderPort providerPort = new AuthorizationProviderPort() {
            @Override
            public ProviderEvaluationEnvelope evaluateTarget(
                    ProviderInputProjection inputProjection,
                    WriteIntent writeIntent
            ) {
                return new ProviderEvaluationEnvelope(
                        ProviderEvaluationEnvelope.SCHEMA_VERSION_V1,
                        "OPA_REGO_V1",
                        "eval-1",
                        dpId.pointKey(),
                        EvaluationMode.TARGET,
                        "praxis.authorization-combining/v1",
                        "rev-1",
                        digest,
                        digest,
                        GateOutcome.ALLOW,
                        List.of(),
                        List.of(
                                new FieldWriteEffectDirective("hr.leave_requests.substitute_code", RuleEffect.ALLOW),
                                new FieldWriteEffectDirective("hr.leave_requests.medical_code", RuleEffect.DENY)
                        ),
                        List.of(new MaskDirective(
                                "hr.leave_requests.medical_code",
                                "REDACT_CONSTANT",
                                Map.of("replacement", "***RESTRICTED-CODE***"))),
                        List.of(
                                new ObligationDirective(
                                        "REQUIRE_JUSTIFICATION",
                                        "ON_PERMIT",
                                        "BEFORE_EXECUTION",
                                        Map.of("minLength", 10)),
                                new ObligationDirective(
                                        "DURABLE_AUDIT_EVIDENCE",
                                        "ALWAYS",
                                        "BEFORE_COMMIT_OUTBOX",
                                        Map.of("auditCategory", "SUBSTITUTE_PATCH"))
                        ),
                        List.of(),
                        List.of(new PolicyUnitContributionTrace(
                                "unit:p1:v1", "p1", "r1", ContributionAuthority.GRANT, RuleEffect.ALLOW, "ALLOW_PATCH")),
                        List.of(),
                        Instant.now(),
                        120L
                );
            }

            @Override
            public SearchProviderEvaluationResult evaluateSearch(ProviderInputProjection inputProjection) {
                throw new UnsupportedOperationException();
            }
        };

        EnforcementPipelineExecutor executor = new EnforcementPipelineExecutor(
                providerPort,
                new HostDecisionNormalizationEngine(),
                new FieldUseQueryGuard(),
                new FieldWriteAuthorizer(),
                new DetachedDtoMaskingProcessor(),
                obligationCoordinator
        );

        // Case 1 (R-11 & P10-R04): Forbidden FIELD_WRITE at STEP_11 aborts BEFORE STEP_12 and still records ALWAYS/ON_DENY audit outbox!
        AtomicBoolean step12Ran = new AtomicBoolean(false);
        WriteIntent forbiddenWrite = new WriteIntent(
                "UPDATE_PARTIAL",
                true,
                BatchAuthorizationMode.REJECT_ALL,
                TransactionCardinality.SINGLE_ITEM,
                List.of(new WriteFieldChange("/medicalCode", "hr.leave_requests.medical_code", WriteChangeKind.SET, "J11"))
        );
        assertThrows(FieldWriteViolationException.class, () ->
                executor.executeTargetPipeline(
                        binding,
                        authorityBinding,
                        true,
                        true,
                        Map.of(),
                        contextCoordinator,
                        factContract,
                        profile,
                        new TemporalContext(Instant.now(), ZoneId.of("UTC")),
                        Set.of("subject.principalId"),
                        Map.of(),
                        forbiddenWrite,
                        null,
                        false,
                        true,
                        Map.of("justificationText", "Valid justification for compliance test"),
                        () -> {
                            step12Ran.set(true);
                            return Map.of();
                        },
                        List.of()
                )
        );
        assertFalse(step12Ran.get(), "STEP_12 (hydrate* / PraxisRulesEngine) must NEVER execute when STEP_11 denies FIELD_WRITE");
        assertEquals(1, outbox.listEntries().size(), "P10-R04: ALWAYS/ON_DENY BEFORE_COMMIT_OUTBOX obligation must be fulfilled on STEP_11 denial");

        // Case 2: Valid write succeeds through STEP_15, masks detached response, and records outbox entry
        WriteIntent allowedWrite = new WriteIntent(
                "UPDATE_PARTIAL",
                true,
                BatchAuthorizationMode.REJECT_ALL,
                TransactionCardinality.SINGLE_ITEM,
                List.of(new WriteFieldChange(
                        "/substituteCode", "hr.leave_requests.substitute_code", WriteChangeKind.SET, "EMP-20499"))
        );
        NormalizedEnforcementOutcome okOutcome = executor.executeTargetPipeline(
                binding,
                authorityBinding,
                true,
                true,
                Map.of(),
                contextCoordinator,
                factContract,
                profile,
                new TemporalContext(Instant.now(), ZoneId.of("UTC")),
                Set.of("subject.principalId"),
                Map.of(),
                allowedWrite,
                null,
                false,
                true,
                Map.of("justificationText", "Substitute assignment approved by department manager"),
                () -> Map.of("id", 77L, "substituteCode", "EMP-20499", "medicalCode", "J11.0"),
                List.of(new DtoFieldSchemaMetadata("medicalCode", "hr.leave_requests.medical_code", FactValueType.STRING, false))
        );
        assertTrue(okOutcome.isPermitted());
        assertEquals("***RESTRICTED-CODE***", okOutcome.maskingResult().detachedProjection().get("medicalCode"));
        assertEquals(2, outbox.listEntries().size());
        int step11Idx = okOutcome.executedSteps().indexOf(EnforcementPipelineStep.STEP_11_ENFORCE_PRE_MUTATION_ACCESS_AND_FIELD_WRITE);
        int step12Idx = okOutcome.executedSteps().indexOf(EnforcementPipelineStep.STEP_12_EXECUTE_SERVER_HYDRATION_AND_BUSINESS_RULES);
        int step14Idx = okOutcome.executedSteps().indexOf(EnforcementPipelineStep.STEP_14_FULFILL_BEFORE_COMMIT_OUTBOX_OBLIGATIONS);
        int step15Idx = okOutcome.executedSteps().indexOf(EnforcementPipelineStep.STEP_15_DETACHED_PROJECTION_MASK_AND_DISCLOSURE);
        assertTrue(step11Idx < step12Idx && step12Idx < step14Idx && step14Idx < step15Idx);

        // Case 3 (P22 / ENF-OBL-003): Simulated outbox failure at STEP_13 revokes PERMIT to DENY and suppresses response!
        outbox.setSimulateWriteFailure(true);
        NormalizedEnforcementOutcome failedOutboxOutcome = executor.executeTargetPipeline(
                binding,
                authorityBinding,
                true,
                true,
                Map.of(),
                contextCoordinator,
                factContract,
                profile,
                new TemporalContext(Instant.now(), ZoneId.of("UTC")),
                Set.of("subject.principalId"),
                Map.of(),
                allowedWrite,
                null,
                false,
                true,
                Map.of("justificationText", "Substitute assignment approved by department manager"),
                () -> Map.of("id", 77L, "substituteCode", "EMP-20499", "medicalCode", "J11.0"),
                List.of(new DtoFieldSchemaMetadata("medicalCode", "hr.leave_requests.medical_code", FactValueType.STRING, false))
        );
        assertEquals(EnforcementDisposition.DENY, failedOutboxOutcome.finalDisposition());
        assertNull(failedOutboxOutcome.maskingResult());
        assertTrue(failedOutboxOutcome.evidence().unfulfilledObligationTypes().contains("DURABLE_AUDIT_EVIDENCE"));
        assertTrue(failedOutboxOutcome.evidence().reasonCodes().contains("OBLIGATION_UNFULFILLED"));

        // Case 4 (P2-R5 / CTX-TMP-001): DecisionEvidence.decidedAt() matches deterministic TemporalContext.instant()
        Instant fixedInstant = Instant.parse("2026-11-08T21:00:00Z");
        outbox.setSimulateWriteFailure(false);
        NormalizedEnforcementOutcome deterministicTimeOutcome = executor.executeTargetPipeline(
                binding,
                authorityBinding,
                true,
                true,
                Map.of(),
                contextCoordinator,
                factContract,
                profile,
                new TemporalContext(fixedInstant, ZoneId.of("UTC")),
                Set.of("subject.principalId"),
                Map.of(),
                allowedWrite,
                null,
                false,
                true,
                Map.of("justificationText", "Substitute assignment approved by department manager"),
                () -> Map.of("id", 77L, "substituteCode", "EMP-20499", "medicalCode", "J11.0"),
                List.of(new DtoFieldSchemaMetadata("medicalCode", "hr.leave_requests.medical_code", FactValueType.STRING, false))
        );
        assertEquals(fixedInstant, deterministicTimeOutcome.evidence().decidedAt());
    }
}
