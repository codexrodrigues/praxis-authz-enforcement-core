package org.praxisplatform.authz.enforcement.pipeline;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;
import java.util.function.Supplier;
import org.praxisplatform.authz.contracts.authority.EffectiveAuthorityBinding;
import org.praxisplatform.authz.contracts.binding.EnforcementPipelineStep;
import org.praxisplatform.authz.contracts.binding.RuntimeEnforcementBinding;
import org.praxisplatform.authz.contracts.binding.WriteIntent;
import org.praxisplatform.authz.contracts.context.ContextCompositionProfile;
import org.praxisplatform.authz.contracts.context.EvaluationContextSnapshot;
import org.praxisplatform.authz.contracts.context.FactContract;
import org.praxisplatform.authz.contracts.context.ProviderInputProjection;
import org.praxisplatform.authz.contracts.context.ResolvedFactValue;
import org.praxisplatform.authz.contracts.context.TemporalContext;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.envelope.DecisionEvidence;
import org.praxisplatform.authz.contracts.envelope.EnforcementDisposition;
import org.praxisplatform.authz.contracts.envelope.ProviderEvaluationEnvelope;
import org.praxisplatform.authz.contracts.obligation.DefaultObligationHandlerRegistry;
import org.praxisplatform.authz.contracts.obligation.ObligationFulfillmentBarrier;
import org.praxisplatform.authz.contracts.obligation.ObligationFulfillmentResult;
import org.praxisplatform.authz.contracts.policy.DualScopeDelegationSpec;
import org.praxisplatform.authz.enforcement.context.ContextCompositionCoordinator;
import org.praxisplatform.authz.enforcement.context.ScopedExecutionContextHolder;
import org.praxisplatform.authz.enforcement.context.UntrustedRequestHeaderGuard;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseQueryGuard;
import org.praxisplatform.authz.enforcement.jpa.CompiledDataScopeCriterion;
import org.praxisplatform.authz.enforcement.jpa.JpaDataScopeAdapter;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingResult;
import org.praxisplatform.authz.enforcement.masking.DtoFieldSchemaMetadata;
import org.praxisplatform.authz.enforcement.obligation.ObligationBarrierCoordinator;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteAuthorizer;

/**
 * Executes the canonical 15-step authorization enforcement pipeline defined in {@code CC06}
 * ({@code STEP_01_RESOLVE_POINT_AND_READINESS} through
 * {@code STEP_15_FULFILL_BEFORE_DISCLOSURE_OBLIGATIONS_AND_EMIT_EVIDENCE}).
 *
 * <p>Guarantees that:
 * <ul>
 *   <li>{@code STEP_11_ENFORCE_PRE_MUTATION_ACCESS_AND_FIELD_WRITE} always executes before
 *       {@code STEP_12_EXECUTE_SERVER_HYDRATION_AND_BUSINESS_RULES} ({@code hydrate*} + {@code PraxisRulesEngine});</li>
 *   <li>Server-side business rules at {@code STEP_12} operate on raw unmasked entity values ({@code P40}),
 *       while {@code STEP_14_PROJECT_AND_MASK_DETACHED_RESPONSE_DTO} masks a detached copy;</li>
 *   <li>{@link ScopedExecutionContextHolder} is always cleaned up in a {@code try-with-resources} block ({@code P02}).</li>
 * </ul>
 */
public final class EnforcementPipelineExecutor {

    private final AuthorizationProviderPort providerPort;
    private final HostDecisionNormalizationEngine normalizationEngine;
    private final FieldUseQueryGuard fieldUseQueryGuard;
    private final FieldWriteAuthorizer fieldWriteAuthorizer;
    private final DetachedDtoMaskingProcessor maskingProcessor;
    private final ObligationBarrierCoordinator obligationCoordinator;

    /**
     * Constructs a 15-step pipeline executor with all canonical enforcement collaborators.
     */
    public EnforcementPipelineExecutor(
            AuthorizationProviderPort providerPort,
            HostDecisionNormalizationEngine normalizationEngine,
            FieldUseQueryGuard fieldUseQueryGuard,
            FieldWriteAuthorizer fieldWriteAuthorizer,
            DetachedDtoMaskingProcessor maskingProcessor,
            ObligationBarrierCoordinator obligationCoordinator
    ) {
        this.providerPort = Objects.requireNonNull(providerPort, "providerPort is required");
        this.normalizationEngine = Objects.requireNonNull(normalizationEngine, "normalizationEngine is required");
        this.fieldUseQueryGuard = Objects.requireNonNull(fieldUseQueryGuard, "fieldUseQueryGuard is required");
        this.fieldWriteAuthorizer = Objects.requireNonNull(fieldWriteAuthorizer, "fieldWriteAuthorizer is required");
        this.maskingProcessor = Objects.requireNonNull(maskingProcessor, "maskingProcessor is required");
        this.obligationCoordinator = Objects.requireNonNull(obligationCoordinator, "obligationCoordinator is required");
    }

    /**
     * Executes the full target/mutation pipeline ({@code STEP_01} through {@code STEP_15}), invoking
     * {@code step12HydrationAndBusinessRulesSupplier} only after pre-mutation authorization and
     * {@code FIELD_WRITE} checks succeed at {@code STEP_11}.
     *
     * @param binding runtime enforcement binding
     * @param authorityBinding effective authority binding
     * @param hardGuardAllowed whether mandatory host hard guards allow the request
     * @param structuralBaselineAllowed whether static structural baseline allows the request
     * @param rawHttpHeaders incoming HTTP headers checked for spoofing ({@code P01}, {@code P42})
     * @param contextCoordinator context composition coordinator
     * @param factContract governing fact contract
     * @param targetProfile target context composition profile
     * @param temporalContext authoritative temporal context
     * @param policyReferencedFactPaths fact paths referenced by active policies
     * @param requestedQueryFieldUses optional query field uses checked at {@code STEP_03}
     * @param writeIntent optional pre-hydration write intent checked at {@code STEP_11}
     * @param dualScopeSpec optional dual-scope custody specification checked at {@code STEP_11}
     * @param callerMatchesCedenteScope whether caller holds origin/cedente custody
     * @param callerMatchesCessionarioScope whether caller holds delegated/cessionario custody
     * @param obligationExecutionContext execution context for MFA/justification/outbox/watermark handlers
     * @param step12HydrationAndBusinessRulesSupplier callback executing {@code hydrate*}, {@code PraxisRulesEngine}, and persistence at {@code STEP_12}
     * @param responseDtoFieldSchemas schema metadata for masking the detached response DTO at {@code STEP_14}
     * @return normalized enforcement outcome with full step trace
     */
    public NormalizedEnforcementOutcome executeTargetPipeline(
            RuntimeEnforcementBinding binding,
            EffectiveAuthorityBinding authorityBinding,
            boolean hardGuardAllowed,
            boolean structuralBaselineAllowed,
            Map<String, String> rawHttpHeaders,
            ContextCompositionCoordinator contextCoordinator,
            FactContract factContract,
            ContextCompositionProfile targetProfile,
            TemporalContext temporalContext,
            Set<String> policyReferencedFactPaths,
            Map<FieldUseCategory, Set<String>> requestedQueryFieldUses,
            WriteIntent writeIntent,
            DualScopeDelegationSpec dualScopeSpec,
            boolean callerMatchesCedenteScope,
            boolean callerMatchesCessionarioScope,
            Map<String, Object> obligationExecutionContext,
            Supplier<Object> step12HydrationAndBusinessRulesSupplier,
            Collection<DtoFieldSchemaMetadata> responseDtoFieldSchemas
    ) {
        List<EnforcementPipelineStep> executedSteps = new ArrayList<>();

        // STEP 1: Resolve decision point and readiness
        recordStep(executedSteps, EnforcementPipelineStep.STEP_01_RESOLVE_POINT_AND_READINESS);
        validateBindingAndProfileAlignment(
                binding, authorityBinding, targetProfile, org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode.TARGET);

        // STEP 2: Extract admission facts and pre-hydration WriteIntent
        recordStep(executedSteps, EnforcementPipelineStep.STEP_02_EXTRACT_ADMISSION_AND_WRITE_INTENT);
        Set<String> modifiedAttrs = writeIntent == null ? Set.of() : writeIntent.modifiedAttributeIds();

        // STEP 8 & 9: Resolve target entity within scope and compose target context snapshot
        EvaluationContextSnapshot snapshot = contextCoordinator.composeSnapshot(
                factContract, targetProfile, temporalContext, modifiedAttrs);

        try (ScopedExecutionContextHolder.ScopeToken ignored = ScopedExecutionContextHolder.open(snapshot)) {
            // P01 / P42: Reject untrusted authority-spoofing HTTP headers
            UntrustedRequestHeaderGuard.assertNoAuthoritySpoofingHeaders(rawHttpHeaders, snapshot.facts());

            ProviderInputProjection inputProjection = ProviderInputProjection.fromSnapshot(
                    "TARGET", snapshot, factContract, targetProfile, policyReferencedFactPaths);
            ProviderEvaluationEnvelope envelope = providerPort.evaluateTarget(inputProjection, writeIntent);

            // STEP 3: Guard query field use if any query attributes were requested
            if (requestedQueryFieldUses != null && !requestedQueryFieldUses.isEmpty()) {
                recordStep(executedSteps, EnforcementPipelineStep.STEP_03_GUARD_QUERY_FIELD_USE);
                try {
                    fieldUseQueryGuard.guardQueryFieldUses(
                            requestedQueryFieldUses, envelope.combinedFieldUseEffects());
                } catch (RuntimeException ex) {
                    fulfillDenyBarriers(envelope, obligationExecutionContext);
                    throw ex;
                }
            }

            // STEP 6: Fulfill BEFORE_EXECUTION obligations
            EnforcementDisposition prelim = normalizationEngine.computePreliminaryDisposition(
                    binding, authorityBinding, hardGuardAllowed, structuralBaselineAllowed, envelope);

            List<ObligationFulfillmentResult> allObligationResults = new ArrayList<>();
            recordStep(executedSteps, EnforcementPipelineStep.STEP_06_FULFILL_BEFORE_EXECUTION_OBLIGATIONS);
            allObligationResults.addAll(obligationCoordinator.fulfillAtBarrier(
                    envelope.decisionPointKey(),
                    envelope.runtimeRevision(),
                    prelim,
                    ObligationFulfillmentBarrier.BEFORE_EXECUTION,
                    envelope.combinedObligationDirectives(),
                    obligationExecutionContext));

            // STEP 8, 9, 10: Target resolution, snapshot composition, and target evaluation normalization
            recordStep(executedSteps, EnforcementPipelineStep.STEP_08_RESOLVE_TARGET_ENTITY_WITHIN_SCOPE);
            recordStep(executedSteps, EnforcementPipelineStep.STEP_09_COMPOSE_TARGET_CONTEXT_SNAPSHOT);
            recordStep(executedSteps, EnforcementPipelineStep.STEP_10_EVALUATE_TARGET_PROVIDER_AND_NORMALIZE);

            if (prelim != EnforcementDisposition.PERMIT
                    || !org.praxisplatform.authz.contracts.obligation.DefaultObligationHandlerRegistry
                            .canHonorPermitDisposition(allObligationResults)) {
                allObligationResults.addAll(fulfillDenyBarriers(envelope, obligationExecutionContext));
                DecisionEvidence denyEvidence = normalizationEngine.finalizeEvidence(
                        envelope, prelim, allObligationResults, Map.of(), temporalContext.instant());
                return new NormalizedEnforcementOutcome(
                        EnforcementDisposition.DENY, denyEvidence, null, null, executedSteps);
            }

            // STEP 11: Enforce pre-mutation ACCESS and FIELD_WRITE (before hydrate* and PraxisRulesEngine!)
            recordStep(executedSteps, EnforcementPipelineStep.STEP_11_ENFORCE_PRE_MUTATION_ACCESS_AND_FIELD_WRITE);
            if (writeIntent != null) {
                try {
                    if (dualScopeSpec != null) {
                        fieldWriteAuthorizer.enforceDualScopeCustody(
                                writeIntent, dualScopeSpec, callerMatchesCedenteScope, callerMatchesCessionarioScope);
                    }
                    if (!writeIntent.changes().isEmpty() && !envelope.combinedFieldWriteEffects().isEmpty()) {
                        fieldWriteAuthorizer.enforceFieldWriteDirectives(
                                writeIntent, envelope.combinedFieldWriteEffects(), true);
                    }
                } catch (RuntimeException ex) {
                    fulfillDenyBarriers(envelope, obligationExecutionContext);
                    throw ex;
                }
            }

            // STEP 12 & 13: Execute server hydration (hydrate*), PraxisRulesEngine, and persist mutation/domain hooks
            recordStep(executedSteps, EnforcementPipelineStep.STEP_12_EXECUTE_SERVER_HYDRATION_AND_BUSINESS_RULES);
            recordStep(executedSteps, EnforcementPipelineStep.STEP_13_PERSIST_MUTATION_AND_DOMAIN_HOOKS);
            Object rawResponseDto = step12HydrationAndBusinessRulesSupplier == null
                    ? Map.of()
                    : step12HydrationAndBusinessRulesSupplier.get();

            // STEP 14: Fulfill BEFORE_COMMIT_OUTBOX obligations (transactional audit outbox)
            recordStep(executedSteps, EnforcementPipelineStep.STEP_14_FULFILL_BEFORE_COMMIT_OUTBOX_OBLIGATIONS);
            allObligationResults.addAll(obligationCoordinator.fulfillAtBarrier(
                    envelope.decisionPointKey(),
                    envelope.runtimeRevision(),
                    prelim,
                    ObligationFulfillmentBarrier.BEFORE_COMMIT_OUTBOX,
                    envelope.combinedObligationDirectives(),
                    obligationExecutionContext));

            if (!org.praxisplatform.authz.contracts.obligation.DefaultObligationHandlerRegistry
                    .canHonorPermitDisposition(allObligationResults)) {
                // ENF-OBL-003 (P22): Outbox write failure revokes PERMIT before disclosure!
                allObligationResults.addAll(obligationCoordinator.fulfillAtBarrier(
                        envelope.decisionPointKey(),
                        envelope.runtimeRevision(),
                        EnforcementDisposition.DENY,
                        ObligationFulfillmentBarrier.BEFORE_DISCLOSURE,
                        envelope.combinedObligationDirectives(),
                        obligationExecutionContext));
                DecisionEvidence denyEvidence = normalizationEngine.finalizeEvidence(
                        envelope, prelim, allObligationResults, Map.of(), temporalContext.instant());
                return new NormalizedEnforcementOutcome(
                        EnforcementDisposition.DENY, denyEvidence, null, null, executedSteps);
            }

            // STEP 15: Project and mask detached response DTO (never mutating rawResponseDto in place!)
            // and fulfill BEFORE_DISCLOSURE obligations before emitting sanitized DecisionEvidence
            recordStep(executedSteps, EnforcementPipelineStep.STEP_15_DETACHED_PROJECTION_MASK_AND_DISCLOSURE);
            Set<String> valueDeniedAttrs = fieldUseQueryGuard.extractValueDeniedAttributeIds(
                    envelope.combinedFieldUseEffects());
            DetachedDtoMaskingResult maskingResult = maskingProcessor.projectAndMask(
                    rawResponseDto,
                    responseDtoFieldSchemas == null ? List.of() : responseDtoFieldSchemas,
                    valueDeniedAttrs,
                    envelope.combinedMaskDirectives());

            allObligationResults.addAll(obligationCoordinator.fulfillAtBarrier(
                    envelope.decisionPointKey(),
                    envelope.runtimeRevision(),
                    prelim,
                    ObligationFulfillmentBarrier.BEFORE_DISCLOSURE,
                    envelope.combinedObligationDirectives(),
                    obligationExecutionContext));

            DecisionEvidence finalEvidence = normalizationEngine.finalizeEvidence(
                    envelope,
                    prelim,
                    allObligationResults,
                    maskingResult.appliedStrategiesByAttributeId(),
                    temporalContext.instant());

            return new NormalizedEnforcementOutcome(
                    finalEvidence.finalDisposition(),
                    finalEvidence,
                    null,
                    finalEvidence.finalDisposition() == EnforcementDisposition.PERMIT ? maskingResult : null,
                    executedSteps
            );
        }
    }

    /**
     * Executes the {@code SEARCH} admission and data-scope compilation pipeline
     * ({@code STEP_01 -> STEP_02 -> STEP_03 -> STEP_04 -> STEP_05 -> STEP_06 -> STEP_07 -> STEP_15}).
     */
    public NormalizedEnforcementOutcome executeSearchPipeline(
            RuntimeEnforcementBinding binding,
            EffectiveAuthorityBinding authorityBinding,
            boolean hardGuardAllowed,
            boolean structuralBaselineAllowed,
            Map<String, String> rawHttpHeaders,
            ContextCompositionCoordinator contextCoordinator,
            FactContract factContract,
            ContextCompositionProfile admissionProfile,
            TemporalContext temporalContext,
            Set<String> policyReferencedFactPaths,
            Map<FieldUseCategory, Set<String>> requestedQueryFieldUses,
            JpaDataScopeAdapter jpaDataScopeAdapter,
            String hardScopeWhereClause,
            Map<String, Object> hardScopeParams,
            Predicate<Map<String, ResolvedFactValue>> hardScopeRowPredicate,
            Map<String, Object> obligationExecutionContext
    ) {
        List<EnforcementPipelineStep> executedSteps = new ArrayList<>();

        recordStep(executedSteps, EnforcementPipelineStep.STEP_01_RESOLVE_POINT_AND_READINESS);
        validateBindingAndProfileAlignment(
                binding, authorityBinding, admissionProfile, org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode.SEARCH);
        recordStep(executedSteps, EnforcementPipelineStep.STEP_02_EXTRACT_ADMISSION_AND_WRITE_INTENT);

        EvaluationContextSnapshot snapshot = contextCoordinator.composeSnapshot(
                factContract, admissionProfile, temporalContext, Set.of());

        try (ScopedExecutionContextHolder.ScopeToken ignored = ScopedExecutionContextHolder.open(snapshot)) {
            UntrustedRequestHeaderGuard.assertNoAuthoritySpoofingHeaders(rawHttpHeaders, snapshot.facts());

            ProviderInputProjection inputProjection = ProviderInputProjection.fromSnapshot(
                    "SEARCH", snapshot, factContract, admissionProfile, policyReferencedFactPaths);

            AuthorizationProviderPort.SearchProviderEvaluationResult searchResult =
                    providerPort.evaluateSearch(inputProjection);
            ProviderEvaluationEnvelope envelope = searchResult.admissionEnvelope();

            if (requestedQueryFieldUses != null && !requestedQueryFieldUses.isEmpty()) {
                recordStep(executedSteps, EnforcementPipelineStep.STEP_03_GUARD_QUERY_FIELD_USE);
                try {
                    fieldUseQueryGuard.guardQueryFieldUses(
                            requestedQueryFieldUses, envelope.combinedFieldUseEffects());
                } catch (RuntimeException ex) {
                    fulfillDenyBarriers(envelope, obligationExecutionContext);
                    throw ex;
                }
            }

            recordStep(executedSteps, EnforcementPipelineStep.STEP_04_EVALUATE_ADMISSION_OR_SEARCH_PROVIDER);
            recordStep(executedSteps, EnforcementPipelineStep.STEP_05_NORMALIZE_ADMISSION_DECISION);
            EnforcementDisposition prelim = normalizationEngine.computePreliminaryDisposition(
                    binding, authorityBinding, hardGuardAllowed, structuralBaselineAllowed, envelope);

            recordStep(executedSteps, EnforcementPipelineStep.STEP_06_FULFILL_BEFORE_EXECUTION_OBLIGATIONS);
            List<ObligationFulfillmentResult> obligationResults = new ArrayList<>(
                    obligationCoordinator.fulfillAtBarrier(
                            envelope.decisionPointKey(),
                            envelope.runtimeRevision(),
                            prelim,
                            ObligationFulfillmentBarrier.BEFORE_EXECUTION,
                            envelope.combinedObligationDirectives(),
                            obligationExecutionContext));

            if (prelim != EnforcementDisposition.PERMIT
                    || !DefaultObligationHandlerRegistry.canHonorPermitDisposition(obligationResults)) {
                obligationResults.addAll(fulfillDenyBarriers(envelope, obligationExecutionContext));
                DecisionEvidence denyEvidence = normalizationEngine.finalizeEvidence(
                        envelope, prelim, obligationResults, Map.of(), temporalContext.instant());
                return new NormalizedEnforcementOutcome(
                        EnforcementDisposition.DENY, denyEvidence, null, null, executedSteps);
            }

            recordStep(executedSteps, EnforcementPipelineStep.STEP_07_INJECT_DATA_SCOPE_PLAN);
            CompiledDataScopeCriterion criterion = jpaDataScopeAdapter.compile(
                    searchResult.dataScopePlan(),
                    hardScopeWhereClause,
                    hardScopeParams,
                    hardScopeRowPredicate);

            obligationResults.addAll(obligationCoordinator.fulfillAtBarrier(
                    envelope.decisionPointKey(),
                    envelope.runtimeRevision(),
                    prelim,
                    ObligationFulfillmentBarrier.BEFORE_COMMIT_OUTBOX,
                    envelope.combinedObligationDirectives(),
                    obligationExecutionContext));

            if (!DefaultObligationHandlerRegistry.canHonorPermitDisposition(obligationResults)) {
                obligationResults.addAll(obligationCoordinator.fulfillAtBarrier(
                        envelope.decisionPointKey(),
                        envelope.runtimeRevision(),
                        EnforcementDisposition.DENY,
                        ObligationFulfillmentBarrier.BEFORE_DISCLOSURE,
                        envelope.combinedObligationDirectives(),
                        obligationExecutionContext));
                DecisionEvidence denyEvidence = normalizationEngine.finalizeEvidence(
                        envelope, prelim, obligationResults, Map.of(), temporalContext.instant());
                return new NormalizedEnforcementOutcome(
                        EnforcementDisposition.DENY, denyEvidence, null, null, executedSteps);
            }

            recordStep(executedSteps, EnforcementPipelineStep.STEP_15_DETACHED_PROJECTION_MASK_AND_DISCLOSURE);
            obligationResults.addAll(obligationCoordinator.fulfillAtBarrier(
                    envelope.decisionPointKey(),
                    envelope.runtimeRevision(),
                    prelim,
                    ObligationFulfillmentBarrier.BEFORE_DISCLOSURE,
                    envelope.combinedObligationDirectives(),
                    obligationExecutionContext));

            DecisionEvidence finalEvidence = normalizationEngine.finalizeEvidence(
                    envelope, prelim, obligationResults, Map.of(), temporalContext.instant());

            return new NormalizedEnforcementOutcome(
                    finalEvidence.finalDisposition(),
                    finalEvidence,
                    finalEvidence.finalDisposition() == EnforcementDisposition.PERMIT ? criterion : null,
                    null,
                    executedSteps
            );
        }
    }

    private List<ObligationFulfillmentResult> fulfillDenyBarriers(
            ProviderEvaluationEnvelope envelope,
            Map<String, Object> obligationExecutionContext
    ) {
        List<ObligationFulfillmentResult> denyResults = new ArrayList<>();
        denyResults.addAll(obligationCoordinator.fulfillAtBarrier(
                envelope.decisionPointKey(),
                envelope.runtimeRevision(),
                EnforcementDisposition.DENY,
                ObligationFulfillmentBarrier.BEFORE_COMMIT_OUTBOX,
                envelope.combinedObligationDirectives(),
                obligationExecutionContext));
        denyResults.addAll(obligationCoordinator.fulfillAtBarrier(
                envelope.decisionPointKey(),
                envelope.runtimeRevision(),
                EnforcementDisposition.DENY,
                ObligationFulfillmentBarrier.BEFORE_DISCLOSURE,
                envelope.combinedObligationDirectives(),
                obligationExecutionContext));
        return denyResults;
    }

    private static void validateBindingAndProfileAlignment(
            RuntimeEnforcementBinding binding,
            EffectiveAuthorityBinding authorityBinding,
            ContextCompositionProfile profile,
            org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode expectedMode
    ) {
        Objects.requireNonNull(binding, "binding is required");
        Objects.requireNonNull(authorityBinding, "authorityBinding is required");
        Objects.requireNonNull(profile, "profile is required");
        if (binding.evaluationMode() != expectedMode) {
            throw new IllegalArgumentException(
                    "RuntimeEnforcementBinding evaluationMode '" + binding.evaluationMode()
                            + "' does not match pipeline mode '" + expectedMode + "'");
        }
        if (binding.pointAuthorityMode() != authorityBinding.pointAuthorityMode()) {
            throw new IllegalArgumentException(
                    "RuntimeEnforcementBinding pointAuthorityMode '" + binding.pointAuthorityMode()
                            + "' does not match EffectiveAuthorityBinding '" + authorityBinding.pointAuthorityMode() + "'");
        }
        if (!binding.decisionPointRef().pointKey().equals(profile.decisionPointKey())) {
            throw new IllegalArgumentException(
                    "RuntimeEnforcementBinding pointKey '" + binding.decisionPointRef().pointKey()
                            + "' does not match ContextCompositionProfile '" + profile.decisionPointKey() + "'");
        }
    }

    /**
     * Records a pipeline step and enforces strictly monotonic ordinal ordering ({@code P23}, {@code ENF-PIPE-001..015}).
     */
    public static void recordStep(List<EnforcementPipelineStep> executedSteps, EnforcementPipelineStep nextStep) {
        Objects.requireNonNull(executedSteps, "executedSteps is required");
        Objects.requireNonNull(nextStep, "nextStep is required");
        if (!executedSteps.isEmpty()) {
            EnforcementPipelineStep last = executedSteps.get(executedSteps.size() - 1);
            if (nextStep.stepNumber() <= last.stepNumber()) {
                throw new IllegalStateException(
                        "Out-of-order enforcement pipeline step: attempted to execute " + nextStep
                                + " (step " + nextStep.stepNumber() + ") after " + last
                                + " (step " + last.stepNumber() + ") (P23 / ENF-PIPE-001)");
            }
        }
        executedSteps.add(nextStep);
    }
}
