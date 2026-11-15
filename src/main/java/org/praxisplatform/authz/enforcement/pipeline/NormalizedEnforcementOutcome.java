package org.praxisplatform.authz.enforcement.pipeline;

import java.util.List;
import java.util.Objects;
import org.praxisplatform.authz.contracts.binding.EnforcementPipelineStep;
import org.praxisplatform.authz.contracts.envelope.DecisionEvidence;
import org.praxisplatform.authz.contracts.envelope.EnforcementDisposition;
import org.praxisplatform.authz.enforcement.jpa.CompiledDataScopeCriterion;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingResult;

/**
 * Complete outcome produced by {@link EnforcementPipelineExecutor}, including the final binary
 * {@link EnforcementDisposition}, sanitized {@link DecisionEvidence}, optional compiled data-scope
 * criterion, optional detached masked response projection, and the ordered trace of executed
 * {@link EnforcementPipelineStep}s ({@code CC06}, {@code CC07}).
 *
 * @param finalDisposition final binary PEP disposition ({@code PERMIT} or {@code DENY})
 * @param evidence sanitized decision evidence
 * @param dataScopeCriterion compiled data-scope criterion (when {@code SEARCH} or scoped target resolution ran)
 * @param maskingResult detached DTO masking result (when response projection ran at {@code STEP_14})
 * @param executedSteps ordered trace of pipeline steps executed
 */
public record NormalizedEnforcementOutcome(
        EnforcementDisposition finalDisposition,
        DecisionEvidence evidence,
        CompiledDataScopeCriterion dataScopeCriterion,
        DetachedDtoMaskingResult maskingResult,
        List<EnforcementPipelineStep> executedSteps
) {

    /** Validates non-null core outcome fields and wraps {@code executedSteps} as unmodifiable. */
    public NormalizedEnforcementOutcome {
        finalDisposition = Objects.requireNonNull(finalDisposition, "finalDisposition is required");
        evidence = Objects.requireNonNull(evidence, "evidence is required");
        executedSteps = executedSteps == null ? List.of() : List.copyOf(executedSteps);
    }

    /** Returns {@code true} iff the final disposition is {@link EnforcementDisposition#PERMIT}. */
    public boolean isPermitted() {
        return finalDisposition == EnforcementDisposition.PERMIT;
    }
}
