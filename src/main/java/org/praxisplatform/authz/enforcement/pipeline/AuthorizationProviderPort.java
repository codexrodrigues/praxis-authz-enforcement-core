package org.praxisplatform.authz.enforcement.pipeline;

import org.praxisplatform.authz.contracts.binding.WriteIntent;
import org.praxisplatform.authz.contracts.context.ProviderInputProjection;
import org.praxisplatform.authz.contracts.datascope.DataScopePlan;
import org.praxisplatform.authz.contracts.envelope.ProviderEvaluationEnvelope;

/**
 * SPI port implemented by dynamic authorization providers (such as {@code praxis-authz-opa}) and
 * invoked by {@link EnforcementPipelineExecutor} ({@code CC06}, {@code CC07}, {@code CC11}).
 */
public interface AuthorizationProviderPort {

    /**
     * Evaluates a {@code TARGET} decision point against the projected input and optional pre-hydration
     * {@link WriteIntent}.
     */
    ProviderEvaluationEnvelope evaluateTarget(
            ProviderInputProjection inputProjection,
            WriteIntent writeIntent
    );

    /**
     * Evaluates admission and compiles a persistence-neutral {@link DataScopePlan} for a {@code SEARCH}
     * decision point.
     */
    SearchProviderEvaluationResult evaluateSearch(ProviderInputProjection inputProjection);

    /**
     * Pair of admission envelope and compiled {@link DataScopePlan} returned by {@link #evaluateSearch}.
     */
    record SearchProviderEvaluationResult(
            ProviderEvaluationEnvelope admissionEnvelope,
            DataScopePlan dataScopePlan
    ) {}
}
