package org.praxisplatform.authz.enforcement.pipeline;

import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.praxisplatform.authz.contracts.authority.EffectiveAuthorityBinding;
import org.praxisplatform.authz.contracts.binding.RuntimeEnforcementBinding;
import org.praxisplatform.authz.contracts.decisionpoint.PointAuthorityMode;
import org.praxisplatform.authz.contracts.envelope.DecisionEvidence;
import org.praxisplatform.authz.contracts.envelope.EnforcementDisposition;
import org.praxisplatform.authz.contracts.envelope.PolicyUnitContributionTrace;
import org.praxisplatform.authz.contracts.envelope.ProviderEvaluationEnvelope;
import org.praxisplatform.authz.contracts.obligation.DefaultObligationHandlerRegistry;
import org.praxisplatform.authz.contracts.obligation.ObligationFulfillmentResult;

/**
 * Normalizes a {@link ProviderEvaluationEnvelope} into a final binary {@link EnforcementDisposition}
 * and sanitized {@link DecisionEvidence}, enforcing readiness gates, algebraic combining rules, and
 * fail-closed obligation barriers ({@code CC06}, {@code CC07}, {@code CC10}, {@code CC12}).
 */
public final class HostDecisionNormalizationEngine {

    /**
     * Computes the preliminary disposition before obligation barriers, checking {@link RuntimeEnforcementBinding#isAuthoritativeReady()}
     * when {@code authorityBinding.pointAuthorityMode() == AUTHORITATIVE} ({@code G0}, {@code P32}).
     */
    public EnforcementDisposition computePreliminaryDisposition(
            RuntimeEnforcementBinding binding,
            EffectiveAuthorityBinding authorityBinding,
            boolean hardGuardAllowed,
            boolean structuralBaselineAllowed,
            ProviderEvaluationEnvelope envelope
    ) {
        Objects.requireNonNull(binding, "binding is required");
        Objects.requireNonNull(authorityBinding, "authorityBinding is required");
        Objects.requireNonNull(envelope, "envelope is required");

        if (authorityBinding.pointAuthorityMode() == PointAuthorityMode.AUTHORITATIVE
                && !binding.isAuthoritativeReady()) {
            // G0 / BND-RDY-001: Unready authoritative binding fails closed
            return EnforcementDisposition.DENY;
        }
        return authorityBinding.normalizeDisposition(hardGuardAllowed, structuralBaselineAllowed, envelope);
    }

    /**
     * Finalizes the binary {@link EnforcementDisposition} and builds a sanitized {@link DecisionEvidence}
     * record after evaluating obligation barriers and DTO masking ({@code BND-PRV-004}, {@code ENF-OBL-003}).
     */
    public DecisionEvidence finalizeEvidence(
            ProviderEvaluationEnvelope envelope,
            EnforcementDisposition preliminaryDisposition,
            Collection<ObligationFulfillmentResult> obligationResults,
            Map<String, String> appliedMaskStrategiesByAttributeId,
            Instant decidedAt
    ) {
        Objects.requireNonNull(envelope, "envelope is required");
        Objects.requireNonNull(preliminaryDisposition, "preliminaryDisposition is required");
        Objects.requireNonNull(decidedAt, "decidedAt is required");

        Collection<ObligationFulfillmentResult> results = obligationResults == null ? Set.of() : obligationResults;
        Set<String> fulfilled = new LinkedHashSet<>();
        Set<String> unfulfilled = new LinkedHashSet<>();
        for (ObligationFulfillmentResult r : results) {
            if (r.fulfilled()) {
                fulfilled.add(r.obligationType());
            } else {
                unfulfilled.add(r.obligationType());
            }
        }

        // ENF-OBL-003: Any unfulfilled obligation revokes PERMIT fail-closed to DENY
        EnforcementDisposition finalDisposition =
                (preliminaryDisposition == EnforcementDisposition.PERMIT
                        && DefaultObligationHandlerRegistry.canHonorPermitDisposition(results))
                ? EnforcementDisposition.PERMIT
                : EnforcementDisposition.DENY;

        Set<String> reasonCodes = new LinkedHashSet<>();
        for (PolicyUnitContributionTrace trace : envelope.unitContributions()) {
            reasonCodes.add(trace.reasonCode());
        }
        if (!envelope.unresolvedConflicts().isEmpty()) {
            reasonCodes.add("AUTHZ_UNRESOLVED_CONFLICT");
        }
        if (!unfulfilled.isEmpty()) {
            reasonCodes.add("OBLIGATION_UNFULFILLED");
        }
        if (reasonCodes.isEmpty()) {
            reasonCodes.add(finalDisposition == EnforcementDisposition.PERMIT ? "AUTHZ_PERMIT" : "AUTHZ_DENY");
        }

        return new DecisionEvidence(
                "ev-" + UUID.randomUUID(),
                envelope.decisionPointKey(),
                envelope.evaluationMode(),
                envelope.runtimeRevision(),
                envelope.policySetDigest(),
                envelope.factContractDigest(),
                envelope.gateOutcome(),
                finalDisposition,
                reasonCodes,
                appliedMaskStrategiesByAttributeId == null ? Map.of() : appliedMaskStrategiesByAttributeId,
                fulfilled,
                unfulfilled,
                decidedAt
        );
    }
}
