package org.praxisplatform.authz.enforcement.context;

import java.util.Map;
import java.util.Set;
import org.praxisplatform.authz.contracts.context.ContextEvaluationPhase;
import org.praxisplatform.authz.contracts.context.FactDescriptor;
import org.praxisplatform.authz.contracts.context.FactResolutionStage;
import org.praxisplatform.authz.contracts.context.ResolvedFactValue;

/**
 * Authoritative server-side source of facts for a given {@link FactResolutionStage}
 * ({@code CC04}, {@code CTX-TRUST-001..004}).
 */
public interface TrustedFactSource {

    /** Stage in which this source participates ({@code EXTRACT}, {@code ENRICH}, or {@code DERIVE}). */
    FactResolutionStage stage();

    /**
     * Optional subset of canonical {@code factPath}s supported by this source. When empty, the source
     * receives all descriptors scheduled for {@link #stage()}.
     */
    default Set<String> supportedFactPaths() {
        return Set.of();
    }

    /**
     * Optional set of upstream {@code factPath}s required by a {@code DERIVE} source ({@code P04}, {@code P30}).
     * If any upstream dependency resolved to {@code UNAVAILABLE}, {@code ERROR}, or {@code STALE}, the
     * coordinator short-circuits the derived facts to {@code UNAVAILABLE} instead of invoking this source.
     */
    default Set<String> requiredUpstreamFactPaths() {
        return Set.of();
    }

    /**
     * Resolves the requested fact descriptors for the given evaluation phase.
     *
     * @param phase evaluation phase ({@code ADMISSION} or {@code TARGET})
     * @param descriptorsToResolve map of {@code factPath -> FactDescriptor} to resolve in this stage
     * @param alreadyResolved immutable map of facts resolved in earlier stages
     * @return map of {@code factPath -> ResolvedFactValue}
     */
    Map<String, ResolvedFactValue> resolveFacts(
            ContextEvaluationPhase phase,
            Map<String, FactDescriptor> descriptorsToResolve,
            Map<String, ResolvedFactValue> alreadyResolved
    );
}
