package org.praxisplatform.authz.enforcement.context;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.praxisplatform.authz.contracts.context.ContextCompositionProfile;
import org.praxisplatform.authz.contracts.context.ContextEvaluationPhase;
import org.praxisplatform.authz.contracts.context.EvaluationContextSnapshot;
import org.praxisplatform.authz.contracts.context.FactContract;
import org.praxisplatform.authz.contracts.context.FactDescriptor;
import org.praxisplatform.authz.contracts.context.FactResolutionStage;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.context.FactUnavailableCause;
import org.praxisplatform.authz.contracts.context.ProviderInputProjection;
import org.praxisplatform.authz.contracts.context.ResolvedFactValue;
import org.praxisplatform.authz.contracts.context.TemporalContext;

/**
 * Coordinates the 4-stage context composition pipeline ({@code EXTRACT -> ENRICH -> DERIVE -> FREEZE})
 * for a decision point and phase ({@code CC04}, {@code P04}, {@code CTX-RES-001..006}).
 *
 * <p>Guarantees that:
 * <ul>
 *   <li>Only facts declared in the governing {@link FactContract} and available in the current
 *       {@link ContextEvaluationPhase} are resolved;</li>
 *   <li>Enricher timeouts or source exceptions are recorded explicitly as
 *       {@link FactResolutionStatus#UNAVAILABLE} or {@link FactResolutionStatus#ERROR} — never
 *       converted into {@link FactResolutionStatus#ABSENT} or {@link FactResolutionStatus#NULL} ({@code P04});</li>
 *   <li>An immutable {@link EvaluationContextSnapshot} is produced at stage 4 ({@code FREEZE}).</li>
 * </ul>
 */
public final class ContextCompositionCoordinator {

    private final List<TrustedFactSource> sources;

    /**
     * Constructs a coordinator with the ordered list of trusted server-side fact sources.
     *
     * @param sources trusted fact sources across {@code EXTRACT}, {@code ENRICH}, and {@code DERIVE}
     */
    public ContextCompositionCoordinator(Collection<TrustedFactSource> sources) {
        Objects.requireNonNull(sources, "sources is required");
        this.sources = List.copyOf(sources);
    }

    /**
     * Executes the 4-stage pipeline ({@code EXTRACT -> ENRICH -> DERIVE -> FREEZE}) and returns the
     * frozen {@link EvaluationContextSnapshot}.
     *
     * @param contract governing fact contract
     * @param profile context composition profile
     * @param temporalContext authoritative server-computed temporal reference
     * @param modifiedAttributeIds set of canonical {@code attributeId}s modified by the caller's write intent
     * @return frozen {@link EvaluationContextSnapshot}
     */
    public EvaluationContextSnapshot composeSnapshot(
            FactContract contract,
            ContextCompositionProfile profile,
            TemporalContext temporalContext,
            Set<String> modifiedAttributeIds
    ) {
        Objects.requireNonNull(contract, "contract is required");
        Objects.requireNonNull(profile, "profile is required");
        Objects.requireNonNull(temporalContext, "temporalContext is required");

        if (!contract.factContractId().equals(profile.factContractId())
                || !contract.factContractDigest().equals(profile.factContractDigest())) {
            throw new IllegalArgumentException(
                    "FactContract digest/id mismatch between contract and ContextCompositionProfile");
        }

        ContextEvaluationPhase phase = profile.phase();
        Map<String, FactDescriptor> targetDescriptors = selectDescriptorsForProfile(contract, profile, phase);
        Map<String, ResolvedFactValue> accumulated = new LinkedHashMap<>();

        // Stage 1: EXTRACT
        runStage(FactResolutionStage.EXTRACT, phase, targetDescriptors, accumulated);
        // Stage 2: ENRICH
        runStage(FactResolutionStage.ENRICH, phase, targetDescriptors, accumulated);
        // Stage 3: DERIVE
        runStage(FactResolutionStage.DERIVE, phase, targetDescriptors, accumulated);

        // Stage 4: FREEZE — fill any unresolved profile facts with ABSENT (if optional/MAY_BE_ABSENT)
        // or UNAVAILABLE(NOT_LOADED_IN_PHASE) (if required/ALWAYS_PRESENT)
        for (Map.Entry<String, FactDescriptor> entry : targetDescriptors.entrySet()) {
            String path = entry.getKey();
            if (!accumulated.containsKey(path)) {
                if (profile.requiredFactPaths().contains(path)) {
                    accumulated.put(
                            path,
                            ResolvedFactValue.unavailable(
                                    path,
                                    FactUnavailableCause.NOT_LOADED_IN_PHASE,
                                    "REQUIRED_FACT_NOT_PRODUCED_BY_SOURCE"));
                } else {
                    accumulated.put(path, ResolvedFactValue.absent(path));
                }
            }
        }

        return new EvaluationContextSnapshot(
                EvaluationContextSnapshot.SCHEMA_VERSION_V1,
                "snap-" + UUID.randomUUID(),
                profile.profileId(),
                contract.factContractId(),
                contract.factContractDigest(),
                phase,
                temporalContext,
                accumulated,
                modifiedAttributeIds == null ? Set.of() : modifiedAttributeIds
        );
    }

    /**
     * Composes the snapshot and immediately projects a minimized {@link ProviderInputProjection}.
     */
    public ProviderInputProjection composeAndProject(
            String evaluationMode,
            FactContract contract,
            ContextCompositionProfile profile,
            TemporalContext temporalContext,
            Set<String> modifiedAttributeIds,
            Set<String> policyReferencedFactPaths
    ) {
        EvaluationContextSnapshot snapshot = composeSnapshot(
                contract, profile, temporalContext, modifiedAttributeIds);
        return ProviderInputProjection.fromSnapshot(
                evaluationMode, snapshot, contract, profile, policyReferencedFactPaths);
    }

    private void runStage(
            FactResolutionStage stage,
            ContextEvaluationPhase phase,
            Map<String, FactDescriptor> allTargetDescriptors,
            Map<String, ResolvedFactValue> accumulated
    ) {
        Map<String, FactDescriptor> stageDescriptors = new LinkedHashMap<>();
        for (FactDescriptor fd : allTargetDescriptors.values()) {
            if (fd.resolutionStage() == stage) {
                stageDescriptors.put(fd.factPath(), fd);
            }
        }
        if (stageDescriptors.isEmpty()) {
            return;
        }

        for (TrustedFactSource source : sources) {
            if (source.stage() != stage) {
                continue;
            }
            Set<String> sourceSupported = source.supportedFactPaths();
            Map<String, FactDescriptor> requestedForSource = new LinkedHashMap<>();
            for (Map.Entry<String, FactDescriptor> entry : stageDescriptors.entrySet()) {
                if (sourceSupported == null || sourceSupported.isEmpty() || sourceSupported.contains(entry.getKey())) {
                    requestedForSource.put(entry.getKey(), entry.getValue());
                }
            }
            if (requestedForSource.isEmpty()) {
                continue;
            }
            if (stage == FactResolutionStage.DERIVE && hasUnhealthyUpstreamDependency(source, accumulated)) {
                // P04 / P30: Never invoke a DERIVE source when an upstream dependency is UNAVAILABLE, ERROR, or STALE
                for (String path : requestedForSource.keySet()) {
                    if (!accumulated.containsKey(path)) {
                        accumulated.put(
                                path,
                                ResolvedFactValue.unavailable(
                                        path,
                                        FactUnavailableCause.NOT_LOADED_IN_PHASE,
                                        "UPSTREAM_DEPENDENCY_UNAVAILABLE_OR_ERROR"));
                    }
                }
                continue;
            }
            try {
                Map<String, ResolvedFactValue> produced = source.resolveFacts(
                        phase, Map.copyOf(requestedForSource), Map.copyOf(accumulated));
                if (produced != null) {
                    for (Map.Entry<String, ResolvedFactValue> entry : produced.entrySet()) {
                        String key = entry.getKey();
                        ResolvedFactValue val = entry.getValue();
                        if (requestedForSource.containsKey(key) && val != null && key.equals(val.factPath())) {
                            accumulated.put(key, val);
                        }
                    }
                }
            } catch (RuntimeException ex) {
                // P04 / P30: Never convert source failure into ABSENT or NULL!
                for (String path : requestedForSource.keySet()) {
                    if (!accumulated.containsKey(path)) {
                        accumulated.put(
                                path,
                                ResolvedFactValue.unavailable(
                                        path,
                                        FactUnavailableCause.SOURCE_TIMEOUT,
                                        "SOURCE_EXCEPTION:" + ex.getClass().getSimpleName()));
                    }
                }
            }
        }
    }

    private static boolean hasUnhealthyUpstreamDependency(
            TrustedFactSource source,
            Map<String, ResolvedFactValue> accumulated
    ) {
        Set<String> deps = source.requiredUpstreamFactPaths();
        if (deps == null || deps.isEmpty()) {
            return false;
        }
        for (String depPath : deps) {
            ResolvedFactValue depVal = accumulated.get(depPath);
            if (depVal == null
                    || depVal.status() == FactResolutionStatus.UNAVAILABLE
                    || depVal.status() == FactResolutionStatus.ERROR
                    || depVal.status() == FactResolutionStatus.STALE) {
                return true;
            }
        }
        return false;
    }

    private static Map<String, FactDescriptor> selectDescriptorsForProfile(
            FactContract contract,
            ContextCompositionProfile profile,
            ContextEvaluationPhase phase
    ) {
        Map<String, FactDescriptor> selected = new LinkedHashMap<>();
        for (String reqPath : profile.requiredFactPaths()) {
            FactDescriptor fd = contract.descriptorsByPath().get(reqPath);
            if (fd == null) {
                throw new IllegalArgumentException(
                        "Required factPath '" + reqPath + "' in profile '" + profile.profileId()
                                + "' is not declared in FactContract '" + contract.factContractId() + "'");
            }
            if (!fd.availableInPhases().contains(phase)) {
                throw new IllegalArgumentException(
                        "Required factPath '" + reqPath + "' is not available in phase " + phase);
            }
            selected.put(reqPath, fd);
        }
        for (String optPath : profile.optionalFactPaths()) {
            FactDescriptor fd = contract.descriptorsByPath().get(optPath);
            if (fd != null && fd.availableInPhases().contains(phase)) {
                selected.put(optPath, fd);
            }
        }
        return selected;
    }
}
