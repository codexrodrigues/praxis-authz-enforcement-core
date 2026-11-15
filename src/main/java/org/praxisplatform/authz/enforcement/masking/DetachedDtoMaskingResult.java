package org.praxisplatform.authz.enforcement.masking;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Result of applying server-side security masking to a detached DTO projection ({@code CC09},
 * {@code STEP_14_PROJECT_AND_MASK_DETACHED_RESPONSE_DTO}).
 *
 * @param detachedProjection detached map projection safe for JSON serialization / export
 * @param appliedStrategiesByAttributeId sanitized map of {@code attributeId -> strategyId} for {@code DecisionEvidence}
 */
public record DetachedDtoMaskingResult(
        Map<String, Object> detachedProjection,
        Map<String, String> appliedStrategiesByAttributeId
) {

    /** Wraps maps as unmodifiable while preserving explicit {@code null} values in {@code detachedProjection}. */
    public DetachedDtoMaskingResult {
        Objects.requireNonNull(detachedProjection, "detachedProjection is required");
        detachedProjection = Collections.unmodifiableMap(new LinkedHashMap<>(detachedProjection));
        appliedStrategiesByAttributeId = appliedStrategiesByAttributeId == null
                ? Map.of()
                : Map.copyOf(appliedStrategiesByAttributeId);
    }
}
