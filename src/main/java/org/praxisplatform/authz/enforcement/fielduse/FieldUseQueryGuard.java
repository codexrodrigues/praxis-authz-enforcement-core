package org.praxisplatform.authz.enforcement.fielduse;

import java.util.EnumMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.envelope.FieldUseEffectDirective;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;

/**
 * Guards query parameters (filters, sorts, group-by dimensions, aggregate metrics, relational joins)
 * and output value projections against inference side-channels at {@code STEP_03_GUARD_QUERY_FIELD_USE}
 * ({@code CC06}, {@code P13}, {@code P14}, {@code P50}, {@code ENF-FU-001..006}).
 */
public final class FieldUseQueryGuard {

    /**
     * Verifies that none of the requested attributes per {@link FieldUseCategory} is denied by
     * {@code directives}.
     *
     * @param requestedAttributesByCategory map of {@link FieldUseCategory} to requested canonical {@code attributeId}s
     * @param directives combined field-use effect directives
     * @throws FieldUseViolationException if any requested attribute is denied for its category
     */
    public void guardQueryFieldUses(
            Map<FieldUseCategory, Set<String>> requestedAttributesByCategory,
            List<FieldUseEffectDirective> directives
    ) {
        Objects.requireNonNull(requestedAttributesByCategory, "requestedAttributesByCategory is required");
        Objects.requireNonNull(directives, "directives is required");

        Map<FieldUseCategory, Set<String>> deniedByCategory = new EnumMap<>(FieldUseCategory.class);
        for (FieldUseEffectDirective dir : directives) {
            if (dir.effect() == RuleEffect.DENY) {
                deniedByCategory
                        .computeIfAbsent(dir.category(), k -> new LinkedHashSet<>())
                        .add(dir.attributeId());
            }
        }

        for (Map.Entry<FieldUseCategory, Set<String>> req : requestedAttributesByCategory.entrySet()) {
            FieldUseCategory category = req.getKey();
            Set<String> deniedForCat = deniedByCategory.getOrDefault(category, Set.of());
            if (deniedForCat.isEmpty() || req.getValue() == null) {
                continue;
            }
            Set<String> violations = new LinkedHashSet<>();
            for (String attrId : req.getValue()) {
                if (deniedForCat.contains(attrId)) {
                    violations.add(attrId);
                }
            }
            if (!violations.isEmpty()) {
                throw new FieldUseViolationException(
                        category,
                        violations,
                        "Query attempted forbidden FIELD_USE(" + category + ") on attributes: "
                                + violations + " (P13 / P50 / ENF-FU-002)");
            }
        }
    }

    /**
     * Returns the set of canonical {@code attributeId}s whose {@link FieldUseCategory#VALUE} is denied
     * and must therefore be completely omitted from response/export/AI projections ({@code PCB-MASK-001}).
     */
    public Set<String> extractValueDeniedAttributeIds(List<FieldUseEffectDirective> directives) {
        Objects.requireNonNull(directives, "directives is required");
        Set<String> denied = new LinkedHashSet<>();
        for (FieldUseEffectDirective dir : directives) {
            if (dir.category() == FieldUseCategory.VALUE && dir.effect() == RuleEffect.DENY) {
                denied.add(dir.attributeId());
            }
        }
        return Set.copyOf(denied);
    }
}
