package org.praxisplatform.authz.enforcement.fielduse;

import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;

/**
 * Exception raised at {@code STEP_03_GUARD_QUERY_FIELD_USE} when a query or projection attempts to use
 * an attribute in a forbidden {@link FieldUseCategory} ({@code VALUE}, {@code FILTER}, {@code SORT},
 * {@code GROUP}, {@code AGGREGATE}, or {@code JOIN}) ({@code P13}, {@code P14}, {@code P50}, {@code ENF-FU-001..006}).
 */
public final class FieldUseViolationException extends RuntimeException {

    private final FieldUseCategory category;
    private final Set<String> forbiddenAttributeIds;

    /**
     * Constructs a field-use violation exception.
     *
     * @param category forbidden field-use category
     * @param forbiddenAttributeIds canonical {@code attributeId}s denied for that category
     * @param message diagnostic message
     */
    public FieldUseViolationException(
            FieldUseCategory category,
            Set<String> forbiddenAttributeIds,
            String message
    ) {
        super(Objects.requireNonNull(message, "message is required"));
        this.category = Objects.requireNonNull(category, "category is required");
        this.forbiddenAttributeIds = Set.copyOf(Objects.requireNonNull(forbiddenAttributeIds, "forbiddenAttributeIds is required"));
    }

    /** Returns the violated {@link FieldUseCategory}. */
    public FieldUseCategory getCategory() {
        return category;
    }

    /** Returns the denied {@code attributeId}s. */
    public Set<String> getForbiddenAttributeIds() {
        return forbiddenAttributeIds;
    }
}
