package org.praxisplatform.authz.enforcement.writeintent;

import java.util.Objects;
import java.util.Set;

/**
 * Exception raised at {@code STEP_11_ENFORCE_PRE_MUTATION_ACCESS_AND_FIELD_WRITE} when a caller
 * attempts to modify one or more attributes forbidden by {@code FIELD_WRITE} directives or
 * {@code DualScopeDelegationSpec} ({@code P16}, {@code P17}, {@code ENF-FW-001..004B}).
 */
public final class FieldWriteViolationException extends RuntimeException {

    private final Set<String> forbiddenAttributeIds;
    private final String reasonCode;

    /**
     * Constructs a field-write violation exception.
     *
     * @param forbiddenAttributeIds canonical {@code attributeId}s whose mutation was denied
     * @param reasonCode semantic reason code
     * @param message diagnostic message
     */
    public FieldWriteViolationException(
            Set<String> forbiddenAttributeIds,
            String reasonCode,
            String message
    ) {
        super(Objects.requireNonNull(message, "message is required"));
        this.forbiddenAttributeIds = Set.copyOf(Objects.requireNonNull(forbiddenAttributeIds, "forbiddenAttributeIds is required"));
        this.reasonCode = Objects.requireNonNull(reasonCode, "reasonCode is required");
    }

    /** Returns the immutable set of forbidden {@code attributeId}s. */
    public Set<String> getForbiddenAttributeIds() {
        return forbiddenAttributeIds;
    }

    /** Returns the semantic reason code. */
    public String getReasonCode() {
        return reasonCode;
    }
}
