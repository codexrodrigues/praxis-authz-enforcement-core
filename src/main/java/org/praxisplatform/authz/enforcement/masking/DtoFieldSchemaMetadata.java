package org.praxisplatform.authz.enforcement.masking;

import java.util.Objects;
import org.praxisplatform.authz.contracts.context.FactValueType;

/**
 * Schema metadata for a single field on a response or export DTO used to validate and apply
 * server-side security masking ({@code CC09}, {@code ENF-MSK-004..008}).
 *
 * @param wireFieldName JSON property name on the DTO (e.g. {@code medicalCode})
 * @param attributeId canonical {@code @DomainLineage.attributeId} (e.g. {@code hr.leave_requests.medical_code})
 * @param valueType field value type
 * @param nullable whether the DTO field is annotated with {@code @Schema(nullable = true)}
 */
public record DtoFieldSchemaMetadata(
        String wireFieldName,
        String attributeId,
        FactValueType valueType,
        boolean nullable
) {

    /** Validates non-blank names and non-null value type. */
    public DtoFieldSchemaMetadata {
        wireFieldName = requireNonBlank(wireFieldName, "wireFieldName");
        attributeId = requireNonBlank(attributeId, "attributeId");
        valueType = Objects.requireNonNull(valueType, "valueType is required");
    }

    /** Alias for {@link #wireFieldName()}. */
    public String fieldName() {
        return wireFieldName;
    }

    private static String requireNonBlank(String value, String field) {
        Objects.requireNonNull(value, field + " is required");
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return trimmed;
    }
}
