package org.praxisplatform.authz.enforcement.jpa;

import java.util.Objects;

/**
 * Persistence-specific binding mapping a canonical {@code resource.*} field path to its JPA path and
 * relation traversal strategy ({@code CC03}, {@code DSP-FLD-004}, {@code R-05}).
 *
 * <p>This record is strictly private to the host persistence adapter and is never serialized inside
 * {@link org.praxisplatform.authz.contracts.datascope.DataScopePlan}.</p>
 *
 * @param resourceKey canonical resource key
 * @param fieldPath canonical {@code resource.*} fact path
 * @param attributeId canonical {@code @DomainLineage.attributeId}
 * @param nativeJpaPath physical JPA attribute path (e.g. {@code assignment.department.id})
 * @param traversalStrategy traversal strategy ({@code DIRECT_ATTRIBUTE}, {@code INNER_JOIN_SCALAR}, or {@code CORRELATED_EXISTS_SUBQUERY})
 * @param nullableColumn whether the underlying database column or join path is nullable
 */
public record QueryAdapterFieldBinding(
        String resourceKey,
        String fieldPath,
        String attributeId,
        String nativeJpaPath,
        RelationTraversalStrategy traversalStrategy,
        boolean nullableColumn
) {

    /** Validates required binding fields. */
    public QueryAdapterFieldBinding {
        resourceKey = requireNonBlank(resourceKey, "resourceKey");
        fieldPath = requireNonBlank(fieldPath, "fieldPath");
        if (!fieldPath.startsWith("resource.")) {
            throw new IllegalArgumentException("fieldPath must start with 'resource.': " + fieldPath);
        }
        attributeId = requireNonBlank(attributeId, "attributeId");
        nativeJpaPath = requireNonBlank(nativeJpaPath, "nativeJpaPath");
        traversalStrategy = Objects.requireNonNull(traversalStrategy, "traversalStrategy is required");
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
