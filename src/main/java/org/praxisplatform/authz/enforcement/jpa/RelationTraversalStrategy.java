package org.praxisplatform.authz.enforcement.jpa;

/**
 * Persistence traversal strategy private to {@link JpaDataScopeAdapter} ({@code CC03}, {@code DSP-FLD-004}, {@code R-05}).
 */
public enum RelationTraversalStrategy {
    DIRECT_ATTRIBUTE,
    INNER_JOIN_SCALAR,
    CORRELATED_EXISTS_SUBQUERY
}
