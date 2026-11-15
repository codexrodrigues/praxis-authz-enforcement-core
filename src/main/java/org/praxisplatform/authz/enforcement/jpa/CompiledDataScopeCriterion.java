package org.praxisplatform.authz.enforcement.jpa;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;
import org.praxisplatform.authz.contracts.context.ResolvedFactValue;
import org.praxisplatform.authz.contracts.datascope.DataScopeOutcome;

/**
 * Compiled persistence criterion combining the mandatory host hard scope with the dynamic policy
 * {@link org.praxisplatform.authz.contracts.datascope.DataScopePlan} ({@code CC03}, {@code P05}, {@code P06}, {@code P07}).
 *
 * @param scopeOutcome data scope outcome ({@code ALL}, {@code NONE}, or {@code FILTER})
 * @param hardScopeWhereClause mandatory host hard-scope JPQL/SQL fragment (never bypassed by {@code ALL})
 * @param policyWhereClause compiled policy JPQL/SQL fragment
 * @param composedWhereClause conjunction {@code (hardScope) AND (policyScope)}
 * @param boundParameters ordered map of bound query parameter names to values
 * @param rowEvaluator deterministic row-level evaluator matching Kleene 3VL and hard-scope conjunction
 */
public record CompiledDataScopeCriterion(
        DataScopeOutcome scopeOutcome,
        String hardScopeWhereClause,
        String policyWhereClause,
        String composedWhereClause,
        Map<String, Object> boundParameters,
        Predicate<Map<String, ResolvedFactValue>> rowEvaluator
) {

    /** Validates non-null components and wraps {@code boundParameters} as unmodifiable. */
    public CompiledDataScopeCriterion {
        scopeOutcome = Objects.requireNonNull(scopeOutcome, "scopeOutcome is required");
        hardScopeWhereClause = Objects.requireNonNull(hardScopeWhereClause, "hardScopeWhereClause is required");
        policyWhereClause = Objects.requireNonNull(policyWhereClause, "policyWhereClause is required");
        composedWhereClause = Objects.requireNonNull(composedWhereClause, "composedWhereClause is required");
        Objects.requireNonNull(boundParameters, "boundParameters is required");
        boundParameters = Collections.unmodifiableMap(new LinkedHashMap<>(boundParameters));
        rowEvaluator = Objects.requireNonNull(rowEvaluator, "rowEvaluator is required");
    }

    /** Evaluates whether a candidate row satisfies both the mandatory hard scope and the policy scope. */
    public boolean matchesRow(Map<String, ResolvedFactValue> rowFacts) {
        return rowEvaluator.test(rowFacts);
    }
}
