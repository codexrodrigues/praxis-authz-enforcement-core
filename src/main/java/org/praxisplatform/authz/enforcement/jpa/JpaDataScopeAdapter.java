package org.praxisplatform.authz.enforcement.jpa;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;
import org.praxisplatform.authz.contracts.context.ResolvedFactValue;
import org.praxisplatform.authz.contracts.datascope.ComparisonPredicateIr;
import org.praxisplatform.authz.contracts.datascope.DataScopeOutcome;
import org.praxisplatform.authz.contracts.datascope.DataScopePlan;
import org.praxisplatform.authz.contracts.datascope.FieldRefOperandIr;
import org.praxisplatform.authz.contracts.datascope.KleeneSearchPredicateEvaluator;
import org.praxisplatform.authz.contracts.datascope.LiteralListOperandIr;
import org.praxisplatform.authz.contracts.datascope.LiteralOperandIr;
import org.praxisplatform.authz.contracts.datascope.LogicalPredicateIr;
import org.praxisplatform.authz.contracts.datascope.NullabilityPredicateIr;
import org.praxisplatform.authz.contracts.datascope.QueryableResourceProjection;
import org.praxisplatform.authz.contracts.datascope.SearchPredicateIr;
import org.praxisplatform.authz.contracts.datascope.SearchPredicateOperator;

/**
 * Translates a persistence-neutral {@link DataScopePlan} into a {@link CompiledDataScopeCriterion}
 * using private {@link QueryAdapterFieldBinding}s while preserving the host's mandatory hard scope
 * ({@code CC03}, {@code P05}, {@code P06}, {@code P07}, {@code DSP-PLAN-002}, {@code DSP-SQL-001..006}).
 */
public final class JpaDataScopeAdapter {

    private final QueryableResourceProjection projection;
    private final Map<String, QueryAdapterFieldBinding> bindingsByFieldPath;

    /**
     * Constructs an adapter for a resource's {@link QueryableResourceProjection} and private JPA bindings.
     *
     * @param projection queryable resource projection
     * @param bindings private JPA field bindings
     */
    public JpaDataScopeAdapter(
            QueryableResourceProjection projection,
            Collection<QueryAdapterFieldBinding> bindings
    ) {
        this.projection = Objects.requireNonNull(projection, "projection is required");
        Objects.requireNonNull(bindings, "bindings is required");
        Map<String, QueryAdapterFieldBinding> map = new LinkedHashMap<>();
        for (QueryAdapterFieldBinding b : bindings) {
            Objects.requireNonNull(b, "binding must not be null");
            if (!projection.resourceKey().equals(b.resourceKey())) {
                throw new IllegalArgumentException(
                        "Binding resourceKey '" + b.resourceKey() + "' does not match projection resourceKey '"
                                + projection.resourceKey() + "'");
            }
            map.put(b.fieldPath(), b);
        }
        this.bindingsByFieldPath = Map.copyOf(map);
    }

    /**
     * Compiles a {@link DataScopePlan} and composes it with the mandatory host {@code hardScope}
     * ({@code P05}: {@code DataScopeOutcome.ALL} never removes {@code hardScope}).
     *
     * @param plan persistence-neutral data scope plan
     * @param hardScopeWhereClause mandatory host hard-scope JPQL/SQL predicate (e.g. {@code e.tenantId = :hardTenantId})
     * @param hardScopeParams mandatory host hard-scope parameters
     * @param hardScopeRowPredicate mandatory host hard-scope row predicate
     * @return compiled criterion
     */
    public CompiledDataScopeCriterion compile(
            DataScopePlan plan,
            String hardScopeWhereClause,
            Map<String, Object> hardScopeParams,
            Predicate<Map<String, ResolvedFactValue>> hardScopeRowPredicate
    ) {
        Objects.requireNonNull(plan, "plan is required");
        Objects.requireNonNull(hardScopeWhereClause, "hardScopeWhereClause is required");
        if (hardScopeWhereClause.isBlank()) {
            throw new IllegalArgumentException("hardScopeWhereClause must not be blank (DSP-PLAN-002)");
        }
        Objects.requireNonNull(hardScopeRowPredicate, "hardScopeRowPredicate is required");

        if (!projection.projectionId().equals(plan.queryProjectionRef())
                || !projection.projectionDigest().equals(plan.queryProjectionDigest())) {
            throw new IllegalArgumentException(
                    "DataScopePlan queryProjectionRef/Digest does not match host QueryableResourceProjection");
        }

        Map<String, Object> params = new LinkedHashMap<>();
        if (hardScopeParams != null) {
            params.putAll(hardScopeParams);
        }

        if (plan.scopeOutcome() == DataScopeOutcome.ALL) {
            // P05 / DSP-PLAN-002: ALL preserves hardScope and never widens beyond it!
            String composed = "(" + hardScopeWhereClause + ") AND (1 = 1)";
            return new CompiledDataScopeCriterion(
                    DataScopeOutcome.ALL,
                    hardScopeWhereClause,
                    "1 = 1",
                    composed,
                    params,
                    hardScopeRowPredicate
            );
        }

        if (plan.scopeOutcome() == DataScopeOutcome.NONE) {
            String composed = "(" + hardScopeWhereClause + ") AND (1 = 0)";
            return new CompiledDataScopeCriterion(
                    DataScopeOutcome.NONE,
                    hardScopeWhereClause,
                    "1 = 0",
                    composed,
                    params,
                    row -> false
            );
        }

        SearchPredicateIr predicateIr = plan.predicateIr();
        projection.validatePredicateIr(predicateIr);
        int[] paramCounter = new int[] {1};
        String policySql = translateNode(predicateIr, false, params, paramCounter);
        String composed = "(" + hardScopeWhereClause + ") AND (" + policySql + ")";
        Predicate<Map<String, ResolvedFactValue>> combinedRowEval = row ->
                hardScopeRowPredicate.test(row)
                        && KleeneSearchPredicateEvaluator.evaluate(predicateIr, row).isRowSelected();

        return new CompiledDataScopeCriterion(
                DataScopeOutcome.FILTER,
                hardScopeWhereClause,
                policySql,
                composed,
                params,
                combinedRowEval
        );
    }

    /**
     * Filters a collection of candidate row fact maps, preserving order and applying both {@code hardScope}
     * and the {@link DataScopePlan} — suitable for {@code findAll}, {@code byIds}, {@code includeIds},
     * cursor pages, and lookup hydration ({@code P06}).
     */
    public List<Map<String, ResolvedFactValue>> filterAuthorizedRows(
            List<Map<String, ResolvedFactValue>> candidateRows,
            CompiledDataScopeCriterion criterion
    ) {
        Objects.requireNonNull(candidateRows, "candidateRows is required");
        Objects.requireNonNull(criterion, "criterion is required");
        return candidateRows.stream()
                .filter(criterion::matchesRow)
                .toList();
    }

    private String translateNode(
            SearchPredicateIr node,
            boolean negatedContext,
            Map<String, Object> params,
            int[] paramCounter
    ) {
        if (node instanceof LogicalPredicateIr logical) {
            return switch (logical.operator()) {
                case NOT -> {
                    SearchPredicateIr child = logical.operands().get(0);
                    // Push negation down via De Morgan's law so nullable columns receive explicit IS NOT NULL guards
                    yield translateNode(child, !negatedContext, params, paramCounter);
                }
                case AND -> {
                    // Under negatedContext, De Morgan's law converts NOT(A AND B) -> (NOT A OR NOT B)
                    String joinOp = negatedContext ? " OR " : " AND ";
                    StringBuilder sb = new StringBuilder("(");
                    for (int i = 0; i < logical.operands().size(); i++) {
                        if (i > 0) {
                            sb.append(joinOp);
                        }
                        sb.append(translateNode(logical.operands().get(i), negatedContext, params, paramCounter));
                    }
                    sb.append(")");
                    yield sb.toString();
                }
                case OR -> {
                    // Under negatedContext, De Morgan's law converts NOT(A OR B) -> (NOT A AND NOT B)
                    String joinOp = negatedContext ? " AND " : " OR ";
                    StringBuilder sb = new StringBuilder("(");
                    for (int i = 0; i < logical.operands().size(); i++) {
                        if (i > 0) {
                            sb.append(joinOp);
                        }
                        sb.append(translateNode(logical.operands().get(i), negatedContext, params, paramCounter));
                    }
                    sb.append(")");
                    yield sb.toString();
                }
                default -> throw new IllegalStateException("Unexpected logical operator: " + logical.operator());
            };
        }
        if (node instanceof NullabilityPredicateIr nullability) {
            QueryAdapterFieldBinding binding = requireBinding(nullability.fieldPath());
            String col = binding.traversalStrategy() == RelationTraversalStrategy.CORRELATED_EXISTS_SUBQUERY
                    ? "sub." + binding.nativeJpaPath()
                    : "e." + binding.nativeJpaPath();
            boolean isNullOp = (nullability.operator() == SearchPredicateOperator.IS_NULL) ^ negatedContext;
            String nullCond = isNullOp ? "(" + col + " IS NULL)" : "(" + col + " IS NOT NULL)";
            if (binding.traversalStrategy() == RelationTraversalStrategy.CORRELATED_EXISTS_SUBQUERY) {
                return "EXISTS (SELECT 1 FROM " + binding.resourceKey() + " sub WHERE sub.parentId = e.id AND "
                        + nullCond + ")";
            }
            return nullCond;
        }
        if (node instanceof ComparisonPredicateIr comp) {
            return translateComparison(comp, negatedContext, params, paramCounter);
        }
        throw new IllegalArgumentException("Unsupported SearchPredicateIr: " + node.getClass());
    }

    private String translateComparison(
            ComparisonPredicateIr comp,
            boolean negated,
            Map<String, Object> params,
            int[] paramCounter
    ) {
        QueryAdapterFieldBinding binding = requireBinding(comp.fieldPath());
        String col = binding.traversalStrategy() == RelationTraversalStrategy.CORRELATED_EXISTS_SUBQUERY
                ? "sub." + binding.nativeJpaPath()
                : "e." + binding.nativeJpaPath();

        String rhsExpr;
        boolean rhsNullableColumn = false;
        boolean caseInsensitive = comp.caseInsensitive();
        if (comp.rightOperand() instanceof LiteralOperandIr lit) {
            String pName = "dspParam" + (paramCounter[0]++);
            Object paramValue = formatLiteralForOperator(comp.operator(), lit.value(), caseInsensitive);
            params.put(pName, paramValue);
            rhsExpr = ":" + pName;
        } else if (comp.rightOperand() instanceof LiteralListOperandIr listLit) {
            String pName = "dspParam" + (paramCounter[0]++);
            List<Object> formattedList = caseInsensitive
                    ? listLit.values().stream()
                            .map(v -> v instanceof String s ? s.toLowerCase(java.util.Locale.ROOT) : v)
                            .toList()
                    : listLit.values();
            params.put(pName, formattedList);
            rhsExpr = "(:" + pName + ")";
        } else if (comp.rightOperand() instanceof FieldRefOperandIr fieldRef) {
            QueryAdapterFieldBinding rhsBinding = requireBinding(fieldRef.targetFieldPath());
            String rawRhs = "e." + rhsBinding.nativeJpaPath();
            rhsExpr = caseInsensitive ? "LOWER(" + rawRhs + ")" : rawRhs;
            rhsNullableColumn = rhsBinding.nullableColumn();
        } else {
            throw new IllegalArgumentException("Unsupported RightOperandIr: " + comp.rightOperand());
        }

        String opSql = switch (comp.operator()) {
            case EQ -> negated ? "<>" : "=";
            case NE -> negated ? "=" : "<>";
            case LT -> negated ? ">=" : "<";
            case LTE -> negated ? ">" : "<=";
            case GT -> negated ? "<=" : ">";
            case GTE -> negated ? "<" : ">=";
            case IN -> negated ? "NOT IN" : "IN";
            case NIN -> negated ? "IN" : "NOT IN";
            case TEXT_CONTAINS, STARTS_WITH, ENDS_WITH -> (negated ? "NOT LIKE" : "LIKE");
            default -> throw new IllegalStateException("Unexpected comparison operator: " + comp.operator());
        };

        String lhsExpr = caseInsensitive ? "LOWER(" + col + ")" : col;
        String baseComparison = switch (comp.operator()) {
            case TEXT_CONTAINS, STARTS_WITH, ENDS_WITH -> lhsExpr + " " + opSql + " " + rhsExpr + " ESCAPE '\\'";
            default -> lhsExpr + " " + opSql + " " + rhsExpr;
        };

        // DSP-SQL-003 (P07): Explicit IS NOT NULL guard on nullable columns (both LHS and RHS FieldRef) under Kleene 3VL
        StringBuilder nullGuard = new StringBuilder();
        if (binding.nullableColumn()) {
            nullGuard.append(col).append(" IS NOT NULL");
        }
        if (rhsNullableColumn && comp.rightOperand() instanceof FieldRefOperandIr fieldRef) {
            if (!nullGuard.isEmpty()) {
                nullGuard.append(" AND ");
            }
            QueryAdapterFieldBinding rhsBinding = requireBinding(fieldRef.targetFieldPath());
            nullGuard.append("e.").append(rhsBinding.nativeJpaPath()).append(" IS NOT NULL");
        }
        String nullSafeComparison = nullGuard.isEmpty()
                ? "(" + baseComparison + ")"
                : "(" + nullGuard + " AND " + baseComparison + ")";

        if (binding.traversalStrategy() == RelationTraversalStrategy.CORRELATED_EXISTS_SUBQUERY) {
            // DSP-SQL-004 (P06 / P07): Use correlated EXISTS subquery for 1:N relations so root rows
            // are never duplicated and count/pagination remain exact.
            return "EXISTS (SELECT 1 FROM " + binding.resourceKey() + " sub WHERE sub.parentId = e.id AND "
                    + nullSafeComparison + ")";
        }
        return nullSafeComparison;
    }

    private static Object formatLiteralForOperator(
            SearchPredicateOperator operator,
            Object rawValue,
            boolean caseInsensitive
    ) {
        if (rawValue == null) {
            return null;
        }
        Object effectiveValue = (caseInsensitive && rawValue instanceof String s)
                ? s.toLowerCase(java.util.Locale.ROOT)
                : rawValue;
        return switch (operator) {
            case TEXT_CONTAINS -> "%" + escapeLikeWildcards(String.valueOf(effectiveValue)) + "%";
            case STARTS_WITH -> escapeLikeWildcards(String.valueOf(effectiveValue)) + "%";
            case ENDS_WITH -> "%" + escapeLikeWildcards(String.valueOf(effectiveValue));
            default -> effectiveValue;
        };
    }

    private static String escapeLikeWildcards(String value) {
        return value
                .replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_");
    }

    private QueryAdapterFieldBinding requireBinding(String fieldPath) {
        QueryAdapterFieldBinding binding = bindingsByFieldPath.get(fieldPath);
        if (binding == null) {
            throw new IllegalArgumentException(
                    "No QueryAdapterFieldBinding registered for queryable fieldPath '" + fieldPath + "'");
        }
        return binding;
    }
}
