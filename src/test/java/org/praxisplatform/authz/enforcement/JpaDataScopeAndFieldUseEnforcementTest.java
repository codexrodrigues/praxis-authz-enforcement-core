package org.praxisplatform.authz.enforcement;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.contracts.context.FactValueType;
import org.praxisplatform.authz.contracts.context.ResolvedFactValue;
import org.praxisplatform.authz.contracts.datascope.ComparisonPredicateIr;
import org.praxisplatform.authz.contracts.datascope.DataScopeOutcome;
import org.praxisplatform.authz.contracts.datascope.DataScopePlan;
import org.praxisplatform.authz.contracts.datascope.LiteralOperandIr;
import org.praxisplatform.authz.contracts.datascope.LogicalPredicateIr;
import org.praxisplatform.authz.contracts.datascope.NullabilityPredicateIr;
import org.praxisplatform.authz.contracts.datascope.PushdownMode;
import org.praxisplatform.authz.contracts.datascope.QueryableFieldDescriptor;
import org.praxisplatform.authz.contracts.datascope.QueryableResourceProjection;
import org.praxisplatform.authz.contracts.datascope.SearchPredicateOperator;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.digest.CanonicalDigestCalculator;
import org.praxisplatform.authz.contracts.digest.DigestDomainKind;
import org.praxisplatform.authz.contracts.envelope.FieldUseEffectDirective;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseQueryGuard;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseViolationException;
import org.praxisplatform.authz.enforcement.jpa.CompiledDataScopeCriterion;
import org.praxisplatform.authz.enforcement.jpa.JpaDataScopeAdapter;
import org.praxisplatform.authz.enforcement.jpa.QueryAdapterFieldBinding;
import org.praxisplatform.authz.enforcement.jpa.RelationTraversalStrategy;

/**
 * Conformance tests for {@code CC03} {@link JpaDataScopeAdapter} ({@code P05}, {@code P06}, {@code P07})
 * and {@code CC06} {@link FieldUseQueryGuard} ({@code P13}, {@code P14}, {@code P50}).
 */
class JpaDataScopeAndFieldUseEnforcementTest {

    @Test
    void p05_p06_p07_jpaDataScopeAdapterPreservesHardScopeAndNullSafeSubqueries() {
        String qpDigest = CanonicalDigestCalculator.computeDigest(DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, "qp");
        QueryableFieldDescriptor departmentField = new QueryableFieldDescriptor(
                "resource.departmentId",
                "hr.leave_requests.department_id",
                FactValueType.INT64,
                Set.of(SearchPredicateOperator.EQ, SearchPredicateOperator.NE, SearchPredicateOperator.IN),
                true
        );
        QueryableFieldDescriptor dependentTaxId = new QueryableFieldDescriptor(
                "resource.dependentTaxId",
                "hr.dependents.tax_id",
                FactValueType.STRING,
                Set.of(SearchPredicateOperator.EQ, SearchPredicateOperator.IS_NULL, SearchPredicateOperator.IS_NOT_NULL),
                false
        );

        QueryableResourceProjection projection = new QueryableResourceProjection(
                QueryableResourceProjection.SCHEMA_VERSION_V1,
                "qp-leave-requests",
                "human-resources.leave-requests",
                qpDigest,
                Map.of(
                        departmentField.fieldPath(), departmentField,
                        dependentTaxId.fieldPath(), dependentTaxId
                )
        );

        QueryAdapterFieldBinding departmentBinding = new QueryAdapterFieldBinding(
                "human-resources.leave-requests",
                "resource.departmentId",
                "hr.leave_requests.department_id",
                "assignment.department.id",
                RelationTraversalStrategy.INNER_JOIN_SCALAR,
                true
        );
        QueryAdapterFieldBinding dependentBinding = new QueryAdapterFieldBinding(
                "human-resources.leave-requests",
                "resource.dependentTaxId",
                "hr.dependents.tax_id",
                "dependents.taxId",
                RelationTraversalStrategy.CORRELATED_EXISTS_SUBQUERY,
                true
        );

        JpaDataScopeAdapter adapter = new JpaDataScopeAdapter(
                projection, List.of(departmentBinding, dependentBinding));

        Predicate<Map<String, ResolvedFactValue>> tenantHardScope = row -> {
            ResolvedFactValue tenant = row.get("resource.tenantId");
            return tenant != null && "tenant-alpha".equals(tenant.value());
        };

        // P05: DataScopeOutcome.ALL preserves hardScopeWhereClause and hardScopeRowPredicate!
        DataScopePlan allPlan = new DataScopePlan(
                DataScopePlan.FORMAT_V1,
                "plan-all",
                "resource-operation/human-resources.leave-requests/filter",
                "human-resources.leave-requests",
                "rev-1",
                qpDigest,
                qpDigest,
                projection.projectionId(),
                qpDigest,
                DataScopeOutcome.ALL,
                PushdownMode.FULL_PUSHDOWN,
                null
        );
        CompiledDataScopeCriterion allCrit = adapter.compile(
                allPlan, "e.tenantId = :hardTenantId", Map.of("hardTenantId", "tenant-alpha"), tenantHardScope);
        assertEquals("(e.tenantId = :hardTenantId) AND (1 = 1)", allCrit.composedWhereClause());
        assertFalse(allCrit.matchesRow(Map.of(
                "resource.tenantId", ResolvedFactValue.present("resource.tenantId", "tenant-beta"),
                "resource.departmentId", ResolvedFactValue.present("resource.departmentId", 101L)
        )));

        // P06 & P07: Negated comparison on nullable column + 1:N correlated EXISTS subquery
        LogicalPredicateIr notDepartment101AndDep = new LogicalPredicateIr(
                SearchPredicateOperator.AND,
                List.of(
                        new LogicalPredicateIr(
                                SearchPredicateOperator.NOT,
                                List.of(new ComparisonPredicateIr(
                                        SearchPredicateOperator.EQ,
                                        "resource.departmentId",
                                        "hr.leave_requests.department_id",
                                        FactValueType.INT64,
                                        new LiteralOperandIr(101L),
                                        false
                                ))
                        ),
                        new ComparisonPredicateIr(
                                SearchPredicateOperator.EQ,
                                "resource.dependentTaxId",
                                "hr.dependents.tax_id",
                                FactValueType.STRING,
                                new LiteralOperandIr("12345678901"),
                                false
                        )
                )
        );

        DataScopePlan filterPlan = new DataScopePlan(
                DataScopePlan.FORMAT_V1,
                "plan-filter",
                "resource-operation/human-resources.leave-requests/filter",
                "human-resources.leave-requests",
                "rev-1",
                qpDigest,
                qpDigest,
                projection.projectionId(),
                qpDigest,
                DataScopeOutcome.FILTER,
                PushdownMode.FULL_PUSHDOWN,
                notDepartment101AndDep
        );

        CompiledDataScopeCriterion filterCrit = adapter.compile(
                filterPlan, "e.tenantId = :hardTenantId", Map.of("hardTenantId", "tenant-alpha"), tenantHardScope);

        // Verify explicit IS NOT NULL guard on nullable column and correlated EXISTS subquery for 1:N
        assertTrue(filterCrit.policyWhereClause().contains("e.assignment.department.id IS NOT NULL AND e.assignment.department.id <> :dspParam1"));
        assertTrue(filterCrit.policyWhereClause().contains("EXISTS (SELECT 1 FROM human-resources.leave-requests sub WHERE sub.parentId = e.id"));

        // Row with NULL departmentId must NOT be selected by NOT(EQ(101)) (Kleene 3VL equivalence)
        Map<String, ResolvedFactValue> rowNullDepartment = Map.of(
                "resource.tenantId", ResolvedFactValue.present("resource.tenantId", "tenant-alpha"),
                "resource.departmentId", ResolvedFactValue.explicitNull("resource.departmentId"),
                "resource.dependentTaxId", ResolvedFactValue.present("resource.dependentTaxId", "12345678901")
        );
        Map<String, ResolvedFactValue> rowDepartment202 = Map.of(
                "resource.tenantId", ResolvedFactValue.present("resource.tenantId", "tenant-alpha"),
                "resource.departmentId", ResolvedFactValue.present("resource.departmentId", 202L),
                "resource.dependentTaxId", ResolvedFactValue.present("resource.dependentTaxId", "12345678901")
        );
        List<Map<String, ResolvedFactValue>> authorized = adapter.filterAuthorizedRows(
                List.of(rowNullDepartment, rowDepartment202), filterCrit);
        assertEquals(1, authorized.size());
        assertEquals(202L, authorized.get(0).get("resource.departmentId").value());

        // P2-R04: De Morgan's law on NOT(AND(A, B)) -> (NOT A OR NOT B) without double negation!
        LogicalPredicateIr notAndTree = new LogicalPredicateIr(
                SearchPredicateOperator.NOT,
                List.of(new LogicalPredicateIr(
                        SearchPredicateOperator.AND,
                        List.of(
                                new ComparisonPredicateIr(
                                        SearchPredicateOperator.EQ,
                                        "resource.departmentId",
                                        "hr.leave_requests.department_id",
                                        FactValueType.INT64,
                                        new LiteralOperandIr(101L),
                                        false
                                ),
                                new ComparisonPredicateIr(
                                        SearchPredicateOperator.EQ,
                                        "resource.departmentId",
                                        "hr.leave_requests.department_id",
                                        FactValueType.INT64,
                                        new LiteralOperandIr(202L),
                                        false
                                )
                        )
                ))
        );
        DataScopePlan deMorganPlan = new DataScopePlan(
                DataScopePlan.FORMAT_V1,
                "plan-demorgan",
                "resource-operation/human-resources.leave-requests/filter",
                "human-resources.leave-requests",
                "rev-1",
                qpDigest,
                qpDigest,
                projection.projectionId(),
                qpDigest,
                DataScopeOutcome.FILTER,
                PushdownMode.FULL_PUSHDOWN,
                notAndTree
        );
        CompiledDataScopeCriterion deMorganCrit = adapter.compile(
                deMorganPlan, "e.tenantId = :hardTenantId", Map.of("hardTenantId", "tenant-alpha"), tenantHardScope);
        assertTrue(deMorganCrit.policyWhereClause().contains(" OR "),
                "NOT(A AND B) must translate via De Morgan to (NOT A OR NOT B)");
        assertFalse(deMorganCrit.policyWhereClause().startsWith("NOT ("),
                "De Morgan pushdown must not double-negate children inside outer NOT(...)");

        // P2-R1 (DSP-SQL-002): Case-insensitive comparison wraps column in LOWER(...) and lowercases bound parameter!
        ComparisonPredicateIr caseInsensitiveComp = new ComparisonPredicateIr(
                SearchPredicateOperator.EQ,
                "resource.dependentTaxId",
                "hr.dependents.tax_id",
                FactValueType.STRING,
                new LiteralOperandIr("ABC-123"),
                true
        );
        DataScopePlan ciPlan = new DataScopePlan(
                DataScopePlan.FORMAT_V1,
                "plan-ci",
                "resource-operation/human-resources.leave-requests/filter",
                "human-resources.leave-requests",
                "rev-1",
                qpDigest,
                qpDigest,
                projection.projectionId(),
                qpDigest,
                DataScopeOutcome.FILTER,
                PushdownMode.FULL_PUSHDOWN,
                caseInsensitiveComp
        );
        CompiledDataScopeCriterion ciCrit = adapter.compile(
                ciPlan, "e.tenantId = :hardTenantId", Map.of("hardTenantId", "tenant-alpha"), tenantHardScope);
        assertTrue(ciCrit.policyWhereClause().contains("LOWER(sub.dependents.taxId) = :dspParam1"));
        assertEquals("abc-123", ciCrit.boundParameters().get("dspParam1"));

        // P10-R04: NullabilityPredicateIr on CORRELATED_EXISTS_SUBQUERY wraps in EXISTS (SELECT 1 ... sub.<path> IS NOT NULL)
        NullabilityPredicateIr nullSubqueryPred = new NullabilityPredicateIr(
                SearchPredicateOperator.IS_NOT_NULL,
                "resource.dependentTaxId",
                "hr.dependents.tax_id"
        );
        DataScopePlan nullSubqueryPlan = new DataScopePlan(
                DataScopePlan.FORMAT_V1,
                "plan-null-sub",
                "resource-operation/human-resources.leave-requests/filter",
                "human-resources.leave-requests",
                "rev-1",
                qpDigest,
                qpDigest,
                projection.projectionId(),
                qpDigest,
                DataScopeOutcome.FILTER,
                PushdownMode.FULL_PUSHDOWN,
                nullSubqueryPred
        );
        CompiledDataScopeCriterion nullSubCrit = adapter.compile(
                nullSubqueryPlan, "e.tenantId = :hardTenantId", Map.of("hardTenantId", "tenant-alpha"), tenantHardScope);
        assertTrue(nullSubCrit.policyWhereClause().contains(
                "EXISTS (SELECT 1 FROM human-resources.leave-requests sub WHERE sub.parentId = e.id AND (sub.dependents.taxId IS NOT NULL))"));

        // C-03a: Negated ComparisonPredicateIr and NullabilityPredicateIr on CORRELATED_EXISTS_SUBQUERY
        // must push negation OUTSIDE EXISTS -> NOT EXISTS (never EXISTS (... <> ...)).
        LogicalPredicateIr notDepComp = new LogicalPredicateIr(
                SearchPredicateOperator.NOT,
                List.of(new ComparisonPredicateIr(
                        SearchPredicateOperator.EQ,
                        "resource.dependentTaxId",
                        "hr.dependents.tax_id",
                        FactValueType.STRING,
                        new LiteralOperandIr("99999999999"),
                        false
                ))
        );
        DataScopePlan notDepCompPlan = new DataScopePlan(
                DataScopePlan.FORMAT_V1,
                "plan-not-dep-comp",
                "resource-operation/human-resources.leave-requests/filter",
                "human-resources.leave-requests",
                "rev-1",
                qpDigest,
                qpDigest,
                projection.projectionId(),
                qpDigest,
                DataScopeOutcome.FILTER,
                PushdownMode.FULL_PUSHDOWN,
                notDepComp
        );
        CompiledDataScopeCriterion notDepCompCrit = adapter.compile(
                notDepCompPlan, "e.tenantId = :hardTenantId", Map.of("hardTenantId", "tenant-alpha"), tenantHardScope);
        assertTrue(notDepCompCrit.policyWhereClause().startsWith("NOT EXISTS (SELECT 1 FROM human-resources.leave-requests sub"),
                "Negated 1:N comparison must translate to NOT EXISTS");
        assertTrue(notDepCompCrit.policyWhereClause().contains("sub.dependents.taxId = :dspParam1"),
                "Inner comparison of NOT EXISTS must stay unnegated (=)");

        LogicalPredicateIr notDepNull = new LogicalPredicateIr(
                SearchPredicateOperator.NOT,
                List.of(new NullabilityPredicateIr(
                        SearchPredicateOperator.IS_NULL,
                        "resource.dependentTaxId",
                        "hr.dependents.tax_id"
                ))
        );
        DataScopePlan notDepNullPlan = new DataScopePlan(
                DataScopePlan.FORMAT_V1,
                "plan-not-dep-null",
                "resource-operation/human-resources.leave-requests/filter",
                "human-resources.leave-requests",
                "rev-1",
                qpDigest,
                qpDigest,
                projection.projectionId(),
                qpDigest,
                DataScopeOutcome.FILTER,
                PushdownMode.FULL_PUSHDOWN,
                notDepNull
        );
        CompiledDataScopeCriterion notDepNullCrit = adapter.compile(
                notDepNullPlan, "e.tenantId = :hardTenantId", Map.of("hardTenantId", "tenant-alpha"), tenantHardScope);
        assertEquals(
                "NOT EXISTS (SELECT 1 FROM human-resources.leave-requests sub WHERE sub.parentId = e.id AND (sub.dependents.taxId IS NULL))",
                notDepNullCrit.policyWhereClause());
    }

    @Test
    void p13_p50_fieldUseQueryGuardBlocksFilterSortAndGroupByInferenceOnRestrictedField() {
        FieldUseQueryGuard guard = new FieldUseQueryGuard();
        String medicalCodeAttr = "hr.leave_requests.medical_code";

        List<FieldUseEffectDirective> directives = List.of(
                new FieldUseEffectDirective(medicalCodeAttr, FieldUseCategory.VALUE, RuleEffect.ALLOW),
                new FieldUseEffectDirective(medicalCodeAttr, FieldUseCategory.FILTER, RuleEffect.DENY),
                new FieldUseEffectDirective(medicalCodeAttr, FieldUseCategory.SORT, RuleEffect.DENY),
                new FieldUseEffectDirective(medicalCodeAttr, FieldUseCategory.GROUP, RuleEffect.DENY)
        );

        // Filtering by a non-restricted attribute is allowed
        guard.guardQueryFieldUses(
                Map.of(FieldUseCategory.FILTER, Set.of("hr.leave_requests.department_id")),
                directives
        );

        // P13 / P50: Filtering or sorting by medical_code to infer its value is blocked fail-closed!
        FieldUseViolationException ex = assertThrows(FieldUseViolationException.class, () ->
                guard.guardQueryFieldUses(
                        Map.of(FieldUseCategory.FILTER, Set.of(medicalCodeAttr)),
                        directives
                )
        );
        assertEquals(FieldUseCategory.FILTER, ex.getCategory());
        assertTrue(ex.getForbiddenAttributeIds().contains(medicalCodeAttr));
    }
}
