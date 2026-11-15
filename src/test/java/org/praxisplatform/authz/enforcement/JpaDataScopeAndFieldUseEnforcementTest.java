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
import org.praxisplatform.authz.contracts.datascope.LiteralListOperandIr;
import org.praxisplatform.authz.contracts.datascope.LiteralOperandIr;
import org.praxisplatform.authz.contracts.datascope.LogicalPredicateIr;
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
        QueryableFieldDescriptor lotacaoField = new QueryableFieldDescriptor(
                "resource.lotacaoSetorId",
                "ergon.afastamentos.lotacao_setor_id",
                FactValueType.INT64,
                Set.of(SearchPredicateOperator.EQ, SearchPredicateOperator.NE, SearchPredicateOperator.IN),
                true
        );
        QueryableFieldDescriptor depCPF = new QueryableFieldDescriptor(
                "resource.dependenteCpf",
                "ergon.dependentes.cpf",
                FactValueType.STRING,
                Set.of(SearchPredicateOperator.EQ, SearchPredicateOperator.IS_NOT_NULL),
                false
        );

        QueryableResourceProjection projection = new QueryableResourceProjection(
                QueryableResourceProjection.SCHEMA_VERSION_V1,
                "qp-afastamentos",
                "human-resources.afastamentos",
                qpDigest,
                Map.of(
                        lotacaoField.fieldPath(), lotacaoField,
                        depCPF.fieldPath(), depCPF
                )
        );

        QueryAdapterFieldBinding lotacaoBinding = new QueryAdapterFieldBinding(
                "human-resources.afastamentos",
                "resource.lotacaoSetorId",
                "ergon.afastamentos.lotacao_setor_id",
                "vinculo.lotacao.id",
                RelationTraversalStrategy.INNER_JOIN_SCALAR,
                true
        );
        QueryAdapterFieldBinding depBinding = new QueryAdapterFieldBinding(
                "human-resources.afastamentos",
                "resource.dependenteCpf",
                "ergon.dependentes.cpf",
                "dependentes.cpf",
                RelationTraversalStrategy.CORRELATED_EXISTS_SUBQUERY,
                true
        );

        JpaDataScopeAdapter adapter = new JpaDataScopeAdapter(
                projection, List.of(lotacaoBinding, depBinding));

        Predicate<Map<String, ResolvedFactValue>> tenantHardScope = row -> {
            ResolvedFactValue tenant = row.get("resource.tenantId");
            return tenant != null && "gov-sp".equals(tenant.value());
        };

        // P05: DataScopeOutcome.ALL preserves hardScopeWhereClause and hardScopeRowPredicate!
        DataScopePlan allPlan = new DataScopePlan(
                DataScopePlan.FORMAT_V1,
                "plan-all",
                "resource-operation/human-resources.afastamentos/filter",
                "human-resources.afastamentos",
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
                allPlan, "e.tenantId = :hardTenantId", Map.of("hardTenantId", "gov-sp"), tenantHardScope);
        assertEquals("(e.tenantId = :hardTenantId) AND (1 = 1)", allCrit.composedWhereClause());
        assertFalse(allCrit.matchesRow(Map.of(
                "resource.tenantId", ResolvedFactValue.present("resource.tenantId", "gov-rj"),
                "resource.lotacaoSetorId", ResolvedFactValue.present("resource.lotacaoSetorId", 101L)
        )));

        // P06 & P07: Negated comparison on nullable column + 1:N correlated EXISTS subquery
        LogicalPredicateIr notLotacao101AndDep = new LogicalPredicateIr(
                SearchPredicateOperator.AND,
                List.of(
                        new LogicalPredicateIr(
                                SearchPredicateOperator.NOT,
                                List.of(new ComparisonPredicateIr(
                                        SearchPredicateOperator.EQ,
                                        "resource.lotacaoSetorId",
                                        "ergon.afastamentos.lotacao_setor_id",
                                        FactValueType.INT64,
                                        new LiteralOperandIr(101L),
                                        false
                                ))
                        ),
                        new ComparisonPredicateIr(
                                SearchPredicateOperator.EQ,
                                "resource.dependenteCpf",
                                "ergon.dependentes.cpf",
                                FactValueType.STRING,
                                new LiteralOperandIr("12345678901"),
                                false
                        )
                )
        );

        DataScopePlan filterPlan = new DataScopePlan(
                DataScopePlan.FORMAT_V1,
                "plan-filter",
                "resource-operation/human-resources.afastamentos/filter",
                "human-resources.afastamentos",
                "rev-1",
                qpDigest,
                qpDigest,
                projection.projectionId(),
                qpDigest,
                DataScopeOutcome.FILTER,
                PushdownMode.FULL_PUSHDOWN,
                notLotacao101AndDep
        );

        CompiledDataScopeCriterion filterCrit = adapter.compile(
                filterPlan, "e.tenantId = :hardTenantId", Map.of("hardTenantId", "gov-sp"), tenantHardScope);

        // Verify explicit IS NOT NULL guard on nullable column and correlated EXISTS subquery for 1:N
        assertTrue(filterCrit.policyWhereClause().contains("e.vinculo.lotacao.id IS NOT NULL AND e.vinculo.lotacao.id <> :dspParam1"));
        assertTrue(filterCrit.policyWhereClause().contains("EXISTS (SELECT 1 FROM human-resources.afastamentos sub WHERE sub.parentId = e.id"));

        // Row with NULL lotacaoSetorId must NOT be selected by NOT(EQ(101)) (Kleene 3VL equivalence)
        Map<String, ResolvedFactValue> rowNullLotacao = Map.of(
                "resource.tenantId", ResolvedFactValue.present("resource.tenantId", "gov-sp"),
                "resource.lotacaoSetorId", ResolvedFactValue.explicitNull("resource.lotacaoSetorId"),
                "resource.dependenteCpf", ResolvedFactValue.present("resource.dependenteCpf", "12345678901")
        );
        Map<String, ResolvedFactValue> rowLotacao202 = Map.of(
                "resource.tenantId", ResolvedFactValue.present("resource.tenantId", "gov-sp"),
                "resource.lotacaoSetorId", ResolvedFactValue.present("resource.lotacaoSetorId", 202L),
                "resource.dependenteCpf", ResolvedFactValue.present("resource.dependenteCpf", "12345678901")
        );
        List<Map<String, ResolvedFactValue>> authorized = adapter.filterAuthorizedRows(
                List.of(rowNullLotacao, rowLotacao202), filterCrit);
        assertEquals(1, authorized.size());
        assertEquals(202L, authorized.get(0).get("resource.lotacaoSetorId").value());

        // P2-R04: De Morgan's law on NOT(AND(A, B)) -> (NOT A OR NOT B) without double negation!
        LogicalPredicateIr notAndTree = new LogicalPredicateIr(
                SearchPredicateOperator.NOT,
                List.of(new LogicalPredicateIr(
                        SearchPredicateOperator.AND,
                        List.of(
                                new ComparisonPredicateIr(
                                        SearchPredicateOperator.EQ,
                                        "resource.lotacaoSetorId",
                                        "ergon.afastamentos.lotacao_setor_id",
                                        FactValueType.INT64,
                                        new LiteralOperandIr(101L),
                                        false
                                ),
                                new ComparisonPredicateIr(
                                        SearchPredicateOperator.EQ,
                                        "resource.lotacaoSetorId",
                                        "ergon.afastamentos.lotacao_setor_id",
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
                "resource-operation/human-resources.afastamentos/filter",
                "human-resources.afastamentos",
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
                deMorganPlan, "e.tenantId = :hardTenantId", Map.of("hardTenantId", "gov-sp"), tenantHardScope);
        assertTrue(deMorganCrit.policyWhereClause().contains(" OR "),
                "NOT(A AND B) must translate via De Morgan to (NOT A OR NOT B)");
        assertFalse(deMorganCrit.policyWhereClause().startsWith("NOT ("),
                "De Morgan pushdown must not double-negate children inside outer NOT(...)");

        // P2-R1 (DSP-SQL-002): Case-insensitive comparison wraps column in LOWER(...) and lowercases bound parameter!
        ComparisonPredicateIr caseInsensitiveComp = new ComparisonPredicateIr(
                SearchPredicateOperator.EQ,
                "resource.dependenteCpf",
                "ergon.dependentes.cpf",
                FactValueType.STRING,
                new LiteralOperandIr("ABC-123"),
                true
        );
        DataScopePlan ciPlan = new DataScopePlan(
                DataScopePlan.FORMAT_V1,
                "plan-ci",
                "resource-operation/human-resources.afastamentos/filter",
                "human-resources.afastamentos",
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
                ciPlan, "e.tenantId = :hardTenantId", Map.of("hardTenantId", "gov-sp"), tenantHardScope);
        assertTrue(ciCrit.policyWhereClause().contains("LOWER(sub.dependentes.cpf) = :dspParam1"));
        assertEquals("abc-123", ciCrit.boundParameters().get("dspParam1"));

        // P10-R04: NullabilityPredicateIr on CORRELATED_EXISTS_SUBQUERY wraps in EXISTS (SELECT 1 ... sub.<path> IS NOT NULL)
        org.praxisplatform.authz.contracts.datascope.NullabilityPredicateIr nullSubqueryPred =
                new org.praxisplatform.authz.contracts.datascope.NullabilityPredicateIr(
                        SearchPredicateOperator.IS_NOT_NULL,
                        "resource.dependenteCpf",
                        "ergon.dependentes.cpf"
                );
        DataScopePlan nullSubqueryPlan = new DataScopePlan(
                DataScopePlan.FORMAT_V1,
                "plan-null-sub",
                "resource-operation/human-resources.afastamentos/filter",
                "human-resources.afastamentos",
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
                nullSubqueryPlan, "e.tenantId = :hardTenantId", Map.of("hardTenantId", "gov-sp"), tenantHardScope);
        assertTrue(nullSubCrit.policyWhereClause().contains(
                "EXISTS (SELECT 1 FROM human-resources.afastamentos sub WHERE sub.parentId = e.id AND (sub.dependentes.cpf IS NOT NULL))"));
    }

    @Test
    void p13_p50_fieldUseQueryGuardBlocksFilterSortAndGroupByInferenceOnRestrictedField() {
        FieldUseQueryGuard guard = new FieldUseQueryGuard();
        String cidAttr = "ergon.afastamentos.cid_codigo";

        List<FieldUseEffectDirective> directives = List.of(
                new FieldUseEffectDirective(cidAttr, FieldUseCategory.VALUE, RuleEffect.ALLOW),
                new FieldUseEffectDirective(cidAttr, FieldUseCategory.FILTER, RuleEffect.DENY),
                new FieldUseEffectDirective(cidAttr, FieldUseCategory.SORT, RuleEffect.DENY),
                new FieldUseEffectDirective(cidAttr, FieldUseCategory.GROUP, RuleEffect.DENY)
        );

        // Filtering by a non-restricted attribute is allowed
        guard.guardQueryFieldUses(
                Map.of(FieldUseCategory.FILTER, Set.of("ergon.afastamentos.lotacao_setor_id")),
                directives
        );

        // P13 / P50: Filtering or sorting by cid_codigo to infer its value is blocked fail-closed!
        FieldUseViolationException ex = assertThrows(FieldUseViolationException.class, () ->
                guard.guardQueryFieldUses(
                        Map.of(FieldUseCategory.FILTER, Set.of(cidAttr)),
                        directives
                )
        );
        assertEquals(FieldUseCategory.FILTER, ex.getCategory());
        assertTrue(ex.getForbiddenAttributeIds().contains(cidAttr));
    }
}
