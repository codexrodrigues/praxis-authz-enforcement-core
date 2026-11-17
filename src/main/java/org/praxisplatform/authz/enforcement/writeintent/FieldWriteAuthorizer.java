package org.praxisplatform.authz.enforcement.writeintent;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.binding.WriteFieldChange;
import org.praxisplatform.authz.contracts.binding.WriteIntent;
import org.praxisplatform.authz.contracts.envelope.FieldWriteEffectDirective;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;
import org.praxisplatform.authz.contracts.policy.DualScopeDelegationSpec;

/**
 * Enforces {@code FIELD_WRITE} directives and {@link DualScopeDelegationSpec} split-custody boundaries
 * at {@code STEP_11_ENFORCE_PRE_MUTATION_ACCESS_AND_FIELD_WRITE} before server-side {@code hydrate*},
 * {@code PraxisRulesEngine}, or {@code repository.save}/{@code flush} ({@code CC06}, {@code P16}, {@code P17}, {@code R-07}).
 */
public final class FieldWriteAuthorizer {

    /**
     * Validates that every {@link WriteFieldChange} in {@code writeIntent} is permitted by the combined
     * {@link FieldWriteEffectDirective}s (where {@code DENY} dominates {@code ALLOW}).
     *
     * @param writeIntent caller's pre-hydration write intent
     * @param directives combined field-write effect directives from the provider envelope
     * @param defaultAllowUnspecifiedFields whether attributes without an explicit directive default to allowed (e.g. in {@code RESTRICT_BASELINE})
     * @throws FieldWriteViolationException if any modified attribute is denied
     */
    public void enforceFieldWriteDirectives(
            WriteIntent writeIntent,
            List<FieldWriteEffectDirective> directives,
            boolean defaultAllowUnspecifiedFields
    ) {
        Objects.requireNonNull(writeIntent, "writeIntent is required");
        Objects.requireNonNull(directives, "directives is required");

        Map<String, RuleEffect> effectiveByAttribute = new LinkedHashMap<>();
        for (FieldWriteEffectDirective dir : directives) {
            RuleEffect current = effectiveByAttribute.get(dir.attributeId());
            if (current == RuleEffect.DENY || dir.effect() == RuleEffect.DENY) {
                effectiveByAttribute.put(dir.attributeId(), RuleEffect.DENY);
            } else {
                effectiveByAttribute.put(dir.attributeId(), RuleEffect.ALLOW);
            }
        }

        Set<String> deniedAttributes = new LinkedHashSet<>();
        for (WriteFieldChange change : writeIntent.changes()) {
            RuleEffect effect = effectiveByAttribute.get(change.attributeId());
            if (effect == RuleEffect.DENY || (effect == null && !defaultAllowUnspecifiedFields)) {
                deniedAttributes.add(change.attributeId());
            }
        }

        if (!deniedAttributes.isEmpty()) {
            throw new FieldWriteViolationException(
                    deniedAttributes,
                    "AUTHZ_FIELD_WRITE_DENIED",
                    "Caller is not authorized to modify attributes: " + deniedAttributes);
        }
    }

    /**
     * Enforces {@link DualScopeDelegationSpec} ({@code R-07}, {@code P17}): verifies that a caller acting
     * under origin custody only mutates {@link DualScopeDelegationSpec#originExclusiveWriteAttributes()},
     * and a caller acting under delegated destination custody only mutates
     * {@link DualScopeDelegationSpec#destinationAllowedWriteAttributes()} when the delegation mode
     * permits destination writes.
     *
     * <p>Supports both neutral modes ({@link DualScopeDelegationSpec#ORIGIN_DESTINATION_SPLIT},
     * {@link DualScopeDelegationSpec#ORIGIN_ONLY_WRITE},
     * {@link DualScopeDelegationSpec#READ_ONLY_DESTINATION}) and legacy backward-compatible aliases
     * ({@code CEDENTE_CESSIONARIO_SPLIT}, {@code CEDENTE_ONLY_WRITE}, {@code READ_ONLY_CESSIONARIO}).</p>
     *
     * @param writeIntent caller's pre-hydration write intent
     * @param dualScopeSpec dual-scope delegation specification
     * @param callerMatchesOriginScope whether the caller holds custody over the origin scope
     * @param callerMatchesDestinationScope whether the caller holds custody over the delegated destination scope
     * @throws FieldWriteViolationException if any modified attribute falls outside the caller's custody partition
     */
    public void enforceDualScopeCustody(
            WriteIntent writeIntent,
            DualScopeDelegationSpec dualScopeSpec,
            boolean callerMatchesOriginScope,
            boolean callerMatchesDestinationScope
    ) {
        Objects.requireNonNull(writeIntent, "writeIntent is required");
        Objects.requireNonNull(dualScopeSpec, "dualScopeSpec is required");

        if (!callerMatchesOriginScope && !callerMatchesDestinationScope) {
            throw new FieldWriteViolationException(
                    writeIntent.modifiedAttributeIds().isEmpty()
                            ? Set.of("<dual-scope-custody>")
                            : writeIntent.modifiedAttributeIds(),
                    "AUTHZ_DUAL_SCOPE_NO_CUSTODY_MATCH:" + dualScopeSpec.mode(),
                    "Caller matches neither origin nor delegated destination custody scope");
        }

        if (!callerMatchesOriginScope && dualScopeSpec.forbidsDestinationOnlyWrites()) {
            throw new FieldWriteViolationException(
                    writeIntent.modifiedAttributeIds().isEmpty()
                            ? Set.of("<dual-scope-mode>")
                            : writeIntent.modifiedAttributeIds(),
                    "AUTHZ_DUAL_SCOPE_MODE_FORBIDS_DESTINATION_WRITE:" + dualScopeSpec.mode(),
                    "Dual-scope mode '" + dualScopeSpec.mode()
                            + "' forbids mutations by a caller holding only delegated destination custody");
        }

        Set<String> allowedEditable = new LinkedHashSet<>();
        if (callerMatchesOriginScope) {
            allowedEditable.addAll(dualScopeSpec.originExclusiveWriteAttributes());
        }
        if (callerMatchesDestinationScope && dualScopeSpec.allowsDestinationWrites()) {
            allowedEditable.addAll(dualScopeSpec.destinationAllowedWriteAttributes());
        }

        Set<String> forbidden = new LinkedHashSet<>();
        for (WriteFieldChange change : writeIntent.changes()) {
            if (!allowedEditable.contains(change.attributeId())) {
                forbidden.add(change.attributeId());
            }
        }

        if (!forbidden.isEmpty()) {
            throw new FieldWriteViolationException(
                    forbidden,
                    "AUTHZ_DUAL_SCOPE_FIELD_WRITE_DENIED:" + dualScopeSpec.mode(),
                    "Dual-scope custody (" + dualScopeSpec.mode()
                            + ") forbids modifying attributes: " + forbidden);
        }
    }
}
