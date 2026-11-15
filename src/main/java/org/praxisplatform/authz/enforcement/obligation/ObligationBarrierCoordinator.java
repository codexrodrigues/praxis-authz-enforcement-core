package org.praxisplatform.authz.enforcement.obligation;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.praxisplatform.authz.contracts.envelope.EnforcementDisposition;
import org.praxisplatform.authz.contracts.envelope.ObligationDirective;
import org.praxisplatform.authz.contracts.obligation.DefaultObligationHandlerRegistry;
import org.praxisplatform.authz.contracts.obligation.ObligationFulfillmentBarrier;
import org.praxisplatform.authz.contracts.obligation.ObligationFulfillmentResult;
import org.praxisplatform.authz.contracts.obligation.ObligationHandler;
import org.praxisplatform.authz.contracts.obligation.ObligationHandlerRegistry;
import org.praxisplatform.authz.contracts.obligation.ObligationMergeOutcome;
import org.praxisplatform.authz.contracts.obligation.ObligationMergeStatus;

/**
 * Coordinates deterministic merging and barrier-scoped fulfillment of {@link ObligationDirective}s,
 * enforcing {@code ENF-OBL-003} fail-closed revocation of {@code PERMIT} whenever an obligation is
 * unknown, conflicting, or unfulfilled at its barrier ({@code CC10}, {@code P21}, {@code P22}).
 */
public final class ObligationBarrierCoordinator {

    private final ObligationHandlerRegistry handlerRegistry;
    private final TransactionalAuditOutboxPort auditOutboxPort;

    /** Constructs a coordinator with the default 4-obligation registry and an in-memory outbox. */
    public ObligationBarrierCoordinator() {
        this(new DefaultObligationHandlerRegistry(), new InMemoryTransactionalAuditOutbox());
    }

    /**
     * Constructs a coordinator with the given handler registry and transactional audit outbox port.
     *
     * @param handlerRegistry obligation handler registry
     * @param auditOutboxPort transactional audit outbox port
     */
    public ObligationBarrierCoordinator(
            ObligationHandlerRegistry handlerRegistry,
            TransactionalAuditOutboxPort auditOutboxPort
    ) {
        this.handlerRegistry = Objects.requireNonNull(handlerRegistry, "handlerRegistry is required");
        this.auditOutboxPort = Objects.requireNonNull(auditOutboxPort, "auditOutboxPort is required");
    }

    /**
     * Merges and fulfills all obligations in {@code directives} that match {@code barrier} and the
     * active {@code preliminaryDisposition}.
     *
     * @param decisionPointKey canonical decision point key
     * @param runtimeRevision provider runtime revision
     * @param preliminaryDisposition disposition prior to this barrier ({@code PERMIT} or {@code DENY})
     * @param barrier barrier being crossed ({@code BEFORE_EXECUTION}, {@code BEFORE_COMMIT_OUTBOX}, or {@code BEFORE_DISCLOSURE})
     * @param directives raw or combined obligation directives from the provider envelope
     * @param executionContext mutable/immutable execution context map containing MFA, justification, or watermark state
     * @return list of fulfillment results at this barrier
     */
    public List<ObligationFulfillmentResult> fulfillAtBarrier(
            String decisionPointKey,
            String runtimeRevision,
            EnforcementDisposition preliminaryDisposition,
            ObligationFulfillmentBarrier barrier,
            List<ObligationDirective> directives,
            Map<String, Object> executionContext
    ) {
        Objects.requireNonNull(decisionPointKey, "decisionPointKey is required");
        Objects.requireNonNull(runtimeRevision, "runtimeRevision is required");
        Objects.requireNonNull(preliminaryDisposition, "preliminaryDisposition is required");
        Objects.requireNonNull(barrier, "barrier is required");
        if (directives == null || directives.isEmpty()) {
            return List.of();
        }

        // Filter directives matching the active disposition and barrier
        Map<String, List<ObligationDirective>> byType = new LinkedHashMap<>();
        for (ObligationDirective dir : directives) {
            if (!barrier.name().equals(dir.fulfillmentBarrier())) {
                continue;
            }
            if (!matchesDisposition(dir.trigger(), preliminaryDisposition)) {
                continue;
            }
            byType.computeIfAbsent(dir.obligationType(), k -> new ArrayList<>()).add(dir);
        }

        List<ObligationFulfillmentResult> results = new ArrayList<>();
        for (Map.Entry<String, List<ObligationDirective>> entry : byType.entrySet()) {
            String obligationType = entry.getKey();
            List<ObligationDirective> group = entry.getValue();

            Optional<ObligationHandler> handlerOpt = handlerRegistry.findHandler(obligationType);
            if (handlerOpt.isEmpty()) {
                results.add(new ObligationFulfillmentResult(
                        obligationType,
                        barrier,
                        false,
                        "AUTHZ_UNKNOWN_OBLIGATION_TYPE:" + obligationType,
                        Map.of()));
                continue;
            }

            ObligationDirective effective = group.get(0);
            boolean mergeFailed = false;
            for (int i = 1; i < group.size(); i++) {
                ObligationMergeOutcome merged = handlerRegistry.merge(effective, group.get(i));
                if (merged.status() != ObligationMergeStatus.MERGED) {
                    results.add(new ObligationFulfillmentResult(
                            obligationType,
                            barrier,
                            false,
                            merged.diagnosticCode(),
                            Map.of()));
                    mergeFailed = true;
                    break;
                }
                effective = merged.mergedDirective();
            }
            if (mergeFailed) {
                continue;
            }

            Map<String, Object> effectiveCtx = new LinkedHashMap<>(
                    executionContext == null ? Map.of() : executionContext);
            if ("DURABLE_AUDIT_EVIDENCE".equals(obligationType)
                    && barrier == ObligationFulfillmentBarrier.BEFORE_COMMIT_OUTBOX
                    && !effectiveCtx.containsKey("auditOutboxPersisted")) {
                boolean written = auditOutboxPort.appendAuditOutboxRecord(
                        decisionPointKey, runtimeRevision, effective.parameters());
                effectiveCtx.put("auditOutboxPersisted", written);
            }

            ObligationHandler handler = handlerOpt.get();
            if (!handler.requiredBarrier().equals(barrier)) {
                results.add(new ObligationFulfillmentResult(
                        obligationType,
                        barrier,
                        false,
                        "AUTHZ_OBLIGATION_BARRIER_MISMATCH:" + barrier,
                        Map.of()));
                continue;
            }
            results.add(handler.fulfill(effective, effectiveCtx));
        }

        return List.copyOf(results);
    }

    private static boolean matchesDisposition(String trigger, EnforcementDisposition disposition) {
        if ("ALWAYS".equals(trigger)) {
            return true;
        }
        if ("ON_PERMIT".equals(trigger)) {
            return disposition == EnforcementDisposition.PERMIT;
        }
        if ("ON_DENY".equals(trigger)) {
            return disposition == EnforcementDisposition.DENY;
        }
        return false;
    }
}
