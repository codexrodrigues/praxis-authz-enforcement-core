package org.praxisplatform.authz.enforcement.obligation;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Deterministic in-memory implementation of {@link TransactionalAuditOutboxPort} for testing and
 * local verification of {@code BEFORE_COMMIT_OUTBOX} fail-closed semantics ({@code CC10}, {@code P22}).
 */
public final class InMemoryTransactionalAuditOutbox implements TransactionalAuditOutboxPort {

    /** Immutable entry recorded in the outbox. */
    public record OutboxEntry(
            String decisionPointKey,
            String runtimeRevision,
            Map<String, Object> obligationParameters
    ) {
        public OutboxEntry {
            Objects.requireNonNull(decisionPointKey, "decisionPointKey is required");
            Objects.requireNonNull(runtimeRevision, "runtimeRevision is required");
            obligationParameters = obligationParameters == null ? Map.of() : Map.copyOf(obligationParameters);
        }
    }

    private final List<OutboxEntry> entries = Collections.synchronizedList(new ArrayList<>());
    private volatile boolean simulateWriteFailure = false;

    @Override
    public boolean appendAuditOutboxRecord(
            String decisionPointKey,
            String runtimeRevision,
            Map<String, Object> obligationParameters
    ) {
        if (simulateWriteFailure) {
            return false;
        }
        entries.add(new OutboxEntry(decisionPointKey, runtimeRevision, obligationParameters));
        return true;
    }

    /** Configures whether subsequent outbox writes should simulate a storage failure. */
    public void setSimulateWriteFailure(boolean simulateWriteFailure) {
        this.simulateWriteFailure = simulateWriteFailure;
    }

    /** Returns an immutable snapshot of all committed outbox entries. */
    public List<OutboxEntry> listEntries() {
        synchronized (entries) {
            return List.copyOf(entries);
        }
    }
}
