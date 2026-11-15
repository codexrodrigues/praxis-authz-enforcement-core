package org.praxisplatform.authz.enforcement.context;

import java.util.Objects;
import java.util.Optional;
import org.praxisplatform.authz.contracts.context.EvaluationContextSnapshot;

/**
 * Thread-scoped and task-scoped execution context holder with mandatory {@link AutoCloseable}
 * restoration semantics, preventing residual principal, authority, or mask leakage across pooled
 * threads or background workers ({@code P02}, {@code P20}).
 */
public final class ScopedExecutionContextHolder {

    private static final ThreadLocal<EvaluationContextSnapshot> CURRENT = new ThreadLocal<>();

    private ScopedExecutionContextHolder() {}

    /**
     * Opens a new execution scope bound to {@code snapshot}, returning an {@link AutoCloseable} token
     * that restores the previous snapshot (or clears the thread-local when outermost) upon {@link ScopeToken#close()}.
     *
     * @param snapshot immutable evaluation context snapshot for the current operation
     * @return scope token to be closed in a {@code try-with-resources} block
     */
    public static ScopeToken open(EvaluationContextSnapshot snapshot) {
        Objects.requireNonNull(snapshot, "snapshot is required");
        EvaluationContextSnapshot previous = CURRENT.get();
        CURRENT.set(snapshot);
        return new ScopeToken(previous);
    }

    /** Returns the currently bound {@link EvaluationContextSnapshot}, if any. */
    public static Optional<EvaluationContextSnapshot> current() {
        return Optional.ofNullable(CURRENT.get());
    }

    /** Explicitly clears the thread-local context for the current thread. */
    public static void clear() {
        CURRENT.remove();
    }

    /**
     * Auto-closeable scope token that guarantees thread-local cleanup even when exceptions occur.
     */
    public static final class ScopeToken implements AutoCloseable {
        private final EvaluationContextSnapshot previous;
        private boolean closed = false;

        private ScopeToken(EvaluationContextSnapshot previous) {
            this.previous = previous;
        }

        @Override
        public void close() {
            if (!closed) {
                closed = true;
                if (previous == null) {
                    CURRENT.remove();
                } else {
                    CURRENT.set(previous);
                }
            }
        }
    }
}
