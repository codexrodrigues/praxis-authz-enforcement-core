package org.praxisplatform.authz.enforcement.obligation;

import java.util.Map;

/**
 * Port for persisting durable audit evidence inside the current business transaction at the
 * {@code BEFORE_COMMIT_OUTBOX} barrier ({@code CC10}, {@code P22}, {@code ENF-OBL-003}).
 */
public interface TransactionalAuditOutboxPort {

    /**
     * Appends an audit evidence record to the transactional outbox.
     *
     * @param decisionPointKey canonical decision point key
     * @param runtimeRevision active provider runtime revision
     * @param obligationParameters merged obligation parameters (e.g. {@code auditCategories})
     * @return {@code true} iff the outbox record was durably staged for commit
     */
    boolean appendAuditOutboxRecord(
            String decisionPointKey,
            String runtimeRevision,
            Map<String, Object> obligationParameters
    );
}
