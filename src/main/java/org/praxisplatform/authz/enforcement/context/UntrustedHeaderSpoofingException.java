package org.praxisplatform.authz.enforcement.context;

import java.util.Objects;

/**
 * Exception raised when an untrusted client header or request attribute attempts to spoof or override
 * an authoritative security fact such as tenant, company, organization unit, role, or workflow stage
 * ({@code P01}, {@code P42}, {@code CTX-TRUST-001..004}).
 */
public final class UntrustedHeaderSpoofingException extends RuntimeException {

    private final String headerName;
    private final String attemptedTargetFactPath;

    /**
     * Constructs a spoofing exception with structured diagnostic fields.
     *
     * @param headerName untrusted HTTP header name
     * @param attemptedTargetFactPath canonical fact path that the header attempted to influence
     * @param message diagnostic message
     */
    public UntrustedHeaderSpoofingException(
            String headerName,
            String attemptedTargetFactPath,
            String message
    ) {
        super(Objects.requireNonNull(message, "message is required"));
        this.headerName = Objects.requireNonNull(headerName, "headerName is required");
        this.attemptedTargetFactPath = Objects.requireNonNull(attemptedTargetFactPath, "attemptedTargetFactPath is required");
    }

    /** Returns the untrusted HTTP header name. */
    public String getHeaderName() {
        return headerName;
    }

    /** Returns the canonical fact path targeted by the spoofing attempt. */
    public String getAttemptedTargetFactPath() {
        return attemptedTargetFactPath;
    }
}
