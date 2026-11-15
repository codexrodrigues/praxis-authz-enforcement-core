package org.praxisplatform.authz.enforcement.masking;

import java.util.Objects;

/**
 * Exception raised fail-closed when masking directives conflict or violate target DTO field
 * compatibility ({@code CC09}, {@code ENF-GEN-019}, {@code ENF-MSK-004..008}).
 */
public final class MaskingConflictException extends RuntimeException {

    private final String attributeId;
    private final String diagnosticCode;

    /**
     * Constructs a masking conflict exception.
     *
     * @param attributeId target canonical attributeId
     * @param diagnosticCode conflict diagnostic code
     * @param message diagnostic message
     */
    public MaskingConflictException(String attributeId, String diagnosticCode, String message) {
        super(Objects.requireNonNull(message, "message is required"));
        this.attributeId = Objects.requireNonNull(attributeId, "attributeId is required");
        this.diagnosticCode = Objects.requireNonNull(diagnosticCode, "diagnosticCode is required");
    }

    /** Returns the target canonical {@code attributeId}. */
    public String getAttributeId() {
        return attributeId;
    }

    /** Returns the conflict diagnostic code. */
    public String getDiagnosticCode() {
        return diagnosticCode;
    }
}
