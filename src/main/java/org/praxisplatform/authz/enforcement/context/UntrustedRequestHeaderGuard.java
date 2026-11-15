package org.praxisplatform.authz.enforcement.context;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.context.ResolvedFactValue;

/**
 * Enforces {@code CTX-TRUST-001..004} ({@code P01}, {@code P42}, {@code P61}): client HTTP headers can
 * never act as an authority source for {@code subject.*}, {@code action.*}, {@code resource.*},
 * {@code transition.*}, or workflow stage facts, nor override server-authenticated grants.
 */
public final class UntrustedRequestHeaderGuard {

    /**
     * Canonical mapping of untrusted client headers (lowercased) to the authoritative fact paths they
     * typically attempt to spoof in legacy or misconfigured systems.
     */
    public static final Map<String, String> FORBIDDEN_AUTHORITY_HEADERS = Map.ofEntries(
            Map.entry("x-tenant-id", "subject.tenantId"),
            Map.entry("x-company-id", "subject.companyIds"),
            Map.entry("x-empresa-id", "subject.companyIds"),
            Map.entry("x-org-id", "subject.organizationUnitIds"),
            Map.entry("x-setor-id", "subject.organizationUnitIds"),
            Map.entry("x-organization-unit-ids", "subject.organizationUnitIds"),
            Map.entry("x-delegated-cessionario-org-ids", "subject.delegatedCessionarioOrgIds"),
            Map.entry("x-principal-id", "subject.principalId"),
            Map.entry("x-user-id", "subject.principalId"),
            Map.entry("x-roles", "subject.roles"),
            Map.entry("x-role", "subject.roles"),
            Map.entry("x-active-role", "subject.activeRole"),
            Map.entry("x-workflow-stage", "transition.workflowStage"),
            Map.entry("x-point-authority", "context.pointAuthorityMode"),
            Map.entry("x-bypass-policy", "context.bypassPolicy"),
            Map.entry("x-authz-allow", "context.bypassPolicy")
    );

    /**
     * Header prefixes (lowercased) that are unconditionally forbidden from client HTTP requests
     * ({@code P01}, {@code P42}).
     */
    public static final List<String> UNCONDITIONALLY_FORBIDDEN_HEADER_PREFIXES = List.of(
            "x-authz-",
            "x-praxis-authz-",
            "x-bypass-",
            "x-effective-authority",
            "x-workflow-"
    );

    private UntrustedRequestHeaderGuard() {}

    /**
     * Validates that the incoming HTTP headers do not assert a tenant, company, organization unit,
     * role, or workflow stage that contradicts or attempts to expand the authenticated subject's
     * authoritative server-side facts ({@code P01}, {@code P42}, {@code P61}).
     *
     * @param rawHttpHeaders map of incoming HTTP headers
     * @param authoritativeSubjectFacts resolved authoritative {@code subject.*} facts from the authenticated principal
     * @throws UntrustedHeaderSpoofingException if any forbidden authority header attempts to spoof or expand access
     */
    public static void assertNoAuthoritySpoofingHeaders(
            Map<String, String> rawHttpHeaders,
            Map<String, ResolvedFactValue> authoritativeSubjectFacts
    ) {
        if (rawHttpHeaders == null || rawHttpHeaders.isEmpty()) {
            return;
        }
        Objects.requireNonNull(authoritativeSubjectFacts, "authoritativeSubjectFacts is required");

        for (Map.Entry<String, String> entry : rawHttpHeaders.entrySet()) {
            if (entry.getKey() == null || entry.getValue() == null || entry.getValue().isBlank()) {
                continue;
            }
            String normalizedHeader = entry.getKey().trim().toLowerCase(Locale.ROOT);
            String targetFactPath = FORBIDDEN_AUTHORITY_HEADERS.get(normalizedHeader);

            for (String prefix : UNCONDITIONALLY_FORBIDDEN_HEADER_PREFIXES) {
                if (normalizedHeader.startsWith(prefix)) {
                    throw new UntrustedHeaderSpoofingException(
                            entry.getKey(),
                            targetFactPath != null ? targetFactPath : "context.untrustedHeaderPrefix",
                            "Untrusted HTTP header '" + entry.getKey()
                                    + "' uses a reserved authority/workflow prefix '" + prefix
                                    + "' and is unconditionally forbidden (P01 / P42 / CTX-TRUST-001)");
                }
            }

            if (targetFactPath == null) {
                continue;
            }

            // P42: Non-subject namespaces (transition.*, context.*, resource.*, action.*) can NEVER be asserted by headers
            if (!targetFactPath.startsWith("subject.")) {
                throw new UntrustedHeaderSpoofingException(
                        entry.getKey(),
                        targetFactPath,
                        "Untrusted HTTP header '" + entry.getKey() + "' cannot assert non-subject fact '"
                                + targetFactPath + "' (P42 / CTX-TRUST-001)");
            }

            String headerValue = entry.getValue().trim();
            ResolvedFactValue authoritative = authoritativeSubjectFacts.get(targetFactPath);
            if (authoritative == null
                    || authoritative.status() != FactResolutionStatus.PRESENT
                    || authoritative.value() == null) {
                throw new UntrustedHeaderSpoofingException(
                        entry.getKey(),
                        targetFactPath,
                        "Untrusted HTTP header '" + entry.getKey() + "' attempted to inject ungranted authority fact '"
                                + targetFactPath + "' (P01 / P42 / CTX-TRUST-001)");
            }
            if (!isValueWithinAuthoritativeGrant(headerValue, authoritative.value())) {
                throw new UntrustedHeaderSpoofingException(
                        entry.getKey(),
                        targetFactPath,
                        "Untrusted HTTP header '" + entry.getKey() + "' value '" + headerValue
                                + "' is outside authoritative grant for '" + targetFactPath + "' (P01 / CTX-TRUST-002)");
            }
        }
    }

    private static boolean isValueWithinAuthoritativeGrant(String headerValue, Object authoritativeValue) {
        String[] tokens = headerValue.split(",");
        if (tokens.length == 0) {
            return false;
        }
        for (String rawToken : tokens) {
            String token = rawToken.trim();
            if (token.isEmpty() || !isSingleTokenGranted(token, authoritativeValue)) {
                return false;
            }
        }
        return true;
    }

    private static boolean isSingleTokenGranted(String token, Object authoritativeValue) {
        if (authoritativeValue instanceof Set<?> set) {
            return set.stream().anyMatch(item -> String.valueOf(item).equals(token));
        }
        if (authoritativeValue instanceof Iterable<?> iter) {
            for (Object item : iter) {
                if (String.valueOf(item).equals(token)) {
                    return true;
                }
            }
            return false;
        }
        return String.valueOf(authoritativeValue).equals(token);
    }
}
