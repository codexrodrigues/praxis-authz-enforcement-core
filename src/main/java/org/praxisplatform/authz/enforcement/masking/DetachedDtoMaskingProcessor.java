package org.praxisplatform.authz.enforcement.masking;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;
import org.praxisplatform.authz.contracts.masking.DefaultMaskStrategyRegistry;
import org.praxisplatform.authz.contracts.masking.MaskMergeOutcome;
import org.praxisplatform.authz.contracts.masking.MaskMergeStatus;
import org.praxisplatform.authz.contracts.masking.MaskStrategyRegistry;

/**
 * Applies server-side security masking and {@code FIELD_USE(VALUE) = DENY} suppression over a
 * detached copy of a DTO or map projection ({@code CC09}, {@code P15}, {@code P40},
 * {@code STEP_14_PROJECT_AND_MASK_DETACHED_RESPONSE_DTO}).
 *
 * <p>Never mutates the caller's source object in place, preventing Hibernate dirty-checking from
 * flushing masked values back to the database.</p>
 */
public final class DetachedDtoMaskingProcessor {

    private static final TypeReference<LinkedHashMap<String, Object>> MAP_TYPE = new TypeReference<>() {};

    private final MaskStrategyRegistry strategyRegistry;
    private final ObjectMapper objectMapper;
    private final byte[] hmacSecretKey;

    /** Constructs a processor with the default 7-strategy registry and a default HMAC key. */
    public DetachedDtoMaskingProcessor() {
        this(new DefaultMaskStrategyRegistry(), "praxis-default-hmac-key-2026".getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Constructs a processor with the given {@link MaskStrategyRegistry} and HMAC secret key.
     *
     * @param strategyRegistry masking strategy registry
     * @param hmacSecretKey secret key bytes for {@code HASH_TOKEN_KEYED}
     */
    public DetachedDtoMaskingProcessor(MaskStrategyRegistry strategyRegistry, byte[] hmacSecretKey) {
        this.strategyRegistry = Objects.requireNonNull(strategyRegistry, "strategyRegistry is required");
        this.objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        this.hmacSecretKey = Objects.requireNonNull(hmacSecretKey, "hmacSecretKey is required").clone();
    }

    /**
     * Clones {@code sourceDtoOrMap} into a detached map projection and applies {@code valueDeniedAttributeIds}
     * and {@code maskDirectives} according to {@code fieldSchemas}.
     *
     * @param sourceDtoOrMap source DTO bean or map (never mutated in place)
     * @param fieldSchemas schema metadata for fields on the DTO
     * @param valueDeniedAttributeIds attributeIds where {@code FIELD_USE(VALUE) == DENY}
     * @param maskDirectives mask directives emitted by the policy evaluation
     * @return detached masking result
     */
    public DetachedDtoMaskingResult projectAndMask(
            Object sourceDtoOrMap,
            Collection<DtoFieldSchemaMetadata> fieldSchemas,
            Set<String> valueDeniedAttributeIds,
            List<MaskDirective> maskDirectives
    ) {
        Objects.requireNonNull(sourceDtoOrMap, "sourceDtoOrMap is required");
        Objects.requireNonNull(fieldSchemas, "fieldSchemas is required");
        Set<String> valueDenied = valueDeniedAttributeIds == null ? Set.of() : valueDeniedAttributeIds;
        List<MaskDirective> directives = maskDirectives == null ? List.of() : maskDirectives;

        // Deep clone into a detached LinkedHashMap so the source object/entity is never touched
        LinkedHashMap<String, Object> detached = objectMapper.convertValue(sourceDtoOrMap, MAP_TYPE);
        Map<String, String> appliedStrategies = new LinkedHashMap<>();

        Map<String, List<MaskDirective>> directivesByAttr = new LinkedHashMap<>();
        for (MaskDirective dir : directives) {
            directivesByAttr.computeIfAbsent(dir.attributeId(), k -> new ArrayList<>()).add(dir);
        }

        for (DtoFieldSchemaMetadata fieldMeta : fieldSchemas) {
            String attrId = fieldMeta.attributeId();
            String wireName = fieldMeta.wireFieldName();
            boolean isDeniedValue = valueDenied.contains(attrId);
            List<MaskDirective> fieldDirectives = directivesByAttr.getOrDefault(attrId, List.of());

            if (!isDeniedValue && fieldDirectives.isEmpty()) {
                continue;
            }

            MaskMergeOutcome outcome = strategyRegistry.resolveForField(fieldDirectives, isDeniedValue);
            if (outcome.status() == MaskMergeStatus.DOMINATED_BY_FIELD_USE_DENY) {
                removeNestedField(detached, splitWirePath(wireName), 0);
                appliedStrategies.put(attrId, "OMIT_BY_FIELD_USE_DENY");
                continue;
            }
            if (outcome.status() == MaskMergeStatus.MASK_CONFLICT) {
                throw new MaskingConflictException(
                        attrId,
                        outcome.conflictDiagnosticCode(),
                        "Unresolvable mask conflict on attribute '" + attrId + "': " + outcome.conflictDiagnosticCode());
            }

            MaskDirective effective = outcome.effectiveDirective();
            if (!strategyRegistry.isCompatibleWithTargetField(
                    effective, fieldMeta.valueType(), fieldMeta.nullable())) {
                throw new MaskingConflictException(
                        attrId,
                        "AUTHZ_MASK_INCOMPATIBLE_WITH_TARGET_FIELD:" + effective.strategyId(),
                        "Mask strategy '" + effective.strategyId() + "' is incompatible with field '"
                                + wireName + "' (type=" + fieldMeta.valueType() + ", nullable=" + fieldMeta.nullable() + ")");
            }

            applyDirectiveToPath(detached, splitWirePath(wireName), 0, effective);
            appliedStrategies.put(attrId, effective.strategyId());
        }

        return new DetachedDtoMaskingResult(detached, appliedStrategies);
    }

    /**
     * Per-row input for paginated detached projection and masking ({@code P12}).
     */
    public record RowMaskingInput(
            Object rowDtoOrMap,
            Set<String> valueDeniedAttributeIds,
            List<MaskDirective> maskDirectives
    ) {}

    /**
     * Projects and masks a paginated list of {@link RowMaskingInput} items ({@code P12}: no cross-row leakage).
     */
    public List<DetachedDtoMaskingResult> projectAndMaskPage(
            List<RowMaskingInput> rowInputs,
            Collection<DtoFieldSchemaMetadata> fieldSchemas
    ) {
        Objects.requireNonNull(rowInputs, "rowInputs is required");
        Objects.requireNonNull(fieldSchemas, "fieldSchemas is required");
        List<DetachedDtoMaskingResult> results = new ArrayList<>(rowInputs.size());
        for (RowMaskingInput row : rowInputs) {
            results.add(projectAndMask(
                    row.rowDtoOrMap(),
                    fieldSchemas,
                    row.valueDeniedAttributeIds(),
                    row.maskDirectives()
            ));
        }
        return List.copyOf(results);
    }

    /**
     * Projects and masks a paginated list of items where each record may have its own row-specific
     * {@code valueDeniedAttributeIds} and {@code maskDirectives} ({@code P12}: no cross-row leakage).
     */
    public List<DetachedDtoMaskingResult> projectAndMaskPage(
            List<?> pageItems,
            Collection<DtoFieldSchemaMetadata> fieldSchemas,
            List<Set<String>> perRowValueDeniedAttributeIds,
            List<List<MaskDirective>> perRowMaskDirectives
    ) {
        Objects.requireNonNull(pageItems, "pageItems is required");
        Objects.requireNonNull(fieldSchemas, "fieldSchemas is required");
        if (perRowValueDeniedAttributeIds != null && perRowValueDeniedAttributeIds.size() != pageItems.size()) {
            throw new IllegalArgumentException("perRowValueDeniedAttributeIds size must match pageItems size");
        }
        if (perRowMaskDirectives != null && perRowMaskDirectives.size() != pageItems.size()) {
            throw new IllegalArgumentException("perRowMaskDirectives size must match pageItems size");
        }
        List<DetachedDtoMaskingResult> results = new ArrayList<>(pageItems.size());
        for (int i = 0; i < pageItems.size(); i++) {
            Set<String> rowDenied = perRowValueDeniedAttributeIds == null ? Set.of() : perRowValueDeniedAttributeIds.get(i);
            List<MaskDirective> rowDirs = perRowMaskDirectives == null ? List.of() : perRowMaskDirectives.get(i);
            results.add(projectAndMask(pageItems.get(i), fieldSchemas, rowDenied, rowDirs));
        }
        return List.copyOf(results);
    }

    private static String[] splitWirePath(String wireName) {
        String normalized = wireName.startsWith("/") ? wireName.substring(1) : wireName;
        normalized = normalized.replace("[]", "");
        return normalized.contains("/") ? normalized.split("/") : normalized.split("\\.");
    }

    @SuppressWarnings("unchecked")
    private void removeNestedField(Object current, String[] segments, int idx) {
        if (current == null || idx >= segments.length) {
            return;
        }
        if (current instanceof List<?> list) {
            for (Object item : list) {
                removeNestedField(item, segments, idx);
            }
            return;
        }
        if (current instanceof Map<?, ?> rawMap) {
            Map<String, Object> map = (Map<String, Object>) rawMap;
            String seg = segments[idx];
            if (idx == segments.length - 1) {
                map.remove(seg);
            } else {
                removeNestedField(map.get(seg), segments, idx + 1);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void applyDirectiveToPath(Object current, String[] segments, int idx, MaskDirective directive) {
        if (current == null || idx >= segments.length) {
            return;
        }
        if (current instanceof List<?> list) {
            for (Object item : list) {
                applyDirectiveToPath(item, segments, idx, directive);
            }
            return;
        }
        if (current instanceof Map<?, ?> rawMap) {
            Map<String, Object> map = (Map<String, Object>) rawMap;
            String seg = segments[idx];
            if (idx == segments.length - 1) {
                applyDirectiveToDetachedMap(map, seg, directive);
            } else if (map.containsKey(seg)) {
                applyDirectiveToPath(map.get(seg), segments, idx + 1, directive);
            }
        }
    }

    private void applyDirectiveToDetachedMap(
            Map<String, Object> detached,
            String wireName,
            MaskDirective directive
    ) {
        if (!detached.containsKey(wireName)) {
            return;
        }
        Object rawValue = detached.get(wireName);
        switch (directive.strategyId()) {
            case "OMIT" -> detached.remove(wireName);
            case "NULLIFY" -> detached.put(wireName, null);
            case "REDACT_CONSTANT" -> {
                String replacement = String.valueOf(
                        directive.parameters().getOrDefault("replacement", "***RESTRITO***"));
                detached.put(wireName, replacement);
            }
            case "HASH_TOKEN_KEYED" -> {
                if (rawValue == null) {
                    detached.put(wireName, null);
                } else {
                    int truncateChars = ((Number) directive.parameters().getOrDefault("truncateChars", 16)).intValue();
                    detached.put(wireName, computeHmacToken(String.valueOf(rawValue), truncateChars));
                }
            }
            case "SUMMARY_ONLY" -> {
                if (rawValue instanceof Collection<?> col) {
                    detached.put(wireName, "COUNT:" + col.size());
                } else if (rawValue instanceof Map<?, ?> map) {
                    detached.put(wireName, "KEYS:" + map.size());
                } else {
                    detached.put(wireName, "SUMMARY");
                }
            }
            case "CPF_CNPJ_PARTIAL" -> {
                if (rawValue instanceof String str && str.length() >= 11) {
                    String digits = str.replaceAll("\\D", "");
                    if (digits.length() == 11) {
                        detached.put(wireName, "***.***.***-" + digits.substring(9));
                    } else {
                        detached.put(wireName, "***.***-" + str.substring(Math.max(0, str.length() - 2)));
                    }
                } else {
                    detached.put(wireName, "***.***-**");
                }
            }
            case "PARTIAL_MASK" -> {
                if (rawValue instanceof String str) {
                    int prefix = ((Number) directive.parameters().getOrDefault("visiblePrefix", 2)).intValue();
                    int suffix = ((Number) directive.parameters().getOrDefault("visibleSuffix", 2)).intValue();
                    String maskChar = String.valueOf(directive.parameters().getOrDefault("maskChar", "*"));
                    if (str.length() <= prefix + suffix) {
                        detached.put(wireName, maskChar.repeat(Math.max(3, str.length())));
                    } else {
                        String p = str.substring(0, prefix);
                        String s = str.substring(str.length() - suffix);
                        int maskedCount = str.length() - prefix - suffix;
                        detached.put(wireName, p + maskChar.repeat(maskedCount) + s);
                    }
                }
            }
            default -> throw new MaskingConflictException(
                    directive.attributeId(),
                    "AUTHZ_UNSUPPORTED_MASK_STRATEGY:" + directive.strategyId(),
                    "Unsupported mask strategy: " + directive.strategyId());
        }
    }

    private String computeHmacToken(String input, int truncateChars) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacSecretKey, "HmacSHA256"));
            String hex = HexFormat.of().formatHex(mac.doFinal(input.getBytes(StandardCharsets.UTF_8)));
            int len = Math.max(4, Math.min(hex.length(), truncateChars));
            return "tok_" + hex.substring(0, len);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to compute HASH_TOKEN_KEYED HMAC-SHA256", ex);
        }
    }
}
