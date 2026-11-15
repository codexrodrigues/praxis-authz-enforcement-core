package org.praxisplatform.authz.enforcement.writeintent;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode;
import org.praxisplatform.authz.contracts.binding.TransactionCardinality;
import org.praxisplatform.authz.contracts.binding.WriteChangeKind;
import org.praxisplatform.authz.contracts.binding.WriteFieldChange;
import org.praxisplatform.authz.contracts.binding.WriteIntent;

/**
 * Extracts a canonical {@link WriteIntent} from raw JSON or map payloads prior to server-side
 * {@code hydrate*} and {@code PraxisRulesEngine} ({@code CC06}, {@code P13}, {@code P16}, {@code P45},
 * {@code ENF-FW-001..004B}).
 *
 * <p>Guarantees that:
 * <ul>
 *   <li>Explicit JSON {@code null} is captured as {@link WriteChangeKind#CLEAR_EXPLICIT_NULL};</li>
 *   <li>Falsy/zero values ({@code 0}, {@code false}, {@code ""}) are captured as {@link WriteChangeKind#SET}
 *       with their exact value preserved;</li>
 *   <li>Omitted fields in {@code PATCH} ({@code partialPatch == true}) are never treated as cleared or modified;</li>
 *   <li>Unmapped wire fields in a mutation payload fail closed with {@link FieldWriteViolationException}
 *       ({@code P13}, {@code P45}) so no unmapped attribute can bypass {@code FIELD_WRITE} authorization.</li>
 * </ul>
 */
public final class DtoWriteIntentExtractor {

    private final ObjectMapper objectMapper;

    /** Constructs an extractor with a default Java-time-enabled Jackson {@link ObjectMapper}. */
    public DtoWriteIntentExtractor() {
        this.objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
    }

    /**
     * Extracts a {@link WriteIntent} from a raw JSON payload string and a wire-path-to-attributeId mapping,
     * rejecting any unmapped wire field fail-closed ({@code P13}, {@code P45}).
     *
     * @param operationVerb semantic operation verb (e.g. {@code CREATE}, {@code UPDATE}, {@code UPDATE_PARTIAL})
     * @param partialPatch whether omitted fields are untouched ({@code true} for {@code PATCH})
     * @param batchMode batch authorization mode
     * @param cardinality transaction cardinality
     * @param rawJsonPayload raw JSON object payload sent by the caller before server hydration
     * @param attributeIdByWirePath mapping of JSON Pointer wire paths (e.g. {@code /substitutoMatricula}) to canonical {@code attributeId}
     * @return extracted {@link WriteIntent}
     */
    public WriteIntent extractFromJson(
            String operationVerb,
            boolean partialPatch,
            BatchAuthorizationMode batchMode,
            TransactionCardinality cardinality,
            String rawJsonPayload,
            Map<String, String> attributeIdByWirePath
    ) {
        return extractFromJson(
                operationVerb,
                partialPatch,
                batchMode,
                cardinality,
                rawJsonPayload,
                attributeIdByWirePath,
                Set.of()
        );
    }

    /**
     * Extracts a {@link WriteIntent} from a raw JSON payload string, allowing explicitly declared
     * technical wire paths (such as {@code /version} or {@code /clientRequestId}) to be ignored while
     * rejecting any unknown/unmapped business wire path fail-closed.
     */
    public WriteIntent extractFromJson(
            String operationVerb,
            boolean partialPatch,
            BatchAuthorizationMode batchMode,
            TransactionCardinality cardinality,
            String rawJsonPayload,
            Map<String, String> attributeIdByWirePath,
            Set<String> ignoredTechnicalWirePaths
    ) {
        Objects.requireNonNull(rawJsonPayload, "rawJsonPayload is required");
        Objects.requireNonNull(attributeIdByWirePath, "attributeIdByWirePath is required");
        Set<String> ignored = ignoredTechnicalWirePaths == null ? Set.of() : ignoredTechnicalWirePaths;
        try {
            JsonNode root = objectMapper.readTree(rawJsonPayload);
            if (root == null || !root.isObject()) {
                throw new IllegalArgumentException("rawJsonPayload must be a JSON object");
            }
            List<WriteFieldChange> changes = new ArrayList<>();
            Set<String> unmappedWirePaths = new LinkedHashSet<>();
            Set<String> seenMappedWirePaths = new LinkedHashSet<>();
            collectChanges("", root, attributeIdByWirePath, ignored, changes, unmappedWirePaths, seenMappedWirePaths);
            if (!unmappedWirePaths.isEmpty()) {
                throw new FieldWriteViolationException(
                        unmappedWirePaths,
                        "AUTHZ_UNMAPPED_WRITE_WIRE_PATH",
                        "Mutation payload contains unmapped wire paths that cannot bypass FIELD_WRITE governance: "
                                + unmappedWirePaths + " (P13 / P45 / ENF-FW-002)");
            }
            if (!partialPatch) {
                for (Map.Entry<String, String> mappedEntry : attributeIdByWirePath.entrySet()) {
                    String wirePath = mappedEntry.getKey();
                    if (!ignored.contains(wirePath) && !seenMappedWirePaths.contains(wirePath)) {
                        changes.add(new WriteFieldChange(
                                wirePath,
                                mappedEntry.getValue(),
                                WriteChangeKind.REMOVE,
                                null
                        ));
                    }
                }
            }
            return new WriteIntent(operationVerb, partialPatch, batchMode, cardinality, changes);
        } catch (JsonProcessingException ex) {
            throw new IllegalArgumentException("Failed to parse rawJsonPayload for WriteIntent extraction", ex);
        }
    }

    private void collectChanges(
            String parentPointer,
            JsonNode objectNode,
            Map<String, String> attributeIdByWirePath,
            Set<String> ignoredTechnicalWirePaths,
            List<WriteFieldChange> target,
            Set<String> unmappedWirePaths,
            Set<String> seenMappedWirePaths
    ) {
        Iterator<Map.Entry<String, JsonNode>> fields = objectNode.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            String pointer = parentPointer + "/" + entry.getKey();
            if (ignoredTechnicalWirePaths.contains(pointer)) {
                continue;
            }
            JsonNode valueNode = entry.getValue();
            if (valueNode.isObject() && !attributeIdByWirePath.containsKey(pointer)) {
                collectChanges(pointer, valueNode, attributeIdByWirePath, ignoredTechnicalWirePaths, target, unmappedWirePaths, seenMappedWirePaths);
                continue;
            }
            String attributeId = attributeIdByWirePath.get(pointer);
            if (attributeId == null) {
                unmappedWirePaths.add(pointer);
                continue;
            }
            seenMappedWirePaths.add(pointer);
            if (valueNode.isNull()) {
                target.add(new WriteFieldChange(pointer, attributeId, WriteChangeKind.CLEAR_EXPLICIT_NULL, null));
            } else {
                Object scalarOrArray = objectMapper.convertValue(valueNode, Object.class);
                target.add(new WriteFieldChange(pointer, attributeId, WriteChangeKind.SET, scalarOrArray));
            }
        }
    }
}
