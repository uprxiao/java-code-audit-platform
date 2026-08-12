package io.github.uprxiao.audit.report;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.uprxiao.audit.finding.ProjectPath;
import java.io.IOException;
import java.nio.file.Path;

final class SarifValidationService {

    private final ObjectMapper json;

    SarifValidationService(ObjectMapper json) {
        this.json = json;
    }

    void validate(Path sarif) throws IOException {
        JsonNode root = json.readTree(sarif.toFile());
        if (!"2.1.0".equals(root.path("version").asText()) || !root.path("runs").isArray()
                || root.path("runs").isEmpty()) {
            throw new IOException("invalid SARIF 2.1.0 document");
        }
        for (JsonNode run : root.path("runs")) {
            if (!run.path("tool").path("driver").path("name").isTextual() || !run.path("results").isArray()
                    || !run.path("invocations").isArray()) {
                throw new IOException("SARIF run is missing tool, results, or invocations");
            }
            for (JsonNode result : run.path("results")) {
                if (!result.path("ruleId").isTextual() || !result.path("message").path("text").isTextual()) {
                    throw new IOException("SARIF result is missing ruleId or message");
                }
                for (JsonNode location : result.path("locations")) {
                    String uri = location.path("physicalLocation").path("artifactLocation").path("uri").asText();
                    try {
                        ProjectPath.normalize(uri);
                    } catch (IllegalArgumentException exception) {
                        throw new IOException("unsafe SARIF artifact URI: " + uri, exception);
                    }
                }
            }
        }
    }
}
