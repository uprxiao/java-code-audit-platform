package io.github.uprxiao.audit.report;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.util.List;
import org.junit.jupiter.api.Test;

class JsonSchemaSyntaxTest {

    private final ObjectMapper json = new ObjectMapper();

    @Test
    void allFrozenSchemasAreValidJsonSchemaDocuments() throws Exception {
        for (String name : List.of("job", "report", "coverage", "manifest")) {
            try (InputStream input = getClass().getClassLoader()
                    .getResourceAsStream("audit/schemas/" + name + ".schema.json")) {
                assertNotNull(input, name);
                JsonNode schema = json.readTree(input);
                assertEquals("https://json-schema.org/draft/2020-12/schema", schema.path("$schema").asText());
                assertEquals("object", schema.path("type").asText());
            }
        }
    }
}
