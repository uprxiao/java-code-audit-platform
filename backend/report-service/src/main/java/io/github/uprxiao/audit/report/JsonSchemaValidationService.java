package io.github.uprxiao.audit.report;

import com.networknt.schema.InputFormat;
import com.networknt.schema.Schema;
import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.SpecificationVersion;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public final class JsonSchemaValidationService {

    public void validate(String schemaName, Path document) throws IOException {
        String resource = "audit/schemas/" + schemaName + ".schema.json";
        String schemaText;
        try (InputStream input = getClass().getClassLoader().getResourceAsStream(resource)) {
            if (input == null) {
                throw new IOException("missing bundled JSON Schema: " + resource);
            }
            schemaText = new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
        String location = "https://audit.local/schema/" + schemaName;
        SchemaRegistry registry = SchemaRegistry.withDefaultDialect(
                SpecificationVersion.DRAFT_2020_12,
                builder -> builder.schemas(Map.of(location, schemaText)));
        Schema schema = registry.getSchema(SchemaLocation.of(location));
        List<com.networknt.schema.Error> errors = schema.validate(
                Files.readString(document), InputFormat.JSON,
                context -> context.executionConfig(config -> config.formatAssertionsEnabled(true)));
        if (!errors.isEmpty()) {
            throw new IOException("JSON Schema validation failed for " + schemaName + ": " + errors);
        }
    }
}
