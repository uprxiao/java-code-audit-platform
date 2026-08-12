package io.github.uprxiao.audit.orchestrator;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record ProfileDefinition(
        String name,
        @JsonProperty("extends") String parent,
        boolean requiresBuild,
        List<EngineDefinition> engines) {

    public ProfileDefinition {
        parent = parent == null ? "" : parent;
        engines = engines == null ? List.of() : List.copyOf(engines);
    }
}
