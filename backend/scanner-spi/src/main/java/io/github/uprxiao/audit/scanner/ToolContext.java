package io.github.uprxiao.audit.scanner;

import java.nio.file.Path;
import java.util.Map;
import java.util.Objects;

public record ToolContext(Path toolRoot, Map<EngineId, ToolInstallation> installations) {

    public ToolContext {
        Objects.requireNonNull(toolRoot, "toolRoot");
        toolRoot = toolRoot.toAbsolutePath().normalize();
        installations = installations == null ? Map.of() : Map.copyOf(installations);
    }

    public record ToolInstallation(Path executable, String version, boolean available) {
        public ToolInstallation {
            Objects.requireNonNull(executable, "executable");
            version = version == null ? "" : version;
            executable = executable.toAbsolutePath().normalize();
        }
    }
}
