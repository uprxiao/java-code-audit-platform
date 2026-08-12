package io.github.uprxiao.audit.intake;

import io.github.uprxiao.audit.finding.ScanProfile;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public record ProjectManifest(
        int schemaVersion,
        String root,
        String rootPom,
        int javaVersion,
        String packaging,
        List<MavenModule> modules,
        SourceDescriptor source,
        Set<ScanProfile> eligibleProfiles,
        List<String> warnings) {

    public static final int CURRENT_SCHEMA_VERSION = 1;

    public ProjectManifest {
        if (schemaVersion != CURRENT_SCHEMA_VERSION) {
            throw new IllegalArgumentException("unsupported ProjectManifest schemaVersion: " + schemaVersion);
        }
        root = requireText(root, "root");
        rootPom = requireText(rootPom, "rootPom");
        if (javaVersion != 17) {
            throw new IllegalArgumentException("V1 only supports Java 17 projects");
        }
        packaging = packaging == null || packaging.isBlank() ? "jar" : packaging;
        modules = modules == null ? List.of() : List.copyOf(modules);
        Objects.requireNonNull(source, "source");
        eligibleProfiles = eligibleProfiles == null ? Set.of() : Set.copyOf(eligibleProfiles);
        warnings = warnings == null ? List.of() : List.copyOf(warnings);
    }

    private static String requireText(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }
}
