package io.github.uprxiao.audit.scanner;

import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.intake.ProjectContext;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

public record ScanContext(
        UUID scanId,
        ScanProfile profile,
        ProjectContext project,
        Path engineOutputDirectory,
        Path engineTemporaryDirectory,
        List<String> mavenProfiles,
        Map<String, String> mavenProperties) {

    public ScanContext(
            UUID scanId,
            ScanProfile profile,
            ProjectContext project,
            Path engineOutputDirectory,
            List<String> mavenProfiles,
            Map<String, String> mavenProperties) {
        this(scanId, profile, project, engineOutputDirectory,
                Objects.requireNonNull(engineOutputDirectory, "engineOutputDirectory")
                        .toAbsolutePath().normalize().resolve("database"),
                mavenProfiles, mavenProperties);
    }

    public ScanContext {
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(profile, "profile");
        Objects.requireNonNull(project, "project");
        Objects.requireNonNull(engineOutputDirectory, "engineOutputDirectory");
        engineOutputDirectory = engineOutputDirectory.toAbsolutePath().normalize();
        Objects.requireNonNull(engineTemporaryDirectory, "engineTemporaryDirectory");
        engineTemporaryDirectory = engineTemporaryDirectory.toAbsolutePath().normalize();
        mavenProfiles = mavenProfiles == null ? List.of() : List.copyOf(mavenProfiles);
        mavenProperties = mavenProperties == null ? Map.of() : Map.copyOf(mavenProperties);
    }
}
