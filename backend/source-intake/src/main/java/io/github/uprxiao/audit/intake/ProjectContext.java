package io.github.uprxiao.audit.intake;

import java.nio.file.Path;
import java.util.Objects;

public record ProjectContext(Path workspaceRoot, ProjectManifest manifest) {

    public ProjectContext {
        Objects.requireNonNull(workspaceRoot, "workspaceRoot");
        Objects.requireNonNull(manifest, "manifest");
        workspaceRoot = workspaceRoot.toAbsolutePath().normalize();
    }

    public Path resolveProjectPath(String relativePath) {
        Path resolved = workspaceRoot.resolve(relativePath).normalize();
        if (!resolved.startsWith(workspaceRoot)) {
            throw new IllegalArgumentException("path escapes project workspace: " + relativePath);
        }
        return resolved;
    }
}
