package io.github.uprxiao.audit.storage;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.LinkOption;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

public final class JobDirectoryLayout {

    private static final Pattern ENGINE_ID = Pattern.compile("[a-z][a-z0-9-]{1,63}");
    private static final List<String> DIRECTORIES = List.of(
            "source", "workspace", "build", "codeql-db", "raw", "normalized", "logs", "report", "archive", "sbom");

    private final Path jobsRoot;
    private final UUID scanId;
    private final Path root;

    public JobDirectoryLayout(Path dataRoot, UUID scanId) {
        Objects.requireNonNull(dataRoot, "dataRoot");
        this.scanId = Objects.requireNonNull(scanId, "scanId");
        this.jobsRoot = dataRoot.toAbsolutePath().normalize().resolve("jobs");
        this.root = safeResolve(scanId.toString());
    }

    public void initialize() throws IOException {
        if (Files.isSymbolicLink(root)) {
            throw new IOException("job root must not be a symbolic link: " + root);
        }
        Files.createDirectories(root);
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("job root is not a directory: " + root);
        }
        for (String directory : DIRECTORIES) {
            Files.createDirectories(safeResolve(directory));
        }
        Files.createDirectories(safeResolve("logs/engines"));
    }

    public UUID scanId() {
        return scanId;
    }

    public Path root() {
        return root;
    }

    public Path source() {
        return safeResolve("source");
    }

    public Path workspace() {
        return safeResolve("workspace");
    }

    public Path rawEngine(String engineId) {
        if (engineId == null || !ENGINE_ID.matcher(engineId).matches()) {
            throw new IllegalArgumentException("invalid engine id: " + engineId);
        }
        return safeResolve("raw/" + engineId);
    }

    public Path report() {
        return safeResolve("report");
    }

    public Path logs() {
        return safeResolve("logs");
    }

    public Path normalized() {
        return safeResolve("normalized");
    }

    public Path archive() {
        return safeResolve("archive");
    }

    public Path jobFile() {
        return safeResolve("job.json");
    }

    public Path safeResolve(String relativePath) {
        Objects.requireNonNull(relativePath, "relativePath");
        Path resolved = root == null
                ? jobsRoot.resolve(relativePath).normalize()
                : root.resolve(relativePath).normalize();
        Path boundary = root == null ? jobsRoot : root;
        if (!resolved.startsWith(boundary)) {
            throw new IllegalArgumentException("job path escapes its root: " + relativePath);
        }
        return resolved;
    }
}
