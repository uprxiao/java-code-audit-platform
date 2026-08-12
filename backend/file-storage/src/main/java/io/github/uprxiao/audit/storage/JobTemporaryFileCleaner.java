package io.github.uprxiao.audit.storage;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.List;

public final class JobTemporaryFileCleaner {

    private static final List<String> TEMPORARY_DIRECTORIES = List.of("source", "workspace", "build", "codeql-db", "tmp");

    public void cleanSuccessfulJob(JobDirectoryLayout layout) throws IOException {
        for (String name : TEMPORARY_DIRECTORIES) {
            deleteTree(layout.root(), layout.safeResolve(name));
        }
    }

    public void deleteEntireJob(JobDirectoryLayout layout) throws IOException {
        deleteTree(layout.root().getParent(), layout.root());
    }

    private void deleteTree(Path boundary, Path target) throws IOException {
        Path normalizedBoundary = boundary.toAbsolutePath().normalize();
        Path normalizedTarget = target.toAbsolutePath().normalize();
        if (normalizedTarget.equals(normalizedBoundary) || !normalizedTarget.startsWith(normalizedBoundary)) {
            throw new IOException("refusing to delete outside the verified job boundary: " + target);
        }
        if (!Files.exists(normalizedTarget, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        try (var paths = Files.walk(normalizedTarget)) {
            for (Path path : paths.sorted((left, right) -> right.getNameCount() - left.getNameCount()).toList()) {
                if (!path.toAbsolutePath().normalize().startsWith(normalizedTarget)) {
                    throw new IOException("cleanup path escaped the verified task root");
                }
                Files.deleteIfExists(path);
            }
        }
    }
}
