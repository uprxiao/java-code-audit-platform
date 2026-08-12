package io.github.uprxiao.audit.api;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Map;

/** Enforces the configured on-disk limit without following links outside a job. */
final class JobWorkspaceCapacityGuard {

    private final long maximumBytes;

    JobWorkspaceCapacityGuard(long maximumBytes) {
        if (maximumBytes < 1) {
            throw new IllegalArgumentException("maximum workspace bytes must be positive");
        }
        this.maximumBytes = maximumBytes;
    }

    void requireWithinLimit(Path jobRoot) throws IOException {
        Path root = jobRoot.toAbsolutePath().normalize();
        if (!Files.isDirectory(root) || Files.isSymbolicLink(root)) {
            throw new WorkspaceCapacityException("JOB_WORKSPACE_INVALID",
                    "job workspace root is unavailable or symbolic", Map.of("jobRoot", root.toString()));
        }
        long[] bytes = {0};
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path directory, BasicFileAttributes attributes)
                    throws IOException {
                if (Files.isSymbolicLink(directory)) {
                    throw new WorkspaceCapacityException("JOB_WORKSPACE_UNSAFE_LINK",
                            "symbolic directory is forbidden in a job workspace",
                            Map.of("path", root.relativize(directory).toString()));
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) throws IOException {
                if (attributes.isSymbolicLink()) {
                    throw new WorkspaceCapacityException("JOB_WORKSPACE_UNSAFE_LINK",
                            "symbolic file is forbidden in a job workspace",
                            Map.of("path", root.relativize(file).toString()));
                }
                long size = attributes.size();
                if (Long.MAX_VALUE - bytes[0] < size) {
                    bytes[0] = Long.MAX_VALUE;
                } else {
                    bytes[0] += size;
                }
                if (bytes[0] > maximumBytes) {
                    throw new WorkspaceCapacityException("JOB_WORKSPACE_LIMIT_EXCEEDED",
                            "job workspace exceeded its configured byte limit",
                            Map.of("actualBytesAtLeast", bytes[0], "maximumBytes", maximumBytes));
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exception) throws IOException {
                // Scanner reports and atomic state writes may disappear between
                // directory enumeration and attribute lookup. They contributed
                // no persistent bytes, so retry on the next poll. Other failures
                // remain fail-closed.
                if (isTransientDisappearance(exception)) return FileVisitResult.CONTINUE;
                throw exception;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path directory, IOException exception) throws IOException {
                if (exception == null || isTransientDisappearance(exception)) return FileVisitResult.CONTINUE;
                throw exception;
            }
        });
    }

    static boolean isTransientDisappearance(IOException exception) {
        return exception instanceof NoSuchFileException;
    }

    long maximumBytes() {
        return maximumBytes;
    }
}
