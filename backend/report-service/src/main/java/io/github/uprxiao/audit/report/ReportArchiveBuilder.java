package io.github.uprxiao.audit.report;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.AtomicMoveNotSupportedException;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

final class ReportArchiveBuilder {

    Path build(UUID scanId, Path jobRoot, Path archiveTarget, List<Path> declaredArtifacts) throws IOException {
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(declaredArtifacts, "declaredArtifacts");
        Path root = jobRoot.toAbsolutePath().normalize();
        Path target = archiveTarget.toAbsolutePath().normalize();
        if (!target.startsWith(root)) {
            throw new IOException("archive target escapes job root");
        }
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("final report archive is immutable and already exists: " + target);
        }
        if (Files.isSymbolicLink(target.getParent())) {
            throw new IOException("archive directory must not be a symbolic link: " + target.getParent());
        }
        Files.createDirectories(target.getParent());
        Path temporary = target.getParent().resolve(target.getFileName() + ".tmp-" + UUID.randomUUID());
        try {
            try (ZipOutputStream zip = new ZipOutputStream(new BufferedOutputStream(Files.newOutputStream(temporary)))) {
                for (Path file : declaredArtifacts.stream()
                        .map(path -> path.toAbsolutePath().normalize())
                        .distinct()
                        .sorted(Comparator.comparing(path -> portable(root.relativize(path))))
                        .toList()) {
                    addDeclaredArtifact(zip, root, file);
                }
            }
            move(temporary, target);
        } catch (IOException exception) {
            Files.deleteIfExists(temporary);
            throw exception;
        }
        return target;
    }

    private void addDeclaredArtifact(ZipOutputStream zip, Path root, Path file) throws IOException {
        if (!file.startsWith(root) || Files.isSymbolicLink(file)
                || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("declared report artifact is not a safe regular file: " + file);
        }
        String name = portable(root.relativize(file));
        if (name.startsWith("/") || name.contains("../") || name.equals("..")) {
            throw new IOException("unsafe ZIP entry name: " + name);
        }
        zip.putNextEntry(new ZipEntry(name.startsWith("report/") ? name.substring("report/".length()) : name));
        try (var input = new BufferedInputStream(Files.newInputStream(file))) {
            input.transferTo(zip);
        }
        zip.closeEntry();
    }

    private String portable(Path path) {
        return path.toString().replace(path.getFileSystem().getSeparator(), "/");
    }

    private void move(Path source, Path target) throws IOException {
        try {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException exception) {
            Files.move(source, target);
        }
    }
}
