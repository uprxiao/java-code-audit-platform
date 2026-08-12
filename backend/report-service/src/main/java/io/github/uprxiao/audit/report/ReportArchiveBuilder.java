package io.github.uprxiao.audit.report;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.AtomicMoveNotSupportedException;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

final class ReportArchiveBuilder {

    Path build(UUID scanId, Path jobRoot, Path archiveTarget) throws IOException {
        Objects.requireNonNull(scanId, "scanId");
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
                addTree(zip, root.resolve("report"), root.resolve("report"), "");
                addTree(zip, root.resolve("raw"), root.resolve("raw"), "raw");
                addTree(zip, root.resolve("logs"), root.resolve("logs"), "logs");
                addTree(zip, root.resolve("sbom"), root.resolve("sbom"), "sbom");
            }
            move(temporary, target);
        } catch (IOException exception) {
            Files.deleteIfExists(temporary);
            throw exception;
        }
        return target;
    }

    private void addTree(ZipOutputStream zip, Path allowedRoot, Path source, String prefix) throws IOException {
        if (Files.isSymbolicLink(source)) {
            throw new IOException("symbolic links are forbidden in report archives: " + source);
        }
        if (!Files.isDirectory(source, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        try (var paths = Files.walk(source)) {
            List<Path> entries = paths.sorted().toList();
            for (Path file : entries) {
                if (Files.isSymbolicLink(file)) {
                    throw new IOException("symbolic links are forbidden in report archives: " + file);
                }
                if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                    continue;
                }
                if (!file.toAbsolutePath().normalize().startsWith(allowedRoot.toAbsolutePath().normalize())) {
                    throw new IOException("unsafe report archive path: " + file);
                }
                String relative = allowedRoot.relativize(file).toString().replace(file.getFileSystem().getSeparator(), "/");
                String name = prefix.isBlank() ? relative : prefix + "/" + relative;
                if (name.startsWith("/") || name.contains("../") || name.equals("..")) {
                    throw new IOException("unsafe ZIP entry name: " + name);
                }
                zip.putNextEntry(new ZipEntry(name));
                try (var input = new BufferedInputStream(Files.newInputStream(file))) {
                    input.transferTo(zip);
                }
                zip.closeEntry();
            }
        }
    }

    private void move(Path source, Path target) throws IOException {
        try {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException exception) {
            Files.move(source, target);
        }
    }
}
