package io.github.uprxiao.audit.report;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
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
        Files.createDirectories(target.getParent());
        try (ZipOutputStream zip = new ZipOutputStream(new BufferedOutputStream(Files.newOutputStream(target)))) {
            addTree(zip, root.resolve("report"), root.resolve("report"), "");
            addTree(zip, root.resolve("raw"), root.resolve("raw"), "raw");
            addTree(zip, root.resolve("logs"), root.resolve("logs"), "logs");
            addTree(zip, root.resolve("sbom"), root.resolve("sbom"), "sbom");
        } catch (IOException exception) {
            Files.deleteIfExists(target);
            throw exception;
        }
        return target;
    }

    private void addTree(ZipOutputStream zip, Path allowedRoot, Path source, String prefix) throws IOException {
        if (!Files.isDirectory(source, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        try (var paths = Files.walk(source)) {
            List<Path> files = paths.filter(path -> Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)).sorted().toList();
            for (Path file : files) {
                if (Files.isSymbolicLink(file) || !file.toAbsolutePath().normalize().startsWith(allowedRoot.toAbsolutePath().normalize())) {
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
}
