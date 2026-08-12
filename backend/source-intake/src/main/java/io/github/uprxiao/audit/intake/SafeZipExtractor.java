package io.github.uprxiao.audit.intake;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.text.Normalizer;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.Locale;
import java.util.regex.Pattern;
import org.apache.commons.compress.archivers.zip.UnixStat;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipFile;

public final class SafeZipExtractor {

    private static final Pattern WINDOWS_DRIVE = Pattern.compile("^[A-Za-z]:.*");

    public ZipExtractionResult extract(Path archive, Path destination, ZipExtractionLimits limits) throws IOException {
        Objects.requireNonNull(archive, "archive");
        Objects.requireNonNull(destination, "destination");
        Objects.requireNonNull(limits, "limits");
        Path normalizedArchive = archive.toAbsolutePath().normalize();
        Path root = destination.toAbsolutePath().normalize();
        long archiveBytes = Files.size(normalizedArchive);
        if (archiveBytes > limits.maxArchiveBytes()) {
            throw new SourceIntakeException("ARCHIVE_LIMIT_EXCEEDED", "archive exceeds upload limit");
        }
        if (Files.exists(root) && hasEntries(root)) {
            throw new SourceIntakeException("DESTINATION_NOT_EMPTY", "extraction destination must be empty");
        }
        Files.createDirectories(root);
        Counters counters = new Counters();
        Set<Path> targets = new HashSet<>();
        Set<String> portableCollisionKeys = new HashSet<>();
        try (ZipFile zip = ZipFile.builder().setPath(normalizedArchive).get()) {
            Enumeration<ZipArchiveEntry> entries = zip.getEntries();
            while (entries.hasMoreElements()) {
                ZipArchiveEntry entry = entries.nextElement();
                counters.entries++;
                if (counters.entries > limits.maxEntries()) {
                    throw limit("archive contains too many entries", counters);
                }
                Path target = validateEntry(root, entry, targets, portableCollisionKeys);
                if (entry.isDirectory()) {
                    Files.createDirectories(target);
                    continue;
                }
                Files.createDirectories(target.getParent());
                counters.files++;
                try (InputStream input = new BufferedInputStream(zip.getInputStream(entry));
                     OutputStream output = new BufferedOutputStream(Files.newOutputStream(target,
                             StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE))) {
                    copyLimited(input, output, entry, archiveBytes, limits, counters);
                }
            }
        } catch (IOException | RuntimeException exception) {
            deleteExtractedTree(root);
            throw exception;
        }
        return new ZipExtractionResult(root, counters.entries, counters.files, counters.expandedBytes);
    }

    private Path validateEntry(
            Path root,
            ZipArchiveEntry entry,
            Set<Path> targets,
            Set<String> portableCollisionKeys) throws IOException {
        String name = entry.getName();
        if (hasForbiddenRawNameByte(entry.getRawName()) || name == null || name.isBlank()
                || name.indexOf('\0') >= 0 || name.indexOf('\\') >= 0
                || name.startsWith("/") || name.startsWith("//") || WINDOWS_DRIVE.matcher(name).matches()) {
            throw new SourceIntakeException("UNSAFE_ARCHIVE_ENTRY", "unsafe ZIP entry name: " + name);
        }
        if (entry.getGeneralPurposeBit().usesEncryption()) {
            throw new SourceIntakeException("UNSAFE_ARCHIVE_ENTRY", "encrypted ZIP entries are not supported");
        }
        int type = entry.getUnixMode() & UnixStat.FILE_TYPE_FLAG;
        if (entry.isUnixSymlink() || (type != 0 && type != UnixStat.FILE_FLAG && type != UnixStat.DIR_FLAG)) {
            throw new SourceIntakeException("UNSAFE_ARCHIVE_ENTRY", "link or special ZIP entry is forbidden: " + name);
        }
        Path target = root.resolve(name).normalize();
        if (!target.startsWith(root)) {
            throw new SourceIntakeException("UNSAFE_ARCHIVE_ENTRY", "ZIP entry escapes extraction root: " + name);
        }
        if (!targets.add(target)) {
            throw new SourceIntakeException("UNSAFE_ARCHIVE_ENTRY", "duplicate ZIP entry target: " + name);
        }
        String collisionKey = Normalizer.normalize(name, Normalizer.Form.NFC).toLowerCase(Locale.ROOT);
        if (!portableCollisionKeys.add(collisionKey)) {
            throw new SourceIntakeException("UNSAFE_ARCHIVE_ENTRY",
                    "ZIP entries collide on a supported target file system: " + name);
        }
        ensureNoSymbolicLink(root, target.getParent());
        return target;
    }

    private boolean hasForbiddenRawNameByte(byte[] rawName) {
        if (rawName == null || rawName.length == 0) {
            return true;
        }
        if (rawName[0] == '/' || rawName[0] == '\\') {
            return true;
        }
        if (rawName.length >= 2 && isAsciiLetter(rawName[0]) && rawName[1] == ':') {
            return true;
        }
        for (byte value : rawName) {
            if (value == 0 || value == '\\') {
                return true;
            }
        }
        return false;
    }

    private boolean isAsciiLetter(byte value) {
        return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z');
    }

    private void copyLimited(
            InputStream input,
            OutputStream output,
            ZipArchiveEntry entry,
            long archiveBytes,
            ZipExtractionLimits limits,
            Counters counters) throws IOException {
        long fileBytes = 0;
        byte[] buffer = new byte[64 * 1024];
        int read;
        while ((read = input.read(buffer)) != -1) {
            fileBytes += read;
            counters.expandedBytes += read;
            if (fileBytes > limits.maxSingleFileBytes() || counters.expandedBytes > limits.maxExpandedBytes()) {
                throw limit("expanded archive exceeds byte limits", counters);
            }
            long compressed = entry.getCompressedSize();
            if (compressed > 0 && fileBytes / (double) compressed > limits.maxCompressionRatio()) {
                throw limit("ZIP entry exceeds compression ratio limit", counters);
            }
            if (archiveBytes > 0 && counters.expandedBytes / (double) archiveBytes > limits.maxCompressionRatio()) {
                throw limit("archive exceeds total compression ratio limit", counters);
            }
            output.write(buffer, 0, read);
        }
    }

    private SourceIntakeException limit(String message, Counters counters) {
        return new SourceIntakeException("ARCHIVE_LIMIT_EXCEEDED", message,
                Map.of("entries", counters.entries, "files", counters.files, "expandedBytes", counters.expandedBytes));
    }

    private void ensureNoSymbolicLink(Path root, Path parent) throws IOException {
        Path cursor = parent;
        while (cursor != null && cursor.startsWith(root)) {
            if (Files.isSymbolicLink(cursor)) {
                throw new SourceIntakeException("UNSAFE_ARCHIVE_ENTRY", "symbolic link in destination path");
            }
            if (cursor.equals(root)) {
                break;
            }
            cursor = cursor.getParent();
        }
    }

    private boolean hasEntries(Path directory) throws IOException {
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
            return true;
        }
        try (var entries = Files.list(directory)) {
            return entries.findAny().isPresent();
        }
    }

    private void deleteExtractedTree(Path root) throws IOException {
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        try (var paths = Files.walk(root)) {
            for (Path path : paths.sorted((left, right) -> right.getNameCount() - left.getNameCount()).toList()) {
                if (!path.normalize().startsWith(root)) {
                    throw new IOException("refusing to clean path outside extraction root");
                }
                Files.deleteIfExists(path);
            }
        }
    }

    private static final class Counters {
        private int entries;
        private int files;
        private long expandedBytes;
    }
}
