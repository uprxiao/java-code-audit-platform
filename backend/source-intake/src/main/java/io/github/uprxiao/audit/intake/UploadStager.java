package io.github.uprxiao.audit.intake;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

public final class UploadStager {

    public StagedUpload stage(InputStream input, Path target, long maximumBytes) throws IOException {
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(target, "target");
        if (maximumBytes < 1) {
            throw new IllegalArgumentException("maximumBytes must be positive");
        }
        Path normalized = target.toAbsolutePath().normalize();
        Files.createDirectories(normalized.getParent());
        MessageDigest digest = sha256();
        long total = 0;
        try (OutputStream output = Files.newOutputStream(normalized,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = input.read(buffer)) != -1) {
                total += read;
                if (total > maximumBytes) {
                    throw new SourceIntakeException("ARCHIVE_LIMIT_EXCEEDED",
                            "uploaded archive exceeds the configured byte limit");
                }
                output.write(buffer, 0, read);
                digest.update(buffer, 0, read);
            }
        } catch (IOException exception) {
            Files.deleteIfExists(normalized);
            throw exception;
        }
        return new StagedUpload(normalized, total, HexFormat.of().formatHex(digest.digest()));
    }

    private MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by Java 17", exception);
        }
    }
}
