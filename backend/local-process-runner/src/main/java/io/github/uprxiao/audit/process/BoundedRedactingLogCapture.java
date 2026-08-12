package io.github.uprxiao.audit.process;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.BufferedOutputStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Comparator;
import java.util.List;

final class BoundedRedactingLogCapture {

    private final long maxBytes;
    private final List<String> secrets;
    private long written;
    private boolean truncated;

    BoundedRedactingLogCapture(long maxBytes, List<String> secrets) {
        this.maxBytes = maxBytes;
        this.secrets = secrets.stream()
                .filter(value -> value != null && !value.isEmpty())
                .distinct()
                .sorted(Comparator.comparingInt(String::length).reversed())
                .toList();
    }

    void drain(InputStream input, Path target) throws IOException {
        Files.createDirectories(target.toAbsolutePath().normalize().getParent());
        try (Reader reader = new InputStreamReader(input, StandardCharsets.UTF_8);
             OutputStream output = new BufferedOutputStream(Files.newOutputStream(target,
                     StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE))) {
            int longestSecret = secrets.stream().mapToInt(String::length).max().orElse(1);
            char[] buffer = new char[8192];
            StringBuilder pending = new StringBuilder(longestSecret + 1);
            StringBuilder redacted = new StringBuilder(8192);
            int read;
            while ((read = reader.read(buffer)) != -1) {
                for (int index = 0; index < read; index++) {
                    pending.append(buffer[index]);
                    emitSafePrefix(pending, redacted, longestSecret, false);
                    if (redacted.length() >= 8192) {
                        writeBounded(output, redacted.toString());
                        redacted.setLength(0);
                    }
                }
            }
            while (!pending.isEmpty()) {
                emitSafePrefix(pending, redacted, longestSecret, true);
            }
            writeBounded(output, redacted.toString());
        }
    }

    boolean truncated() {
        return truncated;
    }

    private void emitSafePrefix(
            StringBuilder pending, StringBuilder redacted, int longestSecret, boolean endOfInput) {
        if (!endOfInput && pending.length() < longestSecret) {
            return;
        }
        for (String secret : secrets) {
            if (startsWith(pending, secret)) {
                redacted.append("***");
                pending.delete(0, secret.length());
                return;
            }
        }
        redacted.append(pending.charAt(0));
        pending.deleteCharAt(0);
    }

    private boolean startsWith(StringBuilder value, String prefix) {
        if (value.length() < prefix.length()) {
            return false;
        }
        for (int index = 0; index < prefix.length(); index++) {
            if (value.charAt(index) != prefix.charAt(index)) {
                return false;
            }
        }
        return true;
    }

    private void writeBounded(OutputStream output, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        long remaining = maxBytes - written;
        if (remaining <= 0) {
            truncated = truncated || bytes.length > 0;
            return;
        }
        int length = (int) Math.min(remaining, bytes.length);
        output.write(bytes, 0, length);
        written += length;
        if (length < bytes.length) {
            truncated = true;
        }
    }
}
