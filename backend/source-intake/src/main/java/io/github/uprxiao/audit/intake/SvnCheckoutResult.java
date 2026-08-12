package io.github.uprxiao.audit.intake;

import java.nio.file.Path;
import java.util.Objects;

public record SvnCheckoutResult(
        Path root,
        long revision,
        int entries,
        int files,
        long expandedBytes,
        String contentSha256) {

    public SvnCheckoutResult {
        Objects.requireNonNull(root, "root");
        if (revision < 0 || entries < 0 || files < 0 || expandedBytes < 0) {
            throw new IllegalArgumentException("SVN checkout counters must not be negative");
        }
        if (contentSha256 == null || !contentSha256.matches("sha256:[0-9a-f]{64}")) {
            throw new IllegalArgumentException("SVN checkout content hash must be a SHA-256 value");
        }
    }
}
