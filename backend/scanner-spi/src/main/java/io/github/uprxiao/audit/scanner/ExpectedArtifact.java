package io.github.uprxiao.audit.scanner;

import java.util.Objects;

public record ExpectedArtifact(String relativePath, boolean required, long maxBytes) {

    public ExpectedArtifact {
        Objects.requireNonNull(relativePath, "relativePath");
        if (relativePath.isBlank() || relativePath.startsWith("/") || relativePath.contains("..")) {
            throw new IllegalArgumentException("artifact path must be safe and relative");
        }
        if (maxBytes < 1) {
            throw new IllegalArgumentException("artifact maxBytes must be positive");
        }
    }
}
