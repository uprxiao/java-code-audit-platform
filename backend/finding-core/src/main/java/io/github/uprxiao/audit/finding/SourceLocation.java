package io.github.uprxiao.audit.finding;

import java.util.Objects;

public record SourceLocation(
        String path,
        int startLine,
        int startColumn,
        int endLine,
        int endColumn) {

    public SourceLocation {
        Objects.requireNonNull(path, "path");
        if (path.isBlank()) {
            throw new IllegalArgumentException("path must not be blank");
        }
        if (startLine < 1 || endLine < startLine) {
            throw new IllegalArgumentException("invalid line range");
        }
        if (startColumn < 0 || endColumn < 0) {
            throw new IllegalArgumentException("columns must be non-negative");
        }
        if (startLine == endLine && endColumn > 0 && startColumn > endColumn) {
            throw new IllegalArgumentException("invalid column range");
        }
    }
}
