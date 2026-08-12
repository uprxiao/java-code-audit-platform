package io.github.uprxiao.audit.finding;

public record SourceLocation(
        String path,
        int startLine,
        int startColumn,
        int endLine,
        int endColumn) {
}
