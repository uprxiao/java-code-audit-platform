package io.github.uprxiao.audit.finding;

import java.util.List;

public record SnippetExtractionResult(CodeSnippet snippet, String fileSha256, List<String> warnings) {
    public SnippetExtractionResult {
        if (fileSha256 == null || !fileSha256.matches("sha256:[0-9a-f]{64}")) {
            throw new IllegalArgumentException("fileSha256 must be a SHA-256 value");
        }
        warnings = List.copyOf(warnings);
    }
}
