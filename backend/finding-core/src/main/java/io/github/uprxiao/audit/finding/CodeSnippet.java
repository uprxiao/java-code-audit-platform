package io.github.uprxiao.audit.finding;

import java.util.List;
import java.util.Objects;

public record CodeSnippet(
        int startLine,
        int endLine,
        List<Integer> highlightLines,
        String text,
        boolean redacted) {

    public CodeSnippet {
        if (startLine < 1 || endLine < startLine) {
            throw new IllegalArgumentException("invalid snippet line range");
        }
        highlightLines = highlightLines == null ? List.of() : List.copyOf(highlightLines);
        if (highlightLines.stream().anyMatch(line -> line < startLine || line > endLine)) {
            throw new IllegalArgumentException("highlight line outside snippet range");
        }
        Objects.requireNonNull(text, "text");
    }
}
