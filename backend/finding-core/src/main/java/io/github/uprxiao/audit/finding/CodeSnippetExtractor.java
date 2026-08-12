package io.github.uprxiao.audit.finding;

import java.io.IOException;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

public final class CodeSnippetExtractor {

    public static final int DEFAULT_CONTEXT_LINES = 5;
    public static final int MAX_SNIPPET_LINES = 50;
    public static final long MAX_TEXT_SOURCE_BYTES = 64L * 1024 * 1024;

    private final SensitiveDataRedactor redactor;
    private final int contextLines;

    public CodeSnippetExtractor(SensitiveDataRedactor redactor) {
        this(redactor, DEFAULT_CONTEXT_LINES);
    }

    public CodeSnippetExtractor(SensitiveDataRedactor redactor, int contextLines) {
        this.redactor = Objects.requireNonNull(redactor, "redactor");
        if (contextLines < 0 || contextLines >= MAX_SNIPPET_LINES / 2) {
            throw new IllegalArgumentException("invalid snippet context line count");
        }
        this.contextLines = contextLines;
    }

    public SnippetExtractionResult extract(Path source, SourceLocation location) throws IOException {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(location, "location");
        String hash = "sha256:" + sha256(source);
        if (Files.size(source) > MAX_TEXT_SOURCE_BYTES) {
            return new SnippetExtractionResult(null, hash, List.of("SNIPPET_SOURCE_TOO_LARGE:" + location.path()));
        }
        byte[] content = Files.readAllBytes(source);
        final String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(content)).toString();
        } catch (CharacterCodingException exception) {
            return new SnippetExtractionResult(null, hash, List.of("SNIPPET_ENCODING_UNSUPPORTED:" + location.path()));
        }
        List<String> lines = text.lines().toList();
        if (location.startLine() > lines.size()) {
            return new SnippetExtractionResult(null, hash, List.of("SNIPPET_LOCATION_OUT_OF_RANGE:" + location.path()));
        }
        int start = Math.max(1, location.startLine() - contextLines);
        int desiredEnd = Math.min(lines.size(), location.endLine() + contextLines);
        int end = Math.min(desiredEnd, start + MAX_SNIPPET_LINES - 1);
        if (end < location.endLine()) {
            start = Math.max(1, location.endLine() - MAX_SNIPPET_LINES + 1);
            end = Math.min(lines.size(), start + MAX_SNIPPET_LINES - 1);
        }
        List<Integer> highlights = new ArrayList<>();
        for (int line = Math.max(start, location.startLine()); line <= Math.min(end, location.endLine()); line++) {
            highlights.add(line);
        }
        String snippetText = String.join("\n", lines.subList(start - 1, end));
        RedactionResult redacted = redactor.redact(snippetText);
        return new SnippetExtractionResult(new CodeSnippet(start, end, highlights, redacted.text(), redacted.redacted()),
                hash, List.of());
    }

    private String sha256(Path source) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (var input = Files.newInputStream(source)) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = input.read(buffer)) >= 0) {
                    if (read > 0) {
                        digest.update(buffer, 0, read);
                    }
                }
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by Java 17", exception);
        }
    }
}
