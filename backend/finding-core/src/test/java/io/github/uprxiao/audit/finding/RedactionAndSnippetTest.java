package io.github.uprxiao.audit.finding;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class RedactionAndSnippetTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void redactsExactValuesCredentialsPrivateKeysAndCanaries() {
        String exact = "svn-password-123456";
        SensitiveDataRedactor redactor = new SensitiveDataRedactor(List.of(exact));
        String input = "password=super-secret-987 token=abcdefghijklmnop " + exact
                + " https://alice:clearpass@example.test AUDIT_CANARY_SECRET_XYZ123\n"
                + "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----";

        RedactionResult result = redactor.redact(input);

        assertTrue(result.redacted());
        assertFalse(result.text().contains("super-secret-987"));
        assertFalse(result.text().contains("abcdefghijklmnop"));
        assertFalse(result.text().contains(exact));
        assertFalse(result.text().contains("clearpass"));
        assertFalse(result.text().contains("AUDIT_CANARY_SECRET_XYZ123"));
        assertFalse(result.text().contains("\nabc\n"));
        assertTrue(result.text().contains("sha256:"));
        assertFalse(redactor.containsSensitiveData(result.text()), "redacted output must be safe and idempotent");
        assertFalse(redactor.containsSensitiveData("password = RE****ED"));
        assertFalse(redactor.containsSensitiveData("password = &quot;su***et&quot;"));
        assertFalse(redactor.containsSensitiveData("token=&#39;ab*de&#39;"));
        assertFalse(redactor.containsSensitiveData("password = \\\"su***et\\\""));
        assertTrue(redactor.containsSensitiveData(input));
        assertFalse(redactor.containsSensitiveData("text.contains(\"AUDIT_CANARY_SECRET_\")"));
    }

    @Test
    void extractsAtMostFiftyUtf8LinesWithCorrectHighlightAndRedaction() throws Exception {
        Path source = temporaryDirectory.resolve("App.java");
        Files.writeString(source, String.join("\n", IntStream.rangeClosed(1, 100)
                .mapToObj(line -> line == 60 ? "String token=abcdefghijklmnop;" : "line " + line).toList()));
        CodeSnippetExtractor extractor = new CodeSnippetExtractor(new SensitiveDataRedactor());

        SnippetExtractionResult result = extractor.extract(source,
                new SourceLocation("src/App.java", 40, 1, 80, 1));

        assertEquals(50, result.snippet().endLine() - result.snippet().startLine() + 1);
        assertTrue(result.snippet().highlightLines().contains(80));
        assertTrue(result.snippet().redacted());
        assertFalse(result.snippet().text().contains("abcdefghijklmnop"));
        assertTrue(result.fileSha256().matches("sha256:[0-9a-f]{64}"));
    }

    @Test
    void recordsWarningInsteadOfPersistingNonUtf8Source() throws Exception {
        Path source = temporaryDirectory.resolve("binary.java");
        Files.write(source, new byte[]{(byte) 0xC3, (byte) 0x28});

        SnippetExtractionResult result = new CodeSnippetExtractor(new SensitiveDataRedactor()).extract(source,
                new SourceLocation("src/binary.java", 1, 0, 1, 0));

        assertNull(result.snippet());
        assertEquals(1, result.warnings().size());
        assertTrue(result.warnings().get(0).startsWith("SNIPPET_ENCODING_UNSUPPORTED"));
    }
}
