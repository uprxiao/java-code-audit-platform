package io.github.uprxiao.audit.report;

import io.github.uprxiao.audit.finding.SensitiveDataRedactor;
import io.github.uprxiao.audit.storage.AtomicFileWriter;
import io.github.uprxiao.audit.storage.NioAtomicFileWriter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

final class ArtifactRedactionService {

    private static final long MAX_TEXT_ARTIFACT_BYTES = 256L * 1024 * 1024;

    private final SensitiveDataRedactor redactor;
    private final AtomicFileWriter writer;

    ArtifactRedactionService(SensitiveDataRedactor redactor) {
        this(redactor, new NioAtomicFileWriter());
    }

    ArtifactRedactionService(SensitiveDataRedactor redactor, AtomicFileWriter writer) {
        this.redactor = Objects.requireNonNull(redactor, "redactor");
        this.writer = Objects.requireNonNull(writer, "writer");
    }

    RedactionSummary sanitize(Path jobRoot) throws IOException {
        int files = 0;
        int replacements = 0;
        for (String directory : List.of("raw", "logs", "sbom")) {
            Path root = jobRoot.resolve(directory).normalize();
            if (!root.startsWith(jobRoot) || !Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
                continue;
            }
            if (Files.isSymbolicLink(root)) {
                throw new IOException("artifact root must not be a symbolic link: " + root);
            }
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted().toList()) {
                    if (Files.isSymbolicLink(path)) {
                        throw new IOException("symbolic links are forbidden in report artifacts: " + path);
                    }
                    if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                        continue;
                    }
                    long size = Files.size(path);
                    if (size > MAX_TEXT_ARTIFACT_BYTES) {
                        throw new IOException("artifact exceeds redaction safety limit: " + path);
                    }
                    byte[] content = Files.readAllBytes(path);
                    final String text;
                    try {
                        text = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(content)).toString();
                    } catch (CharacterCodingException exception) {
                        ensureExactSecretsAbsent(path, content);
                        continue;
                    }
                    var result = redactor.redact(text);
                    if (result.redacted()) {
                        writer.write(path, result.text().getBytes(StandardCharsets.UTF_8));
                        files++;
                        replacements += result.replacementCount();
                    }
                }
            }
        }
        return new RedactionSummary(files, replacements);
    }

    void assertSensitiveValuesAbsent(List<Path> files) throws IOException {
        for (Path file : files) {
            if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                continue;
            }
            byte[] content = Files.readAllBytes(file);
            ensureExactSecretsAbsent(file, content);
            String text;
            try {
                text = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(content)).toString();
            } catch (CharacterCodingException exception) {
                continue;
            }
            if (text.contains("AUDIT_CANARY_SECRET_") || text.contains("-----BEGIN PRIVATE KEY-----")) {
                throw new IOException("sensitive canary remains in finalized artifact: " + file);
            }
        }
    }

    private void ensureExactSecretsAbsent(Path path, byte[] content) throws IOException {
        for (String secret : redactor.exactSecrets()) {
            if (contains(content, secret.getBytes(StandardCharsets.UTF_8))) {
                throw new IOException("configured sensitive value remains in artifact: " + path);
            }
        }
        for (String marker : List.of("AUDIT_CANARY_SECRET_", "-----BEGIN PRIVATE KEY-----")) {
            if (contains(content, marker.getBytes(StandardCharsets.UTF_8))) {
                throw new IOException("sensitive marker remains in binary artifact: " + path);
            }
        }
    }

    private boolean contains(byte[] content, byte[] needle) {
        if (needle.length == 0 || needle.length > content.length) {
            return false;
        }
        outer:
        for (int offset = 0; offset <= content.length - needle.length; offset++) {
            for (int index = 0; index < needle.length; index++) {
                if (content[offset + index] != needle[index]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    record RedactionSummary(int filesChanged, int replacementCount) {
    }
}
