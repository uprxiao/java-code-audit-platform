package io.github.uprxiao.audit.finding;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.Normalizer;
import java.util.Collection;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;
import java.util.TreeSet;

/** V1 stable fingerprints. Line numbers are deliberately excluded from canonical identities. */
public final class FindingFingerprintService {

    public static final int VERSION = 1;

    public Fingerprint source(
            String ruleFamily,
            String projectRelativePath,
            String semanticAnchor,
            String sinkSymbol,
            String message,
            String snippetText) {
        String canonical = String.join("|",
                "source-v1",
                RuleFamilyCatalog.canonical(ruleFamily),
                ProjectPath.normalize(projectRelativePath),
                normalizeAnchor(semanticAnchor, snippetText),
                normalizeToken(sinkSymbol),
                normalizeMessage(message));
        return fingerprint(canonical);
    }

    public Fingerprint dependency(String vulnerabilityId, String purlWithVersion, String affectedModule) {
        String canonical = String.join("|", "dependency-v1", required(vulnerabilityId).toUpperCase(Locale.ROOT),
                required(purlWithVersion), normalizeToken(affectedModule));
        return fingerprint(canonical);
    }

    public Fingerprint duplication(String normalizedTokenText, Collection<String> occurrencePaths) {
        TreeSet<String> paths = new TreeSet<>();
        Objects.requireNonNull(occurrencePaths, "occurrencePaths").forEach(path -> paths.add(ProjectPath.normalize(path)));
        if (paths.size() < 2) {
            throw new IllegalArgumentException("duplicate-code fingerprints require at least two occurrence paths");
        }
        String canonical = "duplication-v1|" + sha256(normalizeCode(normalizedTokenText)) + "|" + String.join(",", paths);
        return fingerprint(canonical);
    }

    Fingerprint group(String canonicalIdentity) {
        return fingerprint("group-v1|" + required(canonicalIdentity));
    }

    public String semanticCodeHash(String text) {
        return sha256(normalizeCode(text));
    }

    private Fingerprint fingerprint(String canonical) {
        String value = "sha256:" + sha256(canonical);
        return new Fingerprint(value, VERSION, "F-" + value.substring(7, 27));
    }

    private String normalizeAnchor(String anchor, String snippet) {
        String normalized = normalizeToken(anchor);
        return normalized.isBlank() ? semanticCodeHash(snippet == null ? "" : snippet) : normalized;
    }

    private String normalizeMessage(String value) {
        return normalizeToken(value)
                .replaceAll("\\b[0-9]+\\b", "#")
                .replaceAll("\\b[0-9a-f]{8,}\\b", "#hex");
    }

    private String normalizeCode(String value) {
        String text = Normalizer.normalize(value == null ? "" : value, Normalizer.Form.NFKC);
        return text.replaceAll("(?s)/\\*.*?\\*/", " ")
                .replaceAll("//[^\\r\\n]*", " ")
                .replaceAll("\"(?:\\\\.|[^\"\\\\])*\"", "\"#string\"")
                .replaceAll("'\\\\?.'", "'#char'")
                .replaceAll("\\s+", "")
                .toLowerCase(Locale.ROOT);
    }

    private String normalizeToken(String value) {
        return Normalizer.normalize(value == null ? "" : value.trim(), Normalizer.Form.NFKC)
                .replaceAll("\\s+", " ")
                .toLowerCase(Locale.ROOT);
    }

    private String required(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("fingerprint identity component must not be blank");
        }
        return value.trim();
    }

    private String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by Java 17", exception);
        }
    }

    public record Fingerprint(String value, int version, String findingId) {
        public Fingerprint {
            Objects.requireNonNull(value, "value");
            Objects.requireNonNull(findingId, "findingId");
        }
    }
}
