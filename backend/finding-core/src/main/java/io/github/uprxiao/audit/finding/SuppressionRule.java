package io.github.uprxiao.audit.finding;

import java.time.Instant;

public record SuppressionRule(
        String id,
        String engine,
        String ruleId,
        String ruleFamily,
        String pathGlob,
        String fingerprint,
        String componentPurl,
        String vulnerabilityId,
        String reason,
        Instant expiresAt) {

    public SuppressionRule {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("suppression id must not be blank");
        }
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("suppression reason must not be blank");
        }
        engine = normalized(engine);
        ruleId = normalized(ruleId);
        ruleFamily = ruleFamily == null || ruleFamily.isBlank() ? "" : RuleFamilyCatalog.canonical(ruleFamily);
        pathGlob = normalized(pathGlob);
        fingerprint = normalized(fingerprint);
        componentPurl = normalized(componentPurl);
        vulnerabilityId = normalized(vulnerabilityId);
        if (engine.isBlank() && ruleId.isBlank() && ruleFamily.isBlank() && pathGlob.isBlank()
                && fingerprint.isBlank() && componentPurl.isBlank() && vulnerabilityId.isBlank()) {
            throw new IllegalArgumentException("suppression requires at least one matcher");
        }
        if (!pathGlob.isBlank()) {
            new PortableGlob(pathGlob);
        }
        if (!fingerprint.isBlank() && !fingerprint.matches("sha256:[0-9a-f]{64}")) {
            throw new IllegalArgumentException("suppression fingerprint must be a SHA-256 value");
        }
    }

    public boolean expired(Instant now) {
        return expiresAt != null && !expiresAt.isAfter(now);
    }

    private static String normalized(String value) {
        return value == null ? "" : value.trim();
    }
}
