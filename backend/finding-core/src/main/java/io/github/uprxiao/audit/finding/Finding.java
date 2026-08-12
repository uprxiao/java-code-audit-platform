package io.github.uprxiao.audit.finding;

import java.util.List;
import java.util.Objects;

public record Finding(
        String id,
        String fingerprint,
        int fingerprintVersion,
        IssueCategory category,
        Severity severity,
        Confidence confidence,
        String ruleFamily,
        String titleZh,
        String titleOriginal,
        String descriptionZh,
        String messageOriginal,
        String impactZh,
        String remediationZh,
        String module,
        SourceLocation location,
        CodeSnippet snippet,
        VulnerabilityIdentifiers identifiers,
        ComponentEvidence component,
        List<DataFlow> dataFlows,
        List<FindingEvidence> evidence,
        FindingSuppression suppression,
        ReviewState reviewState) {

    public Finding {
        id = requireText(id, "id");
        fingerprint = requireText(fingerprint, "fingerprint");
        if (!fingerprint.matches("sha256:[0-9a-f]{64}")) {
            throw new IllegalArgumentException("fingerprint must be a SHA-256 value");
        }
        if (fingerprintVersion < 1) {
            throw new IllegalArgumentException("fingerprintVersion must be positive");
        }
        Objects.requireNonNull(category, "category");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(confidence, "confidence");
        ruleFamily = RuleFamilyCatalog.canonical(requireText(ruleFamily, "ruleFamily"));
        titleZh = normalize(titleZh);
        titleOriginal = normalize(titleOriginal);
        if (titleZh.isBlank() && titleOriginal.isBlank()) {
            throw new IllegalArgumentException("at least one title is required");
        }
        descriptionZh = normalize(descriptionZh);
        messageOriginal = normalize(messageOriginal);
        impactZh = normalize(impactZh);
        remediationZh = normalize(remediationZh);
        module = normalize(module);
        identifiers = identifiers == null ? VulnerabilityIdentifiers.EMPTY : identifiers;
        dataFlows = dataFlows == null ? List.of() : List.copyOf(dataFlows);
        evidence = evidence == null ? List.of() : List.copyOf(evidence);
        if (evidence.isEmpty()) {
            throw new IllegalArgumentException("finding requires at least one evidence source");
        }
        reviewState = reviewState == null ? ReviewState.UNREVIEWED : reviewState;
        if (category == IssueCategory.SECRET_EXPOSURE && snippet != null && !snippet.redacted()) {
            throw new IllegalArgumentException("secret snippets must be redacted");
        }
        if (category == IssueCategory.DEPENDENCY_VULNERABILITY && component == null) {
            throw new IllegalArgumentException("dependency vulnerability requires component evidence");
        }
        if (category == IssueCategory.DEPENDENCY_VULNERABILITY
                && identifiers.cve().isEmpty() && identifiers.ghsa().isEmpty() && identifiers.osv().isEmpty()) {
            throw new IllegalArgumentException("dependency vulnerability requires a CVE, GHSA, or OSV identifier");
        }
    }

    public boolean suppressed() {
        return suppression != null;
    }

    public Finding withSuppression(FindingSuppression value) {
        return copy(evidence, dataFlows, value, severity, confidence, fingerprint, id);
    }

    public Finding withMergedEvidence(
            List<FindingEvidence> mergedEvidence,
            List<DataFlow> mergedDataFlows,
            Severity mergedSeverity,
            Confidence mergedConfidence,
            String mergedFingerprint,
            String mergedId) {
        return copy(mergedEvidence, mergedDataFlows, suppression, mergedSeverity, mergedConfidence,
                mergedFingerprint, mergedId);
    }

    private Finding copy(
            List<FindingEvidence> copiedEvidence,
            List<DataFlow> copiedDataFlows,
            FindingSuppression copiedSuppression,
            Severity copiedSeverity,
            Confidence copiedConfidence,
            String copiedFingerprint,
            String copiedId) {
        return new Finding(copiedId, copiedFingerprint, fingerprintVersion, category, copiedSeverity,
                copiedConfidence, ruleFamily, titleZh, titleOriginal, descriptionZh, messageOriginal,
                impactZh, remediationZh, module, location, snippet, identifiers, component,
                copiedDataFlows, copiedEvidence, copiedSuppression, reviewState);
    }

    private static String requireText(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }

    private static String normalize(String value) {
        return value == null ? "" : value;
    }
}
