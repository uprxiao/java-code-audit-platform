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
        if (fingerprintVersion < 1) {
            throw new IllegalArgumentException("fingerprintVersion must be positive");
        }
        Objects.requireNonNull(category, "category");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(confidence, "confidence");
        ruleFamily = requireText(ruleFamily, "ruleFamily");
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
    }

    public boolean suppressed() {
        return suppression != null;
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
