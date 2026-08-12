package io.github.uprxiao.audit.finding;

public record SeverityMappingRequest(
        String engine,
        String ruleFamily,
        IssueCategory category,
        String engineSeverity,
        Double cvss,
        boolean knownExploited,
        boolean privilegedSecret,
        Confidence confidence) {

    public SeverityMappingRequest {
        if (engine == null || engine.isBlank()) {
            throw new IllegalArgumentException("engine must not be blank");
        }
        ruleFamily = RuleFamilyCatalog.canonical(ruleFamily);
        if (category == null) {
            throw new IllegalArgumentException("category is required");
        }
        engineSeverity = engineSeverity == null ? "" : engineSeverity.trim();
        if (cvss != null && (cvss < 0 || cvss > 10)) {
            throw new IllegalArgumentException("CVSS must be between 0 and 10");
        }
        confidence = confidence == null ? Confidence.MEDIUM : confidence;
    }
}
