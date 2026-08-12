package io.github.uprxiao.audit.finding;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

public final class FindingSuppressionService {

    public SuppressionResult apply(List<Finding> findings, List<SuppressionRule> rules, Instant now) {
        Objects.requireNonNull(findings, "findings");
        Objects.requireNonNull(rules, "rules");
        Objects.requireNonNull(now, "now");
        List<String> warnings = new ArrayList<>();
        List<Finding> result = new ArrayList<>(findings.size());
        for (Finding finding : findings) {
            SuppressionRule match = null;
            for (SuppressionRule rule : rules) {
                if (!matches(rule, finding)) {
                    continue;
                }
                if (rule.expired(now)) {
                    warnings.add("SUPPRESSION_EXPIRED:" + rule.id() + ":" + finding.fingerprint());
                    continue;
                }
                match = rule;
                break;
            }
            result.add(match == null ? finding : finding.withSuppression(
                    new FindingSuppression(match.id(), match.reason(), match.expiresAt())));
        }
        return new SuppressionResult(result, warnings.stream().distinct().toList());
    }

    private boolean matches(SuppressionRule rule, Finding finding) {
        if (!rule.engine().isBlank() && finding.evidence().stream()
                .noneMatch(evidence -> evidence.engine().equalsIgnoreCase(rule.engine()))) {
            return false;
        }
        if (!rule.ruleId().isBlank() && finding.evidence().stream()
                .noneMatch(evidence -> evidence.ruleId().equalsIgnoreCase(rule.ruleId()))) {
            return false;
        }
        if (!rule.ruleFamily().isBlank() && !RuleFamilyCatalog.compatible(rule.ruleFamily(), finding.ruleFamily())) {
            return false;
        }
        if (!rule.pathGlob().isBlank() && (finding.location() == null
                || !new PortableGlob(rule.pathGlob()).matches(finding.location().path()))) {
            return false;
        }
        if (!rule.fingerprint().isBlank() && !rule.fingerprint().equals(finding.fingerprint())) {
            return false;
        }
        if (!rule.componentPurl().isBlank() && (finding.component() == null
                || !rule.componentPurl().equals(finding.component().purl()))) {
            return false;
        }
        return rule.vulnerabilityId().isBlank()
                || vulnerabilityIds(finding).contains(rule.vulnerabilityId().toUpperCase(Locale.ROOT));
    }

    private Set<String> vulnerabilityIds(Finding finding) {
        Set<String> result = new LinkedHashSet<>();
        finding.identifiers().cve().forEach(id -> result.add(id.toUpperCase(Locale.ROOT)));
        finding.identifiers().ghsa().forEach(id -> result.add(id.toUpperCase(Locale.ROOT)));
        finding.identifiers().osv().forEach(id -> result.add(id.toUpperCase(Locale.ROOT)));
        return result;
    }
}
