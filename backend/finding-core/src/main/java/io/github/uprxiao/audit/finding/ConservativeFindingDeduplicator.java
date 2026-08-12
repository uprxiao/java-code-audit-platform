package io.github.uprxiao.audit.finding;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Cross-engine de-duplication which only merges when source/sink or component identity agrees.
 * Ambiguous candidates remain separate by design.
 */
public final class ConservativeFindingDeduplicator {

    private final FindingFingerprintService fingerprints;

    public ConservativeFindingDeduplicator() {
        this(new FindingFingerprintService());
    }

    ConservativeFindingDeduplicator(FindingFingerprintService fingerprints) {
        this.fingerprints = Objects.requireNonNull(fingerprints, "fingerprints");
    }

    public FindingDeduplicationResult deduplicate(List<Finding> candidates) {
        Objects.requireNonNull(candidates, "candidates");
        List<Finding> ordered = candidates.stream()
                .sorted(Comparator.comparing(Finding::fingerprint).thenComparing(Finding::id))
                .toList();
        List<Group> groups = new ArrayList<>();
        for (Finding candidate : ordered) {
            Group match = groups.stream().filter(group -> group.accepts(candidate)).findFirst().orElse(null);
            if (match == null) {
                groups.add(new Group(candidate));
            } else {
                match.add(candidate);
            }
        }
        List<Finding> findings = groups.stream().map(Group::finish)
                .sorted(Comparator.comparing(Finding::fingerprint)).toList();
        return new FindingDeduplicationResult(findings, candidates.size(), candidates.size() - findings.size());
    }

    private boolean compatible(Finding left, Finding right) {
        if (left.category() != right.category()
                || !RuleFamilyCatalog.compatible(left.ruleFamily(), right.ruleFamily())
                || !Objects.equals(left.suppression(), right.suppression())
                || identifiersConflict(left, right)) {
            return false;
        }
        if (left.component() != null || right.component() != null) {
            return componentIdentityMatches(left, right);
        }
        if (left.location() == null || right.location() == null
                || !left.location().path().equals(right.location().path())) {
            return false;
        }
        FlowIdentity leftFlow = flowIdentity(left);
        FlowIdentity rightFlow = flowIdentity(right);
        if (leftFlow != null && rightFlow != null) {
            return leftFlow.equals(rightFlow);
        }
        if (leftFlow != null || rightFlow != null) {
            FlowIdentity flow = leftFlow == null ? rightFlow : leftFlow;
            Finding locationOnly = leftFlow == null ? left : right;
            return sameLocation(flow.sink(), locationOnly.location());
        }
        String leftSink = evidenceProperty(left, "sinkSymbol");
        String rightSink = evidenceProperty(right, "sinkSymbol");
        if (!leftSink.isBlank() && !rightSink.isBlank()) {
            return leftSink.equalsIgnoreCase(rightSink)
                    && Math.abs(left.location().startLine() - right.location().startLine()) <= 2;
        }
        // Without a semantic sink, exact line agreement is the conservative fallback.
        return left.location().startLine() == right.location().startLine();
    }

    private boolean componentIdentityMatches(Finding left, Finding right) {
        if (left.component() == null || right.component() == null) {
            return false;
        }
        return left.component().purl().equals(right.component().purl())
                && Objects.equals(left.module(), right.module())
                && left.component().dependencyPath().equals(right.component().dependencyPath())
                && intersects(vulnerabilityIds(left), vulnerabilityIds(right));
    }

    private boolean identifiersConflict(Finding left, Finding right) {
        Set<String> leftCwe = normalized(left.identifiers().cwe());
        Set<String> rightCwe = normalized(right.identifiers().cwe());
        if (!leftCwe.isEmpty() && !rightCwe.isEmpty() && disjoint(leftCwe, rightCwe)) {
            return true;
        }
        if (left.category() == IssueCategory.DEPENDENCY_VULNERABILITY) {
            Set<String> leftVulnerabilities = vulnerabilityIds(left);
            Set<String> rightVulnerabilities = vulnerabilityIds(right);
            return !leftVulnerabilities.isEmpty() && !rightVulnerabilities.isEmpty()
                    && disjoint(leftVulnerabilities, rightVulnerabilities);
        }
        return false;
    }

    private Set<String> vulnerabilityIds(Finding finding) {
        Set<String> result = new LinkedHashSet<>();
        result.addAll(normalized(finding.identifiers().cve()));
        result.addAll(normalized(finding.identifiers().ghsa()));
        result.addAll(normalized(finding.identifiers().osv()));
        return result;
    }

    private Set<String> normalized(List<String> values) {
        Set<String> result = new LinkedHashSet<>();
        values.forEach(value -> result.add(value.toUpperCase(Locale.ROOT)));
        return result;
    }

    private boolean intersects(Set<String> left, Set<String> right) {
        return !left.isEmpty() && !right.isEmpty() && !disjoint(left, right);
    }

    private boolean disjoint(Set<String> left, Set<String> right) {
        return left.stream().noneMatch(right::contains);
    }

    private FlowIdentity flowIdentity(Finding finding) {
        for (DataFlow flow : finding.dataFlows()) {
            DataFlowNode source = flow.nodes().stream().filter(node -> node.kind() == DataFlowNode.Kind.SOURCE)
                    .findFirst().orElse(null);
            DataFlowNode sink = flow.nodes().stream().filter(node -> node.kind() == DataFlowNode.Kind.SINK)
                    .reduce((first, second) -> second).orElse(null);
            if (source != null && sink != null) {
                return new FlowIdentity(point(source), point(sink));
            }
        }
        return null;
    }

    private FlowPoint point(DataFlowNode node) {
        return new FlowPoint(node.location().path(), node.location().startLine(), normalizedLabel(node.label()));
    }

    private boolean sameLocation(FlowPoint point, SourceLocation location) {
        return point.path().equals(location.path()) && Math.abs(point.line() - location.startLine()) <= 2;
    }

    private String normalizedLabel(String value) {
        return value == null ? "" : value.trim().replaceAll("\\s+", " ").toLowerCase(Locale.ROOT);
    }

    private String evidenceProperty(Finding finding, String key) {
        return finding.evidence().stream().map(FindingEvidence::properties).map(properties -> properties.get(key))
                .filter(Objects::nonNull).map(String::valueOf).filter(value -> !value.isBlank())
                .sorted().findFirst().orElse("");
    }

    private String groupIdentity(Finding finding) {
        if (finding.component() != null) {
            return String.join("|", "component", RuleFamilyCatalog.canonical(finding.ruleFamily()),
                    finding.component().purl(), finding.module(), String.join(",", vulnerabilityIds(finding)),
                    String.join(">", finding.component().dependencyPath()));
        }
        FlowIdentity flow = flowIdentity(finding);
        if (flow != null) {
            return "flow|" + RuleFamilyCatalog.canonical(finding.ruleFamily()) + "|" + flow;
        }
        String anchor = evidenceProperty(finding, "semanticAnchor");
        String sink = evidenceProperty(finding, "sinkSymbol");
        if (anchor.isBlank() && finding.snippet() != null) {
            anchor = fingerprints.semanticCodeHash(finding.snippet().text());
        }
        return String.join("|", "source", RuleFamilyCatalog.canonical(finding.ruleFamily()),
                finding.location().path(), anchor, sink);
    }

    private Confidence strongestConfidence(List<Finding> findings) {
        return findings.stream().map(Finding::confidence).min(Comparator.comparingInt(Enum::ordinal))
                .orElse(Confidence.LOW);
    }

    private Severity highestSeverity(List<Finding> findings) {
        return findings.stream().map(Finding::severity).min(Comparator.comparingInt(Enum::ordinal))
                .orElse(Severity.P3);
    }

    private final class Group {
        private final List<Finding> members = new ArrayList<>();

        private Group(Finding first) {
            members.add(first);
        }

        private boolean accepts(Finding candidate) {
            // Pairwise agreement avoids transitive merging through an ambiguous middle candidate.
            return members.stream().allMatch(existing -> compatible(existing, candidate));
        }

        private void add(Finding candidate) {
            members.add(candidate);
        }

        private Finding finish() {
            Finding base = members.stream().max(Comparator
                    .comparingInt((Finding finding) -> finding.evidence().size())
                    .thenComparingInt(finding -> finding.dataFlows().size())
                    .thenComparing(Finding::fingerprint)).orElseThrow();
            Map<String, FindingEvidence> evidence = new LinkedHashMap<>();
            members.stream().flatMap(finding -> finding.evidence().stream())
                    .sorted(Comparator.comparing(FindingEvidence::engine)
                            .thenComparing(FindingEvidence::ruleId)
                            .thenComparing(FindingEvidence::rawArtifact)
                            .thenComparing(FindingEvidence::rawItemId))
                    .forEach(item -> evidence.putIfAbsent(String.join("|", item.engine(), item.ruleId(),
                            item.rawArtifact(), item.rawItemId()), item));
            Map<String, DataFlow> flows = new LinkedHashMap<>();
            members.stream().flatMap(finding -> finding.dataFlows().stream()).forEach(flow ->
                    flows.putIfAbsent(flow.engine() + "|" + flow.nodes(), flow));
            FindingFingerprintService.Fingerprint groupFingerprint = fingerprints.group(groupIdentity(base));
            return base.withMergedEvidence(List.copyOf(evidence.values()), List.copyOf(flows.values()),
                    highestSeverity(members), strongestConfidence(members), groupFingerprint.value(),
                    groupFingerprint.findingId());
        }
    }

    private record FlowIdentity(FlowPoint source, FlowPoint sink) {
    }

    private record FlowPoint(String path, int line, String label) {
    }
}
