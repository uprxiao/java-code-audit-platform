package io.github.uprxiao.audit.report;

import io.github.uprxiao.audit.finding.CodeSnippet;
import io.github.uprxiao.audit.finding.ComponentEvidence;
import io.github.uprxiao.audit.finding.DataFlow;
import io.github.uprxiao.audit.finding.DataFlowNode;
import io.github.uprxiao.audit.finding.Finding;
import io.github.uprxiao.audit.finding.FindingEvidence;
import io.github.uprxiao.audit.finding.FindingSuppression;
import io.github.uprxiao.audit.finding.SensitiveDataRedactor;
import io.github.uprxiao.audit.finding.SourceLocation;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class ReportInputSanitizer {

    private final SensitiveDataRedactor redactor;

    ReportInputSanitizer(SensitiveDataRedactor redactor) {
        this.redactor = redactor;
    }

    ReportInput sanitize(ReportInput input) {
        return new ReportInput(input.scanId(), input.profile(), input.status(), input.createdAt(), input.completedAt(),
                map(input.source()), input.findings().stream().map(this::finding).toList(), input.coverage(),
                map(input.sbomSummary()), map(input.build()), map(input.toolchain()),
                strings(input.exclusions()), strings(input.warnings()), input.configFingerprint());
    }

    private Finding finding(Finding finding) {
        CodeSnippet snippet = finding.snippet() == null ? null : new CodeSnippet(
                finding.snippet().startLine(), finding.snippet().endLine(), finding.snippet().highlightLines(),
                redact(finding.snippet().text()), finding.snippet().redacted()
                        || redactor.redact(finding.snippet().text()).redacted());
        ComponentEvidence component = finding.component() == null ? null : new ComponentEvidence(
                redact(finding.component().purl()), redact(finding.component().groupId()),
                redact(finding.component().artifactId()), redact(finding.component().version()),
                redact(finding.component().scope()), finding.component().direct(),
                strings(finding.component().dependencyPath()), strings(finding.component().fixedVersions()));
        List<DataFlow> flows = finding.dataFlows().stream().map(flow -> new DataFlow(flow.engine(),
                flow.nodes().stream().map(node -> new DataFlowNode(node.index(), node.kind(), location(node.location()),
                        redact(node.label()))).toList())).toList();
        List<FindingEvidence> evidence = finding.evidence().stream().map(item -> new FindingEvidence(
                item.engine(), item.engineVersion(), item.ruleId(), item.engineSeverity(), item.rawArtifact(),
                redact(item.rawItemId()), map(item.properties()))).toList();
        FindingSuppression suppression = finding.suppression() == null ? null : new FindingSuppression(
                finding.suppression().ruleId(), redact(finding.suppression().reason()),
                finding.suppression().expiresAt());
        return new Finding(finding.id(), finding.fingerprint(), finding.fingerprintVersion(), finding.category(),
                finding.severity(), finding.confidence(), finding.ruleFamily(), redact(finding.titleZh()),
                redact(finding.titleOriginal()), redact(finding.descriptionZh()), redact(finding.messageOriginal()),
                redact(finding.impactZh()), redact(finding.remediationZh()), redact(finding.module()),
                finding.location() == null ? null : location(finding.location()), snippet, finding.identifiers(),
                component, flows, evidence, suppression,
                finding.reviewState());
    }

    private SourceLocation location(SourceLocation source) {
        return new SourceLocation(redact(source.path()), source.startLine(), source.startColumn(),
                source.endLine(), source.endColumn());
    }

    private List<String> strings(List<String> values) {
        return values.stream().map(this::redact).toList();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> map(Map<String, ?> values) {
        Map<String, Object> result = new LinkedHashMap<>();
        values.forEach((key, value) -> result.put(key, object(value)));
        return Map.copyOf(result);
    }

    private Object object(Object value) {
        if (value instanceof String text) {
            return redact(text);
        }
        if (value instanceof Map<?, ?> source) {
            Map<String, Object> result = new LinkedHashMap<>();
            source.forEach((key, nested) -> result.put(String.valueOf(key), object(nested)));
            return Map.copyOf(result);
        }
        if (value instanceof List<?> source) {
            List<Object> result = new ArrayList<>();
            source.forEach(nested -> result.add(object(nested)));
            return List.copyOf(result);
        }
        return value;
    }

    private String redact(String value) {
        return redactor.redact(value == null ? "" : value).text();
    }
}
