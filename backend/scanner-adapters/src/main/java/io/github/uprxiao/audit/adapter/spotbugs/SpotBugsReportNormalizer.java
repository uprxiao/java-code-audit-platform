package io.github.uprxiao.audit.adapter.spotbugs;

import io.github.uprxiao.audit.adapter.support.AdapterSupport;
import io.github.uprxiao.audit.adapter.support.SecureXml;
import io.github.uprxiao.audit.finding.Confidence;
import io.github.uprxiao.audit.finding.EngineCoverage;
import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.finding.Finding;
import io.github.uprxiao.audit.finding.FindingEvidence;
import io.github.uprxiao.audit.finding.FindingFingerprintService;
import io.github.uprxiao.audit.finding.IssueCategory;
import io.github.uprxiao.audit.finding.ReviewState;
import io.github.uprxiao.audit.finding.RuleFamilyCatalog;
import io.github.uprxiao.audit.finding.SeverityMappingRequest;
import io.github.uprxiao.audit.finding.SeverityMappingResult;
import io.github.uprxiao.audit.finding.SeverityMappingService;
import io.github.uprxiao.audit.finding.SourceLocation;
import io.github.uprxiao.audit.finding.VulnerabilityIdentifiers;
import io.github.uprxiao.audit.intake.ProjectContext;
import io.github.uprxiao.audit.scanner.ArtifactValidation;
import io.github.uprxiao.audit.scanner.EngineId;
import io.github.uprxiao.audit.scanner.ExecutionResult;
import io.github.uprxiao.audit.scanner.NormalizationResult;
import io.github.uprxiao.audit.scanner.RawArtifactSet;
import io.github.uprxiao.audit.scanner.ScanContext;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

final class SpotBugsReportNormalizer {

    private final EngineId engine;
    private final boolean securityOnly;
    private final String toolVersion;
    private final FindingFingerprintService fingerprints = new FindingFingerprintService();
    private final SeverityMappingService severities = new SeverityMappingService();

    SpotBugsReportNormalizer(EngineId engine, boolean securityOnly, String toolVersion) {
        this.engine = engine;
        this.securityOnly = securityOnly;
        this.toolVersion = toolVersion;
    }

    ArtifactValidation validate(RawArtifactSet artifacts) throws IOException {
        List<String> errors = new ArrayList<>();
        if (!engine.equals(artifacts.engine())) errors.add("ENGINE_MISMATCH");
        if (artifacts.execution().status() != ExecutionResult.Status.SUCCEEDED) {
            errors.add("EXECUTION_" + artifacts.execution().status());
        }
        Path report = artifacts.artifacts().get("report");
        if (report == null || !Files.isRegularFile(report)) {
            errors.add("REPORT_MISSING");
        } else if (Files.size(report) > SpotBugsExecutionSupport.MAX_REPORT_BYTES) {
            errors.add("REPORT_TOO_LARGE");
        } else {
            try {
                Document document = SecureXml.parse(report);
                if (!"BugCollection".equals(document.getDocumentElement().getNodeName())) {
                    errors.add("REPORT_SCHEMA_INVALID");
                }
            } catch (IOException exception) {
                errors.add("REPORT_XML_INVALID");
            }
        }
        return new ArtifactValidation(errors.isEmpty(), errors);
    }

    NormalizationResult normalize(ScanContext context, RawArtifactSet artifacts) throws IOException {
        ArtifactValidation validation = validate(artifacts);
        if (!validation.valid()) {
            throw new IOException(engine + " artifacts are invalid: " + validation.errors());
        }
        Document document = SecureXml.parse(artifacts.artifacts().get("report"));
        Map<String, PatternMetadata> patterns = patterns(document);
        List<Finding> findings = new ArrayList<>();
        List<String> warnings = reportWarnings(document);
        NodeList instances = document.getElementsByTagName("BugInstance");
        int selectedIndex = 0;
        for (int index = 0; index < instances.getLength(); index++) {
            Element instance = (Element) instances.item(index);
            String category = instance.getAttribute("category");
            if (isFindSecBugs(category) != securityOnly) continue;
            try {
                findings.add(toFinding(context.project(), instance, patterns.get(instance.getAttribute("type")), selectedIndex));
            } catch (IOException | IllegalArgumentException exception) {
                warnings.add(engine.value().toUpperCase(Locale.ROOT) + "_ITEM_" + selectedIndex + ": " + exception.getMessage());
            }
            selectedIndex++;
        }
        int modules = context.project().manifest().modules().size();
        EngineStatus status = warnings.isEmpty() ? EngineStatus.SUCCEEDED : EngineStatus.PARTIAL;
        return new NormalizationResult(findings,
                new EngineCoverage(engine.value(), status, modules, modules, modules, findings.size(),
                        artifacts.execution().duration(), warnings.isEmpty() ? "" : "SPOTBUGS_PARTIAL_ERRORS",
                        "raw/spotbugs/report.xml"), warnings);
    }

    private Finding toFinding(ProjectContext project, Element instance, PatternMetadata pattern, int index)
            throws IOException {
        String type = required(instance.getAttribute("type"), "type");
        String categoryName = instance.getAttribute("category");
        int priority = integer(instance.getAttribute("priority"), 3);
        int rank = integer(instance.getAttribute("rank"), 20);
        Element source = primarySource(instance);
        Path relative = resolveSource(project, source);
        int startLine = Math.max(1, integer(source.getAttribute("start"), 1));
        int endLine = Math.max(startLine, integer(source.getAttribute("end"), startLine));
        String shortMessage = text(instance, "ShortMessage", pattern == null ? type : pattern.shortDescription());
        String longMessage = text(instance, "LongMessage", shortMessage);
        String className = childAttribute(instance, "Class", "classname");
        String methodName = childAttribute(instance, "Method", "name");
        String anchor = className + (methodName.isBlank() ? "" : "#" + methodName);
        String ruleFamily = ruleFamily(type);
        IssueCategory category = issueCategory(categoryName, type);
        Confidence confidence = priority == 1 ? Confidence.HIGH : Confidence.MEDIUM;
        var snippet = AdapterSupport.snippet(project, relative, startLine, endLine);
        FindingFingerprintService.Fingerprint fingerprint = fingerprints.source(
                ruleFamily, AdapterSupport.portable(relative), anchor, methodName, longMessage,
                snippet == null ? "" : snippet.text());
        String severityBasis = severityBasis(priority, rank);
        SeverityMappingResult severity = severities.map(new SeverityMappingRequest(
                engine.value(), ruleFamily, category, severityBasis, null, false, false, confidence));

        int cwe = pattern == null ? 0 : pattern.cwe();
        List<String> cwes = cwe > 0 ? List.of("CWE-" + cwe) : List.of();
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("bugCategory", categoryName);
        properties.put("priority", priority);
        properties.put("rank", rank);
        String instanceHash = instance.getAttribute("instanceHash").trim();
        if (!instanceHash.isEmpty()) {
            properties.put("detectorInstanceKey", "spotbugs:"
                    + instanceHash + ":" + integer(instance.getAttribute("instanceOccurrenceNum"), 0));
        }
        properties.put("severityBasis", "bug-rank:" + rank);
        properties.put("class", className);
        properties.put("method", methodName);
        properties.put("sharedExecution", "spotbugs-findsecbugs");
        properties.put("severityMappingId", severity.mappingId());
        properties.put("severityMappingReason", severity.reason());
        FindingEvidence evidence = new FindingEvidence(engine.value(), toolVersion, type,
                Integer.toString(priority), "raw/spotbugs/report.xml", type + ":" + index, properties);
        return new Finding(fingerprint.findingId(), fingerprint.value(), fingerprint.version(), category,
                severity.severity(), confidence, ruleFamily,
                (securityOnly ? "FindSecBugs：" : "SpotBugs：") + shortMessage, shortMessage,
                securityOnly ? "字节码安全规则识别到 Java Web 或 JVM 安全风险。" : "字节码分析识别到潜在正确性问题。",
                longMessage,
                securityOnly ? "缺陷可能造成输入注入、敏感数据暴露或不安全行为。" : "缺陷可能影响运行正确性、线程安全或资源使用。",
                securityOnly ? "确认输入边界并采用参数化、安全 API 或显式校验。" : "结合调用路径修复缺陷，并增加覆盖该分支的回归测试。",
                AdapterSupport.moduleFor(project, relative),
                new SourceLocation(AdapterSupport.portable(relative), startLine, 0, endLine, 0), snippet,
                new VulnerabilityIdentifiers(cwes, List.of(), List.of(), List.of()), null, List.of(),
                List.of(evidence), null, ReviewState.UNREVIEWED);
    }

    private Map<String, PatternMetadata> patterns(Document document) {
        Map<String, PatternMetadata> result = new HashMap<>();
        NodeList nodes = document.getElementsByTagName("BugPattern");
        for (int index = 0; index < nodes.getLength(); index++) {
            Element element = (Element) nodes.item(index);
            String type = element.getAttribute("type");
            if (!type.isBlank()) {
                result.put(type, new PatternMetadata(text(element, "ShortDescription", type),
                        integer(element.getAttribute("cweid"), 0)));
            }
        }
        return result;
    }

    private List<String> reportWarnings(Document document) {
        List<String> warnings = new ArrayList<>();
        NodeList errors = document.getElementsByTagName("Errors");
        if (errors.getLength() == 0) return warnings;
        Element errorRoot = (Element) errors.item(0);
        int missing = integer(errorRoot.getAttribute("missingClasses"), 0);
        int count = integer(errorRoot.getAttribute("errors"), 0);
        if (missing > 0) warnings.add("SPOTBUGS_MISSING_CLASSES=" + missing);
        if (count > 0) warnings.add("SPOTBUGS_ANALYSIS_ERRORS=" + count);
        NodeList errorNodes = errorRoot.getElementsByTagName("Error");
        for (int index = 0; index < errorNodes.getLength(); index++) {
            warnings.add("SPOTBUGS_ERROR: " + errorNodes.item(index).getTextContent().trim());
        }
        return warnings;
    }

    private Element primarySource(Element instance) throws IOException {
        NodeList sources = instance.getElementsByTagName("SourceLine");
        Element fallback = null;
        Element primary = null;
        for (int index = 0; index < sources.getLength(); index++) {
            Element source = (Element) sources.item(index);
            if (source.getAttribute("sourcepath").isBlank()) continue;
            if (fallback == null) fallback = source;
            String role = source.getAttribute("role");
            if ("SOURCE_LINE_DEREF".equals(role)) return source;
            if ("PRIMARY".equals(role) || "true".equals(source.getAttribute("primary"))) primary = source;
        }
        if (primary != null) return primary;
        if (fallback != null) return fallback;
        throw new IOException("SpotBugs finding has no source location");
    }

    private Path resolveSource(ProjectContext project, Element source) throws IOException {
        String raw = required(source.getAttribute("sourcepath"), "sourcepath").replace('\\', '/');
        Path direct = project.workspaceRoot().resolve(raw).normalize();
        if (direct.startsWith(project.workspaceRoot()) && Files.isRegularFile(direct)) {
            return project.workspaceRoot().relativize(direct);
        }
        Path suffix = Path.of(raw).normalize();
        try (var paths = Files.find(project.workspaceRoot(), 16,
                (path, attributes) -> attributes.isRegularFile() && path.normalize().endsWith(suffix))) {
            List<Path> matches = paths.sorted().limit(2).toList();
            if (matches.size() == 1) return project.workspaceRoot().relativize(matches.get(0).normalize());
            if (matches.size() > 1) throw new IOException("ambiguous SpotBugs sourcepath: " + raw);
        }
        throw new IOException("SpotBugs sourcepath is outside or absent from project: " + raw);
    }

    private boolean isFindSecBugs(String category) {
        return "SECURITY".equalsIgnoreCase(category);
    }

    private IssueCategory issueCategory(String category, String type) {
        if (securityOnly) return IssueCategory.WEB_SECURITY;
        String bugCategory = category.toUpperCase(Locale.ROOT);
        String bugType = type.toUpperCase(Locale.ROOT);
        if (bugType.startsWith("NP_")) return IssueCategory.CORRECTNESS;
        if (bugCategory.equals("MT_CORRECTNESS")
                || bugType.matches("^(AT|DL|LI|ML|NN|RU|SC|SP|STCAL|TLW|UG_SYNC|UL|VO|WA|WS)_.*")) {
            return IssueCategory.CONCURRENCY;
        }
        if (bugCategory.equals("PERFORMANCE")
                || bugType.matches("^(OS|ODR|DM_GC|WMI)_.*")) return IssueCategory.RESOURCE_PERFORMANCE;
        if (bugCategory.equals("STYLE") || bugCategory.equals("DESIGN")
                || bugCategory.equals("EXPERIMENTAL") || bugCategory.equals("I18N")
                || bugCategory.equals("MALICIOUS_CODE")) return IssueCategory.MAINTAINABILITY;
        return IssueCategory.CORRECTNESS;
    }

    private String severityBasis(int priority, int rank) {
        // SpotBugs priority is detector confidence, while bug rank (1..20) represents impact/scariness.
        // Keep high-confidence security findings in the review queue, but never manufacture P0 here.
        if (rank <= 4 || (securityOnly && priority == 1 && rank <= 9)) return "HIGH";
        if (rank <= 14) return "MEDIUM";
        return "LOW";
    }

    private String ruleFamily(String type) {
        String upper = type.toUpperCase(Locale.ROOT);
        if (upper.contains("SQL_INJECTION")) return "SQL_INJECTION";
        if (upper.contains("COMMAND_INJECTION") || upper.contains("COMMAND_EXEC")) return "COMMAND_INJECTION";
        if (upper.contains("PATH_TRAVERSAL") || upper.contains("FILE_UPLOAD_FILENAME")) return "PATH_TRAVERSAL";
        if (upper.contains("XSS")) return "CROSS_SITE_SCRIPTING";
        if (upper.contains("SSRF")) return "SSRF";
        if (upper.contains("DESERIALIZATION")) return "UNSAFE_DESERIALIZATION";
        if (upper.startsWith("NP_")) return "NULL_DEREFERENCE";
        return RuleFamilyCatalog.canonical(type);
    }

    private String childAttribute(Element root, String tag, String attribute) {
        NodeList nodes = root.getElementsByTagName(tag);
        return nodes.getLength() == 0 ? "" : ((Element) nodes.item(0)).getAttribute(attribute);
    }

    private String text(Element root, String tag, String fallback) {
        NodeList nodes = root.getElementsByTagName(tag);
        if (nodes.getLength() == 0) return fallback;
        String value = nodes.item(0).getTextContent().trim();
        return value.isBlank() ? fallback : value;
    }

    private int integer(String value, int fallback) {
        try {
            return value == null || value.isBlank() ? fallback : Integer.parseInt(value);
        } catch (NumberFormatException exception) {
            return fallback;
        }
    }

    private String required(String value, String field) throws IOException {
        if (value == null || value.isBlank()) throw new IOException("missing " + field);
        return value;
    }

    private record PatternMetadata(String shortDescription, int cwe) {
    }
}
