package io.github.uprxiao.audit.adapter.codeql;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.uprxiao.audit.adapter.support.AdapterSupport;
import io.github.uprxiao.audit.finding.CodeSnippet;
import io.github.uprxiao.audit.finding.Confidence;
import io.github.uprxiao.audit.finding.DataFlow;
import io.github.uprxiao.audit.finding.DataFlowNode;
import io.github.uprxiao.audit.finding.EngineCoverage;
import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.finding.Finding;
import io.github.uprxiao.audit.finding.FindingEvidence;
import io.github.uprxiao.audit.finding.FindingFingerprintService;
import io.github.uprxiao.audit.finding.IssueCategory;
import io.github.uprxiao.audit.finding.ReviewState;
import io.github.uprxiao.audit.finding.SeverityMappingRequest;
import io.github.uprxiao.audit.finding.SeverityMappingResult;
import io.github.uprxiao.audit.finding.SeverityMappingService;
import io.github.uprxiao.audit.finding.SourceLocation;
import io.github.uprxiao.audit.finding.VulnerabilityIdentifiers;
import io.github.uprxiao.audit.intake.ProjectContext;
import io.github.uprxiao.audit.scanner.Applicability;
import io.github.uprxiao.audit.scanner.ArtifactValidation;
import io.github.uprxiao.audit.scanner.EngineDescriptor;
import io.github.uprxiao.audit.scanner.EngineId;
import io.github.uprxiao.audit.scanner.ExecutionResult;
import io.github.uprxiao.audit.scanner.ExecutionSpec;
import io.github.uprxiao.audit.scanner.ExpectedArtifact;
import io.github.uprxiao.audit.scanner.NormalizationResult;
import io.github.uprxiao.audit.scanner.RawArtifactSet;
import io.github.uprxiao.audit.scanner.RedactionPolicy;
import io.github.uprxiao.audit.scanner.ResourceClass;
import io.github.uprxiao.audit.scanner.ResourceRequest;
import io.github.uprxiao.audit.scanner.ScanContext;
import io.github.uprxiao.audit.scanner.ScannerAdapter;
import io.github.uprxiao.audit.scanner.ToolContext;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** CodeQL 2.26.2 adapter with a pinned Java security-and-quality query suite. */
public final class CodeqlAdapter implements ScannerAdapter {

    public static final EngineId ID = new EngineId("codeql");
    public static final String CLI_VERSION = "2.26.2";
    public static final String JAVA_QUERY_PACK_VERSION = "1.11.7";
    public static final String QUERY_SUITE_NAME = "java-security-and-quality.qls";
    public static final String REPORT_ARTIFACT = "raw/codeql/report.sarif";
    static final String REPORT_FILE = "report.sarif";
    static final String DATABASE_DIRECTORY = "database";
    private static final long MAX_REPORT_BYTES = 1024L * 1024 * 1024;
    private static final Pattern CWE_TAG = Pattern.compile("(?i)(?:external/cwe/)?cwe-0*([0-9]+)");

    private final Path querySuite;
    private final Path mavenExecutable;
    private final Path javaHome;
    private final ObjectMapper json;
    private final FindingFingerprintService fingerprints = new FindingFingerprintService();
    private final SeverityMappingService severities = new SeverityMappingService();

    public CodeqlAdapter(Path querySuite) {
        this(querySuite, resolveMavenExecutable(), Path.of(System.getProperty("java.home")));
    }

    public CodeqlAdapter(Path querySuite, Path mavenExecutable, Path javaHome) {
        this(querySuite, mavenExecutable, javaHome, new ObjectMapper());
    }

    CodeqlAdapter(Path querySuite, Path mavenExecutable, Path javaHome, ObjectMapper json) {
        this.querySuite = Objects.requireNonNull(querySuite, "querySuite").toAbsolutePath().normalize();
        this.mavenExecutable = Objects.requireNonNull(mavenExecutable, "mavenExecutable").toAbsolutePath().normalize();
        this.javaHome = Objects.requireNonNull(javaHome, "javaHome").toAbsolutePath().normalize();
        this.json = Objects.requireNonNull(json, "json");
    }

    @Override
    public EngineDescriptor descriptor() {
        return new EngineDescriptor(ID, "CodeQL Java", true,
                new ResourceRequest(ResourceClass.DEEP, 8, 8192), Duration.ofHours(2), Set.of());
    }

    @Override
    public Applicability checkApplicability(ProjectContext project, ToolContext tools) {
        ToolContext.ToolInstallation installation = tools.installations().get(ID);
        if (installation == null || !installation.available() || !Files.isExecutable(installation.executable())) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "CODEQL_CLI_UNAVAILABLE",
                    "CodeQL CLI executable is unavailable");
        }
        if (!CLI_VERSION.equals(installation.version())) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "CODEQL_CLI_VERSION_MISMATCH",
                    "expected " + CLI_VERSION + ", actual " + installation.version());
        }
        if (!Files.isExecutable(mavenExecutable)
                || !"mvn".equals(mavenExecutable.getFileName().toString())) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "CODEQL_MAVEN_UNAVAILABLE",
                    mavenExecutable.toString());
        }
        if (!Files.isExecutable(javaHome.resolve("bin/java"))) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "CODEQL_JAVA_UNAVAILABLE",
                    javaHome.toString());
        }
        if (!Files.isRegularFile(querySuite) || !QUERY_SUITE_NAME.equals(querySuite.getFileName().toString())) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "CODEQL_QUERY_SUITE_UNAVAILABLE",
                    querySuite.toString());
        }
        String packVersion;
        try {
            packVersion = queryPackVersion();
        } catch (IOException exception) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "CODEQL_QUERY_PACK_INVALID",
                    exception.getMessage());
        }
        if (!JAVA_QUERY_PACK_VERSION.equals(packVersion)) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "CODEQL_QUERY_PACK_VERSION_MISMATCH",
                    "expected " + JAVA_QUERY_PACK_VERSION + ", actual " + packVersion);
        }
        return Applicability.applicable();
    }

    /** The ScannerAdapter compatibility entry point returns phase one. Use CodeqlWorkflow for full execution. */
    @Override
    public ExecutionSpec prepare(ScanContext context, ToolContext tools) throws IOException {
        return prepareDatabaseCreation(context, tools);
    }

    public ExecutionSpec prepareDatabaseCreation(ScanContext context, ToolContext tools) throws IOException {
        requireApplicable(context, tools);
        ToolContext.ToolInstallation installation = AdapterSupport.requireInstallation(tools, ID);
        Path output = Files.createDirectories(context.engineOutputDirectory());
        Path database = databaseDirectory(context);
        if (Files.exists(database)) {
            throw new IOException("CodeQL database path already exists: " + database);
        }
        Path phaseDirectory = Files.createDirectories(output.resolve("database-create"));
        List<String> command = List.of(
                installation.executable().toString(), "database", "create",
                "--language=java", "--build-mode=none",
                "--source-root=" + context.project().workspaceRoot(),
                "--threads=2", "--ram=8192", "--quiet",
                database.toString());
        return new ExecutionSpec(ID, command, phaseDirectory,
                isolatedEnvironment(phaseDirectory, installation.executable()),
                descriptor().defaultTimeout(), descriptor().resources(), Set.of(), RedactionPolicy.NONE);
    }

    public ExecutionSpec prepareAnalysis(ScanContext context, ToolContext tools) throws IOException {
        requireApplicable(context, tools);
        ToolContext.ToolInstallation installation = AdapterSupport.requireInstallation(tools, ID);
        Path database = databaseDirectory(context);
        if (!Files.isDirectory(database)) {
            throw new IOException("CodeQL database is unavailable: " + database);
        }
        Path output = Files.createDirectories(context.engineOutputDirectory());
        Path report = output.resolve(REPORT_FILE);
        if (Files.exists(report, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("CodeQL report path already exists: " + report);
        }
        List<String> command = List.of(
                installation.executable().toString(), "database", "analyze",
                "--format=sarifv2.1.0", "--output=" + report,
                "--threads=2", "--ram=8192", "--max-paths=4",
                "--no-sarif-add-file-contents", "--no-sarif-add-snippets",
                "--sarif-include-query-help=never", "--no-download", "--quiet",
                database.toString(), querySuite.toString());
        return new ExecutionSpec(ID, command, output,
                isolatedEnvironment(output.resolve("analysis-environment"), installation.executable()),
                descriptor().defaultTimeout(), descriptor().resources(),
                Set.of(new ExpectedArtifact(REPORT_FILE, true, MAX_REPORT_BYTES)), RedactionPolicy.NONE);
    }

    Path databaseDirectory(ScanContext context) throws IOException {
        Path database = context.engineTemporaryDirectory().toAbsolutePath().normalize();
        if (!DATABASE_DIRECTORY.equals(database.getFileName().toString())
                || database.getParent() == null
                || database.equals(context.project().workspaceRoot())
                || database.startsWith(context.project().workspaceRoot())) {
            throw new IOException("unsafe CodeQL database path");
        }
        return database;
    }

    Path reportPath(ScanContext context) {
        return context.engineOutputDirectory().resolve(REPORT_FILE).toAbsolutePath().normalize();
    }

    @Override
    public ArtifactValidation validate(RawArtifactSet artifacts) throws IOException {
        List<String> errors = new ArrayList<>();
        if (!ID.equals(artifacts.engine())) {
            errors.add("ENGINE_MISMATCH");
        }
        if (artifacts.execution().status() != ExecutionResult.Status.SUCCEEDED) {
            errors.add("EXECUTION_" + artifacts.execution().status());
        }
        Path report = artifacts.artifacts().get("report");
        if (report == null || !Files.isRegularFile(report)) {
            errors.add("REPORT_MISSING");
        } else if (Files.size(report) > MAX_REPORT_BYTES) {
            errors.add("REPORT_TOO_LARGE");
        } else {
            try {
                JsonNode root = json.readTree(report.toFile());
                if (!validSarifRoot(root)) {
                    errors.add("REPORT_SCHEMA_INVALID");
                }
            } catch (IOException exception) {
                errors.add("REPORT_JSON_INVALID");
            }
        }
        return new ArtifactValidation(errors.isEmpty(), errors);
    }

    @Override
    public NormalizationResult normalize(ScanContext context, RawArtifactSet artifacts) throws IOException {
        ArtifactValidation validation = validate(artifacts);
        if (!validation.valid()) {
            throw new IOException("CodeQL artifacts are invalid: " + validation.errors());
        }
        JsonNode root = json.readTree(artifacts.artifacts().get("report").toFile());
        List<Finding> findings = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        int rawHitCount = 0;
        for (int runIndex = 0; runIndex < root.path("runs").size(); runIndex++) {
            JsonNode run = root.path("runs").get(runIndex);
            Map<String, JsonNode> rules = rules(run);
            collectRunWarnings(run, runIndex, warnings);
            for (int resultIndex = 0; resultIndex < run.path("results").size(); resultIndex++) {
                JsonNode result = run.path("results").get(resultIndex);
                rawHitCount++;
                try {
                    String ruleId = requiredText(result, "ruleId");
                    findings.add(toFinding(context.project(), result, rules.get(ruleId), runIndex, resultIndex, warnings));
                } catch (IOException | IllegalArgumentException exception) {
                    warnings.add("CODEQL_RESULT_" + runIndex + "_" + resultIndex + ": " + exception.getMessage());
                }
            }
        }
        int modules = context.project().manifest().modules().size();
        EngineStatus status = warnings.isEmpty() ? EngineStatus.SUCCEEDED : EngineStatus.PARTIAL;
        EngineCoverage coverage = new EngineCoverage(ID.value(), status, modules, modules, modules,
                rawHitCount, artifacts.execution().duration(), warnings.isEmpty() ? "" : "CODEQL_PARTIAL_OUTPUT",
                REPORT_ARTIFACT);
        return new NormalizationResult(findings, coverage, warnings);
    }

    private Finding toFinding(ProjectContext project, JsonNode result, JsonNode rule, int runIndex,
            int resultIndex, List<String> warnings) throws IOException {
        String ruleId = requiredText(result, "ruleId");
        JsonNode primary = result.path("locations").path(0).path("physicalLocation");
        SourceLocation location = sourceLocation(project, primary);
        Path relative = Path.of(location.path());
        CodeSnippet snippet = AdapterSupport.snippet(project, relative, location.startLine(), location.endLine());
        String message = message(result.path("message"), ruleId);
        String title = message(rule == null ? null : rule.path("shortDescription"), ruleId);
        List<String> tags = tags(rule);
        List<String> cwes = cwes(tags);
        String ruleFamily = ruleFamily(ruleId, cwes);
        IssueCategory category = category(ruleId, tags, cwes);
        Confidence confidence = confidence(rule);
        String engineSeverity = engineSeverity(result, rule);
        SeverityMappingResult severity = severities.map(new SeverityMappingRequest(
                ID.value(), ruleFamily, category, engineSeverity, null, false, false, confidence));
        List<DataFlow> dataFlows = dataFlows(project, result, runIndex, resultIndex, warnings);
        String semanticAnchor = logicalAnchor(result);
        String sink = dataFlows.isEmpty() ? "" : lastLabel(dataFlows.get(0));
        FindingFingerprintService.Fingerprint fingerprint = fingerprints.source(
                ruleFamily, location.path(), semanticAnchor, sink, message, snippet == null ? "" : snippet.text());

        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("querySuite", QUERY_SUITE_NAME);
        properties.put("queryPack", "codeql/java-queries@" + JAVA_QUERY_PACK_VERSION);
        properties.put("tags", tags);
        properties.put("precision", ruleProperty(rule, "precision"));
        properties.put("securitySeverity", ruleProperty(rule, "security-severity"));
        properties.put("codeFlowCount", dataFlows.size());
        properties.put("dataFlowRoles", "SARIF thread-flow order: first=SOURCE, middle=PROPAGATION, last=SINK");
        properties.put("severityMappingId", severity.mappingId());
        properties.put("severityMappingReason", severity.reason());
        FindingEvidence evidence = new FindingEvidence(ID.value(), CLI_VERSION, ruleId, engineSeverity,
                REPORT_ARTIFACT, ruleId + ":" + runIndex + ":" + resultIndex, properties);
        return new Finding(fingerprint.findingId(), fingerprint.value(), fingerprint.version(), category,
                severity.severity(), confidence, ruleFamily, "CodeQL：" + title, title,
                message(rule == null ? null : rule.path("fullDescription"), "CodeQL 查询识别到潜在缺陷。"),
                message, impact(category), remediation(category), AdapterSupport.moduleFor(project, relative),
                location, snippet, new VulnerabilityIdentifiers(cwes, List.of(), List.of(), List.of()), null,
                dataFlows, List.of(evidence), null, ReviewState.UNREVIEWED);
    }

    private List<DataFlow> dataFlows(ProjectContext project, JsonNode result, int runIndex, int resultIndex,
            List<String> warnings) {
        List<DataFlow> flows = new ArrayList<>();
        int flowIndex = 0;
        for (JsonNode codeFlow : result.path("codeFlows")) {
            for (JsonNode threadFlow : codeFlow.path("threadFlows")) {
                try {
                    List<JsonNode> locations = new ArrayList<>();
                    threadFlow.path("locations").forEach(locations::add);
                    if (locations.size() < 2) {
                        warnings.add("CODEQL_FLOW_" + runIndex + "_" + resultIndex + "_" + flowIndex
                                + ": fewer than two SARIF thread-flow locations; flow omitted");
                        flowIndex++;
                        continue;
                    }
                    List<DataFlowNode> nodes = new ArrayList<>();
                    for (int index = 0; index < locations.size(); index++) {
                        JsonNode threadLocation = locations.get(index);
                        JsonNode sarifLocation = threadLocation.path("location");
                        SourceLocation location = sourceLocation(project, sarifLocation.path("physicalLocation"));
                        DataFlowNode.Kind kind = flowKind(threadLocation, index, locations.size());
                        nodes.add(new DataFlowNode(index, kind, location,
                                message(sarifLocation.path("message"), kind.name())));
                    }
                    flows.add(new DataFlow(ID.value(), nodes));
                } catch (IOException | IllegalArgumentException exception) {
                    warnings.add("CODEQL_FLOW_" + runIndex + "_" + resultIndex + "_" + flowIndex
                            + ": " + exception.getMessage() + "; flow omitted");
                }
                flowIndex++;
            }
        }
        return List.copyOf(flows);
    }

    private DataFlowNode.Kind flowKind(JsonNode threadLocation, int index, int count) {
        for (JsonNode kind : threadLocation.path("kinds")) {
            String value = kind.asText().toLowerCase(Locale.ROOT);
            if (value.contains("source")) return DataFlowNode.Kind.SOURCE;
            if (value.contains("sink")) return DataFlowNode.Kind.SINK;
        }
        if (index == 0) return DataFlowNode.Kind.SOURCE;
        if (index == count - 1) return DataFlowNode.Kind.SINK;
        return DataFlowNode.Kind.PROPAGATION;
    }

    private SourceLocation sourceLocation(ProjectContext project, JsonNode physical) throws IOException {
        String rawUri = requiredText(physical.path("artifactLocation"), "uri");
        Path relative = normalizeSarifPath(project, rawUri);
        JsonNode region = physical.path("region");
        int startLine = positive(region.path("startLine").asInt(), "startLine");
        int startColumn = Math.max(0, region.path("startColumn").asInt(0));
        int endLine = Math.max(startLine, region.path("endLine").asInt(startLine));
        int endColumn = Math.max(0, region.path("endColumn").asInt(0));
        return new SourceLocation(AdapterSupport.portable(relative), startLine, startColumn, endLine, endColumn);
    }

    private Path normalizeSarifPath(ProjectContext project, String rawUri) throws IOException {
        try {
            URI uri = URI.create(rawUri);
            Path path;
            if (uri.isAbsolute()) {
                if (!"file".equalsIgnoreCase(uri.getScheme())) {
                    throw new IOException("unsupported SARIF location scheme: " + uri.getScheme());
                }
                path = Path.of(uri);
            } else {
                String decoded = uri.getPath();
                if (decoded == null || decoded.isBlank()) throw new IOException("empty SARIF location URI");
                path = Path.of(decoded);
            }
            Path absolute = path.isAbsolute() ? path.normalize() : project.workspaceRoot().resolve(path).normalize();
            if (!absolute.startsWith(project.workspaceRoot()) || !Files.isRegularFile(absolute)) {
                throw new IOException("SARIF location is outside or absent from project: " + rawUri);
            }
            Path realRoot = project.workspaceRoot().toRealPath();
            if (!absolute.toRealPath().startsWith(realRoot)) {
                throw new IOException("SARIF location resolves outside project through a symbolic link: " + rawUri);
            }
            return project.workspaceRoot().relativize(absolute);
        } catch (IllegalArgumentException exception) {
            throw new IOException("invalid SARIF location URI: " + rawUri, exception);
        }
    }

    private Map<String, JsonNode> rules(JsonNode run) {
        Map<String, JsonNode> result = new LinkedHashMap<>();
        collectRules(run.path("tool").path("driver").path("rules"), result);
        for (JsonNode extension : run.path("tool").path("extensions")) {
            collectRules(extension.path("rules"), result);
        }
        return result;
    }

    private void collectRules(JsonNode rules, Map<String, JsonNode> result) {
        for (JsonNode rule : rules) {
            String id = rule.path("id").asText();
            if (!id.isBlank()) result.putIfAbsent(id, rule);
        }
    }

    private void collectRunWarnings(JsonNode run, int runIndex, List<String> warnings) {
        int invocationIndex = 0;
        for (JsonNode invocation : run.path("invocations")) {
            if (invocation.has("executionSuccessful") && !invocation.path("executionSuccessful").asBoolean()) {
                warnings.add("CODEQL_INVOCATION_" + runIndex + "_" + invocationIndex + "_INCOMPLETE");
            }
            collectNotifications(invocation.path("toolExecutionNotifications"), runIndex, invocationIndex, warnings);
            invocationIndex++;
        }
    }

    private void collectNotifications(JsonNode notifications, int runIndex, int invocationIndex,
            List<String> warnings) {
        int index = 0;
        for (JsonNode notification : notifications) {
            if ("error".equalsIgnoreCase(notification.path("level").asText())) {
                warnings.add("CODEQL_NOTIFICATION_" + runIndex + "_" + invocationIndex + "_" + index
                        + ": " + message(notification.path("message"), "tool execution error"));
            }
            index++;
        }
    }

    private boolean validSarifRoot(JsonNode root) {
        if (root == null || !"2.1.0".equals(root.path("version").asText()) || !root.path("runs").isArray()
                || root.path("runs").isEmpty()) {
            return false;
        }
        for (JsonNode run : root.path("runs")) {
            if (!run.path("results").isArray() || run.path("tool").path("driver").path("name").asText().isBlank()) {
                return false;
            }
        }
        return true;
    }

    private String queryPackVersion() throws IOException {
        Path current = querySuite.getParent();
        for (int level = 0; level < 4 && current != null; level++, current = current.getParent()) {
            Path manifest = current.resolve("qlpack.yml");
            if (!Files.isRegularFile(manifest)) continue;
            String name = "";
            String version = "";
            for (String line : Files.readAllLines(manifest)) {
                String trimmed = line.trim();
                if (trimmed.startsWith("name:")) name = trimmed.substring(5).trim();
                if (trimmed.startsWith("version:")) version = trimmed.substring(8).trim();
            }
            if (!"codeql/java-queries".equals(name)) {
                throw new IOException("unexpected CodeQL query pack: " + name);
            }
            return version;
        }
        throw new IOException("qlpack.yml was not found above query suite");
    }

    private Map<String, String> isolatedEnvironment(Path root, Path codeqlExecutable) throws IOException {
        Path home = Files.createDirectories(root.resolve("home"));
        Path temporary = Files.createDirectories(root.resolve("tmp"));
        String path = String.join(File.pathSeparator,
                codeqlExecutable.getParent().toString(),
                mavenExecutable.getParent().toString(),
                javaHome.resolve("bin").toString(),
                "/usr/local/bin", "/usr/bin", "/bin");
        return Map.of(
                "PATH", path,
                "JAVA_HOME", javaHome.toString(),
                "HOME", home.toString(),
                "TMPDIR", temporary.toString(),
                "LANG", "C.UTF-8");
    }

    private static Path resolveMavenExecutable() {
        String configured = System.getProperty("audit.maven.executable", "").trim();
        if (!configured.isBlank()) return Path.of(configured);
        String path = System.getenv().getOrDefault("PATH", "");
        for (String directory : path.split(Pattern.quote(File.pathSeparator))) {
            if (directory.isBlank()) continue;
            Path candidate = Path.of(directory).resolve("mvn");
            if (Files.isExecutable(candidate)) return candidate;
        }
        return Path.of("/usr/bin/mvn");
    }

    private void requireApplicable(ScanContext context, ToolContext tools) throws IOException {
        Applicability applicability = checkApplicability(context.project(), tools);
        if (applicability.status() != Applicability.Status.APPLICABLE) {
            throw new IOException(applicability.reasonCode() + ": " + applicability.detail());
        }
    }

    private String engineSeverity(JsonNode result, JsonNode rule) {
        String level = result.path("level").asText();
        if (!level.isBlank()) return level;
        level = rule == null ? "" : rule.path("defaultConfiguration").path("level").asText();
        if (!level.isBlank()) return level;
        String problemSeverity = ruleProperty(rule, "problem.severity");
        if (!problemSeverity.isBlank()) return problemSeverity;
        String securitySeverity = ruleProperty(rule, "security-severity");
        try {
            double score = Double.parseDouble(securitySeverity);
            if (score >= 7) return "HIGH";
            if (score >= 4) return "MEDIUM";
            return "LOW";
        } catch (NumberFormatException ignored) {
            return "UNKNOWN";
        }
    }

    private Confidence confidence(JsonNode rule) {
        return switch (ruleProperty(rule, "precision").toLowerCase(Locale.ROOT)) {
            case "very-high", "high" -> Confidence.HIGH;
            case "low" -> Confidence.LOW;
            default -> Confidence.MEDIUM;
        };
    }

    private IssueCategory category(String ruleId, List<String> tags, List<String> cwes) {
        String value = ruleId.toLowerCase(Locale.ROOT);
        if (tags.stream().anyMatch(tag -> tag.equalsIgnoreCase("security"))
                || value.matches(".*(injection|xss|ssrf|deserial|redirect|request-forgery|crypto|password|cleartext).*")) {
            return IssueCategory.WEB_SECURITY;
        }
        if (value.matches(".*(thread|synchron|lock|race|double-checked).*")) return IssueCategory.CONCURRENCY;
        if (value.matches(".*(resource-leak|stream|performance|inefficient).*")) return IssueCategory.RESOURCE_PERFORMANCE;
        if (value.matches(".*(unused|complex|maintain|deprecated|javadoc|naming).*")) return IssueCategory.MAINTAINABILITY;
        return IssueCategory.CORRECTNESS;
    }

    private String ruleFamily(String ruleId, List<String> cwes) {
        String value = ruleId.toLowerCase(Locale.ROOT);
        if (value.contains("sql-injection") || cwes.contains("CWE-89")) return "SQL_INJECTION";
        if (value.contains("command-line-injection") || value.contains("command-injection") || cwes.contains("CWE-78")) {
            return "COMMAND_INJECTION";
        }
        if (value.contains("path-injection") || value.contains("path-traversal") || cwes.contains("CWE-22")) {
            return "PATH_TRAVERSAL";
        }
        if (value.contains("xss") || value.contains("cross-site-scripting") || cwes.contains("CWE-79")) {
            return "CROSS_SITE_SCRIPTING";
        }
        if (value.contains("ssrf") || value.contains("server-side-request-forgery") || cwes.contains("CWE-918")) {
            return "SSRF";
        }
        if (value.contains("deserial")) return "UNSAFE_DESERIALIZATION";
        if (value.contains("null")) return "NULL_DEREFERENCE";
        if (value.contains("resource-leak")) return "RESOURCE_LEAK";
        String suffix = value.contains("/") ? value.substring(value.lastIndexOf('/') + 1) : value;
        return suffix.replaceAll("[^a-z0-9]+", "_").toUpperCase(Locale.ROOT);
    }

    private List<String> tags(JsonNode rule) {
        if (rule == null) return List.of();
        List<String> result = new ArrayList<>();
        rule.path("properties").path("tags").forEach(tag -> result.add(tag.asText()));
        return List.copyOf(result);
    }

    private List<String> cwes(List<String> tags) {
        Set<String> result = new LinkedHashSet<>();
        for (String tag : tags) {
            Matcher matcher = CWE_TAG.matcher(tag);
            if (matcher.matches()) result.add("CWE-" + Integer.parseInt(matcher.group(1)));
        }
        return List.copyOf(result);
    }

    private String ruleProperty(JsonNode rule, String key) {
        return rule == null ? "" : rule.path("properties").path(key).asText("");
    }

    private String logicalAnchor(JsonNode result) {
        JsonNode logical = result.path("locations").path(0).path("logicalLocations").path(0);
        String anchor = logical.path("fullyQualifiedName").asText();
        return anchor.isBlank() ? logical.path("name").asText() : anchor;
    }

    private String lastLabel(DataFlow flow) {
        return flow.nodes().isEmpty() ? "" : flow.nodes().get(flow.nodes().size() - 1).label();
    }

    private String impact(IssueCategory category) {
        return category == IssueCategory.WEB_SECURITY
                ? "攻击者可能利用不可信输入影响命令、查询、路径或响应内容。"
                : "缺陷可能影响程序正确性、稳定性、并发安全或资源使用。";
    }

    private String remediation(IssueCategory category) {
        return category == IssueCategory.WEB_SECURITY
                ? "确认 Source 到 Sink 的完整路径，使用安全 API、参数化和边界校验，并增加安全回归测试。"
                : "结合 CodeQL 路径和调用上下文修复缺陷，并增加覆盖相关分支的回归测试。";
    }

    private String message(JsonNode node, String fallback) {
        if (node == null) return fallback;
        String text = node.path("text").asText();
        if (!text.isBlank()) return text;
        String markdown = node.path("markdown").asText();
        return markdown.isBlank() ? fallback : markdown;
    }

    private String requiredText(JsonNode node, String field) throws IOException {
        String value = node.path(field).asText();
        if (value.isBlank()) throw new IOException("missing SARIF field " + field);
        return value;
    }

    private int positive(int value, String field) throws IOException {
        if (value < 1) throw new IOException("invalid SARIF " + field);
        return value;
    }
}
