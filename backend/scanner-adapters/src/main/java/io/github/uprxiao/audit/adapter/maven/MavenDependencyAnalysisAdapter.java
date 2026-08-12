package io.github.uprxiao.audit.adapter.maven;

import io.github.uprxiao.audit.finding.EngineCoverage;
import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.finding.Finding;
import io.github.uprxiao.audit.intake.ProjectContext;
import io.github.uprxiao.audit.scanner.Applicability;
import io.github.uprxiao.audit.scanner.ArtifactValidation;
import io.github.uprxiao.audit.scanner.EngineDescriptor;
import io.github.uprxiao.audit.scanner.EngineId;
import io.github.uprxiao.audit.scanner.ExecutionResult;
import io.github.uprxiao.audit.scanner.ExecutionSpec;
import io.github.uprxiao.audit.scanner.NormalizationResult;
import io.github.uprxiao.audit.scanner.RawArtifactSet;
import io.github.uprxiao.audit.scanner.ResourceClass;
import io.github.uprxiao.audit.scanner.ResourceRequest;
import io.github.uprxiao.audit.scanner.ScanContext;
import io.github.uprxiao.audit.scanner.ScannerAdapter;
import io.github.uprxiao.audit.scanner.ToolContext;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class MavenDependencyAnalysisAdapter implements ScannerAdapter {

    public static final EngineId ID = new EngineId("maven-dependency-analysis");
    public static final String TOOL_VERSION = "3.9.0";
    private static final String GOAL = "org.apache.maven.plugins:maven-dependency-plugin:3.9.0:analyze";
    private static final Pattern MODULE = Pattern.compile("--- dependency:3\\.9\\.0:analyze .* @ ([^ ]+) ---");
    private static final Pattern COORDINATE = Pattern.compile("^\\[WARNING]\\s+([A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+(?::[A-Za-z0-9_.-]+){1,3})\\s*$");

    private final Path localRepository;

    public MavenDependencyAnalysisAdapter(Path localRepository) {
        this.localRepository = Objects.requireNonNull(localRepository).toAbsolutePath().normalize();
    }

    @Override
    public EngineDescriptor descriptor() {
        return new EngineDescriptor(ID, "Maven Dependency Analysis", true,
                new ResourceRequest(ResourceClass.MEDIUM, 2, 2048), Duration.ofMinutes(20), Set.of());
    }

    @Override
    public Applicability checkApplicability(ProjectContext project, ToolContext tools) {
        ToolContext.ToolInstallation installation = tools.installations().get(ID);
        if (installation == null || !installation.available()) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "MAVEN_UNAVAILABLE", "System Maven is unavailable");
        }
        if (!TOOL_VERSION.equals(installation.version())) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "PLUGIN_VERSION_MISMATCH", installation.version());
        }
        if (!Files.isRegularFile(project.workspaceRoot().resolve(project.manifest().rootPom()))) {
            return new Applicability(Applicability.Status.NOT_APPLICABLE, "ROOT_POM_MISSING", project.manifest().rootPom());
        }
        return Applicability.applicable();
    }

    @Override
    public ExecutionSpec prepare(ScanContext context, ToolContext tools) throws IOException {
        return MavenAuditSupport.execution(ID, descriptor(), context, tools, localRepository, List.of(
                GOAL, "-DignoreNonCompile=true", "-DfailOnWarning=false", "-Dverbose=true"));
    }

    @Override
    public ArtifactValidation validate(RawArtifactSet artifacts) throws IOException {
        List<String> errors = new ArrayList<>();
        if (!ID.equals(artifacts.engine())) errors.add("ENGINE_MISMATCH");
        if (artifacts.execution().status() != ExecutionResult.Status.SUCCEEDED) {
            errors.add("EXECUTION_" + artifacts.execution().status());
        }
        Path report = artifacts.artifacts().get("report");
        if (report == null || !Files.isRegularFile(report)) {
            errors.add("REPORT_MISSING");
        } else if (Files.size(report) > MavenAuditSupport.MAX_LOG_BYTES) {
            errors.add("REPORT_TOO_LARGE");
        } else {
            String log = MavenAuditSupport.readLog(report);
            if (!log.contains("dependency:3.9.0:analyze") || !log.contains("BUILD SUCCESS")) {
                errors.add("REPORT_SCHEMA_INVALID");
            }
        }
        return new ArtifactValidation(errors.isEmpty(), errors);
    }

    @Override
    public NormalizationResult normalize(ScanContext context, RawArtifactSet artifacts) throws IOException {
        ArtifactValidation validation = validate(artifacts);
        if (!validation.valid()) throw new IOException("Maven dependency artifacts are invalid: " + validation.errors());
        String log = MavenAuditSupport.readLog(artifacts.artifacts().get("report"));
        List<Finding> findings = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        String module = context.project().manifest().modules().get(0).artifactId();
        Section section = Section.NONE;
        int index = 0;
        for (String line : log.lines().toList()) {
            Matcher moduleMatcher = MODULE.matcher(line);
            if (moduleMatcher.find()) module = moduleMatcher.group(1);
            if (line.contains("Used undeclared dependencies found:")) {
                section = Section.USED_UNDECLARED;
                continue;
            }
            if (line.contains("Unused declared dependencies found:")) {
                section = Section.UNUSED_DECLARED;
                continue;
            }
            Matcher coordinate = COORDINATE.matcher(line);
            if (section != Section.NONE && coordinate.matches()) {
                String value = coordinate.group(1);
                String family = section == Section.USED_UNDECLARED
                        ? "USED_UNDECLARED_DEPENDENCY" : "UNUSED_DECLARED_DEPENDENCY";
                String message = (section == Section.USED_UNDECLARED
                        ? "使用了未在 POM 中直接声明的依赖：" : "POM 声明了未被字节码分析识别为使用的依赖：") + value;
                findings.add(MavenAuditSupport.finding(context.project(), ID, TOOL_VERSION, family,
                        section == Section.USED_UNDECLARED ? "使用了未声明的 Maven 依赖" : "存在可能未使用的 Maven 依赖",
                        message, module, value, family + ":" + index++, "LOW",
                        Map.of("coordinate", value, "module", module, "analysisKind", section.name())));
            } else if (section != Section.NONE && line.startsWith("[INFO]")) {
                section = Section.NONE;
            }
            if (line.contains("Could not analyze") || line.contains("could not be analyzed")
                    || line.contains("AUDIT_PARTIAL")) {
                warnings.add("MAVEN_DEPENDENCY_PARTIAL: " + line);
            }
        }
        int modules = context.project().manifest().modules().size();
        EngineStatus status = warnings.isEmpty() ? EngineStatus.SUCCEEDED : EngineStatus.PARTIAL;
        return new NormalizationResult(findings,
                new EngineCoverage(ID.value(), status, modules, modules, modules, findings.size(),
                        artifacts.execution().duration(), warnings.isEmpty() ? "" : "MAVEN_DEPENDENCY_PARTIAL",
                        "raw/maven-dependency-analysis/stdout.log"), warnings);
    }

    private enum Section {
        NONE,
        USED_UNDECLARED,
        UNUSED_DECLARED
    }
}
