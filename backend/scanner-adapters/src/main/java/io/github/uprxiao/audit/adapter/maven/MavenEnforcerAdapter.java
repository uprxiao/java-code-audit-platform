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

public final class MavenEnforcerAdapter implements ScannerAdapter {

    public static final EngineId ID = new EngineId("maven-enforcer");
    public static final String TOOL_VERSION = "3.6.2";
    private static final String GOAL = "org.apache.maven.plugins:maven-enforcer-plugin:3.6.2:enforce";
    private static final Pattern MODULE = Pattern.compile("--- enforcer:3\\.6\\.2:enforce .* @ ([^ ]+) ---");
    private static final Pattern CONVERGENCE = Pattern.compile("Dependency convergence error for ([^ ]+) paths to dependency are:");
    private static final Pattern RULE_FAILURE = Pattern.compile("Rule \\d+: ([A-Za-z0-9_.$]+) failed with message:");

    private final Path localRepository;

    public MavenEnforcerAdapter(Path localRepository) {
        this.localRepository = Objects.requireNonNull(localRepository).toAbsolutePath().normalize();
    }

    @Override
    public EngineDescriptor descriptor() {
        return new EngineDescriptor(ID, "Maven Enforcer", true,
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
        return MavenAuditSupport.execution(ID, descriptor(), context, tools, localRepository,
                List.of(GOAL, "-Drules=dependencyConvergence", "-Denforcer.fail=true"));
    }

    @Override
    public ArtifactValidation validate(RawArtifactSet artifacts) throws IOException {
        List<String> errors = new ArrayList<>();
        if (!ID.equals(artifacts.engine())) errors.add("ENGINE_MISMATCH");
        Path report = artifacts.artifacts().get("report");
        String log = "";
        if (report == null || !Files.isRegularFile(report)) {
            errors.add("REPORT_MISSING");
        } else if (Files.size(report) > MavenAuditSupport.MAX_LOG_BYTES) {
            errors.add("REPORT_TOO_LARGE");
        } else {
            log = MavenAuditSupport.readLog(report);
            if (!log.contains("enforcer:3.6.2:enforce") || !(log.contains("BUILD SUCCESS") || log.contains("BUILD FAILURE"))) {
                errors.add("REPORT_SCHEMA_INVALID");
            }
        }
        ExecutionResult execution = artifacts.execution();
        boolean policyFailure = execution.status() == ExecutionResult.Status.FAILED
                && Integer.valueOf(1).equals(execution.exitCode()) && recognizedPolicyFailure(log);
        if (execution.status() != ExecutionResult.Status.SUCCEEDED && !policyFailure) {
            errors.add("EXECUTION_" + execution.status());
        }
        return new ArtifactValidation(errors.isEmpty(), errors);
    }

    @Override
    public NormalizationResult normalize(ScanContext context, RawArtifactSet artifacts) throws IOException {
        ArtifactValidation validation = validate(artifacts);
        if (!validation.valid()) throw new IOException("Maven Enforcer artifacts are invalid: " + validation.errors());
        String log = MavenAuditSupport.readLog(artifacts.artifacts().get("report"));
        List<Finding> findings = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        String module = context.project().manifest().modules().get(0).artifactId();
        int index = 0;
        for (String line : log.lines().toList()) {
            Matcher moduleMatcher = MODULE.matcher(line);
            if (moduleMatcher.find()) module = moduleMatcher.group(1);
            Matcher convergence = CONVERGENCE.matcher(line);
            if (convergence.find()) {
                String coordinate = convergence.group(1).replace("'", "");
                findings.add(MavenAuditSupport.finding(context.project(), ID, TOOL_VERSION,
                        "DEPENDENCY_CONVERGENCE", "Maven 依赖版本不收敛",
                        "同一依赖存在不一致的版本路径：" + coordinate, module, coordinate,
                        "DEPENDENCY_CONVERGENCE:" + index++, "WARNING",
                        Map.of("coordinate", coordinate, "module", module, "rule", "dependencyConvergence")));
            }
            if (line.contains("could not be evaluated") || line.contains("AUDIT_PARTIAL")) {
                warnings.add("MAVEN_ENFORCER_PARTIAL: " + line);
            }
        }
        if (findings.isEmpty()) {
            Matcher matcher = RULE_FAILURE.matcher(log);
            while (matcher.find()) {
                String rule = matcher.group(1).substring(matcher.group(1).lastIndexOf('.') + 1);
                findings.add(MavenAuditSupport.finding(context.project(), ID, TOOL_VERSION,
                        rule, "Maven Enforcer 规则未通过", "Maven Enforcer 规则未通过：" + rule,
                        module, rule, rule + ":" + index++, "WARNING", Map.of("rule", rule, "module", module)));
            }
        }
        int modules = context.project().manifest().modules().size();
        EngineStatus status = warnings.isEmpty() ? EngineStatus.SUCCEEDED : EngineStatus.PARTIAL;
        return new NormalizationResult(findings,
                new EngineCoverage(ID.value(), status, modules, modules, modules, findings.size(),
                        artifacts.execution().duration(), warnings.isEmpty() ? "" : "MAVEN_ENFORCER_PARTIAL",
                        "raw/maven-enforcer/stdout.log"), warnings);
    }

    private boolean recognizedPolicyFailure(String log) {
        return CONVERGENCE.matcher(log).find() || RULE_FAILURE.matcher(log).find();
    }
}
