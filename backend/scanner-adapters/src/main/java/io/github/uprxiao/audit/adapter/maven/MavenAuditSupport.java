package io.github.uprxiao.audit.adapter.maven;

import io.github.uprxiao.audit.adapter.support.AdapterSupport;
import io.github.uprxiao.audit.finding.Confidence;
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
import io.github.uprxiao.audit.intake.MavenModule;
import io.github.uprxiao.audit.intake.MavenArgumentValidator;
import io.github.uprxiao.audit.intake.ProjectContext;
import io.github.uprxiao.audit.scanner.EngineDescriptor;
import io.github.uprxiao.audit.scanner.EngineId;
import io.github.uprxiao.audit.scanner.ExecutionSpec;
import io.github.uprxiao.audit.scanner.ExpectedArtifact;
import io.github.uprxiao.audit.scanner.RedactionPolicy;
import io.github.uprxiao.audit.scanner.ScanContext;
import io.github.uprxiao.audit.scanner.ToolContext;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.TreeMap;

final class MavenAuditSupport {

    static final long MAX_LOG_BYTES = 32L * 1024 * 1024;
    private static final FindingFingerprintService FINGERPRINTS = new FindingFingerprintService();
    private static final SeverityMappingService SEVERITIES = new SeverityMappingService();
    private static final MavenArgumentValidator MAVEN_ARGUMENTS = new MavenArgumentValidator();

    private MavenAuditSupport() {
    }

    static ExecutionSpec execution(
            EngineId engine,
            EngineDescriptor descriptor,
            ScanContext context,
            ToolContext tools,
            Path localRepository,
            List<String> fixedArguments) throws IOException {
        ToolContext.ToolInstallation installation = AdapterSupport.requireInstallation(tools, engine);
        Path rootPom = context.project().resolveProjectPath(context.project().manifest().rootPom());
        if (!Files.isRegularFile(rootPom)) throw new IOException("root pom is unavailable: " + rootPom);
        Files.createDirectories(context.engineOutputDirectory());
        Files.createDirectories(localRepository);
        Path home = Files.createDirectories(context.engineOutputDirectory().resolve("home"));
        Path temp = Files.createDirectories(context.engineOutputDirectory().resolve("tmp"));

        List<String> command = new ArrayList<>();
        command.add(installation.executable().toString());
        command.add("--batch-mode");
        command.add("--no-transfer-progress");
        command.add("--errors");
        command.add("--file");
        command.add(rootPom.toString());
        command.add("-Dmaven.repo.local=" + localRepository);
        command.add("-Dstyle.color=never");
        command.add("-DskipTests");
        MAVEN_ARGUMENTS.validate(context.mavenProfiles(), context.mavenProperties());
        Set<Integer> sensitiveArguments = new HashSet<>();
        if (!context.mavenProfiles().isEmpty()) {
            command.add("-P" + String.join(",", context.mavenProfiles()));
        }
        for (Map.Entry<String, String> property : new TreeMap<>(context.mavenProperties()).entrySet()) {
            int argumentIndex = command.size();
            command.add("-D" + property.getKey() + "=" + property.getValue());
            if (MAVEN_ARGUMENTS.isSensitiveProperty(property.getKey())) {
                sensitiveArguments.add(argumentIndex);
            }
        }
        command.addAll(fixedArguments);

        String path = installation.executable().getParent() + File.pathSeparator + "/usr/bin" + File.pathSeparator + "/bin";
        Map<String, String> environment = Map.of(
                "PATH", path,
                "JAVA_HOME", Path.of(System.getProperty("java.home")).toString(),
                "HOME", home.toString(),
                "TMPDIR", temp.toString(),
                "MAVEN_OPTS", "-Xmx2048m -Djava.awt.headless=true -Duser.home=" + home);
        return new ExecutionSpec(engine, command, context.engineOutputDirectory(), environment,
                descriptor.defaultTimeout(), descriptor.resources(),
                Set.of(new ExpectedArtifact("stdout.log", true, MAX_LOG_BYTES)),
                new RedactionPolicy(sensitiveArguments, Set.of()));
    }

    static Finding finding(
            ProjectContext project,
            EngineId engine,
            String version,
            String ruleFamily,
            String title,
            String message,
            String module,
            String anchor,
            String evidenceId,
            String engineSeverity,
            Map<String, Object> engineProperties) throws IOException {
        Path pom = pomFor(project, module);
        Path relative = project.workspaceRoot().relativize(pom);
        String family = RuleFamilyCatalog.canonical(ruleFamily);
        var snippet = AdapterSupport.snippet(project, relative, 1, 1);
        FindingFingerprintService.Fingerprint fingerprint = FINGERPRINTS.source(
                family, AdapterSupport.portable(relative), anchor, "", message,
                snippet == null ? "" : snippet.text());
        SeverityMappingResult severity = SEVERITIES.map(new SeverityMappingRequest(
                engine.value(), family, IssueCategory.BUILD_GOVERNANCE, engineSeverity,
                null, false, false, Confidence.MEDIUM));
        Map<String, Object> properties = new LinkedHashMap<>(engineProperties);
        properties.put("severityMappingId", severity.mappingId());
        properties.put("severityMappingReason", severity.reason());
        FindingEvidence evidence = new FindingEvidence(engine.value(), version, family, engineSeverity,
                "raw/" + engine.value() + "/stdout.log", evidenceId, properties);
        return new Finding(fingerprint.findingId(), fingerprint.value(), fingerprint.version(),
                IssueCategory.BUILD_GOVERNANCE, severity.severity(), Confidence.MEDIUM, family,
                title, family, "Maven 构建治理规则识别到依赖声明或收敛问题。", message,
                "依赖声明不准确或版本不收敛会造成构建差异、运行时冲突和维护风险。",
                "确认真实使用关系和依赖路径，在对应模块 POM 中声明、删除或统一版本。",
                module, new SourceLocation(AdapterSupport.portable(relative), 1, 0, 1, 0), snippet,
                VulnerabilityIdentifiers.EMPTY, null, List.of(), List.of(evidence), null, ReviewState.UNREVIEWED);
    }

    static String readLog(Path report) throws IOException {
        if (Files.size(report) > MAX_LOG_BYTES) throw new IOException("Maven log is too large");
        return Files.readString(report).replaceAll("\\u001B\\[[;\\d]*m", "");
    }

    static Path pomFor(ProjectContext project, String artifactId) throws IOException {
        MavenModule module = project.manifest().modules().stream()
                .filter(value -> value.artifactId().equals(artifactId))
                .findFirst()
                .orElse(project.manifest().modules().get(0));
        String relative = ".".equals(module.path()) ? "pom.xml" : module.path() + "/pom.xml";
        return project.resolveProjectPath(relative);
    }
}
