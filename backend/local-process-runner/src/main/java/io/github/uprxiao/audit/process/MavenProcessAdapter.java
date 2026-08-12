package io.github.uprxiao.audit.process;

import io.github.uprxiao.audit.scanner.CancellationToken;
import io.github.uprxiao.audit.scanner.EngineId;
import io.github.uprxiao.audit.scanner.ExecutionBackend;
import io.github.uprxiao.audit.scanner.ExecutionResult;
import io.github.uprxiao.audit.scanner.ExecutionSpec;
import io.github.uprxiao.audit.scanner.RedactionPolicy;
import io.github.uprxiao.audit.scanner.ResourceClass;
import io.github.uprxiao.audit.scanner.ResourceRequest;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

public final class MavenProcessAdapter {

    public static final EngineId ID = new EngineId("maven");

    private static final Pattern SAFE_NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}");
    private static final Pattern SAFE_VALUE = Pattern.compile("[A-Za-z0-9._:/@+\\-]{0,512}");
    private static final Set<String> FORBIDDEN_PROPERTIES = Set.of(
            "maven.repo.local", "maven.multimoduleprojectdirectory", "maven.home",
            "java.home", "user.dir", "settings", "file", "f");
    private static final String CLASSPATH_GOAL =
            "org.apache.maven.plugins:maven-dependency-plugin:3.9.0:build-classpath";
    public static final String CLASSPATH_FILE = "audit-runtime-classpath.txt";

    private final ExecutionBackend backend;
    private final MavenProcessConfiguration configuration;
    private final MavenBuildOutputParser outputParser = new MavenBuildOutputParser();

    public MavenProcessAdapter(ExecutionBackend backend, MavenProcessConfiguration configuration) {
        this.backend = Objects.requireNonNull(backend, "backend");
        this.configuration = Objects.requireNonNull(configuration, "configuration");
    }

    public ExecutionSpec prepare(MavenBuildRequest request) throws IOException {
        Objects.requireNonNull(request, "request");
        Files.createDirectories(request.engineOutputDirectory());
        Files.createDirectories(configuration.localRepository());
        Files.createDirectories(request.engineOutputDirectory().resolve("home"));

        List<String> command = new ArrayList<>();
        Set<Integer> sensitiveArguments = new HashSet<>();
        command.add(configuration.executable());
        command.add("--batch-mode");
        command.add("--no-transfer-progress");
        command.add("--file");
        command.add(request.projectRoot().resolve("pom.xml").toString());
        command.add("-DskipTests");
        command.add("-Dmaven.repo.local=" + configuration.localRepository());
        if (configuration.settingsFile() != null) {
            command.add("--settings");
            command.add(configuration.settingsFile().toString());
        }
        if (!request.profiles().isEmpty()) {
            request.profiles().forEach(MavenProcessAdapter::validateName);
            command.add("-P" + String.join(",", request.profiles()));
        }
        for (Map.Entry<String, String> property : request.properties().entrySet()) {
            validateProperty(property.getKey(), property.getValue());
            int argumentIndex = command.size();
            command.add("-D" + property.getKey() + "=" + property.getValue());
            if (isSensitive(property.getKey())) {
                sensitiveArguments.add(argumentIndex);
            }
        }
        command.add("package");

        Map<String, String> environment = Map.of(
                "PATH", configuration.pathEnvironment(),
                "JAVA_HOME", configuration.javaHome().toString(),
                "HOME", request.engineOutputDirectory().resolve("home").toString(),
                "MAVEN_OPTS", "-Xmx" + configuration.maxHeapMb() + "m -Djava.awt.headless=true");
        return new ExecutionSpec(
                ID,
                command,
                request.engineOutputDirectory(),
                environment,
                request.timeout(),
                new ResourceRequest(ResourceClass.HEAVY, 4, configuration.maxHeapMb()),
                Set.of(),
                new RedactionPolicy(sensitiveArguments, Set.of()));
    }

    public MavenBuildResult execute(MavenBuildRequest request, CancellationToken cancellationToken)
            throws IOException, InterruptedException {
        ExecutionResult execution = backend.execute(prepare(request), cancellationToken);
        MavenBuildResult.Status status = switch (execution.status()) {
            case SUCCEEDED -> MavenBuildResult.Status.SUCCEEDED;
            case FAILED -> MavenBuildResult.Status.FAILED;
            case TIMED_OUT -> MavenBuildResult.Status.TIMED_OUT;
            case CANCELLED -> MavenBuildResult.Status.CANCELLED;
        };
        return new MavenBuildResult(status, execution, outputParser.parse(execution.stdout()));
    }

    /** Resolves each reactor module's dependency classpath without accepting a user goal. */
    public ExecutionResult resolveClasspath(MavenBuildRequest request, CancellationToken cancellationToken)
            throws IOException, InterruptedException {
        Objects.requireNonNull(request, "request");
        Path output = Files.createDirectories(request.engineOutputDirectory().resolve("classpath"));
        Files.createDirectories(configuration.localRepository());
        Path home = Files.createDirectories(request.engineOutputDirectory().resolve("home"));
        List<String> command = new ArrayList<>();
        Set<Integer> sensitiveArguments = new HashSet<>();
        command.add(configuration.executable());
        command.add("--batch-mode");
        command.add("--no-transfer-progress");
        command.add("--file");
        command.add(request.projectRoot().resolve("pom.xml").toString());
        command.add("-DskipTests");
        command.add("-Dmaven.repo.local=" + configuration.localRepository());
        if (configuration.settingsFile() != null) {
            command.add("--settings");
            command.add(configuration.settingsFile().toString());
        }
        if (!request.profiles().isEmpty()) {
            request.profiles().forEach(MavenProcessAdapter::validateName);
            command.add("-P" + String.join(",", request.profiles()));
        }
        for (Map.Entry<String, String> property : request.properties().entrySet()) {
            validateProperty(property.getKey(), property.getValue());
            int argumentIndex = command.size();
            command.add("-D" + property.getKey() + "=" + property.getValue());
            if (isSensitive(property.getKey())) sensitiveArguments.add(argumentIndex);
        }
        command.add(CLASSPATH_GOAL);
        command.add("-Dmdep.outputFile=target/" + CLASSPATH_FILE);
        Map<String, String> environment = Map.of(
                "PATH", configuration.pathEnvironment(),
                "JAVA_HOME", configuration.javaHome().toString(),
                "HOME", home.toString(),
                "MAVEN_OPTS", "-Xmx" + configuration.maxHeapMb() + "m -Djava.awt.headless=true");
        return backend.execute(new ExecutionSpec(
                ID, command, output, environment, request.timeout(),
                new ResourceRequest(ResourceClass.HEAVY, 4, configuration.maxHeapMb()), Set.of(),
                new RedactionPolicy(sensitiveArguments, Set.of())), cancellationToken);
    }

    private static void validateName(String name) {
        if (name == null || !SAFE_NAME.matcher(name).matches()) {
            throw new IllegalArgumentException("unsafe Maven profile or property name: " + name);
        }
    }

    private static void validateProperty(String key, String value) {
        validateName(key);
        if (FORBIDDEN_PROPERTIES.contains(key.toLowerCase(Locale.ROOT))) {
            throw new IllegalArgumentException("Maven property is controlled by the server: " + key);
        }
        if (value == null || !SAFE_VALUE.matcher(value).matches()) {
            throw new IllegalArgumentException("unsafe Maven property value for " + key);
        }
    }

    private static boolean isSensitive(String key) {
        String lower = key.toLowerCase(Locale.ROOT);
        return lower.contains("password") || lower.contains("passwd") || lower.contains("token")
                || lower.contains("secret") || lower.contains("credential") || lower.endsWith("key");
    }
}
