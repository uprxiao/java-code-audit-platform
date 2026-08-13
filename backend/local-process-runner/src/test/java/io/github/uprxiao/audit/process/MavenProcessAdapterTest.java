package io.github.uprxiao.audit.process;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.uprxiao.audit.scanner.CancellationToken;
import io.github.uprxiao.audit.scanner.ExecutionBackend;
import io.github.uprxiao.audit.scanner.ExecutionResult;
import io.github.uprxiao.audit.scanner.ExecutionSpec;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MavenProcessAdapterTest {

    @TempDir
    Path temporaryDirectory;

    private Path project;
    private Path output;
    private MavenProcessConfiguration configuration;

    @BeforeEach
    void setUp() throws Exception {
        project = Files.createDirectory(temporaryDirectory.resolve("project"));
        Files.writeString(project.resolve("pom.xml"), "<project/>");
        output = temporaryDirectory.resolve("raw/maven");
        configuration = new MavenProcessConfiguration(
                "mvn",
                Path.of(System.getProperty("java.home")),
                temporaryDirectory.resolve("repository"),
                null,
                "/usr/local/bin:/usr/bin:/bin",
                1024);
    }

    @Test
    void preparesFixedSystemMavenCommandWithoutShellOrArbitraryGoal() throws Exception {
        MavenProcessAdapter adapter = new MavenProcessAdapter(unusedBackend(), configuration);

        ExecutionSpec specification = adapter.prepare(new MavenBuildRequest(
                project,
                output,
                List.of("opensource"),
                Map.of("revision", "1.0.0", "repositoryPassword", "canary-token"),
                Duration.ofMinutes(10)));

        assertEquals("mvn", specification.command().get(0));
        assertTrue(specification.command().contains("package"));
        assertTrue(specification.command().contains(
                "org.apache.maven.plugins:maven-dependency-plugin:3.9.0:build-classpath"));
        assertTrue(specification.command().contains(
                "-Dmdep.outputFile=target/" + MavenProcessAdapter.CLASSPATH_FILE));
        assertTrue(specification.command().contains("--batch-mode"));
        assertTrue(specification.command().contains("--no-transfer-progress"));
        assertTrue(specification.command().contains("-DskipTests"));
        assertTrue(specification.command().contains("-Popensource"));
        assertTrue(specification.command().contains("--file"));
        assertTrue(specification.command().contains(project.resolve("pom.xml").toString()));
        assertFalse(specification.command().contains("sh"));
        int passwordIndex = specification.command().indexOf("-DrepositoryPassword=canary-token");
        assertTrue(specification.redactionPolicy().sensitiveArgumentIndexes().contains(passwordIndex));
        assertEquals(output.toAbsolutePath(), specification.workingDirectory());
        assertEquals(configuration.javaHome().toString(), specification.environment().get("JAVA_HOME"));
    }

    @Test
    void rejectsProfilesPropertiesAndServerControlledOverridesThatCouldChangeExecution() {
        MavenProcessAdapter adapter = new MavenProcessAdapter(unusedBackend(), configuration);

        assertThrows(IllegalArgumentException.class, () -> adapter.prepare(request(
                List.of("safe;package"), Map.of())));
        assertThrows(IllegalArgumentException.class, () -> adapter.prepare(request(
                List.of(), Map.of("revision", "$(touch-pwned)"))));
        assertThrows(IllegalArgumentException.class, () -> adapter.prepare(request(
                List.of(), Map.of("revision", "`touch-pwned`"))));
        assertThrows(IllegalArgumentException.class, () -> adapter.prepare(request(
                List.of(), Map.of("maven.repo.local", "/tmp/elsewhere"))));
        assertThrows(IllegalArgumentException.class, () -> adapter.prepare(request(
                List.of(), Map.of("revision", "bad\nvalue"))));
    }

    @Test
    void mapsBuildFailureAndParsesDeterministicReactorSummary() throws Exception {
        ExecutionBackend backend = (specification, cancellationToken) -> {
            Path stdout = specification.workingDirectory().resolve("stdout.log");
            Path stderr = specification.workingDirectory().resolve("stderr.log");
            Files.writeString(stdout, """
                    [INFO] Reactor Summary:
                    [INFO] root ........................................ SUCCESS [  0.100 s]
                    [INFO] module-a .................................... FAILURE [  0.200 s]
                    [INFO] module-b .................................... SKIPPED
                    """);
            Files.writeString(stderr, "build failed");
            Instant now = Instant.parse("2026-08-12T00:00:00Z");
            return new ExecutionResult(
                    ExecutionResult.Status.FAILED, 1, now, now.plusSeconds(1), Duration.ofSeconds(1),
                    123, stdout, stderr, false, false, "process exited with code 1");
        };
        MavenProcessAdapter adapter = new MavenProcessAdapter(backend, configuration);

        MavenBuildResult result = adapter.execute(request(List.of(), Map.of()), CancellationToken.NONE);

        assertEquals(MavenBuildResult.Status.FAILED, result.status());
        assertEquals(List.of(
                new MavenModuleResult("root", MavenModuleResult.Status.SUCCESS),
                new MavenModuleResult("module-a", MavenModuleResult.Status.FAILURE),
                new MavenModuleResult("module-b", MavenModuleResult.Status.SKIPPED)), result.modules());
    }

    @Test
    void runsARealSystemMavenBuildWhenExplicitlyEnabled() throws Exception {
        String executable = System.getProperty("audit.maven.executable", "");
        Assumptions.assumeTrue(!executable.isBlank(), "real Maven smoke is opt-in");
        Files.writeString(project.resolve("pom.xml"), """
                <?xml version="1.0" encoding="UTF-8"?>
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>io.github.uprxiao.fixture</groupId>
                  <artifactId>maven-process-smoke</artifactId>
                  <version>1.0.0</version>
                  <properties>
                    <maven.compiler.release>17</maven.compiler.release>
                  </properties>
                </project>
                """);
        MavenProcessConfiguration realConfiguration = new MavenProcessConfiguration(
                executable,
                Path.of(System.getProperty("java.home")),
                Path.of(System.getProperty("user.home"), ".m2", "repository"),
                null,
                System.getenv().getOrDefault("PATH", "/usr/bin:/bin"),
                512);
        MavenProcessAdapter adapter = new MavenProcessAdapter(
                new LocalProcessExecutionBackend(), realConfiguration);

        MavenBuildResult result = adapter.execute(
                request(List.of(), Map.of()), CancellationToken.NONE);

        assertEquals(MavenBuildResult.Status.SUCCEEDED, result.status());
        assertEquals(0, result.execution().exitCode());
        assertTrue(Files.readString(result.execution().stdout()).contains("BUILD SUCCESS"));
        assertTrue(Files.isRegularFile(project.resolve("target").resolve(MavenProcessAdapter.CLASSPATH_FILE)));
    }

    @Test
    void runsRealMultiModulePackageAndClasspathInOneReactorSession() throws Exception {
        String executable = System.getProperty("audit.maven.executable", "");
        Assumptions.assumeTrue(!executable.isBlank(), "real Maven smoke is opt-in");
        Files.writeString(project.resolve("pom.xml"), """
                <project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
                  <groupId>example</groupId><artifactId>root</artifactId><version>1.0</version><packaging>pom</packaging>
                  <modules><module>a</module><module>b</module></modules>
                  <properties><maven.compiler.release>17</maven.compiler.release></properties>
                </project>
                """);
        Path a = Files.createDirectories(project.resolve("a"));
        Path b = Files.createDirectories(project.resolve("b"));
        Files.writeString(a.resolve("pom.xml"), """
                <project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
                  <parent><groupId>example</groupId><artifactId>root</artifactId><version>1.0</version></parent>
                  <artifactId>a</artifactId>
                </project>
                """);
        Files.writeString(b.resolve("pom.xml"), """
                <project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
                  <parent><groupId>example</groupId><artifactId>root</artifactId><version>1.0</version></parent>
                  <artifactId>b</artifactId><dependencies>
                    <dependency><groupId>example</groupId><artifactId>a</artifactId><version>1.0</version></dependency>
                  </dependencies>
                </project>
                """);
        MavenProcessConfiguration realConfiguration = new MavenProcessConfiguration(
                executable, Path.of(System.getProperty("java.home")),
                temporaryDirectory.resolve("reactor-repository"), null,
                System.getenv().getOrDefault("PATH", "/usr/bin:/bin"), 512);

        MavenBuildResult result = new MavenProcessAdapter(
                new LocalProcessExecutionBackend(), realConfiguration)
                .execute(request(List.of(), Map.of()), CancellationToken.NONE);

        assertEquals(MavenBuildResult.Status.SUCCEEDED, result.status(),
                () -> read(result.execution().stdout()) + read(result.execution().stderr()));
        for (Path module : List.of(project, a, b)) {
            assertTrue(Files.isRegularFile(
                    module.resolve("target").resolve(MavenProcessAdapter.CLASSPATH_FILE)), module.toString());
        }
    }

    private String read(Path path) {
        try { return Files.readString(path); }
        catch (Exception exception) { return exception.toString(); }
    }

    private MavenBuildRequest request(List<String> profiles, Map<String, String> properties) {
        return new MavenBuildRequest(project, output, profiles, properties, Duration.ofMinutes(10));
    }

    private ExecutionBackend unusedBackend() {
        return (specification, cancellationToken) -> {
            throw new AssertionError("backend should not be invoked");
        };
    }
}
