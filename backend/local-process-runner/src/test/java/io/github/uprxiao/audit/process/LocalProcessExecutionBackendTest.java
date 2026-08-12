package io.github.uprxiao.audit.process;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.uprxiao.audit.scanner.CancellationToken;
import io.github.uprxiao.audit.scanner.EngineId;
import io.github.uprxiao.audit.scanner.ExecutionResult;
import io.github.uprxiao.audit.scanner.ExecutionSpec;
import io.github.uprxiao.audit.scanner.ExpectedArtifact;
import io.github.uprxiao.audit.scanner.RedactionPolicy;
import io.github.uprxiao.audit.scanner.ResourceClass;
import io.github.uprxiao.audit.scanner.ResourceRequest;
import io.github.uprxiao.audit.scanner.ToolHealth;
import io.github.uprxiao.audit.scanner.ToolProbeRequest;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class LocalProcessExecutionBackendTest {

    @TempDir
    Path temporaryDirectory;

    private final ProcessRunnerConfiguration configuration = new ProcessRunnerConfiguration(
            4096, Duration.ofMillis(20), Duration.ofMillis(500), Set.of("java"),
            Set.of("SVN_PASSWORD"));
    private final LocalProcessExecutionBackend backend = new LocalProcessExecutionBackend(configuration, Clock.systemUTC());

    @Test
    void handlesSuccessFindingFailureAndInvalidReportModes() throws Exception {
        ExecutionResult success = backend.execute(spec("success", Duration.ofSeconds(5)), CancellationToken.NONE);
        assertEquals(ExecutionResult.Status.SUCCEEDED, success.status());
        assertEquals(0, success.exitCode());
        assertEquals("ok\n", Files.readString(success.stdout()));

        Path findingDirectory = Files.createDirectory(temporaryDirectory.resolve("finding"));
        ExecutionResult finding = backend.execute(spec(findingDirectory, "finding", Duration.ofSeconds(5),
                Map.of(), RedactionPolicy.NONE), CancellationToken.NONE);
        assertEquals(ExecutionResult.Status.SUCCEEDED, finding.status());
        assertTrue(Files.readString(findingDirectory.resolve("report.json")).contains("FAKE-1"));

        ExecutionResult failure = backend.execute(spec("failure", Duration.ofSeconds(5)), CancellationToken.NONE);
        assertEquals(ExecutionResult.Status.FAILED, failure.status());
        assertEquals(7, failure.exitCode());

        Path invalidDirectory = Files.createDirectory(temporaryDirectory.resolve("invalid"));
        ExecutionResult invalid = backend.execute(spec(invalidDirectory, "invalid-report", Duration.ofSeconds(5),
                Map.of(), RedactionPolicy.NONE), CancellationToken.NONE);
        assertEquals(ExecutionResult.Status.SUCCEEDED, invalid.status());
        assertEquals("{not-json", Files.readString(invalidDirectory.resolve("report.json")));
    }

    @Test
    void drainsLargeOutputConcurrentlyAndMarksBothLogsTruncated() throws Exception {
        ExecutionResult result = backend.execute(spec("large-output", Duration.ofSeconds(10)), CancellationToken.NONE);

        assertEquals(ExecutionResult.Status.SUCCEEDED, result.status());
        assertTrue(result.stdoutTruncated());
        assertTrue(result.stderrTruncated());
        assertEquals(4096, Files.size(result.stdout()));
        assertEquals(4096, Files.size(result.stderr()));
    }

    @Test
    void timeoutKillsParentAndDescendant() throws Exception {
        Path directory = Files.createDirectory(temporaryDirectory.resolve("tree"));
        ExecutionResult result = backend.execute(spec(directory, "spawn-child", Duration.ofMillis(500),
                Map.of(), RedactionPolicy.NONE), CancellationToken.NONE);

        long childPid = Long.parseLong(Files.readString(directory.resolve("child.pid")));
        assertEquals(ExecutionResult.Status.TIMED_OUT, result.status());
        assertNull(result.exitCode());
        assertFalse(ProcessHandle.of(result.processId()).map(ProcessHandle::isAlive).orElse(false));
        assertFalse(ProcessHandle.of(childPid).map(ProcessHandle::isAlive).orElse(false));
    }

    @Test
    void cancellationKillsTheProcess() throws Exception {
        AtomicBoolean cancelled = new AtomicBoolean();
        Thread requester = new Thread(() -> {
            try {
                Thread.sleep(150);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            }
            cancelled.set(true);
        });
        requester.start();
        ExecutionResult result = backend.execute(spec("timeout", Duration.ofSeconds(10)), cancelled::get);
        requester.join();

        assertEquals(ExecutionResult.Status.CANCELLED, result.status());
        assertFalse(ProcessHandle.of(result.processId()).map(ProcessHandle::isAlive).orElse(false));
    }

    @Test
    void redactsSensitiveArgumentsAndEnvironmentAcrossBothLogs() throws Exception {
        String secret = "very-secret-value";
        Path directory = Files.createDirectory(temporaryDirectory.resolve("secret"));
        RedactionPolicy policy = new RedactionPolicy(Set.of(5), Set.of("SVN_PASSWORD"));
        ExecutionResult result = backend.execute(spec(directory, "secret", Duration.ofSeconds(5),
                Map.of("SVN_PASSWORD", secret), policy, secret), CancellationToken.NONE);

        assertFalse(Files.readString(result.stdout()).contains(secret));
        assertFalse(Files.readString(result.stderr()).contains(secret));
        assertTrue(Files.readString(result.stdout()).contains("***"));
        assertTrue(Files.readString(result.stderr()).contains("***"));
    }

    @Test
    void rejectsShellsAndUnapprovedEnvironment() throws Exception {
        Path directory = Files.createDirectory(temporaryDirectory.resolve("unsafe"));
        ExecutionSpec shell = new ExecutionSpec(new EngineId("fake"), List.of("/bin/sh", "-c", "true"), directory,
                Map.of(), Duration.ofSeconds(1), resources(), Set.of(), RedactionPolicy.NONE);
        assertThrows(UnsafeCommandException.class, () -> backend.execute(shell, CancellationToken.NONE));

        ExecutionSpec badEnvironment = spec(directory, "success", Duration.ofSeconds(1),
                Map.of("AWS_SECRET_ACCESS_KEY", "clear"), RedactionPolicy.NONE);
        assertThrows(UnsafeCommandException.class,
                () -> backend.execute(badEnvironment, CancellationToken.NONE));
    }

    @Test
    void leavesNoDrainThreadsAfterExceptionalModes() throws Exception {
        backend.execute(spec("failure", Duration.ofSeconds(5)), CancellationToken.NONE);
        backend.execute(spec("timeout", Duration.ofMillis(200)), CancellationToken.NONE);
        Thread.sleep(100);

        assertTrue(Thread.getAllStackTraces().keySet().stream()
                .filter(Thread::isAlive)
                .noneMatch(thread -> thread.getName().startsWith("audit-process-drain-")));
    }

    @Test
    void probesAvailableAndMissingExecutables() throws Exception {
        LocalToolProbe probe = new LocalToolProbe(backend, Clock.systemUTC());
        Path probeDirectory = Files.createDirectory(temporaryDirectory.resolve("probe"));
        Path java = Path.of(System.getProperty("java.home"), "bin", "java");

        ToolHealth available = probe.probe(new ToolProbeRequest(
                new EngineId("java-probe"), java, List.of("-version"), probeDirectory,
                Map.of(), Duration.ofSeconds(5)));
        ToolHealth missing = probe.probe(new ToolProbeRequest(
                new EngineId("missing-tool"), temporaryDirectory.resolve("missing"), List.of("--version"),
                Files.createDirectory(temporaryDirectory.resolve("missing-probe")), Map.of(), Duration.ofSeconds(1)));

        assertEquals(ToolHealth.Status.AVAILABLE, available.status());
        assertTrue(available.version().contains("version"));
        assertEquals(ToolHealth.Status.UNAVAILABLE, missing.status());
        assertEquals("EXECUTABLE_NOT_FOUND", missing.reasonCode());
    }

    private ExecutionSpec spec(String mode, Duration timeout, String... extra) throws Exception {
        return spec(Files.createDirectory(temporaryDirectory.resolve(mode + "-" + System.nanoTime())),
                mode, timeout, Map.of(), RedactionPolicy.NONE, extra);
    }

    private ExecutionSpec spec(
            Path directory,
            String mode,
            Duration timeout,
            Map<String, String> environment,
            RedactionPolicy redactionPolicy,
            String... extra) {
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        command.add("-cp");
        command.add(System.getProperty("java.class.path"));
        command.add(FakeToolMain.class.getName());
        command.add(mode);
        command.addAll(List.of(extra));
        return new ExecutionSpec(new EngineId("fake"), command, directory, environment, timeout, resources(),
                Set.of(new ExpectedArtifact("report.json", false, 1024 * 1024)), redactionPolicy);
    }

    private ResourceRequest resources() {
        return new ResourceRequest(ResourceClass.LIGHT, 1, 128);
    }
}
