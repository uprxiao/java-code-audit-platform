package io.github.uprxiao.audit.process;

import io.github.uprxiao.audit.scanner.CancellationToken;
import io.github.uprxiao.audit.scanner.ExecutionBackend;
import io.github.uprxiao.audit.scanner.ExecutionResult;
import io.github.uprxiao.audit.scanner.ExecutionSpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

public final class LocalProcessExecutionBackend implements ExecutionBackend {

    private static final Set<String> SHELLS = Set.of("sh", "bash", "zsh", "dash", "ksh", "csh", "fish");
    private static final AtomicInteger THREAD_SEQUENCE = new AtomicInteger();

    private final ProcessRunnerConfiguration configuration;
    private final Clock clock;

    public LocalProcessExecutionBackend() {
        this(ProcessRunnerConfiguration.defaults(), Clock.systemUTC());
    }

    public LocalProcessExecutionBackend(ProcessRunnerConfiguration configuration, Clock clock) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public ExecutionResult execute(ExecutionSpec specification, CancellationToken cancellationToken)
            throws IOException, InterruptedException {
        Objects.requireNonNull(specification, "specification");
        cancellationToken = cancellationToken == null ? CancellationToken.NONE : cancellationToken;
        validate(specification);
        Files.createDirectories(specification.workingDirectory());
        Path stdout = specification.workingDirectory().resolve("stdout.log");
        Path stderr = specification.workingDirectory().resolve("stderr.log");
        List<String> secrets = secrets(specification);
        BoundedRedactingLogCapture stdoutCapture = new BoundedRedactingLogCapture(configuration.maxLogBytes(), secrets);
        BoundedRedactingLogCapture stderrCapture = new BoundedRedactingLogCapture(configuration.maxLogBytes(), secrets);

        ProcessBuilder builder = new ProcessBuilder(specification.command());
        builder.directory(specification.workingDirectory().toFile());
        Map<String, String> environment = builder.environment();
        environment.clear();
        environment.putAll(specification.environment());

        Instant startedAt = clock.instant();
        long startedNanos = System.nanoTime();
        Process process = builder.start();
        ExecutorService drains = Executors.newFixedThreadPool(2, runnable -> {
            Thread thread = new Thread(runnable, "audit-process-drain-" + THREAD_SEQUENCE.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        });
        Future<?> stdoutFuture = drains.submit(() -> drain(stdoutCapture, process.getInputStream(), stdout));
        Future<?> stderrFuture = drains.submit(() -> drain(stderrCapture, process.getErrorStream(), stderr));

        ExecutionResult.Status status;
        Integer exitCode = null;
        String message = "";
        try {
            long timeoutNanos = specification.timeout().toNanos();
            while (process.isAlive()) {
                if (cancellationToken.isCancellationRequested()) {
                    status = ExecutionResult.Status.CANCELLED;
                    message = "execution cancelled";
                    terminateTree(process);
                    return result(process, status, exitCode, startedAt, startedNanos, stdout, stderr,
                            stdoutCapture, stderrCapture, message, stdoutFuture, stderrFuture, drains);
                }
                if (System.nanoTime() - startedNanos >= timeoutNanos) {
                    status = ExecutionResult.Status.TIMED_OUT;
                    message = "execution timed out after " + specification.timeout();
                    terminateTree(process);
                    return result(process, status, exitCode, startedAt, startedNanos, stdout, stderr,
                            stdoutCapture, stderrCapture, message, stdoutFuture, stderrFuture, drains);
                }
                process.waitFor(configuration.pollInterval().toMillis(), TimeUnit.MILLISECONDS);
            }
            exitCode = process.exitValue();
            status = exitCode == 0 ? ExecutionResult.Status.SUCCEEDED : ExecutionResult.Status.FAILED;
            if (exitCode != 0) {
                message = "process exited with code " + exitCode;
            }
            return result(process, status, exitCode, startedAt, startedNanos, stdout, stderr,
                    stdoutCapture, stderrCapture, message, stdoutFuture, stderrFuture, drains);
        } catch (InterruptedException exception) {
            terminateTree(process);
            Thread.currentThread().interrupt();
            throw exception;
        } finally {
            if (process.isAlive()) {
                terminateTree(process);
            }
            drains.shutdownNow();
            drains.awaitTermination(configuration.gracefulTermination().toMillis(), TimeUnit.MILLISECONDS);
        }
    }

    private ExecutionResult result(
            Process process,
            ExecutionResult.Status status,
            Integer exitCode,
            Instant startedAt,
            long startedNanos,
            Path stdout,
            Path stderr,
            BoundedRedactingLogCapture stdoutCapture,
            BoundedRedactingLogCapture stderrCapture,
            String message,
            Future<?> stdoutFuture,
            Future<?> stderrFuture,
            ExecutorService drains) throws IOException, InterruptedException {
        awaitDrain(stdoutFuture);
        awaitDrain(stderrFuture);
        drains.shutdown();
        Instant completedAt = clock.instant();
        Duration duration = Duration.ofNanos(Math.max(0, System.nanoTime() - startedNanos));
        return new ExecutionResult(status, exitCode, startedAt, completedAt, duration, process.pid(), stdout, stderr,
                stdoutCapture.truncated(), stderrCapture.truncated(), message);
    }

    private void awaitDrain(Future<?> future) throws IOException, InterruptedException {
        try {
            future.get(Math.max(1000, configuration.gracefulTermination().toMillis()), TimeUnit.MILLISECONDS);
        } catch (ExecutionException exception) {
            Throwable cause = exception.getCause();
            if (cause instanceof IOException ioException) {
                throw ioException;
            }
            throw new IOException("cannot drain process output", cause);
        } catch (TimeoutException exception) {
            future.cancel(true);
            throw new IOException("process output drain did not terminate", exception);
        }
    }

    private void drain(BoundedRedactingLogCapture capture, java.io.InputStream input, Path target) {
        try {
            capture.drain(input, target);
        } catch (IOException exception) {
            throw new OutputDrainException(exception);
        }
    }

    private void validate(ExecutionSpec specification) {
        String executable = specification.command().get(0);
        Path executablePath = Path.of(executable);
        String commandName = executablePath.getFileName().toString().toLowerCase(Locale.ROOT);
        if (SHELLS.contains(commandName)) {
            throw new UnsafeCommandException("shell execution is forbidden: " + commandName);
        }
        if (executablePath.isAbsolute()) {
            if (!Files.isRegularFile(executablePath) || !Files.isExecutable(executablePath)) {
                throw new UnsafeCommandException("executable is unavailable: " + executablePath);
            }
        } else if (executablePath.getNameCount() != 1
                || !configuration.allowedSystemCommands().contains(executable)) {
            throw new UnsafeCommandException("system command is not allowlisted: " + executable);
        }
        for (String key : specification.environment().keySet()) {
            if (!configuration.allowedEnvironmentKeys().contains(key)) {
                throw new UnsafeCommandException("environment key is not allowlisted: " + key);
            }
        }
    }

    private List<String> secrets(ExecutionSpec specification) {
        List<String> result = new ArrayList<>();
        for (Integer index : specification.redactionPolicy().sensitiveArgumentIndexes()) {
            if (index < specification.command().size()) {
                result.add(specification.command().get(index));
            }
        }
        for (String key : specification.redactionPolicy().sensitiveEnvironmentKeys()) {
            String value = specification.environment().get(key);
            if (value != null) {
                result.add(value);
            }
        }
        return result;
    }

    private void terminateTree(Process process) throws InterruptedException {
        List<ProcessHandle> descendants = process.toHandle().descendants()
                .sorted(Comparator.comparingLong(ProcessHandle::pid).reversed())
                .toList();
        descendants.forEach(ProcessHandle::destroy);
        process.destroy();
        waitForTermination(process, descendants, configuration.gracefulTermination());
        descendants.stream().filter(ProcessHandle::isAlive).forEach(ProcessHandle::destroyForcibly);
        if (process.isAlive()) {
            process.destroyForcibly();
        }
        waitForTermination(process, descendants, configuration.gracefulTermination());
    }

    private void waitForTermination(Process process, List<ProcessHandle> descendants, Duration duration)
            throws InterruptedException {
        long deadline = System.nanoTime() + duration.toNanos();
        while ((process.isAlive() || descendants.stream().anyMatch(ProcessHandle::isAlive))
                && System.nanoTime() < deadline) {
            Thread.sleep(Math.min(20, Math.max(1, configuration.pollInterval().toMillis())));
        }
    }

    private static final class OutputDrainException extends RuntimeException {
        private OutputDrainException(IOException cause) {
            super(cause);
        }
    }
}
