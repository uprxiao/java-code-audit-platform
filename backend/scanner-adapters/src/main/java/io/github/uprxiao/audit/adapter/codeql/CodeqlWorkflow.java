package io.github.uprxiao.audit.adapter.codeql;

import io.github.uprxiao.audit.scanner.ArtifactValidation;
import io.github.uprxiao.audit.scanner.CancellationToken;
import io.github.uprxiao.audit.scanner.ExecutionBackend;
import io.github.uprxiao.audit.scanner.ExecutionResult;
import io.github.uprxiao.audit.scanner.ExecutionSpec;
import io.github.uprxiao.audit.scanner.RawArtifactSet;
import io.github.uprxiao.audit.scanner.ScanContext;
import io.github.uprxiao.audit.scanner.ToolContext;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Map;
import java.util.Objects;
import java.util.function.UnaryOperator;

/** Runs a pinned, shell-free CodeQL manual Maven trace and analysis workflow. */
public final class CodeqlWorkflow {

    private final ExecutionBackend executionBackend;

    public CodeqlWorkflow(ExecutionBackend executionBackend) {
        this.executionBackend = Objects.requireNonNull(executionBackend, "executionBackend");
    }

    public Result execute(CodeqlAdapter adapter, ScanContext context, ToolContext tools,
            CancellationToken cancellationToken) throws IOException, InterruptedException {
        return execute(adapter, context, tools, cancellationToken, UnaryOperator.identity());
    }

    public Result execute(CodeqlAdapter adapter, ScanContext context, ToolContext tools,
            CancellationToken cancellationToken, UnaryOperator<ExecutionSpec> executionPolicy)
            throws IOException, InterruptedException {
        Objects.requireNonNull(adapter, "adapter");
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(tools, "tools");
        cancellationToken = cancellationToken == null ? CancellationToken.NONE : cancellationToken;
        executionPolicy = Objects.requireNonNull(executionPolicy, "executionPolicy");

        ExecutionSpec initializeSpec = executionPolicy.apply(adapter.prepareDatabaseInitialization(context, tools));
        ExecutionResult initializeResult = executionBackend.execute(initializeSpec, cancellationToken);
        requireSuccess(Phase.DATABASE_INITIALIZE, initializeResult);

        ExecutionSpec traceSpec = executionPolicy.apply(adapter.prepareBuildTrace(context, tools));
        ExecutionResult traceResult = executionBackend.execute(traceSpec, cancellationToken);
        requireSuccess(Phase.BUILD_TRACE, traceResult);

        ExecutionSpec finalizeSpec = executionPolicy.apply(adapter.prepareDatabaseFinalization(context, tools));
        ExecutionResult finalizeResult = executionBackend.execute(finalizeSpec, cancellationToken);
        requireSuccess(Phase.DATABASE_FINALIZE, finalizeResult);

        ExecutionSpec analyzeSpec = executionPolicy.apply(adapter.prepareAnalysis(context, tools));
        ExecutionResult analyzeResult = executionBackend.execute(analyzeSpec, cancellationToken);
        requireSuccess(Phase.DATABASE_ANALYZE, analyzeResult);
        ExecutionResult totalResult = totalExecution(initializeResult, traceResult, finalizeResult, analyzeResult);
        RawArtifactSet artifacts = new RawArtifactSet(CodeqlAdapter.ID,
                Map.of("report", adapter.reportPath(context)), totalResult);
        ArtifactValidation validation = adapter.validate(artifacts);
        if (!validation.valid()) {
            throw new CodeqlWorkflowException(Phase.OUTPUT_VALIDATION,
                    "CodeQL SARIF validation failed: " + validation.errors(), analyzeResult);
        }
        deleteDatabase(adapter.databaseDirectory(context), context.engineTemporaryDirectory());
        return new Result(artifacts, initializeResult, traceResult, finalizeResult, analyzeResult, totalResult, true);
    }

    private ExecutionResult totalExecution(ExecutionResult initialize, ExecutionResult trace,
            ExecutionResult finalizeResult, ExecutionResult analyze) {
        return new ExecutionResult(
                ExecutionResult.Status.SUCCEEDED, 0, initialize.startedAt(), analyze.completedAt(),
                java.time.Duration.between(initialize.startedAt(), analyze.completedAt()),
                analyze.processId(), analyze.stdout(), analyze.stderr(),
                initialize.stdoutTruncated() || trace.stdoutTruncated() || finalizeResult.stdoutTruncated()
                        || analyze.stdoutTruncated(),
                initialize.stderrTruncated() || trace.stderrTruncated() || finalizeResult.stderrTruncated()
                        || analyze.stderrTruncated(),
                "");
    }

    private void requireSuccess(Phase phase, ExecutionResult result) throws CodeqlWorkflowException {
        if (result.status() != ExecutionResult.Status.SUCCEEDED) {
            throw new CodeqlWorkflowException(phase,
                    "CodeQL " + phase.name().toLowerCase().replace('_', ' ') + " failed: " + result.message(), result);
        }
    }

    private void deleteDatabase(Path database, Path configuredTemporaryDirectory) throws IOException {
        Path safeTemporaryDirectory = configuredTemporaryDirectory.toAbsolutePath().normalize();
        Path safeDatabase = database.toAbsolutePath().normalize();
        if (!safeDatabase.equals(safeTemporaryDirectory)
                || safeDatabase.getParent() == null
                || !CodeqlAdapter.DATABASE_DIRECTORY.equals(safeDatabase.getFileName().toString())) {
            throw new IOException("refusing to delete unsafe CodeQL database path: " + safeDatabase);
        }
        if (!Files.exists(safeDatabase)) return;
        Files.walkFileTree(safeDatabase, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) throws IOException {
                Files.deleteIfExists(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exception) throws IOException {
                if (exception instanceof NoSuchFileException) return FileVisitResult.CONTINUE;
                throw exception;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path directory, IOException exception) throws IOException {
                if (exception != null && !(exception instanceof NoSuchFileException)) throw exception;
                Files.deleteIfExists(directory);
                return FileVisitResult.CONTINUE;
            }
        });
    }

    public enum Phase {
        DATABASE_INITIALIZE,
        BUILD_TRACE,
        DATABASE_FINALIZE,
        DATABASE_ANALYZE,
        OUTPUT_VALIDATION
    }

    public record Result(
            RawArtifactSet artifacts,
            ExecutionResult databaseInitialization,
            ExecutionResult buildTrace,
            ExecutionResult databaseFinalization,
            ExecutionResult analysis,
            ExecutionResult totalExecution,
            boolean databaseDeleted) {
        public Result {
            Objects.requireNonNull(artifacts, "artifacts");
            Objects.requireNonNull(databaseInitialization, "databaseInitialization");
            Objects.requireNonNull(buildTrace, "buildTrace");
            Objects.requireNonNull(databaseFinalization, "databaseFinalization");
            Objects.requireNonNull(analysis, "analysis");
            Objects.requireNonNull(totalExecution, "totalExecution");
        }
    }

    public static final class CodeqlWorkflowException extends IOException {
        private final Phase phase;
        private final ExecutionResult execution;

        CodeqlWorkflowException(Phase phase, String message, ExecutionResult execution) {
            super(message);
            this.phase = Objects.requireNonNull(phase, "phase");
            this.execution = Objects.requireNonNull(execution, "execution");
        }

        public Phase phase() {
            return phase;
        }

        public ExecutionResult execution() {
            return execution;
        }
    }
}
