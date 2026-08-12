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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.Map;
import java.util.Objects;

/** Runs CodeQL's database-create and database-analyze phases without a shell or a user command string. */
public final class CodeqlWorkflow {

    private final ExecutionBackend executionBackend;

    public CodeqlWorkflow(ExecutionBackend executionBackend) {
        this.executionBackend = Objects.requireNonNull(executionBackend, "executionBackend");
    }

    public Result execute(CodeqlAdapter adapter, ScanContext context, ToolContext tools,
            CancellationToken cancellationToken) throws IOException, InterruptedException {
        Objects.requireNonNull(adapter, "adapter");
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(tools, "tools");
        cancellationToken = cancellationToken == null ? CancellationToken.NONE : cancellationToken;

        ExecutionSpec createSpec = adapter.prepareDatabaseCreation(context, tools);
        ExecutionResult createResult = executionBackend.execute(createSpec, cancellationToken);
        requireSuccess(Phase.DATABASE_CREATE, createResult);

        ExecutionSpec analyzeSpec = adapter.prepareAnalysis(context, tools);
        ExecutionResult analyzeResult = executionBackend.execute(analyzeSpec, cancellationToken);
        requireSuccess(Phase.DATABASE_ANALYZE, analyzeResult);
        RawArtifactSet artifacts = new RawArtifactSet(CodeqlAdapter.ID,
                Map.of("report", adapter.reportPath(context)), analyzeResult);
        ArtifactValidation validation = adapter.validate(artifacts);
        if (!validation.valid()) {
            throw new CodeqlWorkflowException(Phase.OUTPUT_VALIDATION,
                    "CodeQL SARIF validation failed: " + validation.errors(), analyzeResult);
        }
        deleteDatabase(adapter.databaseDirectory(context), context.engineTemporaryDirectory());
        return new Result(artifacts, createResult, analyzeResult, true);
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
        try (var paths = Files.walk(safeDatabase)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.delete(path);
            }
        }
    }

    public enum Phase {
        DATABASE_CREATE,
        DATABASE_ANALYZE,
        OUTPUT_VALIDATION
    }

    public record Result(
            RawArtifactSet artifacts,
            ExecutionResult databaseCreation,
            ExecutionResult analysis,
            boolean databaseDeleted) {
        public Result {
            Objects.requireNonNull(artifacts, "artifacts");
            Objects.requireNonNull(databaseCreation, "databaseCreation");
            Objects.requireNonNull(analysis, "analysis");
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
