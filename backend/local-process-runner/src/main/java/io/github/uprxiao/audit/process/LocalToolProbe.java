package io.github.uprxiao.audit.process;

import io.github.uprxiao.audit.scanner.CancellationToken;
import io.github.uprxiao.audit.scanner.ExecutionBackend;
import io.github.uprxiao.audit.scanner.ExecutionResult;
import io.github.uprxiao.audit.scanner.ExecutionSpec;
import io.github.uprxiao.audit.scanner.RedactionPolicy;
import io.github.uprxiao.audit.scanner.ResourceClass;
import io.github.uprxiao.audit.scanner.ResourceRequest;
import io.github.uprxiao.audit.scanner.ToolHealth;
import io.github.uprxiao.audit.scanner.ToolProbe;
import io.github.uprxiao.audit.scanner.ToolProbeRequest;
import java.io.IOException;
import java.nio.file.Files;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public final class LocalToolProbe implements ToolProbe {

    private final ExecutionBackend backend;
    private final Clock clock;

    public LocalToolProbe(ExecutionBackend backend, Clock clock) {
        this.backend = Objects.requireNonNull(backend, "backend");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public ToolHealth probe(ToolProbeRequest request) throws IOException, InterruptedException {
        if (!Files.isRegularFile(request.executable()) || !Files.isExecutable(request.executable())) {
            return new ToolHealth(ToolHealth.Status.UNAVAILABLE, "", "EXECUTABLE_NOT_FOUND",
                    request.executable().toString(), clock.instant());
        }
        Files.createDirectories(request.workingDirectory());
        List<String> command = new ArrayList<>();
        command.add(request.executable().toString());
        command.addAll(request.versionArguments());
        ExecutionResult result = backend.execute(new ExecutionSpec(
                request.engine(), command, request.workingDirectory(), request.environment(), request.timeout(),
                new ResourceRequest(ResourceClass.LIGHT, 1, 128), Set.of(), RedactionPolicy.NONE),
                CancellationToken.NONE);
        if (result.status() != ExecutionResult.Status.SUCCEEDED) {
            return new ToolHealth(ToolHealth.Status.UNAVAILABLE, "", "VERSION_COMMAND_FAILED",
                    result.message(), clock.instant());
        }
        String output = (Files.readString(result.stdout()) + "\n" + Files.readString(result.stderr())).trim();
        String version = output.lines().findFirst().orElse("").trim();
        if (version.isBlank()) {
            return new ToolHealth(ToolHealth.Status.INCOMPATIBLE, "", "VERSION_NOT_DETECTED",
                    "version command returned no output", clock.instant());
        }
        return new ToolHealth(ToolHealth.Status.AVAILABLE, version, "", "", clock.instant());
    }
}
