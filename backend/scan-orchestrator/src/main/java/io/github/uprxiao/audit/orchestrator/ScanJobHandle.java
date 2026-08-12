package io.github.uprxiao.audit.orchestrator;

import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.scanner.EngineId;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

public final class ScanJobHandle {

    private final UUID scanId;
    private final CompletableFuture<ScanJobExecutionResult> completion;
    private final BooleanSupplier cancellation;
    private final Supplier<Map<EngineId, EngineStatus>> snapshot;

    ScanJobHandle(
            UUID scanId,
            CompletableFuture<ScanJobExecutionResult> completion,
            BooleanSupplier cancellation,
            Supplier<Map<EngineId, EngineStatus>> snapshot) {
        this.scanId = scanId;
        this.completion = completion;
        this.cancellation = cancellation;
        this.snapshot = snapshot;
    }

    public UUID scanId() {
        return scanId;
    }

    public CompletableFuture<ScanJobExecutionResult> completion() {
        return completion;
    }

    public boolean cancel() {
        return cancellation.getAsBoolean();
    }

    public Map<EngineId, EngineStatus> engineStates() {
        return snapshot.get();
    }
}
