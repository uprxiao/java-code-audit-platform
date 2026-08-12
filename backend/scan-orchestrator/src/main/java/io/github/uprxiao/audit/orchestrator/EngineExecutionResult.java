package io.github.uprxiao.audit.orchestrator;

import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.finding.FailureDetails;
import java.util.Map;
import java.util.Objects;

public record EngineExecutionResult(EngineStatus status, FailureDetails failure) {

    public EngineExecutionResult {
        Objects.requireNonNull(status, "status");
        if (!status.isTerminal() || status == EngineStatus.SKIPPED) {
            throw new IllegalArgumentException("engine action must return an executable terminal status");
        }
        boolean requiresFailure = status == EngineStatus.PARTIAL
                || status == EngineStatus.FAILED
                || status == EngineStatus.TIMED_OUT;
        if (requiresFailure != (failure != null)) {
            throw new IllegalArgumentException("failure details do not match engine status " + status);
        }
    }

    public static EngineExecutionResult succeeded() {
        return new EngineExecutionResult(EngineStatus.SUCCEEDED, null);
    }

    public static EngineExecutionResult partial(String code, String message) {
        return failedLike(EngineStatus.PARTIAL, code, message);
    }

    public static EngineExecutionResult failed(String code, String message) {
        return failedLike(EngineStatus.FAILED, code, message);
    }

    public static EngineExecutionResult timedOut(String code, String message) {
        return failedLike(EngineStatus.TIMED_OUT, code, message);
    }

    public static EngineExecutionResult cancelled() {
        return new EngineExecutionResult(EngineStatus.CANCELLED, null);
    }

    private static EngineExecutionResult failedLike(EngineStatus status, String code, String message) {
        return new EngineExecutionResult(status, new FailureDetails(code, message, Map.of()));
    }
}
