package io.github.uprxiao.audit.orchestrator;

import java.util.concurrent.RejectedExecutionException;

public final class SchedulerShuttingDownException extends RejectedExecutionException {
    public SchedulerShuttingDownException() {
        super("scan scheduler is shutting down");
    }
}
