package io.github.uprxiao.audit.orchestrator;

import java.time.Duration;
import java.util.concurrent.RejectedExecutionException;

public final class ScanJobQueueFullException extends RejectedExecutionException {

    private final int queueLength;
    private final int queueCapacity;
    private final Duration retryAfter;

    public ScanJobQueueFullException(int queueLength, int queueCapacity, Duration retryAfter) {
        super("scan job queue is full (" + queueLength + "/" + queueCapacity + ")");
        this.queueLength = queueLength;
        this.queueCapacity = queueCapacity;
        this.retryAfter = retryAfter;
    }

    public int queueLength() {
        return queueLength;
    }

    public int queueCapacity() {
        return queueCapacity;
    }

    public Duration retryAfter() {
        return retryAfter;
    }
}
