package io.github.uprxiao.audit.finding;

public enum ScanStatus {
    QUEUED,
    RUNNING,
    SUCCEEDED,
    PARTIAL,
    FAILED,
    TIMED_OUT,
    CANCELLED
}
