package io.github.uprxiao.audit.finding;

public enum ScanPhase {
    ACCEPTED,
    SOURCE,
    PREFLIGHT,
    ENGINES,
    REPORTING,
    TERMINAL;

    public static ScanPhase forStatus(ScanStatus status) {
        return switch (status) {
            case QUEUED -> ACCEPTED;
            case ACQUIRING_SOURCE -> SOURCE;
            case PREFLIGHT -> PREFLIGHT;
            case RUNNING -> ENGINES;
            case FINALIZING -> REPORTING;
            case COMPLETED, COMPLETED_WITH_ERRORS, FAILED, CANCELLED, INTERRUPTED -> TERMINAL;
        };
    }
}
