package io.github.uprxiao.audit.finding;

public enum ScanStatus {
    QUEUED(false),
    ACQUIRING_SOURCE(false),
    PREFLIGHT(false),
    RUNNING(false),
    FINALIZING(false),
    COMPLETED(true),
    COMPLETED_WITH_ERRORS(true),
    FAILED(true),
    CANCELLED(true),
    INTERRUPTED(true);

    private final boolean terminal;

    ScanStatus(boolean terminal) {
        this.terminal = terminal;
    }

    public boolean isTerminal() {
        return terminal;
    }
}
