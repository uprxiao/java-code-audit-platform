package io.github.uprxiao.audit.finding;

public enum EngineStatus {
    PENDING(false),
    READY(false),
    RUNNING(false),
    SUCCEEDED(true),
    PARTIAL(true),
    FAILED(true),
    TIMED_OUT(true),
    SKIPPED(true),
    CANCELLED(true);

    private final boolean terminal;

    EngineStatus(boolean terminal) {
        this.terminal = terminal;
    }

    public boolean isTerminal() {
        return terminal;
    }
}
