package io.github.uprxiao.audit.scanner;

@FunctionalInterface
public interface CancellationToken {
    CancellationToken NONE = () -> false;

    boolean isCancellationRequested();
}
