package io.github.uprxiao.audit.storage;

import java.io.IOException;
import java.nio.file.Path;

public final class InstanceAlreadyRunningException extends IOException {
    public InstanceAlreadyRunningException(Path lockFile) {
        super("another audit instance owns the lock: " + lockFile);
    }
}
