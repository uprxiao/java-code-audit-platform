package io.github.uprxiao.audit.storage;

import java.util.UUID;

public final class StaleJobRevisionException extends IllegalStateException {
    public StaleJobRevisionException(UUID scanId, long currentRevision, long attemptedRevision) {
        super("stale job revision for " + scanId + ": current=" + currentRevision + ", attempted=" + attemptedRevision);
    }
}
