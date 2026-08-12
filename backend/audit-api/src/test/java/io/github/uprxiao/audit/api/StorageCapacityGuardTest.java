package io.github.uprxiao.audit.api;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class StorageCapacityGuardTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void rejectsNewWorkBelowConfiguredWatermark() {
        AuditRuntimePaths paths = new AuditRuntimePaths(
                temporaryDirectory, temporaryDirectory.resolve("semgrep"), temporaryDirectory.resolve("rules"));
        assertDoesNotThrow(() -> new StorageCapacityGuard(paths, 1).requireCapacity());

        ApiException failure = assertThrows(ApiException.class,
                () -> new StorageCapacityGuard(paths, Long.MAX_VALUE).requireCapacity());
        assertEquals(ApiErrorCode.DISK_SPACE_LOW, failure.code());
        assertEquals(507, failure.status().value());
    }
}
