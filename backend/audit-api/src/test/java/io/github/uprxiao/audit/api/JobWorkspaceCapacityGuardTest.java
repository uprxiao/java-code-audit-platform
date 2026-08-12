package io.github.uprxiao.audit.api;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.uprxiao.audit.scanner.CancellationToken;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class JobWorkspaceCapacityGuardTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void acceptsBoundedWorkspaceAndRejectsOversizedWorkspace() throws Exception {
        JobWorkspaceCapacityGuard guard = new JobWorkspaceCapacityGuard(8);
        Files.writeString(temporaryDirectory.resolve("small"), "12345678");
        assertDoesNotThrow(() -> guard.requireWithinLimit(temporaryDirectory));
        Files.writeString(temporaryDirectory.resolve("extra"), "9");

        WorkspaceCapacityException exception = assertThrows(
                WorkspaceCapacityException.class, () -> guard.requireWithinLimit(temporaryDirectory));

        assertEquals("JOB_WORKSPACE_LIMIT_EXCEEDED", exception.code());
        assertEquals(8L, exception.details().get("maximumBytes"));
    }

    @Test
    void processCancellationTokenRecordsCapacityReason() throws Exception {
        Files.writeString(temporaryDirectory.resolve("large"), "123456789");
        WorkspaceLimitCancellationToken token = new WorkspaceLimitCancellationToken(
                new JobWorkspaceCapacityGuard(8), temporaryDirectory,
                CancellationToken.NONE, Duration.ofMillis(1));

        assertTrue(token.isCancellationRequested());
        assertEquals("JOB_WORKSPACE_LIMIT_EXCEEDED", token.failure().code());
    }

    @Test
    void concurrentDisappearanceDoesNotTurnIntoCapacityFailure() throws Exception {
        JobWorkspaceCapacityGuard guard = new JobWorkspaceCapacityGuard(1024);
        Path transientFile = Files.writeString(temporaryDirectory.resolve("transient"), "temporary");
        Files.delete(transientFile);

        assertDoesNotThrow(() -> guard.requireWithinLimit(temporaryDirectory));
        assertTrue(JobWorkspaceCapacityGuard.isTransientDisappearance(
                new NoSuchFileException(transientFile.toString())));
    }
}
