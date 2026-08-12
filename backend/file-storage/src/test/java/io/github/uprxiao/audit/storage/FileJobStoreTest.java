package io.github.uprxiao.audit.storage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.uprxiao.audit.finding.ScanJob;
import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.finding.ScanStatus;
import io.github.uprxiao.audit.finding.SourceType;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FileJobStoreTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void persistsAtomicallyAndRejectsStaleRevision() throws Exception {
        FileJobStore store = new FileJobStore(temporaryDirectory);
        UUID id = UUID.fromString("00000000-0000-0000-0000-000000000001");
        ScanJob queued = ScanJob.queued(id, SourceType.ZIP, ScanProfile.QUICK,
                Instant.parse("2026-08-12T00:00:00Z"));
        store.save(StoredScanJob.from(queued));

        ScanJob acquiring = queued.transitionTo(ScanStatus.ACQUIRING_SOURCE,
                Instant.parse("2026-08-12T00:00:01Z"));
        store.save(StoredScanJob.from(acquiring));

        assertEquals(1, store.find(id).orElseThrow().revision());
        assertEquals(1, store.list().size());
        assertThrows(StaleJobRevisionException.class, () -> store.save(StoredScanJob.from(queued)));
        try (var paths = Files.walk(temporaryDirectory)) {
            assertTrue(paths.noneMatch(path -> path.getFileName().toString().contains(".tmp-")));
        }
    }

    @Test
    void enforcesSingleProcessOwnership() throws Exception {
        try (SingleInstanceLock ignored = SingleInstanceLock.acquire(temporaryDirectory)) {
            assertThrows(InstanceAlreadyRunningException.class,
                    () -> SingleInstanceLock.acquire(temporaryDirectory));
        }
        try (SingleInstanceLock ignored = SingleInstanceLock.acquire(temporaryDirectory)) {
            assertTrue(Files.exists(temporaryDirectory.resolve("instance.lock")));
        }
    }

    @Test
    void recoveryIsolatesCorruptedStateInsteadOfGuessing() throws Exception {
        FileJobStore store = new FileJobStore(temporaryDirectory);
        ScanJob valid = ScanJob.queued(UUID.randomUUID(), SourceType.ZIP, ScanProfile.QUICK,
                Instant.parse("2026-08-12T00:00:00Z"));
        store.save(StoredScanJob.from(valid));
        UUID corruptedId = UUID.randomUUID();
        Path corruptedDirectory = temporaryDirectory.resolve("jobs").resolve(corruptedId.toString());
        Files.createDirectories(corruptedDirectory);
        Files.writeString(corruptedDirectory.resolve("job.json"), "{not-json");

        JobRecoveryService.RecoveryResult result = new JobRecoveryService(temporaryDirectory).recover();

        assertEquals(1, result.recovered().size());
        assertEquals(valid.id(), result.recovered().get(0).scanId());
        assertEquals(1, result.corrupted().size());
        assertEquals("CORRUPTED_STATE", result.corrupted().get(0).reasonCode());
    }
}
