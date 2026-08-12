package io.github.uprxiao.audit.finding;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

class ScanJobTest {

    @Test
    void createsQueuedJob() {
        ScanJob job = ScanJob.queued(SourceType.ZIP, ScanProfile.STANDARD);

        assertNotNull(job.id());
        assertNotNull(job.createdAt());
        assertEquals(ScanStatus.QUEUED, job.status());
    }
}
