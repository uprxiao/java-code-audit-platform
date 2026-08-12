package io.github.uprxiao.audit.storage;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class JobTemporaryFileCleanerTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void successfulCleanupPreservesReportsRawLogsAndState() throws Exception {
        JobDirectoryLayout layout = new JobDirectoryLayout(temporaryDirectory, UUID.randomUUID());
        layout.initialize();
        Files.writeString(layout.source().resolve("upload.zip"), "source");
        Files.writeString(layout.workspace().resolve("App.java"), "class App {}");
        Files.writeString(layout.report().resolve("report.json"), "{}");
        Files.createDirectories(layout.rawEngine("semgrep"));
        Files.writeString(layout.rawEngine("semgrep").resolve("report.json"), "{}");
        Files.writeString(layout.jobFile(), "{}");

        new JobTemporaryFileCleaner().cleanSuccessfulJob(layout);

        assertFalse(Files.exists(layout.source()));
        assertFalse(Files.exists(layout.workspace()));
        assertTrue(Files.exists(layout.report().resolve("report.json")));
        assertTrue(Files.exists(layout.rawEngine("semgrep").resolve("report.json")));
        assertTrue(Files.exists(layout.jobFile()));
    }
}
