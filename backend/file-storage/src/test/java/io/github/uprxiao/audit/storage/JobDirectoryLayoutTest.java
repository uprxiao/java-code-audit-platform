package io.github.uprxiao.audit.storage;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class JobDirectoryLayoutTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void createsTheFrozenTaskLayoutAndRejectsEscapes() throws Exception {
        JobDirectoryLayout layout = new JobDirectoryLayout(temporaryDirectory, UUID.randomUUID());
        layout.initialize();

        assertTrue(Files.isDirectory(layout.source()));
        assertTrue(Files.isDirectory(layout.workspace()));
        assertTrue(Files.isDirectory(layout.report()));
        assertTrue(layout.rawEngine("semgrep").startsWith(layout.root()));
        assertThrows(IllegalArgumentException.class, () -> layout.safeResolve("../../outside"));
        assertThrows(IllegalArgumentException.class, () -> layout.rawEngine("../outside"));
    }
}
