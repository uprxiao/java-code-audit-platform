package io.github.uprxiao.audit.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.uprxiao.audit.process.LocalProcessExecutionBackend;
import io.github.uprxiao.audit.storage.NioAtomicFileWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class StartupPrerequisiteCheckerTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void verifiesSystemMavenUsesTheRunningJdkAndPersistsSnapshot() throws Exception {
        AuditRuntimePaths paths = new AuditRuntimePaths(
                temporaryDirectory, temporaryDirectory.resolve("semgrep"), temporaryDirectory.resolve("rules"));
        StartupPrerequisiteChecker checker = new StartupPrerequisiteChecker(
                paths, new LocalProcessExecutionBackend(), new NioAtomicFileWriter(),
                new ObjectMapper().findAndRegisterModules(), Clock.systemUTC(), "mvn", 1, missingSemgrep(paths));

        StartupHealthSnapshot snapshot = checker.checkAndPersist();

        assertEquals("DEGRADED", snapshot.status());
        assertTrue(snapshot.mavenVersion().startsWith("3."));
        assertEquals("17", snapshot.mavenJavaVersion());
        assertTrue(Files.readString(temporaryDirectory.resolve("health/startup.json"))
                .contains("\"status\":\"DEGRADED\""));
    }

    @Test
    void rejectsAnImpossibleDiskMinimumBeforeAcceptingWork() {
        AuditRuntimePaths paths = new AuditRuntimePaths(
                temporaryDirectory, temporaryDirectory.resolve("semgrep"), temporaryDirectory.resolve("rules"));
        StartupPrerequisiteChecker checker = new StartupPrerequisiteChecker(
                paths, new LocalProcessExecutionBackend(), new NioAtomicFileWriter(),
                new ObjectMapper().findAndRegisterModules(), Clock.systemUTC(), "mvn", Long.MAX_VALUE,
                missingSemgrep(paths));

        assertThrows(IllegalStateException.class, checker::checkAndPersist);
    }

    private ToolInstallationHealth missingSemgrep(AuditRuntimePaths paths) {
        return new ToolInstallationHealth(
                "semgrep", "UNAVAILABLE", "", paths.semgrepExecutable(), "",
                "EXECUTABLE_NOT_FOUND", "test fixture", Instant.EPOCH);
    }
}
