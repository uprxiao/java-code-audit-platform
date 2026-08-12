package io.github.uprxiao.audit.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.uprxiao.audit.process.LocalProcessExecutionBackend;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CodeqlToolIntegrityCheckerTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void missingControlledLocalInstallationMakesOnlyCodeqlUnavailable() throws Exception {
        AuditRuntimePaths paths = new AuditRuntimePaths(
                temporaryDirectory.resolve("data"),
                Path.of(System.getProperty("java.home"), "bin", "java"),
                temporaryDirectory.resolve("rules"));

        ToolInstallationHealth health = new CodeqlToolIntegrityChecker(
                paths, new LocalProcessExecutionBackend(), new ObjectMapper(), Clock.systemUTC()).check();

        assertEquals("codeql", health.id());
        assertEquals("UNAVAILABLE", health.status());
        assertEquals("EXECUTABLE_NOT_FOUND", health.reasonCode());
        assertFalse(health.available());
    }
}
