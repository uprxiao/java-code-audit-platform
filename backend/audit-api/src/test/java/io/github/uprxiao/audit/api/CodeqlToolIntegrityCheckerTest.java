package io.github.uprxiao.audit.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.uprxiao.audit.process.LocalProcessExecutionBackend;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
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

    @Test
    void authorizationAndTermsAreAuditableIndependentGates() throws Exception {
        AuditRuntimePaths paths = new AuditRuntimePaths(
                temporaryDirectory.resolve("gate-data"),
                Path.of(System.getProperty("java.home"), "bin", "java"),
                temporaryDirectory.resolve("rules"));
        AuditRuntimeConfiguration configuration = new AuditRuntimeConfiguration();
        LocalProcessExecutionBackend processes = new LocalProcessExecutionBackend();

        ToolInstallationHealth disabled = configuration.controlledCodeqlHealth(
                paths, processes, Clock.systemUTC(), false, false);
        ToolInstallationHealth terms = configuration.controlledCodeqlHealth(
                paths, processes, Clock.systemUTC(), true, false);

        assertEquals("CODEQL_DISABLED", disabled.reasonCode());
        assertEquals("CODEQL_TERMS_NOT_ACCEPTED", terms.reasonCode());
        assertFalse(disabled.available());
        assertTrue(disabled.detail().contains("AUDIT_CODEQL_ENABLED"));
    }

    @Test
    void probePathIncludesRequiredOperatingSystemCommands() throws Exception {
        Path executable = temporaryDirectory.resolve("codeql/codeql");
        Files.createDirectories(executable.getParent());
        Files.writeString(executable, """
                #!/bin/sh
                uname >/dev/null || exit 3
                printf '{\"version\":\"2.26.2\"}\\n'
                """);
        Files.setPosixFilePermissions(executable, PosixFilePermissions.fromString("rwxr-xr-x"));
        Path pack = temporaryDirectory.resolve("packs/codeql/java-queries/1.11.7");
        Path suite = pack.resolve("codeql-suites/java-security-and-quality.qls");
        Files.createDirectories(suite.getParent());
        Files.writeString(suite, "- description: acceptance fixture\n");
        Files.writeString(pack.resolve("qlpack.yml"), "name: codeql/java-queries\nversion: 1.11.7\n");
        AuditRuntimePaths defaults = new AuditRuntimePaths(
                temporaryDirectory.resolve("probe-data"), executable, temporaryDirectory.resolve("rules"));
        AuditRuntimePaths paths = new AuditRuntimePaths(
                defaults.dataRoot(), defaults.semgrepExecutable(), defaults.semgrepRules(),
                defaults.quickToolRoot(), defaults.standardAnalysisToolRoot(), defaults.standardSupplyToolRoot(),
                defaults.vulnerabilityDataRoot(), executable, suite, defaults.gitleaksRules(), defaults.pmdRules(),
                defaults.checkstyleRules(), defaults.spotbugsExcludeFilter());

        ToolInstallationHealth health = new CodeqlToolIntegrityChecker(
                paths, new LocalProcessExecutionBackend(), new ObjectMapper(), Clock.systemUTC()).check();

        assertEquals("AVAILABLE", health.status());
        assertEquals("2.26.2", health.version());
    }
}
