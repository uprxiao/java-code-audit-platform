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

class SemgrepIntegrityCheckerTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void missingMetadataMakesAnExecutableUnavailableToProfiles() throws Exception {
        Path executable = fakeExecutable();
        ToolInstallationHealth health = checker(executable).check();

        assertFalse(health.available());
        assertEquals("TOOL_METADATA_MISSING", health.reasonCode());
    }

    @Test
    void metadataHashMismatchIsDetectedBeforeExecution() throws Exception {
        Path executable = fakeExecutable();
        Path metadata = executable.getParent().getParent().getParent().resolve("pack-metadata.json");
        Files.writeString(metadata, """
                {"semgrepVersion":"1.170.0","entrypointSha256":"%s"}
                """.formatted("0".repeat(64)));

        ToolInstallationHealth health = checker(executable).check();

        assertFalse(health.available());
        assertEquals("TOOL_SHA256_MISMATCH", health.reasonCode());
    }

    @Test
    void versionProbeCannotRewriteTheBundledPythonRuntime() throws Exception {
        Path executable = fakeExecutable();
        Files.writeString(executable, """
                #!/bin/sh
                [ "${PYTHONDONTWRITEBYTECODE:-}" = "1" ] || exit 17
                printf '1.170.0\n'
                """);
        Path metadata = executable.getParent().getParent().getParent().resolve("pack-metadata.json");
        Files.writeString(metadata, """
                {"semgrepVersion":"1.170.0","entrypointSha256":"%s"}
                """.formatted(sha(executable)));

        ToolInstallationHealth health = checker(executable).check();

        assertTrue(health.available(), health.toString());
    }

    private Path fakeExecutable() throws Exception {
        Path executable = temporaryDirectory.resolve("pack/semgrep/bin/semgrep");
        Files.createDirectories(executable.getParent());
        Files.writeString(executable, "#!/bin/sh\nprintf '1.170.0\\n'\n");
        Files.setPosixFilePermissions(executable, PosixFilePermissions.fromString("rwx------"));
        return executable;
    }

    private SemgrepIntegrityChecker checker(Path executable) {
        AuditRuntimePaths paths = new AuditRuntimePaths(
                temporaryDirectory.resolve("data"), executable, temporaryDirectory.resolve("rules"));
        return new SemgrepIntegrityChecker(
                paths, new LocalProcessExecutionBackend(), new ObjectMapper(), Clock.systemUTC(), "1.170.0");
    }

    private String sha(Path file) throws Exception {
        return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                .digest(Files.readAllBytes(file)));
    }
}
