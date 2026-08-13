package io.github.uprxiao.audit.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.uprxiao.audit.process.LocalProcessExecutionBackend;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class StandardSupplyToolIntegrityCheckerTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void requiredDatabasesGateStandardSupplyWithoutClaimingCleanResults() throws Exception {
        Fixture fixture = fixture();

        List<ToolInstallationHealth> missing = fixture.checker().checkAll();
        assertEquals("VULNERABILITY_DATABASE_UNAVAILABLE", health(missing, "dependency-check").reasonCode());
        assertEquals("VULNERABILITY_DATABASE_UNAVAILABLE", health(missing, "trivy-artifact").reasonCode());
        assertTrue(health(missing, "osv-scanner").available());
        assertTrue(health(missing, "cyclonedx").available());

        Files.createDirectories(fixture.paths().dependencyCheckData());
        Path database = fixture.paths().dependencyCheckData().resolve("odc.mv.db");
        Files.writeString(database, "database");
        writeTrivyDatabase(fixture.paths().vulnerabilityTrivyCache());

        List<ToolInstallationHealth> missingProvenance = fixture.checker().checkAll();
        assertEquals("VULNERABILITY_DATABASE_PROVENANCE_UNAVAILABLE",
                health(missingProvenance, "dependency-check").reasonCode());

        Files.writeString(fixture.paths().dependencyCheckData().resolve("ACCEPTANCE-ONLY.txt"), "never production");
        List<ToolInstallationHealth> acceptanceOnly = fixture.checker().checkAll();
        assertEquals("VULNERABILITY_DATABASE_NON_PRODUCTION",
                health(acceptanceOnly, "dependency-check").reasonCode());

        Files.delete(fixture.paths().dependencyCheckData().resolve("ACCEPTANCE-ONLY.txt"));
        writeDependencyCheckMetadata(fixture.paths().dependencyCheckData(), database,
                Instant.parse("2026-08-11T00:00:00Z"));

        List<ToolInstallationHealth> available = fixture.checker().checkAll();
        assertTrue(available.stream().allMatch(ToolInstallationHealth::available), available.toString());
        assertEquals("2.9.3", health(available, "cyclonedx").version());
        assertEquals(false, health(available, "dependency-check").database().get("stale"));
        assertEquals("2/2", health(available, "trivy-artifact").database().get("version"));

        writeDependencyCheckMetadata(fixture.paths().dependencyCheckData(), database,
                Instant.parse("2026-08-01T00:00:00Z"));
        Files.writeString(fixture.paths().vulnerabilityTrivyCache().resolve("db/metadata.json"),
                "{\"Version\":2,\"UpdatedAt\":\"2026-08-01T00:00:00Z\"}");
        List<ToolInstallationHealth> stale = fixture.checker().checkAll();
        assertEquals("DEGRADED", health(stale, "dependency-check").status());
        assertEquals("DEGRADED", health(stale, "trivy-artifact").status());
        assertTrue(health(stale, "dependency-check").available(), "stale data remains controlled but usable");
    }

    @Test
    void rejectsAProductionDatabaseWhoseContentNoLongerMatchesItsProvenance() throws Exception {
        Fixture fixture = fixture();
        Path data = Files.createDirectories(fixture.paths().dependencyCheckData());
        Path database = data.resolve("odc.mv.db");
        Files.writeString(database, "original database");
        writeDependencyCheckMetadata(data, database, Instant.parse("2026-08-11T00:00:00Z"));
        Files.writeString(database, "tampered database");

        assertEquals("VULNERABILITY_DATABASE_SHA256_MISMATCH",
                health(fixture.checker().checkAll(), "dependency-check").reasonCode());
    }

    private Fixture fixture() throws Exception {
        Path supply = temporaryDirectory.resolve("standard-supply");
        Path dcDirectory = supply.resolve("dependency-check");
        Path dc = dcDirectory.resolve("dependency-check/bin/dependency-check.sh");
        script(dc, "echo 'Dependency-Check Core version 12.2.2'");
        metadata(dcDirectory.resolve("pack-metadata.json"), "dependency-check", "12.2.2",
                "dependency-check/bin/dependency-check.sh", sha(dc), "", "");

        Path osvDirectory = supply.resolve("osv-scanner");
        Path osv = osvDirectory.resolve("bin/osv-scanner");
        Path osvReal = osvDirectory.resolve("bin/osv-scanner.real");
        script(osv, "echo 'osv-scanner version: 2.3.8'");
        script(osvReal, "echo 'upstream binary'");
        metadata(osvDirectory.resolve("pack-metadata.json"), "osv-scanner", "2.3.8",
                "bin/osv-scanner", sha(osv), "bin/osv-scanner.real", sha(osvReal));

        Path maven = temporaryDirectory.resolve("bin/mvn");
        script(maven, "printf 'Apache Maven 3.9.11\\nJava version: 17.0.16, vendor: test\\n'");
        Path cyclone = supply.resolve("cyclonedx/pack-metadata.json");
        Files.createDirectories(cyclone.getParent());
        Files.writeString(cyclone, """
                {"id":"cyclonedx","version":"2.9.3",
                 "coordinate":"org.cyclonedx:cyclonedx-maven-plugin:2.9.3",
                 "artifactSha256":"c452d5eebe28bc86bef2e7c72d129f04f60877bef843eac8120f01fb655be293"}
                """);

        AuditRuntimePaths defaults = new AuditRuntimePaths(
                temporaryDirectory.resolve("data"), maven, temporaryDirectory.resolve("rules"));
        AuditRuntimePaths paths = new AuditRuntimePaths(
                defaults.dataRoot(), defaults.semgrepExecutable(), defaults.semgrepRules(),
                defaults.quickToolRoot(), defaults.standardAnalysisToolRoot(), supply,
                temporaryDirectory.resolve("databases"), defaults.codeqlExecutable(), defaults.codeqlQuerySuite(),
                defaults.gitleaksRules(), defaults.pmdRules(), defaults.checkstyleRules(),
                defaults.spotbugsExcludeFilter());
        ToolInstallationHealth quickTrivy = new ToolInstallationHealth(
                "trivy-repository", "AVAILABLE", "0.73.0", maven, sha(maven), "", "",
                Instant.parse("2026-08-12T00:00:00Z"));
        StandardSupplyToolIntegrityChecker checker = new StandardSupplyToolIntegrityChecker(
                paths, new LocalProcessExecutionBackend(), new ObjectMapper(),
                Clock.fixed(Instant.parse("2026-08-12T00:00:00Z"), ZoneOffset.UTC),
                maven.toString(), maven.getParent().toString(), List.of(quickTrivy));
        return new Fixture(paths, checker);
    }

    private void metadata(
            Path target, String id, String version, String entrypoint, String entrySha,
            String upstream, String upstreamSha) throws Exception {
        Files.createDirectories(target.getParent());
        String optional = upstream.isBlank() ? "" : ",\"upstreamBinary\":\"" + upstream
                + "\",\"upstreamBinarySha256\":\"" + upstreamSha + "\"";
        Files.writeString(target, "{\"id\":\"" + id + "\",\"version\":\"" + version
                + "\",\"entrypoint\":\"" + entrypoint + "\",\"entrypointSha256\":\""
                + entrySha + "\"" + optional + "}");
    }

    private void script(Path target, String body) throws Exception {
        Files.createDirectories(target.getParent());
        Files.writeString(target, "#!/bin/sh\n" + body + "\n", StandardCharsets.UTF_8);
        target.toFile().setExecutable(true, false);
    }

    private void writeTrivyDatabase(Path root) throws Exception {
        for (String folder : List.of("db", "java-db")) {
            Path directory = Files.createDirectories(root.resolve(folder));
            Files.writeString(directory.resolve("metadata.json"),
                    "{\"Version\":2,\"UpdatedAt\":\"2026-08-11T00:00:00Z\"}");
        }
        Files.writeString(root.resolve("db/trivy.db"), "database");
        Files.writeString(root.resolve("java-db/trivy-java.db"), "java database");
    }

    private void writeDependencyCheckMetadata(Path root, Path database, Instant updatedAt) throws Exception {
        Files.writeString(root.resolve("database-metadata.json"), """
                {"schemaVersion":1,"id":"dependency-check-nvd","mode":"production-full",
                 "productionUseProhibited":false,"dependencyCheckVersion":"12.2.2","source":"nvd-api",
                 "databaseFile":"%s","databaseSha256":"%s","databaseSizeBytes":%d,"updatedAt":"%s"}
                """.formatted(database.getFileName(), sha(database), Files.size(database), updatedAt));
    }

    private ToolInstallationHealth health(List<ToolInstallationHealth> health, String id) {
        return health.stream().filter(value -> id.equals(value.id())).findFirst().orElseThrow();
    }

    private String sha(Path file) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file)));
    }

    private record Fixture(AuditRuntimePaths paths, StandardSupplyToolIntegrityChecker checker) { }
}
