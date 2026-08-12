package io.github.uprxiao.audit.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.orchestrator.DefaultScanPlanner;
import io.github.uprxiao.audit.scanner.Applicability;
import io.github.uprxiao.audit.scanner.ArtifactValidation;
import io.github.uprxiao.audit.scanner.EngineDescriptor;
import io.github.uprxiao.audit.scanner.EngineId;
import io.github.uprxiao.audit.scanner.ExecutionSpec;
import io.github.uprxiao.audit.scanner.NormalizationResult;
import io.github.uprxiao.audit.scanner.RawArtifactSet;
import io.github.uprxiao.audit.scanner.ResourceClass;
import io.github.uprxiao.audit.scanner.ResourceRequest;
import io.github.uprxiao.audit.scanner.ScanContext;
import io.github.uprxiao.audit.scanner.ScannerAdapter;
import io.github.uprxiao.audit.scanner.ToolContext;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ScannerRegistryTest {

    @TempDir
    Path temporaryDirectory;

    private final DefaultScanPlanner planner = new DefaultScanPlanner();

    @Test
    void derivesAvailabilityFromTheYamlPlanAndNeverClaimsAnIncompleteStandard() {
        List<String> quick = planner.plan(ScanProfile.QUICK).engines().stream()
                .map(engine -> engine.id().value()).toList();
        List<String> firstTen = planner.plan(ScanProfile.STANDARD).engines().stream()
                .map(engine -> engine.id().value()).limit(10).toList();
        ScannerRegistry registry = registry(firstTen, true);

        assertTrue(registry.available(ScanProfile.QUICK));
        assertFalse(registry.available(ScanProfile.STANDARD));
        assertEquals("AVAILABLE", registry.profileAvailability().get("QUICK"));
        assertEquals("UNAVAILABLE", registry.profileAvailability().get("STANDARD"));
        assertEquals(4, registry.unavailable(ScanProfile.STANDARD).size());
        assertTrue(registry.unavailable(ScanProfile.STANDARD).stream()
                .allMatch(reason -> reason.endsWith(":ADAPTER_NOT_REGISTERED")));
        assertEquals(6, quick.size());
    }

    @Test
    void opensStandardOnlyWhenAllFourteenLogicalEnginesAndMavenBuildAreAvailable() {
        List<String> standard = planner.plan(ScanProfile.STANDARD).engines().stream()
                .map(engine -> engine.id().value()).toList();

        ScannerRegistry available = registry(standard, true);
        ScannerRegistry noMaven = registry(standard, false);

        assertEquals(14, available.adapters().size());
        assertTrue(available.available(ScanProfile.STANDARD));
        assertFalse(available.available(ScanProfile.DEEP));
        assertFalse(noMaven.available(ScanProfile.STANDARD));
        assertTrue(noMaven.unavailable(ScanProfile.STANDARD).contains("maven-build:TOOL_UNAVAILABLE"));
    }

    @Test
    void codeqlHealthOpensDeepWithoutChangingQuickOrStandard() {
        List<String> deep = planner.plan(ScanProfile.DEEP).engines().stream()
                .map(engine -> engine.id().value()).toList();
        ScannerRegistry registry = registry(deep, true);

        assertEquals(15, registry.adapters().size());
        assertTrue(registry.available(ScanProfile.QUICK));
        assertTrue(registry.available(ScanProfile.STANDARD));
        assertTrue(registry.available(ScanProfile.DEEP));
    }

    @Test
    void rejectsDuplicateLogicalAdaptersAndHealthEntries() {
        ScannerAdapter duplicate = new StubAdapter("semgrep");
        List<ToolInstallationHealth> health = List.of(health("semgrep"));
        AuditRuntimePaths paths = paths();
        assertThrows(IllegalArgumentException.class, () -> new ScannerRegistry(
                List.of(duplicate, duplicate), health, paths, planner, true));
        assertThrows(IllegalArgumentException.class, () -> new ScannerRegistry(
                List.of(duplicate), List.of(health("semgrep"), health("semgrep")), paths, planner, true));
    }

    private ScannerRegistry registry(List<String> ids, boolean maven) {
        return new ScannerRegistry(
                ids.stream().map(StubAdapter::new).map(ScannerAdapter.class::cast).toList(),
                ids.stream().map(this::health).toList(), paths(), planner, maven);
    }

    private ToolInstallationHealth health(String id) {
        return new ToolInstallationHealth(
                id, "AVAILABLE", "test", Path.of(System.getProperty("java.home"), "bin", "java"),
                "sha256", "", "", Instant.parse("2026-08-12T00:00:00Z"));
    }

    private AuditRuntimePaths paths() {
        return new AuditRuntimePaths(
                temporaryDirectory.resolve("data"),
                Path.of(System.getProperty("java.home"), "bin", "java"),
                temporaryDirectory.resolve("rules.yaml"));
    }

    private static final class StubAdapter implements ScannerAdapter {
        private final EngineDescriptor descriptor;

        private StubAdapter(String id) {
            descriptor = new EngineDescriptor(new EngineId(id), id, false,
                    new ResourceRequest(ResourceClass.LIGHT, 1, 128), Duration.ofSeconds(10), Set.of());
        }

        @Override
        public EngineDescriptor descriptor() {
            return descriptor;
        }

        @Override
        public Applicability checkApplicability(io.github.uprxiao.audit.intake.ProjectContext project, ToolContext tools) {
            return Applicability.applicable();
        }

        @Override
        public ExecutionSpec prepare(ScanContext context, ToolContext tools) {
            throw new UnsupportedOperationException();
        }

        @Override
        public ArtifactValidation validate(RawArtifactSet artifacts) {
            throw new UnsupportedOperationException();
        }

        @Override
        public NormalizationResult normalize(ScanContext context, RawArtifactSet artifacts) {
            throw new UnsupportedOperationException();
        }
    }
}
