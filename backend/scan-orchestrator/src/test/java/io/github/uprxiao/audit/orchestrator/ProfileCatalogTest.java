package io.github.uprxiao.audit.orchestrator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.scanner.ResourceClass;
import java.util.List;
import org.junit.jupiter.api.Test;

class ProfileCatalogTest {

    @Test
    void defaultsProduceFrozenV1EngineCounts() {
        ProfileCatalog catalog = ProfileCatalogLoader.loadDefaults();
        assertEquals(6, catalog.plan(ScanProfile.QUICK).engines().size());
        assertEquals(14, catalog.plan(ScanProfile.STANDARD).engines().size());
        assertEquals(15, catalog.plan(ScanProfile.DEEP).engines().size());
    }

    @Test
    void rejectsEngineDependencyCycle() {
        assertThrows(ProfileConfigurationException.class, () -> new ProfileCatalog(List.of(
                profile("quick", "", List.of(engine("gitleaks", List.of("semgrep")),
                        engine("semgrep", List.of("gitleaks")))),
                profile("standard", "quick", List.of()),
                profile("deep", "standard", List.of()))));
    }

    @Test
    void rejectsProfileInheritanceCycle() {
        assertThrows(ProfileConfigurationException.class, () -> new ProfileCatalog(List.of(
                profile("quick", "deep", List.of(engine("gitleaks", List.of()))),
                profile("standard", "quick", List.of()),
                profile("deep", "standard", List.of()))));
    }

    private static ProfileDefinition profile(String name, String parent, List<EngineDefinition> engines) {
        return new ProfileDefinition(name, parent, false, engines);
    }

    private static EngineDefinition engine(String id, List<String> dependencies) {
        return new EngineDefinition(id, false, ResourceClass.LIGHT, 1, 512, 60, dependencies);
    }
}
