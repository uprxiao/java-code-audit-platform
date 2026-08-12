package io.github.uprxiao.audit.finding;

import java.util.List;

public record ScanCoverage(
        int modulesDiscovered,
        int modulesBuilt,
        int modulesScanned,
        List<String> excludedPaths,
        List<EngineCoverage> engines) {

    public ScanCoverage {
        if (modulesDiscovered < 0 || modulesBuilt < 0 || modulesScanned < 0) {
            throw new IllegalArgumentException("module counts must be non-negative");
        }
        if (modulesBuilt > modulesDiscovered || modulesScanned > modulesDiscovered) {
            throw new IllegalArgumentException("module counts are inconsistent");
        }
        excludedPaths = excludedPaths == null ? List.of() : List.copyOf(excludedPaths);
        engines = engines == null ? List.of() : List.copyOf(engines);
    }
}
