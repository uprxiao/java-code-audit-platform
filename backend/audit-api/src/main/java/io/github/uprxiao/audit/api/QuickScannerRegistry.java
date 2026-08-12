package io.github.uprxiao.audit.api;

import io.github.uprxiao.audit.scanner.EngineId;
import io.github.uprxiao.audit.scanner.ScannerAdapter;
import io.github.uprxiao.audit.scanner.ToolContext;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Immutable registry for the six engines that make up the V1 Quick profile. */
final class QuickScannerRegistry {

    private final Map<EngineId, ScannerAdapter> adapters;
    private final ToolContext tools;
    private final List<ToolInstallationHealth> health;

    QuickScannerRegistry(
            List<ScannerAdapter> adapters,
            List<ToolInstallationHealth> health,
            AuditRuntimePaths paths) {
        Objects.requireNonNull(paths, "paths");
        Map<EngineId, ScannerAdapter> byId = new LinkedHashMap<>();
        for (ScannerAdapter adapter : adapters) {
            EngineId id = adapter.descriptor().id();
            if (byId.putIfAbsent(id, adapter) != null) {
                throw new IllegalArgumentException("duplicate scanner adapter: " + id);
            }
        }
        this.adapters = Map.copyOf(byId);
        this.health = List.copyOf(health);
        Map<EngineId, ToolContext.ToolInstallation> installations = new LinkedHashMap<>();
        for (ToolInstallationHealth tool : health) {
            installations.put(new EngineId(tool.id()), new ToolContext.ToolInstallation(
                    tool.executable(), tool.version(), tool.available()));
        }
        this.tools = new ToolContext(paths.quickToolRoot(), installations);
    }

    ScannerAdapter require(EngineId id) {
        ScannerAdapter adapter = adapters.get(id);
        if (adapter == null) {
            throw new IllegalArgumentException("no scanner adapter registered for " + id);
        }
        return adapter;
    }

    Map<EngineId, ScannerAdapter> adapters() {
        return adapters;
    }

    ToolContext tools() {
        return tools;
    }

    List<ToolInstallationHealth> health() {
        return health;
    }

    boolean available() {
        return health.size() == adapters.size() && health.stream().allMatch(ToolInstallationHealth::available);
    }
}
