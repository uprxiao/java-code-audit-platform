package io.github.uprxiao.audit.api;

import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.orchestrator.DefaultScanPlanner;
import io.github.uprxiao.audit.orchestrator.ScanPlan;
import io.github.uprxiao.audit.scanner.EngineId;
import io.github.uprxiao.audit.scanner.ScannerAdapter;
import io.github.uprxiao.audit.scanner.ToolContext;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable registry for every installed logical scanner.
 *
 * <p>Profile membership is deliberately not duplicated here. The frozen YAML profile catalog is
 * the only source for the engine plan; this registry only answers whether that plan can be
 * executed by the current installation.</p>
 */
final class ScannerRegistry {

    private final Map<EngineId, ScannerAdapter> adapters;
    private final Map<EngineId, ToolInstallationHealth> healthByEngine;
    private final List<ToolInstallationHealth> health;
    private final ToolContext tools;
    private final DefaultScanPlanner planner;
    private final boolean mavenBuildAvailable;

    ScannerRegistry(
            List<ScannerAdapter> adapters,
            List<ToolInstallationHealth> health,
            AuditRuntimePaths paths,
            DefaultScanPlanner planner,
            boolean mavenBuildAvailable) {
        Objects.requireNonNull(paths, "paths");
        this.planner = Objects.requireNonNull(planner, "planner");
        this.mavenBuildAvailable = mavenBuildAvailable;

        Map<EngineId, ScannerAdapter> byId = new LinkedHashMap<>();
        for (ScannerAdapter adapter : Objects.requireNonNull(adapters, "adapters")) {
            EngineId id = adapter.descriptor().id();
            if (byId.putIfAbsent(id, adapter) != null) {
                throw new IllegalArgumentException("duplicate scanner adapter: " + id);
            }
        }
        this.adapters = Map.copyOf(byId);

        Map<EngineId, ToolInstallationHealth> installationsById = new LinkedHashMap<>();
        for (ToolInstallationHealth installation : Objects.requireNonNull(health, "health")) {
            EngineId id = new EngineId(installation.id());
            if (installationsById.putIfAbsent(id, installation) != null) {
                throw new IllegalArgumentException("duplicate tool health: " + id);
            }
        }
        this.healthByEngine = Map.copyOf(installationsById);
        this.health = List.copyOf(health);

        Map<EngineId, ToolContext.ToolInstallation> toolInstallations = new LinkedHashMap<>();
        installationsById.forEach((id, installation) -> toolInstallations.put(id,
                new ToolContext.ToolInstallation(
                        installation.executable(), installation.version(), installation.available())));
        this.tools = new ToolContext(paths.quickToolRoot(), toolInstallations);
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

    boolean available(ScanProfile profile) {
        return unavailable(profile).isEmpty();
    }

    List<String> unavailable(ScanProfile profile) {
        ScanPlan plan = planner.plan(profile);
        List<String> reasons = new ArrayList<>();
        if (plan.plannedEngines().stream().anyMatch(engine -> engine.requiresBuild()) && !mavenBuildAvailable) {
            reasons.add("maven-build:TOOL_UNAVAILABLE");
        }
        for (var engine : plan.engines()) {
            if (!adapters.containsKey(engine.id())) {
                reasons.add(engine.id() + ":ADAPTER_NOT_REGISTERED");
                continue;
            }
            ToolInstallationHealth installation = healthByEngine.get(engine.id());
            if (installation == null) {
                reasons.add(engine.id() + ":TOOL_HEALTH_MISSING");
            } else if (!installation.available()) {
                String reason = installation.reasonCode().isBlank()
                        ? installation.status() : installation.reasonCode();
                reasons.add(engine.id() + ":" + reason);
            }
        }
        return List.copyOf(reasons);
    }

    Map<String, String> profileAvailability() {
        Map<ScanProfile, String> statuses = new EnumMap<>(ScanProfile.class);
        for (ScanProfile profile : ScanProfile.values()) {
            statuses.put(profile, available(profile) ? "AVAILABLE" : "UNAVAILABLE");
        }
        Map<String, String> result = new LinkedHashMap<>();
        statuses.forEach((profile, status) -> result.put(profile.name(), status));
        return Map.copyOf(result);
    }
}
