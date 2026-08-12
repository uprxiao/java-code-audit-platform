package io.github.uprxiao.audit.orchestrator;

import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.scanner.EngineId;
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public final class ProfileCatalog {

    private final Map<ScanProfile, List<PlannedEngine>> plans;

    public ProfileCatalog(List<ProfileDefinition> definitions) {
        Objects.requireNonNull(definitions, "definitions");
        Map<String, ProfileDefinition> byName = index(definitions);
        requireAllProfiles(byName);
        this.plans = new EnumMap<>(ScanProfile.class);
        for (ScanProfile profile : ScanProfile.values()) {
            LinkedHashMap<EngineId, EngineDefinition> resolved = resolve(
                    profile.name().toLowerCase(Locale.ROOT), byName, new HashSet<>());
            validateDag(resolved);
            plans.put(profile, resolved.values().stream().map(this::toPlannedEngine).toList());
        }
    }

    public ScanPlan plan(ScanProfile profile) {
        Objects.requireNonNull(profile, "profile");
        return new ScanPlan(profile, plans.get(profile));
    }

    private Map<String, ProfileDefinition> index(List<ProfileDefinition> definitions) {
        Map<String, ProfileDefinition> result = new HashMap<>();
        for (ProfileDefinition definition : definitions) {
            if (definition.name() == null || definition.name().isBlank()) {
                throw new ProfileConfigurationException("profile name must not be blank");
            }
            String name = definition.name().toLowerCase(Locale.ROOT);
            if (result.put(name, definition) != null) {
                throw new ProfileConfigurationException("duplicate profile: " + name);
            }
        }
        return result;
    }

    private void requireAllProfiles(Map<String, ProfileDefinition> byName) {
        for (ScanProfile profile : ScanProfile.values()) {
            String name = profile.name().toLowerCase(Locale.ROOT);
            if (!byName.containsKey(name)) {
                throw new ProfileConfigurationException("missing V1 profile: " + name);
            }
        }
    }

    private LinkedHashMap<EngineId, EngineDefinition> resolve(
            String name, Map<String, ProfileDefinition> byName, Set<String> visiting) {
        ProfileDefinition definition = byName.get(name);
        if (definition == null) {
            throw new ProfileConfigurationException("unknown parent profile: " + name);
        }
        if (!visiting.add(name)) {
            throw new ProfileConfigurationException("profile inheritance cycle at: " + name);
        }
        LinkedHashMap<EngineId, EngineDefinition> result = new LinkedHashMap<>();
        if (!definition.parent().isBlank()) {
            result.putAll(resolve(definition.parent().toLowerCase(Locale.ROOT), byName, visiting));
        }
        for (EngineDefinition engine : definition.engines()) {
            validateEngine(engine);
            EngineId id = new EngineId(engine.id());
            if (result.putIfAbsent(id, engine) != null) {
                throw new ProfileConfigurationException("duplicate inherited engine " + id + " in profile " + name);
            }
        }
        visiting.remove(name);
        boolean derivedRequiresBuild = result.values().stream().anyMatch(EngineDefinition::requiresBuild);
        if (definition.requiresBuild() != derivedRequiresBuild) {
            throw new ProfileConfigurationException("requiresBuild does not match engines for profile " + name);
        }
        return result;
    }

    private void validateEngine(EngineDefinition engine) {
        if (engine.id() == null) {
            throw new ProfileConfigurationException("engine id must not be null");
        }
        new EngineId(engine.id());
        if (engine.resourceClass() == null || engine.weight() < 1 || engine.memoryMb() < 1 || engine.timeoutSeconds() < 1) {
            throw new ProfileConfigurationException("invalid resources for engine: " + engine.id());
        }
    }

    private void validateDag(LinkedHashMap<EngineId, EngineDefinition> engines) {
        Map<EngineId, Set<EngineId>> graph = new HashMap<>();
        for (Map.Entry<EngineId, EngineDefinition> entry : engines.entrySet()) {
            Set<EngineId> dependencies = new HashSet<>();
            for (String dependencyValue : entry.getValue().dependsOn()) {
                EngineId dependency = new EngineId(dependencyValue);
                if (!engines.containsKey(dependency)) {
                    throw new ProfileConfigurationException(entry.getKey() + " depends on unknown engine " + dependency);
                }
                dependencies.add(dependency);
            }
            graph.put(entry.getKey(), dependencies);
        }
        Set<EngineId> complete = new HashSet<>();
        Set<EngineId> visiting = new HashSet<>();
        for (EngineId engine : graph.keySet()) {
            visit(engine, graph, visiting, complete);
        }
    }

    private void visit(
            EngineId engine,
            Map<EngineId, Set<EngineId>> graph,
            Set<EngineId> visiting,
            Set<EngineId> complete) {
        if (complete.contains(engine)) {
            return;
        }
        if (!visiting.add(engine)) {
            throw new ProfileConfigurationException("engine dependency cycle at: " + engine);
        }
        for (EngineId dependency : graph.getOrDefault(engine, Set.of())) {
            visit(dependency, graph, visiting, complete);
        }
        visiting.remove(engine);
        complete.add(engine);
    }

    private PlannedEngine toPlannedEngine(EngineDefinition definition) {
        return new PlannedEngine(
                ScanEngine.fromId(new EngineId(definition.id())),
                definition.requiresBuild(),
                definition.resourceClass(),
                definition.weight(),
                definition.memoryMb(),
                Duration.ofSeconds(definition.timeoutSeconds()),
                definition.dependsOn().stream().map(EngineId::new).map(ScanEngine::fromId).toList());
    }
}
