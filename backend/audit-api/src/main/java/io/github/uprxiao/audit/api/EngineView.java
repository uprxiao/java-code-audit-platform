package io.github.uprxiao.audit.api;

import io.github.uprxiao.audit.finding.EngineCoverage;
import io.github.uprxiao.audit.finding.EngineStatus;
import java.time.Instant;
import java.util.List;
import java.util.Map;

public record EngineView(
        String engineId,
        EngineStatus status,
        List<String> dependencies,
        boolean requiresBuild,
        String toolVersion,
        Instant createdAt,
        Instant updatedAt,
        Instant startedAt,
        Instant completedAt,
        long waitingMillis,
        long durationMillis,
        EngineCoverage coverage,
        Map<String, Object> failure,
        boolean rawArtifactAvailable,
        boolean stdoutLogAvailable,
        boolean stderrLogAvailable) {
}
