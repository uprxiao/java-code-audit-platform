package io.github.uprxiao.audit.storage;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Stream;

public final class JobRecoveryService {

    private final Path jobsRoot;
    private final ObjectMapper json;

    public JobRecoveryService(Path dataRoot) {
        this(dataRoot, FileJobStore.defaultMapper());
    }

    public JobRecoveryService(Path dataRoot, ObjectMapper json) {
        Objects.requireNonNull(dataRoot, "dataRoot");
        this.jobsRoot = dataRoot.toAbsolutePath().normalize().resolve("jobs");
        this.json = Objects.requireNonNull(json, "json");
    }

    public RecoveryResult recover() throws IOException {
        if (!Files.isDirectory(jobsRoot)) {
            return new RecoveryResult(List.of(), List.of());
        }
        List<StoredScanJob> recovered = new ArrayList<>();
        List<CorruptedJobState> corrupted = new ArrayList<>();
        try (Stream<Path> entries = Files.list(jobsRoot)) {
            for (Path directory : entries.filter(Files::isDirectory).sorted().toList()) {
                UUID scanId;
                try {
                    scanId = UUID.fromString(directory.getFileName().toString());
                } catch (IllegalArgumentException exception) {
                    continue;
                }
                Path stateFile = directory.resolve("job.json");
                if (!Files.isRegularFile(stateFile)) {
                    corrupted.add(new CorruptedJobState(scanId, stateFile, "JOB_STATE_MISSING"));
                    continue;
                }
                try {
                    recovered.add(json.readValue(stateFile.toFile(), StoredScanJob.class));
                } catch (IOException | RuntimeException exception) {
                    corrupted.add(new CorruptedJobState(scanId, stateFile, "CORRUPTED_STATE"));
                }
            }
        }
        recovered.sort(Comparator.comparing(StoredScanJob::createdAt));
        return new RecoveryResult(recovered, corrupted);
    }

    public record RecoveryResult(List<StoredScanJob> recovered, List<CorruptedJobState> corrupted) {
        public RecoveryResult {
            recovered = List.copyOf(recovered);
            corrupted = List.copyOf(corrupted);
        }
    }

    public record CorruptedJobState(UUID scanId, Path stateFile, String reasonCode) {
    }
}
