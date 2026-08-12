package io.github.uprxiao.audit.storage;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.LinkOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

public final class FileJobStore implements JobStore {

    private final Path jobsRoot;
    private final AtomicFileWriter writer;
    private final ObjectMapper json;

    public FileJobStore(Path dataRoot) {
        this(dataRoot, new NioAtomicFileWriter(), defaultMapper());
    }

    public FileJobStore(Path dataRoot, AtomicFileWriter writer, ObjectMapper json) {
        Objects.requireNonNull(dataRoot, "dataRoot");
        this.jobsRoot = dataRoot.toAbsolutePath().normalize().resolve("jobs");
        this.writer = Objects.requireNonNull(writer, "writer");
        this.json = Objects.requireNonNull(json, "json");
    }

    @Override
    public synchronized void save(StoredScanJob job) throws IOException {
        Objects.requireNonNull(job, "job");
        Optional<StoredScanJob> current = find(job.scanId());
        if (current.isPresent() && job.revision() <= current.get().revision()) {
            throw new StaleJobRevisionException(job.scanId(), current.get().revision(), job.revision());
        }
        writer.write(jobFile(job.scanId()), json.writerWithDefaultPrettyPrinter().writeValueAsBytes(job));
    }

    @Override
    public Optional<StoredScanJob> find(UUID scanId) throws IOException {
        Path file = jobFile(scanId);
        if (Files.isSymbolicLink(file.getParent()) || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            return Optional.empty();
        }
        return Optional.of(json.readValue(file.toFile(), StoredScanJob.class));
    }

    @Override
    public List<StoredScanJob> list() throws IOException {
        if (!Files.isDirectory(jobsRoot)) {
            return List.of();
        }
        List<StoredScanJob> result = new ArrayList<>();
        try (Stream<Path> directories = Files.list(jobsRoot)) {
            for (Path directory : directories
                    .filter(path -> Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS))
                    .filter(path -> !Files.isSymbolicLink(path)).toList()) {
                try {
                    UUID id = UUID.fromString(directory.getFileName().toString());
                    find(id).ifPresent(result::add);
                } catch (IllegalArgumentException ignored) {
                    // A non-job directory is not part of the in-memory index.
                }
            }
        }
        result.sort(Comparator.comparing(StoredScanJob::createdAt));
        return List.copyOf(result);
    }

    private Path jobFile(UUID scanId) {
        Objects.requireNonNull(scanId, "scanId");
        Path result = jobsRoot.resolve(scanId.toString()).resolve("job.json").normalize();
        if (!result.startsWith(jobsRoot)) {
            throw new IllegalArgumentException("scan id escapes jobs root");
        }
        return result;
    }

    public static ObjectMapper defaultMapper() {
        return new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    }
}
