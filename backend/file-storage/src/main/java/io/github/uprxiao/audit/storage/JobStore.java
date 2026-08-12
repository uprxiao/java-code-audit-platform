package io.github.uprxiao.audit.storage;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface JobStore {
    void save(StoredScanJob job) throws IOException;

    Optional<StoredScanJob> find(UUID scanId) throws IOException;

    List<StoredScanJob> list() throws IOException;
}
