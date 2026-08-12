package io.github.uprxiao.audit.api;

import java.io.IOException;
import java.nio.file.Files;

final class StorageCapacityGuard {

    private final AuditRuntimePaths paths;
    private final long minimumFreeBytes;

    StorageCapacityGuard(AuditRuntimePaths paths, long minimumFreeBytes) {
        if (minimumFreeBytes < 1) {
            throw new IllegalArgumentException("minimumFreeBytes must be positive");
        }
        this.paths = paths;
        this.minimumFreeBytes = minimumFreeBytes;
    }

    void requireCapacity() throws IOException {
        long usable = Files.getFileStore(paths.dataRoot()).getUsableSpace();
        if (usable < minimumFreeBytes) {
            throw new ApiException(
                    org.springframework.http.HttpStatus.INSUFFICIENT_STORAGE,
                    ApiErrorCode.DISK_SPACE_LOW,
                    "可用磁盘空间低于扫描任务安全水位。",
                    java.util.Map.of("usableBytes", usable, "minimumFreeBytes", minimumFreeBytes));
        }
    }
}
