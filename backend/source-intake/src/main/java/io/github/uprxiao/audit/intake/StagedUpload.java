package io.github.uprxiao.audit.intake;

import java.nio.file.Path;

public record StagedUpload(Path path, long size, String sha256) {
}
