package io.github.uprxiao.audit.intake;

import java.nio.file.Path;

public record ZipExtractionResult(Path destination, int entries, int files, long expandedBytes) {
}
