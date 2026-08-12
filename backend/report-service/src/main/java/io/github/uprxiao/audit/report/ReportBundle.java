package io.github.uprxiao.audit.report;

import java.nio.file.Path;

public record ReportBundle(
        Path html,
        Path json,
        Path sarif,
        Path coverage,
        Path manifest,
        Path archive) {
}
