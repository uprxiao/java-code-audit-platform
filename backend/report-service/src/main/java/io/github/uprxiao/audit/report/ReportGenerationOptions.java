package io.github.uprxiao.audit.report;

import io.github.uprxiao.audit.finding.SensitiveDataRedactor;
import java.util.List;
import java.util.Objects;

public record ReportGenerationOptions(SensitiveDataRedactor redactor, boolean sanitizeRawLogsAndSbom) {

    public ReportGenerationOptions {
        Objects.requireNonNull(redactor, "redactor");
    }

    public static ReportGenerationOptions defaults() {
        return new ReportGenerationOptions(new SensitiveDataRedactor(), true);
    }

    public static ReportGenerationOptions withSensitiveValues(List<String> sensitiveValues) {
        return new ReportGenerationOptions(new SensitiveDataRedactor(sensitiveValues), true);
    }
}
