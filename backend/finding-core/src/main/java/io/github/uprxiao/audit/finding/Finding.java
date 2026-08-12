package io.github.uprxiao.audit.finding;

import java.util.List;

public record Finding(
        String fingerprint,
        String engine,
        String ruleId,
        String title,
        String description,
        Severity severity,
        SourceLocation location,
        List<String> cwe,
        List<String> tags) {

    public Finding {
        cwe = List.copyOf(cwe);
        tags = List.copyOf(tags);
    }
}
