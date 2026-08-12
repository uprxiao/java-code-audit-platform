package io.github.uprxiao.audit.finding;

import java.time.Instant;
import java.util.Objects;

public record FindingSuppression(String ruleId, String reason, Instant expiresAt) {

    public FindingSuppression {
        Objects.requireNonNull(ruleId, "ruleId");
        Objects.requireNonNull(reason, "reason");
        if (reason.isBlank()) {
            throw new IllegalArgumentException("suppression reason must not be blank");
        }
    }

    public boolean isExpired(Instant now) {
        return expiresAt != null && !expiresAt.isAfter(now);
    }
}
