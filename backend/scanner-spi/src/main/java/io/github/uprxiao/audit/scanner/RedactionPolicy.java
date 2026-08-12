package io.github.uprxiao.audit.scanner;

import java.util.Set;

public record RedactionPolicy(Set<Integer> sensitiveArgumentIndexes, Set<String> sensitiveEnvironmentKeys) {

    public static final RedactionPolicy NONE = new RedactionPolicy(Set.of(), Set.of());

    public RedactionPolicy {
        sensitiveArgumentIndexes = sensitiveArgumentIndexes == null ? Set.of() : Set.copyOf(sensitiveArgumentIndexes);
        sensitiveEnvironmentKeys = sensitiveEnvironmentKeys == null ? Set.of() : Set.copyOf(sensitiveEnvironmentKeys);
        if (sensitiveArgumentIndexes.stream().anyMatch(index -> index < 0)) {
            throw new IllegalArgumentException("sensitive argument indexes must be non-negative");
        }
    }
}
