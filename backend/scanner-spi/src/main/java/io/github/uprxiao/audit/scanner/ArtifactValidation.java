package io.github.uprxiao.audit.scanner;

import java.util.List;

public record ArtifactValidation(boolean valid, List<String> errors) {

    public ArtifactValidation {
        errors = errors == null ? List.of() : List.copyOf(errors);
        if (valid && !errors.isEmpty()) {
            throw new IllegalArgumentException("valid artifact result cannot contain errors");
        }
    }

    public static ArtifactValidation success() {
        return new ArtifactValidation(true, List.of());
    }
}
