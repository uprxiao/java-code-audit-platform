package io.github.uprxiao.audit.intake;

import java.util.Objects;

public record MavenModule(String path, String artifactId, String packaging) {

    public MavenModule {
        path = requireText(path, "path");
        artifactId = requireText(artifactId, "artifactId");
        packaging = packaging == null || packaging.isBlank() ? "jar" : packaging;
    }

    private static String requireText(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }
}
