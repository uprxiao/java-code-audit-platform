package io.github.uprxiao.audit.intake;

import io.github.uprxiao.audit.finding.SourceType;
import java.util.Objects;

public record SourceDescriptor(
        SourceType type,
        String displayName,
        String location,
        String revision,
        String contentSha256) {

    public SourceDescriptor {
        Objects.requireNonNull(type, "type");
        displayName = displayName == null ? "" : displayName;
        location = location == null ? "" : location;
        revision = revision == null ? "" : revision;
        contentSha256 = contentSha256 == null ? "" : contentSha256;
    }
}
