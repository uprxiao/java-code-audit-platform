package io.github.uprxiao.audit.finding;

import java.util.Objects;

public record DataFlowNode(int index, Kind kind, SourceLocation location, String label) {

    public DataFlowNode {
        if (index < 0) {
            throw new IllegalArgumentException("index must be non-negative");
        }
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(location, "location");
        label = label == null ? "" : label;
    }

    public enum Kind {
        SOURCE,
        PROPAGATION,
        SINK
    }
}
