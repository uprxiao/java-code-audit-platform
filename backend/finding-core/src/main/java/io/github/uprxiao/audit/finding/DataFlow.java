package io.github.uprxiao.audit.finding;

import java.util.List;
import java.util.Objects;

public record DataFlow(String engine, List<DataFlowNode> nodes) {

    public DataFlow {
        Objects.requireNonNull(engine, "engine");
        nodes = nodes == null ? List.of() : List.copyOf(nodes);
        for (int i = 0; i < nodes.size(); i++) {
            if (nodes.get(i).index() != i) {
                throw new IllegalArgumentException("data-flow node indexes must be contiguous");
            }
        }
    }
}
