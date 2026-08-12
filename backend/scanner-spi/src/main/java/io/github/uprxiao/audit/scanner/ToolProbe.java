package io.github.uprxiao.audit.scanner;

import java.io.IOException;

public interface ToolProbe {
    ToolHealth probe(ToolProbeRequest request) throws IOException, InterruptedException;
}
