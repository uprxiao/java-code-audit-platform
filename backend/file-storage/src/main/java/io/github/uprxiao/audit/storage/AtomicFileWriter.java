package io.github.uprxiao.audit.storage;

import java.io.IOException;
import java.nio.file.Path;

public interface AtomicFileWriter {
    void write(Path target, byte[] content) throws IOException;
}
