package io.github.uprxiao.audit.api;

import java.nio.file.Files;
import java.nio.file.Path;

/** Test child process used by the 14-engine API contract test. */
public final class FakeScannerToolMain {

    private FakeScannerToolMain() {
    }

    public static void main(String[] args) throws Exception {
        Files.writeString(Path.of(args[0]), "{}");
    }
}
