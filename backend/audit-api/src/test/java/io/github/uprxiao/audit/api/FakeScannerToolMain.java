package io.github.uprxiao.audit.api;

import java.nio.file.Files;
import java.nio.file.Path;

/** Test child process used by the 14-engine API contract test. */
public final class FakeScannerToolMain {

    private FakeScannerToolMain() {
    }

    public static void main(String[] args) throws Exception {
        Path target = Path.of(args[0]);
        Files.createDirectories(target.getParent());
        String content = target.endsWith("bom.json") ? """
                {"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
                 "components":[{"type":"library","name":"fixture","version":"1.0.0",
                                  "purl":"pkg:maven/example/fixture@1.0.0"}],
                 "dependencies":[]}
                """ : "{}";
        Files.writeString(target, content);
    }
}
