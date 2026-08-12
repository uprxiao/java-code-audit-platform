package io.github.uprxiao.audit.process;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class FakeToolMain {

    private FakeToolMain() {
    }

    public static void main(String[] arguments) throws Exception {
        String mode = arguments[0];
        switch (mode) {
            case "success" -> System.out.println("ok");
            case "finding" -> {
                Files.writeString(Path.of("report.json"), "{\"findings\":[{\"rule\":\"FAKE-1\"}]}\n");
                System.out.println("finding");
            }
            case "failure" -> {
                System.err.println("fake failure");
                System.exit(7);
            }
            case "timeout" -> Thread.sleep(60_000);
            case "large-output" -> {
                byte[] block = "x".repeat(8192).getBytes(StandardCharsets.UTF_8);
                for (int index = 0; index < 256; index++) {
                    System.out.write(block);
                    System.err.write(block);
                }
            }
            case "spawn-child" -> {
                Process child = new ProcessBuilder("/bin/sleep", "60").start();
                Files.writeString(Path.of("child.pid"), Long.toString(child.pid()));
                Thread.sleep(60_000);
            }
            case "invalid-report" -> Files.writeString(Path.of("report.json"), "{not-json");
            case "secret" -> {
                System.out.println("arg=" + arguments[1]);
                System.err.println("env=" + System.getenv("SVN_PASSWORD"));
            }
            default -> throw new IllegalArgumentException("unknown fake mode: " + mode);
        }
    }
}
