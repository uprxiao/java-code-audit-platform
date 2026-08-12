package io.github.uprxiao.audit.process;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Objects;

public record MavenProcessConfiguration(
        String executable,
        Path javaHome,
        Path localRepository,
        Path settingsFile,
        String pathEnvironment,
        int maxHeapMb) {

    public MavenProcessConfiguration {
        executable = requireText(executable, "executable");
        Path executablePath = Path.of(executable);
        String executableName = executablePath.getFileName().toString().toLowerCase(Locale.ROOT);
        if (!executableName.equals("mvn") && !executableName.equals("mvn.cmd")
                && !executableName.equals("mvn.bat")) {
            throw new IllegalArgumentException("configured Maven executable must be mvn");
        }
        if (!executablePath.isAbsolute() && executablePath.getNameCount() != 1) {
            throw new IllegalArgumentException("relative Maven executable must be the system mvn command");
        }
        if (executablePath.isAbsolute() && (!Files.isRegularFile(executablePath) || !Files.isExecutable(executablePath))) {
            throw new IllegalArgumentException("configured Maven executable is unavailable: " + executablePath);
        }
        javaHome = normalize(javaHome, "javaHome");
        localRepository = normalize(localRepository, "localRepository");
        if (settingsFile != null) {
            settingsFile = settingsFile.toAbsolutePath().normalize();
            if (!Files.isRegularFile(settingsFile)) {
                throw new IllegalArgumentException("configured Maven settings file is unavailable: " + settingsFile);
            }
        }
        pathEnvironment = requireText(pathEnvironment, "pathEnvironment");
        if (maxHeapMb < 128) {
            throw new IllegalArgumentException("Maven max heap must be at least 128 MiB");
        }
    }

    private static Path normalize(Path value, String name) {
        return Objects.requireNonNull(value, name).toAbsolutePath().normalize();
    }

    private static String requireText(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }
}
