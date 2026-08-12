package io.github.uprxiao.audit.process;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class MavenBuildOutputParser {

    private static final Pattern MODULE = Pattern.compile(
            "^\\[INFO]\\s+(.+?)\\s+\\.{2,}\\s+(SUCCESS|FAILURE|SKIPPED)(?:\\s+.*)?$");
    private static final Pattern ANSI = Pattern.compile("\\x1B\\[[;\\d]*m");

    List<MavenModuleResult> parse(Path stdout) throws IOException {
        if (!Files.isRegularFile(stdout)) {
            return List.of();
        }
        List<MavenModuleResult> modules = new ArrayList<>();
        for (String rawLine : Files.readAllLines(stdout)) {
            String line = ANSI.matcher(rawLine).replaceAll("");
            Matcher matcher = MODULE.matcher(line);
            if (matcher.matches()) {
                modules.add(new MavenModuleResult(
                        matcher.group(1).trim(),
                        MavenModuleResult.Status.valueOf(matcher.group(2).toUpperCase(Locale.ROOT))));
            }
        }
        return List.copyOf(modules);
    }
}
