package io.github.uprxiao.audit.adapter.spotbugs;

import io.github.uprxiao.audit.adapter.support.AdapterSupport;
import io.github.uprxiao.audit.scanner.EngineDescriptor;
import io.github.uprxiao.audit.scanner.EngineId;
import io.github.uprxiao.audit.scanner.ExecutionSpec;
import io.github.uprxiao.audit.scanner.ExpectedArtifact;
import io.github.uprxiao.audit.scanner.RedactionPolicy;
import io.github.uprxiao.audit.scanner.ScanContext;
import io.github.uprxiao.audit.scanner.ToolContext;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

final class SpotBugsExecutionSupport {

    static final long MAX_REPORT_BYTES = 256L * 1024 * 1024;

    private SpotBugsExecutionSupport() {
    }

    static ExecutionSpec prepare(
            EngineId engine,
            EngineDescriptor descriptor,
            ScanContext context,
            ToolContext tools,
            Path spotbugsHome,
            Path findSecBugsPlugin,
            Path excludeFilter) throws IOException {
        ToolContext.ToolInstallation installation = AdapterSupport.requireInstallation(tools, engine);
        Path lib = spotbugsHome.resolve("lib");
        if (!Files.isDirectory(lib) || !Files.isRegularFile(lib.resolve("spotbugs.jar"))) {
            throw new IOException("SpotBugs home is invalid: " + spotbugsHome);
        }
        if (!Files.isRegularFile(findSecBugsPlugin)) {
            throw new IOException("FindSecBugs plugin is unavailable: " + findSecBugsPlugin);
        }
        if (excludeFilter != null && !Files.isRegularFile(excludeFilter)) {
            throw new IOException("SpotBugs exclude filter is unavailable: " + excludeFilter);
        }
        Files.createDirectories(context.engineOutputDirectory());
        Path report = context.engineOutputDirectory().resolve("report.xml");
        List<Path> classes = classDirectories(context.project().workspaceRoot());
        if (classes.isEmpty()) {
            throw new IOException("SpotBugs requires compiled target/classes directories");
        }
        List<Path> sources = sourceDirectories(context.project().workspaceRoot());

        List<String> command = new ArrayList<>();
        command.add(installation.executable().toString());
        command.add("-Duser.language=en");
        command.add("-Duser.country=US");
        command.add("-Djava.awt.headless=true");
        command.add("-Xmx2048m");
        command.add("-cp");
        command.add(lib.resolve("*").toString());
        command.add("edu.umd.cs.findbugs.LaunchAppropriateUI");
        command.add("-textui");
        command.add("-effort:max");
        command.add("-low");
        command.add("-xml:withMessages");
        command.add("-output");
        command.add(report.toString());
        command.add("-pluginList");
        command.add(findSecBugsPlugin.toString());
        if (excludeFilter != null) {
            command.add("-exclude");
            command.add(excludeFilter.toString());
        }
        if (!sources.isEmpty()) {
            command.add("-sourcepath");
            command.add(join(sources));
        }
        command.add("-auxclasspath");
        command.add(join(classes));
        classes.forEach(path -> command.add(path.toString()));

        return new ExecutionSpec(engine, command, context.engineOutputDirectory(),
                AdapterSupport.isolatedEnvironment(context.engineOutputDirectory(), installation.executable()),
                descriptor.defaultTimeout(), descriptor.resources(),
                Set.of(new ExpectedArtifact("report.xml", true, MAX_REPORT_BYTES)), RedactionPolicy.NONE);
    }

    private static List<Path> classDirectories(Path projectRoot) throws IOException {
        try (var paths = Files.find(projectRoot, 12,
                (path, attributes) -> attributes.isDirectory()
                        && path.getFileName().toString().equals("classes")
                        && path.getParent() != null
                        && path.getParent().getFileName().toString().equals("target"))) {
            return paths.map(Path::toAbsolutePath).map(Path::normalize).sorted(Comparator.comparing(Path::toString)).toList();
        }
    }

    private static List<Path> sourceDirectories(Path projectRoot) throws IOException {
        try (var paths = Files.find(projectRoot, 12,
                (path, attributes) -> attributes.isDirectory()
                        && path.endsWith(Path.of("src", "main", "java")))) {
            return paths.map(Path::toAbsolutePath).map(Path::normalize).sorted(Comparator.comparing(Path::toString)).toList();
        }
    }

    private static String join(List<Path> paths) {
        return paths.stream().map(Path::toString).reduce((left, right) -> left + File.pathSeparator + right).orElse("");
    }
}
