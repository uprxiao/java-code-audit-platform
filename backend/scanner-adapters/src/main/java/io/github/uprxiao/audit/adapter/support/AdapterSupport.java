package io.github.uprxiao.audit.adapter.support;

import io.github.uprxiao.audit.finding.CodeSnippet;
import io.github.uprxiao.audit.intake.ProjectContext;
import io.github.uprxiao.audit.scanner.EngineId;
import io.github.uprxiao.audit.scanner.ToolContext;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class AdapterSupport {

    private AdapterSupport() {
    }

    public static ToolContext.ToolInstallation requireInstallation(ToolContext tools, EngineId id) throws IOException {
        ToolContext.ToolInstallation installation = tools.installations().get(id);
        if (installation == null || !installation.available()) {
            throw new IOException(id + " tool installation is unavailable");
        }
        return installation;
    }

    public static Map<String, String> isolatedEnvironment(Path output, Path executable) throws IOException {
        Path home = Files.createDirectories(output.resolve("home"));
        Path temp = Files.createDirectories(output.resolve("tmp"));
        String path = executable.getParent() + File.pathSeparator + "/usr/bin" + File.pathSeparator + "/bin";
        return Map.of("PATH", path, "HOME", home.toString(), "TMPDIR", temp.toString());
    }

    public static Path normalizeFindingPath(ProjectContext project, String rawPath) throws IOException {
        if (rawPath == null || rawPath.isBlank()) {
            throw new IOException("finding path is missing");
        }
        Path path;
        try {
            path = rawPath.startsWith("file:") ? Path.of(URI.create(rawPath)) : Path.of(rawPath);
        } catch (IllegalArgumentException exception) {
            throw new IOException("finding path is invalid: " + rawPath, exception);
        }
        Path absolute = path.isAbsolute() ? path.normalize() : project.workspaceRoot().resolve(path).normalize();
        if (!absolute.startsWith(project.workspaceRoot())) {
            throw new IOException("finding path escapes project root: " + rawPath);
        }
        return project.workspaceRoot().relativize(absolute);
    }

    public static CodeSnippet snippet(ProjectContext project, Path relativePath, int startLine, int endLine)
            throws IOException {
        Path source = project.resolveProjectPath(portable(relativePath));
        if (!Files.isRegularFile(source)) {
            return null;
        }
        List<String> lines = Files.readAllLines(source, StandardCharsets.UTF_8);
        if (lines.isEmpty()) {
            return null;
        }
        int safeStart = Math.max(1, Math.min(startLine, lines.size()));
        int safeEnd = Math.max(safeStart, Math.min(Math.max(endLine, startLine), lines.size()));
        int snippetStart = Math.max(1, safeStart - 5);
        int snippetEnd = Math.min(lines.size(), safeEnd + 5);
        List<Integer> highlights = java.util.stream.IntStream.rangeClosed(safeStart, safeEnd).boxed().toList();
        return new CodeSnippet(snippetStart, snippetEnd, highlights,
                String.join("\n", lines.subList(snippetStart - 1, snippetEnd)), false);
    }

    public static CodeSnippet redactedSnippet(int startLine, int endLine, String kind) {
        int safeStart = Math.max(1, startLine);
        int safeEnd = Math.max(safeStart, endLine);
        return new CodeSnippet(safeStart, safeEnd, List.of(safeStart),
                "[REDACTED " + kind + " at lines " + safeStart + "-" + safeEnd + "]", true);
    }

    public static String moduleFor(ProjectContext project, Path relativePath) {
        return project.manifest().modules().stream()
                .filter(module -> !module.path().equals("."))
                .filter(module -> relativePath.startsWith(Path.of(module.path())))
                .map(module -> module.artifactId())
                .findFirst()
                .orElse(project.manifest().modules().isEmpty() ? "" : project.manifest().modules().get(0).artifactId());
    }

    public static String fingerprint(String canonical) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(canonical.getBytes(StandardCharsets.UTF_8));
            return "sha256:" + HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by Java 17", exception);
        }
    }

    public static String findingId(String fingerprint) {
        return "F-" + fingerprint.substring("sha256:".length(), "sha256:".length() + 20);
    }

    public static String normalizedMessage(String message) {
        return message == null ? "" : message.toLowerCase(Locale.ROOT).replaceAll("\\s+", " ").trim();
    }

    public static String portable(Path path) {
        return path.toString().replace(path.getFileSystem().getSeparator(), "/");
    }
}
