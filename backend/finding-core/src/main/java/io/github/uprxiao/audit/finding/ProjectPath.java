package io.github.uprxiao.audit.finding;

import java.text.Normalizer;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Objects;

/** Canonical, portable project-relative paths used by findings and coverage. */
public final class ProjectPath {

    private ProjectPath() {
    }

    public static String normalize(String value) {
        Objects.requireNonNull(value, "value");
        String portable = Normalizer.normalize(value.trim().replace('\\', '/'), Normalizer.Form.NFC);
        if (portable.isBlank() || portable.indexOf('\0') >= 0 || portable.startsWith("/")
                || portable.startsWith("//") || portable.matches("^[A-Za-z]:/.*")) {
            throw new IllegalArgumentException("path must be a safe project-relative path: " + value);
        }
        Deque<String> segments = new ArrayDeque<>();
        for (String segment : portable.split("/+")) {
            if (segment.isBlank() || segment.equals(".")) {
                continue;
            }
            if (segment.equals("..")) {
                throw new IllegalArgumentException("path must not contain parent traversal: " + value);
            }
            segments.addLast(segment);
        }
        if (segments.isEmpty()) {
            throw new IllegalArgumentException("path must identify a project-relative file");
        }
        return String.join("/", segments);
    }
}
