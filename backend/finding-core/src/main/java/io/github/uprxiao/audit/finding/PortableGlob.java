package io.github.uprxiao.audit.finding;

import java.util.Objects;
import java.util.regex.Pattern;

final class PortableGlob {

    private final String source;
    private final Pattern pattern;

    PortableGlob(String source) {
        Objects.requireNonNull(source, "source");
        this.source = source.trim().replace('\\', '/');
        if (this.source.isBlank() || this.source.indexOf('\0') >= 0 || this.source.startsWith("/")
                || this.source.matches("^[A-Za-z]:/.*") || containsParentSegment(this.source)) {
            throw new IllegalArgumentException("unsafe project-relative glob: " + source);
        }
        this.pattern = Pattern.compile(toRegex(this.source));
    }

    boolean matches(String projectPath) {
        return pattern.matcher(ProjectPath.normalize(projectPath)).matches();
    }

    String source() {
        return source;
    }

    private boolean containsParentSegment(String value) {
        for (String segment : value.split("/")) {
            if (segment.equals("..")) {
                return true;
            }
        }
        return false;
    }

    private String toRegex(String glob) {
        StringBuilder regex = new StringBuilder("^");
        for (int index = 0; index < glob.length(); index++) {
            char current = glob.charAt(index);
            if (current == '*') {
                if (index + 1 < glob.length() && glob.charAt(index + 1) == '*') {
                    index++;
                    if (index + 1 < glob.length() && glob.charAt(index + 1) == '/') {
                        index++;
                        regex.append("(?:.*/)?");
                    } else {
                        regex.append(".*");
                    }
                } else {
                    regex.append("[^/]*");
                }
            } else if (current == '?') {
                regex.append("[^/]");
            } else {
                if (".[]{}()+-^$|\\".indexOf(current) >= 0) {
                    regex.append('\\');
                }
                regex.append(current);
            }
        }
        return regex.append('$').toString();
    }
}
