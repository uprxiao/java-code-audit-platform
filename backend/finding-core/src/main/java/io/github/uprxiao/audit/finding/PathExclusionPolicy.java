package io.github.uprxiao.audit.finding;

import java.util.List;

/** Pre-scan path exclusions. These are coverage facts, not suppressed findings. */
public final class PathExclusionPolicy {

    private final List<PortableGlob> patterns;

    public PathExclusionPolicy(List<String> patterns) {
        this.patterns = patterns == null ? List.of() : patterns.stream().map(PortableGlob::new).toList();
    }

    public boolean excludes(String projectRelativePath) {
        return patterns.stream().anyMatch(pattern -> pattern.matches(projectRelativePath));
    }

    public List<String> coveragePatterns() {
        return patterns.stream().map(PortableGlob::source).toList();
    }
}
