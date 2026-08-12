package io.github.uprxiao.audit.api;

import java.nio.file.Path;

record AuditRuntimePaths(
        Path dataRoot,
        Path semgrepExecutable,
        Path semgrepRules,
        Path quickToolRoot,
        Path gitleaksRules,
        Path pmdRules,
        Path checkstyleRules) {

    AuditRuntimePaths(Path dataRoot, Path semgrepExecutable, Path semgrepRules) {
        this(dataRoot, semgrepExecutable, semgrepRules,
                Path.of("./tools/downloads/quick").toAbsolutePath().normalize(),
                Path.of("./config/rules/gitleaks/gitleaks.toml").toAbsolutePath().normalize(),
                Path.of("./config/rules/pmd/java-audit.xml").toAbsolutePath().normalize(),
                Path.of("./config/rules/checkstyle/java-audit.xml").toAbsolutePath().normalize());
    }

    Path gitleaksExecutable() {
        return quickToolRoot.resolve("gitleaks/bin/gitleaks");
    }

    Path pmdHome() {
        return quickToolRoot.resolve("pmd/home");
    }

    Path checkstyleJar() {
        return quickToolRoot.resolve("checkstyle/checkstyle-12.3.1-all.jar");
    }

    Path trivyExecutable() {
        return quickToolRoot.resolve("trivy/bin/trivy");
    }

    Path trivyCache() {
        return dataRoot.resolve("cache/trivy");
    }

    Path javaExecutable() {
        return Path.of(System.getProperty("java.home"), "bin", "java").toAbsolutePath().normalize();
    }
}
