package io.github.uprxiao.audit.api;

import java.nio.file.Path;

record AuditRuntimePaths(Path dataRoot, Path semgrepExecutable, Path semgrepRules) {
}
