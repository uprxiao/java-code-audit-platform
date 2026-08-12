package io.github.uprxiao.audit.finding;

import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/** Stable platform rule-family names independent from scanner-specific rule IDs. */
public final class RuleFamilyCatalog {

    private static final Map<String, String> ALIASES = Map.ofEntries(
            Map.entry("SQLI", "SQL_INJECTION"),
            Map.entry("SQL_INJECTION", "SQL_INJECTION"),
            Map.entry("COMMAND_INJECTION", "COMMAND_INJECTION"),
            Map.entry("OS_COMMAND_INJECTION", "COMMAND_INJECTION"),
            Map.entry("PATH_TRAVERSAL", "PATH_TRAVERSAL"),
            Map.entry("DIRECTORY_TRAVERSAL", "PATH_TRAVERSAL"),
            Map.entry("XSS", "CROSS_SITE_SCRIPTING"),
            Map.entry("CROSS_SITE_SCRIPTING", "CROSS_SITE_SCRIPTING"),
            Map.entry("HARDCODED_SECRET", "SECRET"),
            Map.entry("SECRET_EXPOSURE", "SECRET"),
            Map.entry("SECRET", "SECRET"),
            Map.entry("DEPENDENCY_VULNERABILITY", "DEPENDENCY_VULNERABILITY"),
            Map.entry("CVE", "DEPENDENCY_VULNERABILITY"),
            Map.entry("DUPLICATE_CODE", "DUPLICATION"),
            Map.entry("DUPLICATION", "DUPLICATION"));

    private RuleFamilyCatalog() {
    }

    public static String canonical(String value) {
        Objects.requireNonNull(value, "value");
        String normalized = value.trim().toUpperCase(Locale.ROOT)
                .replaceAll("[^A-Z0-9]+", "_")
                .replaceAll("^_+|_+$", "");
        if (normalized.isBlank()) {
            throw new IllegalArgumentException("rule family must not be blank");
        }
        return ALIASES.getOrDefault(normalized, normalized);
    }

    public static boolean compatible(String left, String right) {
        return canonical(left).equals(canonical(right));
    }
}
