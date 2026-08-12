package io.github.uprxiao.audit.scanner;

import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

public record EngineId(String value) implements Comparable<EngineId> {

    private static final Pattern VALID = Pattern.compile("[a-z][a-z0-9-]{1,63}");

    public EngineId {
        Objects.requireNonNull(value, "value");
        value = value.trim().toLowerCase(Locale.ROOT);
        if (!VALID.matcher(value).matches()) {
            throw new IllegalArgumentException("invalid engine id: " + value);
        }
    }

    @Override
    public int compareTo(EngineId other) {
        return value.compareTo(other.value);
    }

    @Override
    public String toString() {
        return value;
    }
}
