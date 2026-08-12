package io.github.uprxiao.audit.intake;

import java.util.Locale;
import java.util.OptionalLong;

/** A single immutable SVN snapshot revision. */
public record SvnRevision(OptionalLong number) {

    public SvnRevision {
        number = number == null ? OptionalLong.empty() : number;
        if (number.isPresent() && number.getAsLong() < 0) {
            throw new IllegalArgumentException("SVN revision must not be negative");
        }
    }

    public static SvnRevision head() {
        return new SvnRevision(OptionalLong.empty());
    }

    public static SvnRevision parse(String value) throws SourceIntakeException {
        if (value == null || value.isBlank() || "HEAD".equals(value.toUpperCase(Locale.ROOT))) {
            return head();
        }
        if (value.length() > 19 || !value.chars().allMatch(character -> character >= '0' && character <= '9')) {
            throw new SourceIntakeException("INVALID_SVN_REVISION",
                    "SVN revision must be HEAD or a non-negative decimal number");
        }
        try {
            return new SvnRevision(OptionalLong.of(Long.parseLong(value)));
        } catch (NumberFormatException exception) {
            throw new SourceIntakeException("INVALID_SVN_REVISION", "SVN revision is outside the supported range");
        }
    }

    public String displayValue() {
        return number.isPresent() ? Long.toString(number.getAsLong()) : "HEAD";
    }
}
