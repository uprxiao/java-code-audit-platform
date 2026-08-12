package io.github.uprxiao.audit.intake;

import java.time.Duration;

public record SvnCheckoutLimits(
        long maxExpandedBytes,
        long maxSingleFileBytes,
        int maxEntries,
        int maxPathCharacters,
        Duration connectTimeout,
        Duration readTimeout) {

    public SvnCheckoutLimits {
        if (maxExpandedBytes < 1 || maxSingleFileBytes < 1 || maxEntries < 1 || maxPathCharacters < 32
                || connectTimeout == null || connectTimeout.isNegative() || connectTimeout.isZero()
                || readTimeout == null || readTimeout.isNegative() || readTimeout.isZero()) {
            throw new IllegalArgumentException("SVN checkout limits must be positive");
        }
        if (maxSingleFileBytes > maxExpandedBytes) {
            throw new IllegalArgumentException("SVN single-file limit cannot exceed the total byte limit");
        }
        if (connectTimeout.toMillis() > Integer.MAX_VALUE || readTimeout.toMillis() > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("SVN timeouts must fit the SVNKit millisecond range");
        }
    }

    public static SvnCheckoutLimits defaults() {
        return new SvnCheckoutLimits(
                10L * 1024 * 1024 * 1024,
                1024L * 1024 * 1024,
                200_000,
                4096,
                Duration.ofSeconds(15),
                Duration.ofMinutes(5));
    }
}
