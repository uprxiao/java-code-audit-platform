package io.github.uprxiao.audit.intake;

public record ZipExtractionLimits(
        long maxArchiveBytes,
        long maxExpandedBytes,
        long maxSingleFileBytes,
        int maxEntries,
        double maxCompressionRatio) {

    public static ZipExtractionLimits defaults() {
        return new ZipExtractionLimits(
                1024L * 1024 * 1024,
                10L * 1024 * 1024 * 1024,
                1024L * 1024 * 1024,
                200_000,
                100.0);
    }

    public ZipExtractionLimits {
        if (maxArchiveBytes < 1 || maxExpandedBytes < 1 || maxSingleFileBytes < 1
                || maxEntries < 1 || maxCompressionRatio < 1.0) {
            throw new IllegalArgumentException("ZIP extraction limits must be positive");
        }
        if (maxSingleFileBytes > maxExpandedBytes) {
            throw new IllegalArgumentException("single-file limit cannot exceed expanded archive limit");
        }
    }
}
