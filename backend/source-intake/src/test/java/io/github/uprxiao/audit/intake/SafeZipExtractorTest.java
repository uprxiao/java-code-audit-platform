package io.github.uprxiao.audit.intake;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.apache.commons.compress.archivers.zip.UnixStat;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SafeZipExtractorTest {

    @TempDir
    Path temporaryDirectory;

    private final SafeZipExtractor extractor = new SafeZipExtractor();

    @Test
    void extractsAValidArchiveAndCountsBytes() throws Exception {
        Path archive = zip("valid.zip", Map.of(
                "project/pom.xml", "<project/>",
                "project/src/main/java/App.java", "class App {}"));

        ZipExtractionResult result = extractor.extract(archive, temporaryDirectory.resolve("output"),
                new ZipExtractionLimits(100_000, 100_000, 50_000, 10, 100));

        assertEquals(2, result.files());
        assertTrue(Files.isRegularFile(result.destination().resolve("project/pom.xml")));
        assertEquals("class App {}", Files.readString(result.destination().resolve("project/src/main/java/App.java")));
    }

    @Test
    void rejectsZipSlipAbsoluteWindowsAndBackslashNames() throws Exception {
        for (String entry : new String[]{"../outside", "/absolute", "C:/windows", "dir\\escape"}) {
            Path archive = zip("unsafe-" + Math.abs(entry.hashCode()) + ".zip", Map.of(entry, "bad"));
            Path output = temporaryDirectory.resolve("output-" + Math.abs(entry.hashCode()));

            SourceIntakeException error = assertThrows(SourceIntakeException.class,
                    () -> extractor.extract(archive, output,
                            new ZipExtractionLimits(100_000, 100_000, 50_000, 10, 100)), entry);
            assertEquals("UNSAFE_ARCHIVE_ENTRY", error.code());
            assertFalse(Files.exists(output));
        }
    }

    @Test
    void rejectsSymbolicLinksAndSpecialEntries() throws Exception {
        Path symlink = temporaryDirectory.resolve("symlink.zip");
        try (ZipArchiveOutputStream output = new ZipArchiveOutputStream(symlink)) {
            ZipArchiveEntry entry = new ZipArchiveEntry("project/link");
            entry.setUnixMode(UnixStat.LINK_FLAG | 0777);
            output.putArchiveEntry(entry);
            output.write("../../outside".getBytes(StandardCharsets.UTF_8));
            output.closeArchiveEntry();
        }

        SourceIntakeException error = assertThrows(SourceIntakeException.class,
                () -> extractor.extract(symlink, temporaryDirectory.resolve("symlink-output"),
                        new ZipExtractionLimits(100_000, 100_000, 50_000, 10, 100)));
        assertEquals("UNSAFE_ARCHIVE_ENTRY", error.code());
    }

    @Test
    void rejectsCaseAndUnicodeNormalizationCollisionsAcrossSupportedPlatforms() throws Exception {
        Path caseCollision = zip("case-collision.zip", Map.of("src/App.java", "one", "src/app.java", "two"));
        SourceIntakeException caseError = assertThrows(SourceIntakeException.class,
                () -> extractor.extract(caseCollision, temporaryDirectory.resolve("case-output"),
                        new ZipExtractionLimits(100_000, 100_000, 50_000, 10, 100)));
        assertEquals("UNSAFE_ARCHIVE_ENTRY", caseError.code());

        Path unicodeCollision = zip("unicode-collision.zip", Map.of(
                "src/caf\u00e9.java", "one",
                "src/cafe\u0301.java", "two"));
        SourceIntakeException unicodeError = assertThrows(SourceIntakeException.class,
                () -> extractor.extract(unicodeCollision, temporaryDirectory.resolve("unicode-output"),
                        new ZipExtractionLimits(100_000, 100_000, 50_000, 10, 100)));
        assertEquals("UNSAFE_ARCHIVE_ENTRY", unicodeError.code());
    }

    @Test
    void rejectsCompressionBombSingleFileAndEntryCountLimits() throws Exception {
        Path bomb = zip("bomb.zip", Map.of("bomb.txt", "a".repeat(50_000)));
        SourceIntakeException ratio = assertThrows(SourceIntakeException.class,
                () -> extractor.extract(bomb, temporaryDirectory.resolve("bomb-output"),
                        new ZipExtractionLimits(100_000, 100_000, 100_000, 10, 2)));
        assertEquals("ARCHIVE_LIMIT_EXCEEDED", ratio.code());

        Path large = zip("large.zip", Map.of("large.txt", "x".repeat(101)));
        assertEquals("ARCHIVE_LIMIT_EXCEEDED", assertThrows(SourceIntakeException.class,
                () -> extractor.extract(large, temporaryDirectory.resolve("large-output"),
                        new ZipExtractionLimits(100_000, 1000, 100, 10, 100))).code());

        Path many = zip("many.zip", Map.of("one", "1", "two", "2", "three", "3"));
        assertEquals("ARCHIVE_LIMIT_EXCEEDED", assertThrows(SourceIntakeException.class,
                () -> extractor.extract(many, temporaryDirectory.resolve("many-output"),
                        new ZipExtractionLimits(100_000, 1000, 100, 2, 100))).code());
    }

    @Test
    void uploadStagingIsBoundedAndDeletesPartialFiles() throws Exception {
        UploadStager stager = new UploadStager();
        Path acceptedPath = temporaryDirectory.resolve("accepted.zip");
        StagedUpload accepted = stager.stage(new ByteArrayInputStream("abc".getBytes(StandardCharsets.UTF_8)),
                acceptedPath, 3);
        assertEquals(3, accepted.size());
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", accepted.sha256());

        Path rejectedPath = temporaryDirectory.resolve("rejected.zip");
        SourceIntakeException error = assertThrows(SourceIntakeException.class,
                () -> stager.stage(new ByteArrayInputStream("abcd".getBytes(StandardCharsets.UTF_8)), rejectedPath, 3));
        assertEquals("ARCHIVE_LIMIT_EXCEEDED", error.code());
        assertFalse(Files.exists(rejectedPath));
    }

    private Path zip(String name, Map<String, String> entries) throws IOException {
        Path archive = temporaryDirectory.resolve(name);
        try (java.util.zip.ZipOutputStream output = new java.util.zip.ZipOutputStream(Files.newOutputStream(archive))) {
            for (Map.Entry<String, String> item : entries.entrySet()) {
                java.util.zip.ZipEntry entry = new java.util.zip.ZipEntry(item.getKey());
                output.putNextEntry(entry);
                output.write(item.getValue().getBytes(StandardCharsets.UTF_8));
                output.closeEntry();
            }
        }
        return archive;
    }
}
