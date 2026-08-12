package io.github.uprxiao.audit.intake;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class MavenArgumentValidatorTest {

    private final MavenArgumentValidator validator = new MavenArgumentValidator();

    @Test
    void acceptsControlledProfilesAndPropertiesAsData() {
        assertDoesNotThrow(() -> validator.validate(
                List.of("opensource", "release-17"),
                Map.of("revision", "1.0.0", "project.build.sourceEncoding", "UTF-8")));
    }

    @Test
    void rejectsOptionGoalControlCharacterAndHostPathEscapeAttempts() {
        for (List<String> profiles : List.of(
                List.of("-f", "/tmp/evil.xml"),
                List.of("clean package"),
                List.of("safe", "safe"))) {
            SourceIntakeException failure = assertThrows(SourceIntakeException.class,
                    () -> validator.validate(profiles, Map.of()));
            assertEquals("INVALID_MAVEN_ARGUMENT", failure.code());
        }

        for (Map<String, String> properties : List.of(
                Map.of("maven.repo.local", "/tmp/attacker"),
                Map.of("maven.ext.class.path", "/tmp/extension.jar"),
                Map.of("revision", "1.0\npackage"),
                Map.of("-f", "/tmp/evil.xml"))) {
            assertThrows(SourceIntakeException.class, () -> validator.validate(List.of(), properties));
        }
    }

    @Test
    void classifiesCommonCredentialPropertyNamesForRedaction() {
        assertTrue(validator.isSensitiveProperty("repositoryPassword"));
        assertTrue(validator.isSensitiveProperty("api.token"));
        assertTrue(validator.isSensitiveProperty("signingKey"));
    }
}
