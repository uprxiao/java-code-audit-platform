package io.github.uprxiao.audit.intake;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/** Validates the only Maven arguments that V1 accepts from an API request. */
public final class MavenArgumentValidator {

    private static final Pattern PROFILE = Pattern.compile("[A-Za-z0-9][A-Za-z0-9_.-]{0,63}");
    private static final Pattern PROPERTY = Pattern.compile("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}");
    private static final Pattern PROPERTY_VALUE = Pattern.compile("[A-Za-z0-9._:/@+\\-]{0,512}");
    private static final int MAX_PROFILES = 16;
    private static final int MAX_PROPERTIES = 64;
    private static final Set<String> FORBIDDEN_PROPERTIES = Set.of(
            "maven.repo.local",
            "maven.home",
            "maven.multimoduleprojectdirectory",
            "java.home",
            "user.home",
            "user.dir",
            "classworlds.conf",
            "maven.ext.class.path",
            "jdk.attach.allowattachself",
            "settings",
            "file",
            "f");

    public void validate(List<String> profiles, Map<String, String> properties) throws SourceIntakeException {
        Objects.requireNonNull(profiles, "profiles");
        Objects.requireNonNull(properties, "properties");
        if (profiles.size() > MAX_PROFILES || properties.size() > MAX_PROPERTIES) {
            throw invalid("too many Maven profiles or properties");
        }
        Set<String> uniqueProfiles = new HashSet<>();
        for (String profile : profiles) {
            if (profile == null || !PROFILE.matcher(profile).matches() || !uniqueProfiles.add(profile)) {
                throw invalid("Maven profile names must be unique safe identifiers");
            }
        }
        for (Map.Entry<String, String> property : properties.entrySet()) {
            String key = property.getKey();
            String value = property.getValue();
            if (key == null || !PROPERTY.matcher(key).matches() || isForbiddenProperty(key)) {
                throw invalid("Maven property is not allowed: " + safeKey(key));
            }
            if (value == null || !PROPERTY_VALUE.matcher(value).matches()) {
                throw invalid("Maven property value is invalid: " + safeKey(key));
            }
        }
    }

    public boolean isSensitiveProperty(String key) {
        if (key == null) {
            return false;
        }
        String normalized = key.toLowerCase(Locale.ROOT);
        return normalized.contains("password") || normalized.contains("passwd")
                || normalized.contains("secret") || normalized.contains("token")
                || normalized.endsWith("key") || normalized.contains("credential");
    }

    private boolean isForbiddenProperty(String key) {
        String normalized = key.toLowerCase(Locale.ROOT);
        return FORBIDDEN_PROPERTIES.contains(normalized)
                || normalized.startsWith("maven.ext.")
                || normalized.startsWith("javax.net.ssl.keystore");
    }

    private String safeKey(String key) {
        if (key == null) {
            return "<null>";
        }
        return key.length() <= 128 ? key : key.substring(0, 128);
    }

    private SourceIntakeException invalid(String message) {
        return new SourceIntakeException("INVALID_MAVEN_ARGUMENT", message);
    }
}
