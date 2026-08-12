package io.github.uprxiao.audit.api;

import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.finding.SourceType;
import java.util.List;
import java.util.Map;

/** Credential-free request data used to rebuild queued work after a clean restart. */
record PersistedScanRequest(
        int schemaVersion,
        SourceType sourceType,
        String originalName,
        String displayName,
        ScanProfile profile,
        List<String> mavenProfiles,
        Map<String, String> mavenProperties,
        boolean sensitivePropertiesOmitted) {

    PersistedScanRequest {
        if (schemaVersion != 1) {
            throw new IllegalArgumentException("unsupported persisted request schema: " + schemaVersion);
        }
        if (sourceType == null || profile == null) {
            throw new IllegalArgumentException("persisted request source/profile is required");
        }
        originalName = originalName == null ? "" : originalName;
        displayName = displayName == null ? "" : displayName;
        mavenProfiles = mavenProfiles == null ? List.of() : List.copyOf(mavenProfiles);
        mavenProperties = mavenProperties == null ? Map.of() : Map.copyOf(mavenProperties);
    }

    static PersistedScanRequest zip(
            String originalName,
            ZipScanRequest request,
            Map<String, String> persistedProperties,
            boolean sensitivePropertiesOmitted) {
        return new PersistedScanRequest(1, SourceType.ZIP, originalName, request.displayName(), request.profile(),
                request.mavenProfiles(), persistedProperties, sensitivePropertiesOmitted);
    }

    ZipScanRequest toZipRequest() {
        return new ZipScanRequest(displayName, profile, mavenProfiles, mavenProperties);
    }
}
