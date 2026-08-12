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
        String repositoryUrl,
        String revision,
        String displayName,
        ScanProfile profile,
        List<String> mavenProfiles,
        Map<String, String> mavenProperties,
        boolean sensitivePropertiesOmitted,
        boolean sourceCredentialsOmitted) {

    PersistedScanRequest {
        if (schemaVersion != 1) {
            throw new IllegalArgumentException("unsupported persisted request schema: " + schemaVersion);
        }
        if (sourceType == null || profile == null) {
            throw new IllegalArgumentException("persisted request source/profile is required");
        }
        originalName = originalName == null ? "" : originalName;
        repositoryUrl = repositoryUrl == null ? "" : repositoryUrl;
        revision = revision == null ? "" : revision;
        displayName = displayName == null ? "" : displayName;
        mavenProfiles = mavenProfiles == null ? List.of() : List.copyOf(mavenProfiles);
        mavenProperties = mavenProperties == null ? Map.of() : Map.copyOf(mavenProperties);
    }

    static PersistedScanRequest zip(
            String originalName,
            ZipScanRequest request,
            Map<String, String> persistedProperties,
            boolean sensitivePropertiesOmitted) {
        return new PersistedScanRequest(1, SourceType.ZIP, originalName, "", "", request.displayName(),
                request.profile(), request.mavenProfiles(), persistedProperties, sensitivePropertiesOmitted, false);
    }

    static PersistedScanRequest svn(
            String repositoryUrl,
            String revision,
            String effectiveDisplayName,
            SvnScanRequest request,
            Map<String, String> persistedProperties,
            boolean sensitivePropertiesOmitted,
            boolean sourceCredentialsOmitted) {
        return new PersistedScanRequest(1, SourceType.SVN, "", repositoryUrl, revision, effectiveDisplayName,
                request.profile(), request.mavenProfiles(), persistedProperties,
                sensitivePropertiesOmitted, sourceCredentialsOmitted);
    }

    ZipScanRequest toZipRequest() {
        return new ZipScanRequest(displayName, profile, mavenProfiles, mavenProperties);
    }
}
