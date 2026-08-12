package io.github.uprxiao.audit.api;

import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.finding.SourceType;
import java.util.List;
import java.util.Map;

public record CreateScanRequest(
        SourceType sourceType,
        String displayName,
        ScanProfile profile,
        List<String> mavenProfiles,
        Map<String, String> mavenProperties) {

    public CreateScanRequest {
        displayName = displayName == null ? "" : displayName;
        profile = profile == null ? ScanProfile.QUICK : profile;
        mavenProfiles = mavenProfiles == null ? List.of() : List.copyOf(mavenProfiles);
        mavenProperties = mavenProperties == null ? Map.of() : Map.copyOf(mavenProperties);
    }

    public CreateScanRequest(SourceType sourceType, ScanProfile profile) {
        this(sourceType, "", profile, List.of(), Map.of());
    }
}
