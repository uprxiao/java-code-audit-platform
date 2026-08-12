package io.github.uprxiao.audit.api;

import io.github.uprxiao.audit.finding.ScanProfile;
import java.util.List;
import java.util.Map;

public record ZipScanRequest(
        String displayName,
        ScanProfile profile,
        List<String> mavenProfiles,
        Map<String, String> mavenProperties) {

    public ZipScanRequest {
        displayName = displayName == null ? "" : displayName;
        profile = profile == null ? ScanProfile.QUICK : profile;
        mavenProfiles = mavenProfiles == null ? List.of() : List.copyOf(mavenProfiles);
        mavenProperties = mavenProperties == null ? Map.of() : Map.copyOf(mavenProperties);
    }

    public static ZipScanRequest defaults() {
        return new ZipScanRequest("", ScanProfile.QUICK, List.of(), Map.of());
    }
}
