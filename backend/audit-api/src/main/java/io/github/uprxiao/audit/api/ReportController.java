package io.github.uprxiao.audit.api;

import java.nio.file.Path;
import java.util.Map;
import java.util.UUID;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/scans/{scanId}/reports")
class ReportController {

    private static final Map<String, MediaType> TYPES = Map.of(
            "html", MediaType.TEXT_HTML,
            "json", MediaType.APPLICATION_JSON,
            "sarif", MediaType.parseMediaType("application/sarif+json"),
            "archive", MediaType.parseMediaType("application/zip"));

    private final ScanService scans;

    ReportController(ScanService scans) {
        this.scans = scans;
    }

    @GetMapping("/{type:html|json|sarif|archive}")
    ResponseEntity<Resource> download(@PathVariable UUID scanId, @PathVariable String type) {
        Path report = scans.report(scanId, type);
        String extension = type.equals("archive") ? "zip" : type;
        String filename = "scan-report-" + scanId + "." + extension;
        return ResponseEntity.ok()
                .contentType(TYPES.get(type))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                .body(new FileSystemResource(report));
    }
}
