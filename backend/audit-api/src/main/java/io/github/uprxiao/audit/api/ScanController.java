package io.github.uprxiao.audit.api;

import io.github.uprxiao.audit.finding.Finding;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.List;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/v1/scans")
class ScanController {

    private final ScanService scans;

    ScanController(ScanService scans) {
        this.scans = scans;
    }

    @PostMapping(value = "/zip", consumes = "multipart/form-data")
    ResponseEntity<CreateScanResponse> createZip(
            @RequestPart("source") MultipartFile source,
            @RequestPart(value = "request", required = false) ZipScanRequest request) throws IOException {
        ZipScanRequest effectiveRequest = request == null ? ZipScanRequest.defaults() : request;
        CreateScanResponse response;
        try (InputStream input = source.getInputStream()) {
            response = scans.submitZip(input, source.getOriginalFilename(), effectiveRequest);
        }
        return ResponseEntity.accepted()
                .location(URI.create("/api/v1/scans/" + response.scanId()))
                .body(response);
    }

    @GetMapping("/{scanId}")
    ScanView get(@PathVariable UUID scanId) {
        return scans.view(scanId);
    }

    @GetMapping("/{scanId}/findings")
    List<Finding> findings(@PathVariable UUID scanId) {
        return scans.findings(scanId);
    }
}
