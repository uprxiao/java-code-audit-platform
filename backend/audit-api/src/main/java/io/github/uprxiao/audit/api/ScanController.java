package io.github.uprxiao.audit.api;

import io.github.uprxiao.audit.finding.Finding;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/v1/scans")
class ScanController {

    private final ScanService scans;

    ScanController(ScanService scans) {
        this.scans = scans;
    }

    @PostMapping(value = "/svn", consumes = "application/json")
    ResponseEntity<CreateScanResponse> createSvn(@RequestBody SvnScanRequest request) throws IOException {
        CreateScanResponse response = scans.submitSvn(request);
        return ResponseEntity.accepted()
                .location(URI.create("/api/v1/scans/" + response.scanId()))
                .body(response);
    }

    @PostMapping(value = "/zip", consumes = "multipart/form-data")
    ResponseEntity<CreateScanResponse> createZip(
            @RequestPart("source") MultipartFile source,
            @RequestPart(value = "request", required = false) ZipScanRequest request) throws IOException {
        if (source.isEmpty()) {
            throw new ApiException(org.springframework.http.HttpStatus.BAD_REQUEST,
                    ApiErrorCode.INVALID_REQUEST, "上传的 ZIP 文件不能为空。");
        }
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

    @GetMapping("/{scanId}/findings/{findingId}")
    Finding finding(@PathVariable UUID scanId, @PathVariable String findingId) {
        return scans.finding(scanId, findingId);
    }

    @GetMapping("/{scanId}/engines")
    List<io.github.uprxiao.audit.finding.EngineTaskState> engines(@PathVariable UUID scanId) {
        return scans.engines(scanId);
    }

    @GetMapping("/{scanId}/engines/{engineId}")
    io.github.uprxiao.audit.finding.EngineTaskState engine(
            @PathVariable UUID scanId, @PathVariable String engineId) {
        return scans.engine(scanId, engineId);
    }

    @PostMapping("/{scanId}/cancel")
    ResponseEntity<ScanView> cancel(@PathVariable UUID scanId) {
        CancelScanResult result = scans.cancel(scanId);
        return ResponseEntity.status(result.accepted() ? HttpStatus.ACCEPTED : HttpStatus.OK)
                .body(result.scan());
    }

    @DeleteMapping("/{scanId}")
    ResponseEntity<Void> delete(@PathVariable UUID scanId) throws IOException {
        scans.delete(scanId);
        return ResponseEntity.noContent().build();
    }
}
