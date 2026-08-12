package io.github.uprxiao.audit.api;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
class HealthController {

    private final ScanService scans;

    HealthController(ScanService scans) {
        this.scans = scans;
    }

    @GetMapping({"/health", "/tools", "/profiles"})
    Map<String, Object> health() {
        return scans.toolHealth();
    }
}
