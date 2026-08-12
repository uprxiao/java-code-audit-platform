package io.github.uprxiao.audit.api;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
class HealthController {

    private final ScanService scans;
    private final StartupHealthSnapshot startup;

    HealthController(ScanService scans, StartupHealthSnapshot startup) {
        this.scans = scans;
        this.startup = startup;
    }

    @GetMapping({"/health", "/tools", "/profiles"})
    Map<String, Object> health() {
        Map<String, Object> toolHealth = scans.toolHealth();
        return Map.of(
                "status", toolHealth.get("status"),
                "startup", startup,
                "tools", toolHealth.get("tools"),
                "profiles", toolHealth.get("profiles"));
    }
}
