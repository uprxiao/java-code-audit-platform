package io.github.uprxiao.audit.api;

import io.github.uprxiao.audit.finding.ScanJob;
import io.github.uprxiao.audit.orchestrator.DefaultScanPlanner;
import io.github.uprxiao.audit.orchestrator.ScanEngine;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/scans")
class ScanController {

    private final DefaultScanPlanner planner;

    ScanController(DefaultScanPlanner planner) {
        this.planner = planner;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.ACCEPTED)
    CreateScanResponse create(@RequestBody CreateScanRequest request) {
        ScanJob job = ScanJob.queued(request.sourceType(), request.profile());
        List<String> engines = planner.plan(request.profile()).engines().stream()
                .map(ScanEngine::name)
                .toList();
        return new CreateScanResponse(job.id(), job.status(), engines);
    }
}
