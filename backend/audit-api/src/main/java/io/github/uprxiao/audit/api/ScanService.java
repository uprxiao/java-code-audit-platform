package io.github.uprxiao.audit.api;

import io.github.uprxiao.audit.adapter.semgrep.SemgrepAdapter;
import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.finding.EngineTaskState;
import io.github.uprxiao.audit.finding.FailureDetails;
import io.github.uprxiao.audit.finding.Finding;
import io.github.uprxiao.audit.finding.ScanCoverage;
import io.github.uprxiao.audit.finding.ScanIdGenerator;
import io.github.uprxiao.audit.finding.ScanJob;
import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.finding.ScanStatus;
import io.github.uprxiao.audit.finding.SourceType;
import io.github.uprxiao.audit.intake.MavenProjectInspector;
import io.github.uprxiao.audit.intake.MavenArgumentValidator;
import io.github.uprxiao.audit.intake.ProjectContext;
import io.github.uprxiao.audit.intake.SafeZipExtractor;
import io.github.uprxiao.audit.intake.SourceDescriptor;
import io.github.uprxiao.audit.intake.SourceIntakeException;
import io.github.uprxiao.audit.intake.StagedUpload;
import io.github.uprxiao.audit.intake.UploadStager;
import io.github.uprxiao.audit.intake.ZipExtractionLimits;
import io.github.uprxiao.audit.process.LocalProcessExecutionBackend;
import io.github.uprxiao.audit.report.ReportBundle;
import io.github.uprxiao.audit.report.ReportGenerator;
import io.github.uprxiao.audit.report.ReportInput;
import io.github.uprxiao.audit.scanner.Applicability;
import io.github.uprxiao.audit.scanner.CancellationToken;
import io.github.uprxiao.audit.scanner.ExecutionResult;
import io.github.uprxiao.audit.scanner.ExecutionSpec;
import io.github.uprxiao.audit.scanner.NormalizationResult;
import io.github.uprxiao.audit.scanner.RawArtifactSet;
import io.github.uprxiao.audit.scanner.ScanContext;
import io.github.uprxiao.audit.scanner.ToolContext;
import io.github.uprxiao.audit.storage.JobDirectoryLayout;
import io.github.uprxiao.audit.storage.JobStore;
import io.github.uprxiao.audit.storage.JobTemporaryFileCleaner;
import io.github.uprxiao.audit.storage.StoredScanJob;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public final class ScanService {

    private final AuditRuntimePaths paths;
    private final JobStore jobs;
    private final ExecutorService executor;
    private final Clock clock;
    private final ScanIdGenerator ids;
    private final UploadStager uploads;
    private final SafeZipExtractor archives;
    private final ZipExtractionLimits zipLimits;
    private final MavenProjectInspector projects;
    private final MavenArgumentValidator mavenArguments;
    private final LocalProcessExecutionBackend processes;
    private final SemgrepAdapter semgrep;
    private final ReportGenerator reports;
    private final JobTemporaryFileCleaner cleaner;
    private final Map<UUID, RuntimeScan> scans = new ConcurrentHashMap<>();

    ScanService(
            AuditRuntimePaths paths,
            JobStore jobs,
            ExecutorService executor,
            Clock clock,
            ScanIdGenerator ids,
            UploadStager uploads,
            SafeZipExtractor archives,
            ZipExtractionLimits zipLimits,
            MavenProjectInspector projects,
            MavenArgumentValidator mavenArguments,
            LocalProcessExecutionBackend processes,
            SemgrepAdapter semgrep,
            ReportGenerator reports,
            JobTemporaryFileCleaner cleaner) {
        this.paths = paths;
        this.jobs = jobs;
        this.executor = executor;
        this.clock = clock;
        this.ids = ids;
        this.uploads = uploads;
        this.archives = archives;
        this.zipLimits = zipLimits;
        this.projects = projects;
        this.mavenArguments = mavenArguments;
        this.processes = processes;
        this.semgrep = semgrep;
        this.reports = reports;
        this.cleaner = cleaner;
    }

    public CreateScanResponse submitZip(InputStream source, String originalName, ZipScanRequest request) throws IOException {
        mavenArguments.validate(request.mavenProfiles(), request.mavenProperties());
        if (request.profile() != ScanProfile.QUICK) {
            throw new ApiException(HttpStatus.CONFLICT, ApiErrorCode.PROFILE_UNAVAILABLE,
                    "当前纵向切片只开放 QUICK；Standard/Deep 将在对应扫描器就绪后开放。");
        }
        UUID scanId = ids.nextId();
        JobDirectoryLayout layout = new JobDirectoryLayout(paths.dataRoot(), scanId);
        layout.initialize();
        StagedUpload staged;
        try {
            staged = uploads.stage(source, layout.source().resolve("upload.zip"), zipLimits.maxArchiveBytes());
        } catch (IOException exception) {
            cleaner.deleteEntireJob(layout);
            throw exception;
        }
        Instant now = clock.instant();
        ScanJob job = ScanJob.queued(scanId, SourceType.ZIP, request.profile(), now);
        EngineTaskState semgrepTask = EngineTaskState.pending(SemgrepAdapter.ID.value(), now);
        RuntimeScan runtime = new RuntimeScan(layout, job, Map.of(SemgrepAdapter.ID.value(), semgrepTask), staged, request);
        persist(runtime);
        scans.put(scanId, runtime);
        try {
            executor.execute(() -> run(runtime, originalName));
        } catch (RejectedExecutionException exception) {
            scans.remove(scanId);
            cleaner.deleteEntireJob(layout);
            throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, ApiErrorCode.QUEUE_FULL,
                    "扫描队列已满，请稍后重试。", Map.of("retryAfterSeconds", 30));
        }
        return new CreateScanResponse(scanId, job.status(), job.profile(), job.createdAt(), List.of("semgrep"));
    }

    public ScanView view(UUID scanId) {
        RuntimeScan runtime = require(scanId);
        synchronized (runtime) {
            int terminal = (int) runtime.engines.values().stream().filter(task -> task.status().isTerminal()).count();
            int running = (int) runtime.engines.values().stream().filter(task -> task.status() == EngineStatus.RUNNING).count();
            return new ScanView(
                    runtime.job.id(), runtime.job.status(), runtime.job.profile(), runtime.job.phase(),
                    Map.of(
                            "enginesTotal", runtime.engines.size(),
                            "enginesTerminal", terminal,
                            "enginesRunning", running,
                            "enginesWaiting", runtime.engines.size() - terminal - running),
                    Map.of(
                            "uniqueFindingCount", runtime.findings.size(),
                            "rawHitCount", runtime.coverage == null ? 0 : runtime.coverage.engines().stream()
                                    .mapToLong(engine -> engine.rawHitCount()).sum(),
                            "partial", !runtime.job.status().isTerminal()),
                    runtime.job.createdAt(), runtime.job.startedAt(), runtime.job.updatedAt(), runtime.job.completedAt(),
                    runtime.job.failure() == null ? Map.of() : Map.of(
                            "code", runtime.job.failure().code(),
                            "message", runtime.job.failure().message(),
                            "details", runtime.job.failure().details()),
                    runtime.bundle == null ? Map.of() : Map.of(
                            "html", "/api/v1/scans/" + scanId + "/reports/html",
                            "json", "/api/v1/scans/" + scanId + "/reports/json",
                            "sarif", "/api/v1/scans/" + scanId + "/reports/sarif",
                            "archive", "/api/v1/scans/" + scanId + "/reports/archive"));
        }
    }

    public List<Finding> findings(UUID scanId) {
        RuntimeScan runtime = require(scanId);
        synchronized (runtime) {
            return List.copyOf(runtime.findings);
        }
    }

    public Path report(UUID scanId, String type) {
        RuntimeScan runtime = require(scanId);
        synchronized (runtime) {
            if (runtime.bundle == null) {
                throw new ApiException(HttpStatus.CONFLICT, ApiErrorCode.REPORT_NOT_READY, "报告尚未生成。");
            }
            return switch (type) {
                case "html" -> runtime.bundle.html();
                case "json" -> runtime.bundle.json();
                case "sarif" -> runtime.bundle.sarif();
                case "archive" -> runtime.bundle.archive();
                default -> throw new ApiException(HttpStatus.NOT_FOUND, ApiErrorCode.SCAN_NOT_FOUND, "报告类型不存在。");
            };
        }
    }

    public Map<String, Object> toolHealth() {
        boolean semgrepAvailable = Files.isExecutable(paths.semgrepExecutable());
        return Map.of(
                "status", semgrepAvailable ? "UP" : "DEGRADED",
                "tools", List.of(Map.of(
                        "id", "semgrep",
                        "available", semgrepAvailable,
                        "path", paths.semgrepExecutable().toString())),
                "profiles", Map.of(
                        "QUICK", semgrepAvailable ? "PARTIAL_M3" : "UNAVAILABLE",
                        "STANDARD", "UNAVAILABLE",
                        "DEEP", "UNAVAILABLE"));
    }

    private void run(RuntimeScan runtime, String originalName) {
        try {
            transition(runtime, ScanStatus.ACQUIRING_SOURCE, null);
            Path extracted = runtime.layout.workspace().resolve("extracted");
            archives.extract(runtime.staged.path(), extracted, zipLimits);
            Files.deleteIfExists(runtime.staged.path());

            SourceDescriptor source = new SourceDescriptor(
                    SourceType.ZIP,
                    runtime.request.displayName().isBlank() ? safeDisplayName(originalName) : runtime.request.displayName(),
                    "upload.zip",
                    "",
                    "sha256:" + runtime.staged.sha256());
            ProjectContext project = projects.inspect(extracted, source, runtime.request.profile());
            transition(runtime, ScanStatus.PREFLIGHT, null);
            Applicability applicability = semgrep.checkApplicability(project, toolContext());
            if (applicability.status() != Applicability.Status.APPLICABLE) {
                throw new SourceIntakeException(applicability.reasonCode(), applicability.detail());
            }
            transitionEngine(runtime, EngineStatus.READY, null);
            transition(runtime, ScanStatus.RUNNING, null);
            transitionEngine(runtime, EngineStatus.RUNNING, null);

            Path engineOutput = runtime.layout.rawEngine(SemgrepAdapter.ID.value());
            ScanContext scanContext = new ScanContext(runtime.job.id(), runtime.job.profile(), project, engineOutput,
                    runtime.request.mavenProfiles(), runtime.request.mavenProperties());
            ExecutionSpec specification = semgrep.prepare(scanContext, toolContext());
            ExecutionResult execution = processes.execute(specification, CancellationToken.NONE);
            RawArtifactSet raw = new RawArtifactSet(SemgrepAdapter.ID,
                    Map.of("report", engineOutput.resolve("report.json")), execution);
            NormalizationResult normalized = semgrep.normalize(scanContext, raw);
            synchronized (runtime) {
                runtime.findings = normalized.findings();
                runtime.coverage = new ScanCoverage(
                        project.manifest().modules().size(), 0, project.manifest().modules().size(),
                        List.of("**/target/**", "**/.git/**"), List.of(normalized.coverage()));
            }
            if (normalized.coverage().status() == EngineStatus.PARTIAL) {
                transitionEngine(runtime, EngineStatus.PARTIAL,
                        new FailureDetails("SEMGREP_PARTIAL_ERRORS", "Semgrep completed with parser warnings",
                                Map.of("warnings", normalized.warnings())));
            } else {
                transitionEngine(runtime, EngineStatus.SUCCEEDED, null);
            }
            transition(runtime, ScanStatus.FINALIZING, null);
            Instant reportCompletedAt = clock.instant();
            ScanStatus finalStatus = normalized.coverage().status() == EngineStatus.PARTIAL
                    ? ScanStatus.COMPLETED_WITH_ERRORS : ScanStatus.COMPLETED;
            ReportInput reportInput = new ReportInput(
                    runtime.job.id(), runtime.job.profile(), finalStatus, runtime.job.createdAt(), reportCompletedAt,
                    Map.of(
                            "type", "ZIP",
                            "displayName", source.displayName(),
                            "sha256", source.contentSha256()),
                    normalized.findings(), runtime.coverage,
                    Map.of("components", 0, "vulnerableComponents", 0),
                    Map.of("status", "NOT_REQUIRED", "mavenProfiles", runtime.request.mavenProfiles()),
                    Map.of(
                            "mavenVersion", "system",
                            "tools", List.of(Map.of("id", "semgrep", "version",
                                    normalized.findings().stream().findFirst()
                                            .flatMap(finding -> finding.evidence().stream().findFirst())
                                            .map(evidence -> evidence.engineVersion()).orElse("1.170.0"))),
                            "rules", List.of(Map.of("id", "java-audit", "sha256", "sha256:" + sha256(paths.semgrepRules()))),
                            "databases", List.of()),
                    runtime.coverage.excludedPaths(), normalized.warnings(), configFingerprint());
            ReportBundle bundle = reports.generate(reportInput, runtime.layout.root());
            synchronized (runtime) {
                runtime.bundle = bundle;
            }
            cleaner.cleanSuccessfulJob(runtime.layout);
            FailureDetails partial = finalStatus == ScanStatus.COMPLETED_WITH_ERRORS
                    ? new FailureDetails("PARTIAL_ENGINE_RESULT", "one or more engines completed partially", Map.of())
                    : null;
            synchronized (runtime) {
                runtime.job = runtime.job.transitionTo(finalStatus, clock.instant(), partial);
                persist(runtime, Map.of(
                        "html", relative(runtime.layout.root(), bundle.html()),
                        "json", relative(runtime.layout.root(), bundle.json()),
                        "sarif", relative(runtime.layout.root(), bundle.sarif()),
                        "archive", relative(runtime.layout.root(), bundle.archive())));
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            fail(runtime, new FailureDetails("SCAN_INTERRUPTED", "scan worker was interrupted", Map.of()));
        } catch (Exception exception) {
            fail(runtime, failure(exception));
        }
    }

    private void fail(RuntimeScan runtime, FailureDetails failure) {
        synchronized (runtime) {
            EngineTaskState engine = runtime.engines.get(SemgrepAdapter.ID.value());
            if (engine != null && engine.status() == EngineStatus.RUNNING) {
                runtime.engines = Map.of(engine.engineId(), engine.transitionTo(EngineStatus.FAILED, clock.instant(), failure));
            }
            if (!runtime.job.status().isTerminal()) {
                try {
                    runtime.job = runtime.job.transitionTo(ScanStatus.FAILED, clock.instant(), failure);
                } catch (RuntimeException transitionFailure) {
                    return;
                }
            }
            try {
                persist(runtime);
            } catch (IOException ignored) {
                // The in-memory failure remains visible; recovery will isolate an unreadable state file.
            }
        }
    }

    private FailureDetails failure(Exception exception) {
        if (exception instanceof SourceIntakeException intake) {
            return new FailureDetails(intake.code(), intake.getMessage(), intake.details());
        }
        return new FailureDetails("SCAN_EXECUTION_FAILED",
                exception.getMessage() == null ? exception.getClass().getSimpleName() : exception.getMessage(), Map.of());
    }

    private void transition(RuntimeScan runtime, ScanStatus next, FailureDetails failure) throws IOException {
        synchronized (runtime) {
            runtime.job = runtime.job.transitionTo(next, clock.instant(), failure);
            persist(runtime);
        }
    }

    private void transitionEngine(RuntimeScan runtime, EngineStatus next, FailureDetails failure) throws IOException {
        synchronized (runtime) {
            EngineTaskState current = runtime.engines.get(SemgrepAdapter.ID.value());
            EngineTaskState updated = current.transitionTo(next, clock.instant(), failure);
            runtime.engines = Map.of(SemgrepAdapter.ID.value(), updated);
            runtime.job = runtime.job.touch(clock.instant());
            persist(runtime);
        }
    }

    private ToolContext toolContext() {
        boolean available = Files.isExecutable(paths.semgrepExecutable());
        return new ToolContext(paths.semgrepExecutable().getParent(), Map.of(
                SemgrepAdapter.ID, new ToolContext.ToolInstallation(paths.semgrepExecutable(), "1.170.0", available)));
    }

    private RuntimeScan require(UUID scanId) {
        RuntimeScan runtime = scans.get(scanId);
        if (runtime == null) {
            throw new ApiException(HttpStatus.NOT_FOUND, ApiErrorCode.SCAN_NOT_FOUND, "扫描任务不存在。");
        }
        return runtime;
    }

    private void persist(RuntimeScan runtime) throws IOException {
        persist(runtime, Map.of());
    }

    private void persist(RuntimeScan runtime, Map<String, String> artifacts) throws IOException {
        jobs.save(StoredScanJob.from(runtime.job, runtime.engines, artifacts));
    }

    private String configFingerprint() throws IOException {
        return "sha256:" + sha256(paths.semgrepRules());
    }

    private String sha256(Path file) throws IOException {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by Java 17", exception);
        }
    }

    private String relative(Path root, Path path) {
        return root.relativize(path).toString().replace(path.getFileSystem().getSeparator(), "/");
    }

    private String safeDisplayName(String originalName) {
        if (originalName == null || originalName.isBlank()) {
            return "uploaded-project";
        }
        String cleaned = originalName.replaceAll("[\\r\\n\\t]", "_");
        return cleaned.length() > 200 ? cleaned.substring(0, 200) : cleaned;
    }

    private static final class RuntimeScan {
        private final JobDirectoryLayout layout;
        private final StagedUpload staged;
        private final ZipScanRequest request;
        private ScanJob job;
        private Map<String, EngineTaskState> engines;
        private List<Finding> findings = List.of();
        private ScanCoverage coverage;
        private ReportBundle bundle;

        private RuntimeScan(
                JobDirectoryLayout layout,
                ScanJob job,
                Map<String, EngineTaskState> engines,
                StagedUpload staged,
                ZipScanRequest request) {
            this.layout = layout;
            this.job = job;
            this.engines = engines;
            this.staged = staged;
            this.request = request;
        }
    }
}
