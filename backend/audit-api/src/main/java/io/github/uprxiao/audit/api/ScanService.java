package io.github.uprxiao.audit.api;

import io.github.uprxiao.audit.adapter.codeql.CodeqlAdapter;
import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.finding.ConservativeFindingDeduplicator;
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
import io.github.uprxiao.audit.intake.SourceCredential;
import io.github.uprxiao.audit.intake.SourceIntakeException;
import io.github.uprxiao.audit.intake.StagedUpload;
import io.github.uprxiao.audit.intake.SvnCheckoutResult;
import io.github.uprxiao.audit.intake.SvnRepositoryPolicy;
import io.github.uprxiao.audit.intake.SvnRevision;
import io.github.uprxiao.audit.intake.SvnSourceCheckout;
import io.github.uprxiao.audit.intake.UploadStager;
import io.github.uprxiao.audit.intake.ZipExtractionLimits;
import io.github.uprxiao.audit.orchestrator.ScanJobQueueFullException;
import io.github.uprxiao.audit.orchestrator.DefaultScanPlanner;
import io.github.uprxiao.audit.orchestrator.EngineAction;
import io.github.uprxiao.audit.orchestrator.EngineExecutionResult;
import io.github.uprxiao.audit.orchestrator.FairDagScheduler;
import io.github.uprxiao.audit.orchestrator.ScanEngine;
import io.github.uprxiao.audit.orchestrator.ScanExecutionPlanFactory;
import io.github.uprxiao.audit.orchestrator.ScanJobHandle;
import io.github.uprxiao.audit.orchestrator.ScanJobListener;
import io.github.uprxiao.audit.orchestrator.ScanPlan;
import io.github.uprxiao.audit.process.LocalProcessExecutionBackend;
import io.github.uprxiao.audit.process.MavenBuildRequest;
import io.github.uprxiao.audit.process.MavenBuildResult;
import io.github.uprxiao.audit.process.MavenProcessAdapter;
import io.github.uprxiao.audit.adapter.codeql.CodeqlAdapter;
import io.github.uprxiao.audit.adapter.codeql.CodeqlWorkflow;
import io.github.uprxiao.audit.report.ReportBundle;
import io.github.uprxiao.audit.report.ReportGenerator;
import io.github.uprxiao.audit.report.ReportGenerationOptions;
import io.github.uprxiao.audit.report.ReportInput;
import io.github.uprxiao.audit.report.AuditReport;
import io.github.uprxiao.audit.scanner.Applicability;
import io.github.uprxiao.audit.scanner.ArtifactValidation;
import io.github.uprxiao.audit.scanner.EngineId;
import io.github.uprxiao.audit.scanner.ExecutionResult;
import io.github.uprxiao.audit.scanner.ExecutionSpec;
import io.github.uprxiao.audit.scanner.NormalizationResult;
import io.github.uprxiao.audit.scanner.RawArtifactSet;
import io.github.uprxiao.audit.scanner.ScanContext;
import io.github.uprxiao.audit.scanner.ScannerAdapter;
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
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.atomic.AtomicBoolean;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public final class ScanService {

    private final AuditRuntimePaths paths;
    private final JobStore jobs;
    private final ThreadPoolExecutor executor;
    private final Clock clock;
    private final ScanIdGenerator ids;
    private final UploadStager uploads;
    private final SafeZipExtractor archives;
    private final ZipExtractionLimits zipLimits;
    private final MavenProjectInspector projects;
    private final MavenArgumentValidator mavenArguments;
    private final LocalProcessExecutionBackend processes;
    private final ScannerRegistry scanners;
    private final FairDagScheduler scheduler;
    private final DefaultScanPlanner planner;
    private final ScanExecutionPlanFactory executionPlans = new ScanExecutionPlanFactory();
    private final ConservativeFindingDeduplicator deduplicator = new ConservativeFindingDeduplicator();
    private final MavenProcessAdapter maven;
    private final Duration mavenBuildTimeout;
    private final CodeqlWorkflow codeql;
    private final ReportGenerator reports;
    private final JobTemporaryFileCleaner cleaner;
    private final StorageCapacityGuard storageCapacity;
    private final SvnRepositoryPolicy svnRepositoryPolicy;
    private final SvnSourceCheckout svnCheckout;
    private final ObjectMapper json = new ObjectMapper().findAndRegisterModules();
    private final Map<UUID, RuntimeScan> scans = new ConcurrentHashMap<>();

    ScanService(
            AuditRuntimePaths paths,
            JobStore jobs,
            ThreadPoolExecutor executor,
            Clock clock,
            ScanIdGenerator ids,
            UploadStager uploads,
            SafeZipExtractor archives,
            ZipExtractionLimits zipLimits,
            MavenProjectInspector projects,
            MavenArgumentValidator mavenArguments,
            LocalProcessExecutionBackend processes,
            ScannerRegistry scanners,
            FairDagScheduler scheduler,
            DefaultScanPlanner planner,
            MavenProcessAdapter maven,
            CodeqlWorkflow codeql,
            @org.springframework.beans.factory.annotation.Value("${audit.maven.build-timeout:20m}")
                    Duration mavenBuildTimeout,
            ReportGenerator reports,
            JobTemporaryFileCleaner cleaner,
            StorageCapacityGuard storageCapacity,
            SvnRepositoryPolicy svnRepositoryPolicy,
            SvnSourceCheckout svnCheckout) {
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
        this.scanners = scanners;
        this.scheduler = scheduler;
        this.planner = planner;
        this.maven = maven;
        this.codeql = codeql;
        this.mavenBuildTimeout = mavenBuildTimeout;
        this.reports = reports;
        this.cleaner = cleaner;
        this.storageCapacity = storageCapacity;
        this.svnRepositoryPolicy = svnRepositoryPolicy;
        this.svnCheckout = svnCheckout;
    }

    public CreateScanResponse submitZip(InputStream source, String originalName, ZipScanRequest request) throws IOException {
        mavenArguments.validate(request.mavenProfiles(), request.mavenProperties());
        storageCapacity.requireCapacity();
        requireProfile(request.profile());
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
        ScanPlan plan = planner.plan(request.profile());
        Map<String, EngineTaskState> engineStates = new LinkedHashMap<>();
        for (ScanEngine engine : plan.engines()) {
            scanners.require(engine.id());
            engineStates.put(engine.id().value(), EngineTaskState.pending(engine.id().value(), now));
        }
        RuntimeScan runtime = new RuntimeScan(layout, job, Map.copyOf(engineStates), staged, request, plan);
        Map<String, String> persistedProperties = new LinkedHashMap<>();
        boolean sensitivePropertiesOmitted = false;
        for (Map.Entry<String, String> property : request.mavenProperties().entrySet()) {
            if (mavenArguments.isSensitiveProperty(property.getKey())) {
                sensitivePropertiesOmitted = true;
            } else {
                persistedProperties.put(property.getKey(), property.getValue());
            }
        }
        writeRequest(runtime, PersistedScanRequest.zip(
                originalName, request, Map.copyOf(persistedProperties), sensitivePropertiesOmitted));
        persist(runtime);
        scans.put(scanId, runtime);
        Runnable workItem = () -> run(runtime, originalName);
        runtime.workItem = workItem;
        try {
            executor.execute(workItem);
        } catch (ScanJobQueueFullException exception) {
            scans.remove(scanId);
            cleaner.deleteEntireJob(layout);
            throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, ApiErrorCode.QUEUE_FULL,
                    "扫描队列已满，请稍后重试。", Map.of(
                            "retryAfterSeconds", exception.retryAfter().toSeconds(),
                            "queueLength", exception.queueLength(),
                            "queueCapacity", exception.queueCapacity()));
        } catch (RejectedExecutionException exception) {
            scans.remove(scanId);
            cleaner.deleteEntireJob(layout);
            throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, ApiErrorCode.QUEUE_FULL,
                    "扫描服务正在停止，请稍后重试。", Map.of(
                            "retryAfterSeconds", 30,
                            "queueLength", executor.getQueue().size(),
                            "queueCapacity", executor.getQueue().size() + executor.getQueue().remainingCapacity()));
        }
        return new CreateScanResponse(scanId, job.status(), job.profile(), job.createdAt(),
                plan.engines().stream().map(engine -> engine.id().value()).toList());
    }

    public CreateScanResponse submitSvn(SvnScanRequest request) throws IOException {
        try {
            return submitSvnRequest(request);
        } finally {
            request.close();
        }
    }

    private CreateScanResponse submitSvnRequest(SvnScanRequest request) throws IOException {
        mavenArguments.validate(request.mavenProfiles(), request.mavenProperties());
        storageCapacity.requireCapacity();
        SvnRepositoryPolicy.ValidatedSvnUrl validated = svnRepositoryPolicy.validate(request.repositoryUrl());
        SvnRevision revision = SvnRevision.parse(request.revision());
        requireProfile(request.profile());

        SourceCredential credential;
        try {
            credential = request.transferCredential();
        } catch (IllegalArgumentException exception) {
            throw new SourceIntakeException(
                    "INVALID_SVN_CREDENTIAL", "SVN username or password exceeds its safe limit");
        }
        UUID scanId = ids.nextId();
        JobDirectoryLayout layout = new JobDirectoryLayout(paths.dataRoot(), scanId);
        try {
            layout.initialize();
            Instant now = clock.instant();
            ScanJob job = ScanJob.queued(scanId, SourceType.SVN, request.profile(), now);
            ScanPlan plan = planner.plan(request.profile());
            Map<String, EngineTaskState> engineStates = initialEngineStates(plan, now);
            String displayName = request.displayName().isBlank()
                    ? safeSvnDisplayName(validated.value()) : request.displayName();
            ZipScanRequest scanOptions = new ZipScanRequest(
                    displayName, request.profile(), request.mavenProfiles(), request.mavenProperties());
            SvnRuntimeRequest svnRequest = new SvnRuntimeRequest(validated.value(), revision);
            RuntimeScan runtime = new RuntimeScan(
                    layout, job, engineStates, scanOptions, plan, svnRequest, credential);
            Map<String, String> persistedProperties = persistedMavenProperties(request.mavenProperties());
            writeRequest(runtime, PersistedScanRequest.svn(
                    validated.value(), revision.displayValue(), displayName, request, persistedProperties,
                    persistedProperties.size() != request.mavenProperties().size(), credential.isPresent()));
            persist(runtime);
            scans.put(scanId, runtime);
            Runnable workItem = () -> run(runtime, "");
            runtime.workItem = workItem;
            try {
                executor.execute(workItem);
            } catch (ScanJobQueueFullException exception) {
                rejectSvnRuntime(runtime);
                throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, ApiErrorCode.QUEUE_FULL,
                        "扫描队列已满，请稍后重试。", Map.of(
                                "retryAfterSeconds", exception.retryAfter().toSeconds(),
                                "queueLength", exception.queueLength(),
                                "queueCapacity", exception.queueCapacity()));
            } catch (RejectedExecutionException exception) {
                rejectSvnRuntime(runtime);
                throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, ApiErrorCode.QUEUE_FULL,
                        "扫描服务正在停止，请稍后重试。", Map.of(
                                "retryAfterSeconds", 30,
                                "queueLength", executor.getQueue().size(),
                                "queueCapacity", executor.getQueue().size() + executor.getQueue().remainingCapacity()));
            }
            return new CreateScanResponse(scanId, job.status(), job.profile(), job.createdAt(),
                    plan.engines().stream().map(engine -> engine.id().value()).toList());
        } catch (IOException | RuntimeException exception) {
            credential.close();
            scans.remove(scanId);
            cleaner.deleteEntireJob(layout);
            throw exception;
        }
    }

    void restoreQueued(StoredScanJob stored) throws IOException {
        if (stored.status().isTerminal()) {
            restoreTerminal(stored);
            return;
        }
        if (stored.status() != ScanStatus.QUEUED) {
            throw new IOException("only queued or terminal scans can be restored: " + stored.scanId());
        }
        JobDirectoryLayout layout = new JobDirectoryLayout(paths.dataRoot(), stored.scanId());
        Path requestFile = layout.safeResolve("request.json");
        if (!Files.isRegularFile(requestFile)) {
            throw new IOException("queued scan input is incomplete: " + stored.scanId());
        }
        PersistedScanRequest persisted = json.readValue(requestFile.toFile(), PersistedScanRequest.class);
        if (persisted.sourceType() != stored.sourceType() || persisted.profile() != stored.profile()) {
            throw new IOException("queued request does not match job state: " + stored.scanId());
        }
        if (persisted.sensitivePropertiesOmitted() || persisted.sourceCredentialsOmitted()) {
            StoredScanJob expired = expireQueuedRequest(stored, persisted.sourceCredentialsOmitted()
                    ? "SVN credentials are never persisted and must be resubmitted after restart"
                    : "sensitive Maven properties are never persisted and must be resubmitted after restart");
            restoreTerminal(expired);
            return;
        }
        ZipScanRequest request = persisted.toZipRequest();
        mavenArguments.validate(request.mavenProfiles(), request.mavenProperties());
        ScanPlan plan = planner.plan(request.profile());
        RuntimeScan runtime;
        if (stored.sourceType() == SourceType.ZIP) {
            Path uploadFile = layout.source().resolve("upload.zip");
            if (!Files.isRegularFile(uploadFile)) {
                throw new IOException("queued ZIP input is incomplete: " + stored.scanId());
            }
            StagedUpload staged = new StagedUpload(uploadFile, Files.size(uploadFile), sha256(uploadFile));
            runtime = new RuntimeScan(layout, stored.toScanJob(), stored.engines(), staged, request, plan);
        } else if (stored.sourceType() == SourceType.SVN) {
            SvnRepositoryPolicy.ValidatedSvnUrl validated = svnRepositoryPolicy.validate(persisted.repositoryUrl());
            SvnRevision revision = SvnRevision.parse(persisted.revision());
            runtime = new RuntimeScan(
                    layout, stored.toScanJob(), stored.engines(), request, plan,
                    new SvnRuntimeRequest(validated.value(), revision), new SourceCredential("", new char[0]));
        } else {
            throw new IOException("unsupported queued source type: " + stored.sourceType());
        }
        if (scans.putIfAbsent(stored.scanId(), runtime) != null) {
            releaseSourceCredential(runtime);
            throw new IOException("queued scan is already in the runtime index: " + stored.scanId());
        }
        Runnable workItem = () -> run(runtime, persisted.originalName());
        runtime.workItem = workItem;
        try {
            executor.execute(workItem);
        } catch (RuntimeException exception) {
            scans.remove(stored.scanId(), runtime);
            releaseSourceCredential(runtime);
            throw new IOException("cannot requeue scan after restart: " + stored.scanId(), exception);
        }
    }

    private StoredScanJob expireQueuedRequest(StoredScanJob stored, String message) throws IOException {
        Instant observed = clock.instant();
        Instant now = observed.isBefore(stored.updatedAt()) ? stored.updatedAt() : observed;
        FailureDetails failure = new FailureDetails("SOURCE_CREDENTIALS_EXPIRED", message, Map.of());
        Map<String, EngineTaskState> cancelled = new LinkedHashMap<>();
        stored.engines().forEach((id, state) -> cancelled.put(id,
                state.status().isTerminal() ? state : state.transitionTo(EngineStatus.CANCELLED, now)));
        StoredScanJob expired = StoredScanJob.from(
                stored.toScanJob().transitionTo(ScanStatus.INTERRUPTED, now, failure),
                Map.copyOf(cancelled), stored.artifacts());
        jobs.save(expired);
        return expired;
    }

    private void restoreTerminal(StoredScanJob stored) throws IOException {
        JobDirectoryLayout layout = new JobDirectoryLayout(paths.dataRoot(), stored.scanId());
        ZipScanRequest request = new ZipScanRequest("", stored.profile(), List.of(), Map.of());
        Path requestFile = layout.safeResolve("request.json");
        if (Files.isRegularFile(requestFile)) {
            PersistedScanRequest persisted = json.readValue(requestFile.toFile(), PersistedScanRequest.class);
            request = persisted.toZipRequest();
        }
        RuntimeScan runtime = new RuntimeScan(
                layout, stored.toScanJob(), stored.engines(), null, request, planner.plan(stored.profile()));
        Path reportJson = layout.report().resolve("report.json");
        if (Files.isRegularFile(reportJson)) {
            AuditReport report = json.readValue(reportJson.toFile(), AuditReport.class);
            runtime.findings = java.util.stream.Stream.concat(
                    report.findings().stream(), report.suppressedFindings().stream()).toList();
        }
        Path html = layout.report().resolve("report.html");
        Path sarif = layout.report().resolve("report.sarif");
        Path coverage = layout.report().resolve("coverage.json");
        Path manifest = layout.report().resolve("manifest.json");
        Path archive = stored.artifacts().containsKey("archive")
                ? layout.safeResolve(stored.artifacts().get("archive"))
                : layout.archive().resolve("scan-report-" + stored.scanId() + ".zip");
        if (Files.isRegularFile(html) && Files.isRegularFile(reportJson) && Files.isRegularFile(sarif)
                && Files.isRegularFile(coverage) && Files.isRegularFile(manifest) && Files.isRegularFile(archive)) {
            runtime.bundle = new ReportBundle(html, reportJson, sarif, coverage, manifest, archive);
        }
        scans.putIfAbsent(stored.scanId(), runtime);
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

    public Finding finding(UUID scanId, String findingId) {
        return findings(scanId).stream()
                .filter(finding -> finding.id().equals(findingId))
                .findFirst()
                .orElseThrow(() -> new ApiException(
                        HttpStatus.NOT_FOUND, ApiErrorCode.SCAN_NOT_FOUND, "问题记录不存在。"));
    }

    public List<EngineTaskState> engines(UUID scanId) {
        RuntimeScan runtime = require(scanId);
        synchronized (runtime) {
            return runtime.engines.values().stream()
                    .sorted(java.util.Comparator.comparing(EngineTaskState::engineId))
                    .toList();
        }
    }

    public EngineTaskState engine(UUID scanId, String engineId) {
        RuntimeScan runtime = require(scanId);
        synchronized (runtime) {
            EngineTaskState state = runtime.engines.get(engineId);
            if (state == null) {
                throw new ApiException(HttpStatus.NOT_FOUND, ApiErrorCode.SCAN_NOT_FOUND, "扫描引擎不存在。");
            }
            return state;
        }
    }

    public void delete(UUID scanId) throws IOException {
        RuntimeScan runtime = require(scanId);
        synchronized (runtime) {
            if (!runtime.job.status().isTerminal()) {
                throw new ApiException(HttpStatus.CONFLICT, ApiErrorCode.INVALID_SCAN_STATE,
                        "运行或排队中的任务不能删除。");
            }
            StoredScanJob stored = jobs.find(scanId).orElseThrow(() -> new ApiException(
                    HttpStatus.NOT_FOUND, ApiErrorCode.SCAN_NOT_FOUND, "扫描任务不存在。"));
            cleaner.deleteTerminalJob(runtime.layout, stored);
            scans.remove(scanId, runtime);
        }
    }

    public CancelScanResult cancel(UUID scanId) {
        RuntimeScan runtime = require(scanId);
        boolean accepted;
        synchronized (runtime) {
            if (runtime.job.status().isTerminal()) {
                accepted = false;
            } else {
                runtime.cancelRequested.set(true);
                if (runtime.schedulerHandle != null) {
                    runtime.schedulerHandle.cancel();
                }
                accepted = true;
                if (runtime.job.status() == ScanStatus.QUEUED && executor.remove(runtime.workItem)) {
                    cancelRuntime(runtime);
                }
            }
        }
        return new CancelScanResult(view(scanId), accepted);
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
        boolean quickAvailable = scanners.available(ScanProfile.QUICK);
        return Map.of(
                "status", quickAvailable ? "UP" : "DEGRADED",
                "tools", scanners.health(),
                "profiles", scanners.profileAvailability());
    }

    void forget(UUID scanId) {
        scans.remove(scanId);
    }

    private void run(RuntimeScan runtime, String originalName) {
        try {
            if (runtime.cancelRequested.get()) {
                cancelRuntime(runtime);
                return;
            }
            transition(runtime, ScanStatus.ACQUIRING_SOURCE, null);
            Path extracted = runtime.layout.workspace().resolve("extracted");
            SourceDescriptor source;
            if (runtime.svnRequest == null) {
                archives.extract(runtime.staged.path(), extracted, zipLimits);
                Files.deleteIfExists(runtime.staged.path());
                source = new SourceDescriptor(
                        SourceType.ZIP,
                        runtime.request.displayName().isBlank()
                                ? safeDisplayName(originalName) : runtime.request.displayName(),
                        "upload.zip",
                        "",
                        "sha256:" + runtime.staged.sha256());
            } else {
                SvnCheckoutResult checkout;
                try {
                    checkout = svnCheckout.checkout(
                            runtime.svnRequest.repositoryUrl(),
                            runtime.svnRequest.revision(),
                            extracted,
                            runtime.sourceCredential,
                            runtime.cancelRequested::get);
                } finally {
                    releaseSourceCredential(runtime);
                }
                source = new SourceDescriptor(
                        SourceType.SVN,
                        runtime.request.displayName(),
                        runtime.svnRequest.repositoryUrl(),
                        "svn:" + checkout.revision(),
                        checkout.contentSha256());
            }
            if (runtime.cancelRequested.get()) {
                cancelRuntime(runtime);
                return;
            }
            ProjectContext project = projects.inspect(extracted, source, runtime.request.profile());
            runtime.project = project;
            transition(runtime, ScanStatus.PREFLIGHT, null);
            transition(runtime, ScanStatus.RUNNING, null);

            Map<ScanEngine, EngineAction> actions = new LinkedHashMap<>();
            for (ScanEngine engine : runtime.plan.engines()) {
                ScannerAdapter adapter = scanners.require(engine.id());
                if (engine == ScanEngine.FINDSECBUGS) {
                    actions.put(engine, token -> executeSharedFindSecBugs(runtime, project, adapter, token));
                } else if (engine == ScanEngine.CODEQL) {
                    actions.put(engine, token -> executeCodeql(runtime, project, (CodeqlAdapter) adapter, token));
                } else {
                    actions.put(engine, token -> executeScanner(runtime, project, adapter, token));
                }
            }
            EngineAction mavenBuild = runtime.plan.plannedEngines().stream().anyMatch(engine -> engine.requiresBuild())
                    ? token -> executeMavenBuild(runtime, project, token) : null;
            ScanJobHandle handle = scheduler.submit(executionPlans.create(
                    runtime.job.id(), runtime.plan, mavenBuild, actions, listener(runtime)));
            runtime.schedulerHandle = handle;
            var executionResult = handle.completion().get();
            if (executionResult.disposition()
                    == io.github.uprxiao.audit.orchestrator.ScanJobExecutionResult.Disposition.CANCELLED) {
                cancelRuntime(runtime);
                return;
            }
            if (runtime.persistenceFailure != null) {
                throw runtime.persistenceFailure;
            }

            List<NormalizationResult> normalizedResults = runtime.normalized.values().stream().toList();
            List<Finding> normalizedFindings = normalizedResults.stream()
                    .flatMap(result -> result.findings().stream()).toList();
            List<Finding> activeFindings = deduplicator.deduplicate(
                    normalizedFindings.stream().filter(finding -> !finding.suppressed()).toList()).findings();
            List<Finding> suppressedFindings = deduplicator.deduplicate(
                    normalizedFindings.stream().filter(Finding::suppressed).toList()).findings();
            List<Finding> allFindings = java.util.stream.Stream.concat(
                    activeFindings.stream(), suppressedFindings.stream()).toList();
            List<io.github.uprxiao.audit.finding.EngineCoverage> engineCoverage = coverage(runtime, project);
            List<String> warnings = normalizedResults.stream()
                    .flatMap(result -> result.warnings().stream()).toList();
            synchronized (runtime) {
                runtime.findings = allFindings;
                runtime.coverage = new ScanCoverage(
                        project.manifest().modules().size(), modulesBuilt(runtime, project),
                        engineCoverage.stream().anyMatch(value -> value.modulesScanned() > 0)
                                ? project.manifest().modules().size() : 0,
                        List.of("**/target/**", "**/.git/**"), engineCoverage);
            }
            transition(runtime, ScanStatus.FINALIZING, null);
            Instant reportCompletedAt = clock.instant();
            ScanStatus finalStatus = runtime.engines.values().stream()
                    .allMatch(task -> task.status() == EngineStatus.SUCCEEDED)
                            ? ScanStatus.COMPLETED : ScanStatus.COMPLETED_WITH_ERRORS;
            Map<String, Object> sbomSummary = finalizeSbom(runtime, activeFindings);
            ReportInput reportInput = new ReportInput(
                    runtime.job.id(), runtime.job.profile(), finalStatus, runtime.job.createdAt(), reportCompletedAt,
                    reportSource(source),
                    allFindings, runtime.coverage,
                    sbomSummary,
                    mavenBuildSummary(runtime),
                    Map.of(
                            "mavenVersion", "system",
                            "tools", scanners.health().stream().map(tool -> Map.<String, Object>of(
                                    "id", tool.id(), "version", tool.version(), "sha256", tool.sha256(),
                                    "status", tool.status())).toList(),
                            "rules", ruleManifest(),
                            "databases", List.of()),
                    runtime.coverage.excludedPaths(), warnings, configFingerprint());
            ReportBundle bundle = reports.generate(
                    reportInput, runtime.layout.root(),
                    ReportGenerationOptions.withSensitiveValues(sensitiveRequestValues(runtime.request)));
            synchronized (runtime) {
                runtime.bundle = bundle;
            }
            cleaner.cleanSuccessfulJob(runtime.layout);
            FailureDetails partial = finalStatus == ScanStatus.COMPLETED_WITH_ERRORS
                    ? new FailureDetails("PARTIAL_ENGINE_RESULT", "one or more engines did not fully succeed", Map.of())
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
            if (runtime.cancelRequested.get()) {
                cancelRuntime(runtime);
            } else {
                fail(runtime, new FailureDetails("SCAN_INTERRUPTED", "scan worker was interrupted", Map.of()));
            }
        } catch (ExecutionException exception) {
            fail(runtime, failure(exception.getCause() instanceof Exception cause ? cause : exception));
        } catch (Exception exception) {
            if (runtime.cancelRequested.get()) {
                cancelRuntime(runtime);
            } else {
                fail(runtime, failure(exception));
            }
        } finally {
            releaseSourceCredential(runtime);
        }
    }

    private EngineExecutionResult executeScanner(
            RuntimeScan runtime,
            ProjectContext project,
            ScannerAdapter adapter,
            io.github.uprxiao.audit.scanner.CancellationToken cancellationToken) {
        EngineId id = adapter.descriptor().id();
        try {
            Applicability applicability = adapter.checkApplicability(project, scanners.tools());
            if (applicability.status() != Applicability.Status.APPLICABLE) {
                return EngineExecutionResult.failed(applicability.reasonCode(), applicability.detail());
            }
            Path engineOutput = runtime.layout.rawEngine(id.value());
            Path engineTemporary = CodeqlAdapter.ID.equals(id)
                    ? runtime.layout.safeResolve("codeql-db/database")
                    : engineOutput.resolve("database");
            ScanContext context = new ScanContext(runtime.job.id(), runtime.job.profile(), project, engineOutput,
                    engineTemporary,
                    runtime.request.mavenProfiles(), runtime.request.mavenProperties());
            ExecutionSpec specification = adapter.prepare(context, scanners.tools());
            ExecutionResult execution = processes.execute(specification,
                    () -> runtime.cancelRequested.get() || cancellationToken.isCancellationRequested());
            runtime.executions.put(id, execution);
            if (execution.status() == ExecutionResult.Status.CANCELLED) {
                return EngineExecutionResult.cancelled();
            }
            if (execution.status() == ExecutionResult.Status.TIMED_OUT) {
                return EngineExecutionResult.timedOut("ENGINE_TIMEOUT", execution.message());
            }
            String relativeArtifact = specification.expectedArtifacts().stream().findFirst()
                    .orElseThrow(() -> new IOException("scanner did not declare a report artifact"))
                    .relativePath();
            RawArtifactSet raw = new RawArtifactSet(id,
                    Map.of("report", engineOutput.resolve(relativeArtifact)), execution);
            ArtifactValidation validation = adapter.validate(raw);
            if (!validation.valid()) {
                return execution.status() == ExecutionResult.Status.FAILED
                        ? EngineExecutionResult.failed("ENGINE_PROCESS_FAILED", execution.message())
                        : EngineExecutionResult.failed("ENGINE_ARTIFACT_INVALID", String.join(",", validation.errors()));
            }
            NormalizationResult normalized = adapter.normalize(context, raw);
            runtime.normalized.put(id, normalized);
            return normalized.coverage().status() == EngineStatus.PARTIAL
                    ? EngineExecutionResult.partial(
                            normalized.coverage().reasonCode().isBlank()
                                    ? "ENGINE_PARTIAL" : normalized.coverage().reasonCode(),
                            String.join("; ", normalized.warnings()))
                    : EngineExecutionResult.succeeded();
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return runtime.cancelRequested.get() || cancellationToken.isCancellationRequested()
                    ? EngineExecutionResult.cancelled()
                    : EngineExecutionResult.failed("ENGINE_INTERRUPTED", exception.getMessage());
        } catch (Exception exception) {
            return EngineExecutionResult.failed("ENGINE_EXECUTION_FAILED",
                    exception.getMessage() == null ? exception.getClass().getSimpleName() : exception.getMessage());
        }
    }

    private EngineExecutionResult executeSharedFindSecBugs(
            RuntimeScan runtime,
            ProjectContext project,
            ScannerAdapter adapter,
            io.github.uprxiao.audit.scanner.CancellationToken cancellationToken) {
        if (runtime.cancelRequested.get() || cancellationToken.isCancellationRequested()) {
            return EngineExecutionResult.cancelled();
        }
        try {
            Applicability applicability = adapter.checkApplicability(project, scanners.tools());
            if (applicability.status() != Applicability.Status.APPLICABLE) {
                return EngineExecutionResult.failed(applicability.reasonCode(), applicability.detail());
            }
            ExecutionResult execution = runtime.executions.get(io.github.uprxiao.audit.adapter.spotbugs.SpotBugsAdapter.ID);
            Path sharedReport = runtime.layout.rawEngine("spotbugs").resolve("report.xml");
            if (execution == null || execution.status() != ExecutionResult.Status.SUCCEEDED
                    || !Files.isRegularFile(sharedReport)) {
                return EngineExecutionResult.failed(
                        "SHARED_SPOTBUGS_ARTIFACT_UNAVAILABLE",
                        "the SpotBugs execution group did not produce a reusable report");
            }
            EngineId id = adapter.descriptor().id();
            ScanContext context = new ScanContext(runtime.job.id(), runtime.job.profile(), project,
                    runtime.layout.rawEngine(id.value()), runtime.request.mavenProfiles(), runtime.request.mavenProperties());
            RawArtifactSet raw = new RawArtifactSet(id, Map.of("report", sharedReport), execution);
            ArtifactValidation validation = adapter.validate(raw);
            if (!validation.valid()) {
                return EngineExecutionResult.failed(
                        "ENGINE_ARTIFACT_INVALID", String.join(",", validation.errors()));
            }
            NormalizationResult normalized = adapter.normalize(context, raw);
            runtime.executions.put(id, execution);
            runtime.normalized.put(id, normalized);
            return normalized.coverage().status() == EngineStatus.PARTIAL
                    ? EngineExecutionResult.partial(
                            normalized.coverage().reasonCode().isBlank()
                                    ? "ENGINE_PARTIAL" : normalized.coverage().reasonCode(),
                            String.join("; ", normalized.warnings()))
                    : EngineExecutionResult.succeeded();
        } catch (Exception exception) {
            return EngineExecutionResult.failed("ENGINE_EXECUTION_FAILED",
                    exception.getMessage() == null ? exception.getClass().getSimpleName() : exception.getMessage());
        }
    }

    private EngineExecutionResult executeMavenBuild(
            RuntimeScan runtime,
            ProjectContext project,
            io.github.uprxiao.audit.scanner.CancellationToken cancellationToken) {
        try {
            MavenBuildResult result = maven.execute(new MavenBuildRequest(
                            project.workspaceRoot(),
                            runtime.layout.rawEngine(ScanExecutionPlanFactory.MAVEN_BUILD.value()),
                            runtime.request.mavenProfiles(),
                            runtime.request.mavenProperties(),
                            mavenBuildTimeout),
                    () -> runtime.cancelRequested.get() || cancellationToken.isCancellationRequested());
            runtime.mavenBuild = result;
            runtime.executions.put(ScanExecutionPlanFactory.MAVEN_BUILD, result.execution());
            return switch (result.status()) {
                case SUCCEEDED -> EngineExecutionResult.succeeded();
                case FAILED -> EngineExecutionResult.failed("MAVEN_BUILD_FAILED", result.execution().message());
                case TIMED_OUT -> EngineExecutionResult.timedOut("MAVEN_BUILD_TIMEOUT", result.execution().message());
                case CANCELLED -> EngineExecutionResult.cancelled();
            };
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return runtime.cancelRequested.get() || cancellationToken.isCancellationRequested()
                    ? EngineExecutionResult.cancelled()
                    : EngineExecutionResult.failed("MAVEN_BUILD_INTERRUPTED", "Maven build was interrupted");
        } catch (Exception exception) {
            return EngineExecutionResult.failed("MAVEN_BUILD_FAILED",
                    exception.getMessage() == null ? exception.getClass().getSimpleName() : exception.getMessage());
        }
    }

    private EngineExecutionResult executeCodeql(
            RuntimeScan runtime,
            ProjectContext project,
            CodeqlAdapter adapter,
            io.github.uprxiao.audit.scanner.CancellationToken cancellationToken) {
        try {
            Applicability applicability = adapter.checkApplicability(project, scanners.tools());
            if (applicability.status() != Applicability.Status.APPLICABLE) {
                return EngineExecutionResult.failed(applicability.reasonCode(), applicability.detail());
            }
            Path engineOutput = runtime.layout.rawEngine(CodeqlAdapter.ID.value());
            ScanContext context = new ScanContext(runtime.job.id(), runtime.job.profile(), project, engineOutput,
                    runtime.request.mavenProfiles(), runtime.request.mavenProperties());
            CodeqlWorkflow.Result result = codeql.execute(
                    adapter, context, scanners.tools(),
                    () -> runtime.cancelRequested.get() || cancellationToken.isCancellationRequested());
            runtime.executions.put(CodeqlAdapter.ID, result.analysis());
            NormalizationResult normalized = adapter.normalize(context, result.artifacts());
            runtime.normalized.put(CodeqlAdapter.ID, normalized);
            return normalized.coverage().status() == EngineStatus.PARTIAL
                    ? EngineExecutionResult.partial(
                            normalized.coverage().reasonCode().isBlank()
                                    ? "ENGINE_PARTIAL" : normalized.coverage().reasonCode(),
                            String.join("; ", normalized.warnings()))
                    : EngineExecutionResult.succeeded();
        } catch (CodeqlWorkflow.CodeqlWorkflowException exception) {
            runtime.executions.put(CodeqlAdapter.ID, exception.execution());
            return switch (exception.execution().status()) {
                case CANCELLED -> EngineExecutionResult.cancelled();
                case TIMED_OUT -> EngineExecutionResult.timedOut(
                        "CODEQL_" + exception.phase().name() + "_TIMEOUT", exception.getMessage());
                case FAILED, SUCCEEDED -> EngineExecutionResult.failed(
                        "CODEQL_" + exception.phase().name() + "_FAILED", exception.getMessage());
            };
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return runtime.cancelRequested.get() || cancellationToken.isCancellationRequested()
                    ? EngineExecutionResult.cancelled()
                    : EngineExecutionResult.failed("CODEQL_INTERRUPTED", "CodeQL workflow was interrupted");
        } catch (Exception exception) {
            return EngineExecutionResult.failed("CODEQL_EXECUTION_FAILED",
                    exception.getMessage() == null ? exception.getClass().getSimpleName() : exception.getMessage());
        }
    }

    private ScanJobListener listener(RuntimeScan runtime) {
        return new ScanJobListener() {
            @Override
            public void onEngineStateChanged(
                    UUID scanId, EngineId engineId, EngineStatus status, FailureDetails failure) {
                synchronized (runtime) {
                    EngineTaskState current = runtime.engines.get(engineId.value());
                    if (current == null || current.status().isTerminal()) {
                        return;
                    }
                    try {
                        Instant now = clock.instant();
                        EngineTaskState updated = advanceEngineState(current, status, failure, now);
                        if (updated == current) {
                            return;
                        }
                        Map<String, EngineTaskState> states = new LinkedHashMap<>(runtime.engines);
                        states.put(engineId.value(), updated);
                        runtime.engines = Map.copyOf(states);
                        runtime.job = runtime.job.touch(clock.instant());
                        persist(runtime);
                    } catch (IOException exception) {
                        runtime.persistenceFailure = exception;
                    }
                }
            }
        };
    }

    /**
     * Scheduler callbacks originate from multiple worker threads. A very fast engine can finish
     * before an earlier READY notification has acquired this runtime lock, so persistence must
     * monotonically catch up instead of allowing a late callback to move state backwards.
     */
    private EngineTaskState advanceEngineState(
            EngineTaskState current,
            EngineStatus observed,
            FailureDetails failure,
            Instant now) {
        if (observed == EngineStatus.READY) {
            return current.status() == EngineStatus.PENDING
                    ? current.transitionTo(EngineStatus.READY, now) : current;
        }
        if (observed == EngineStatus.RUNNING) {
            if (current.status() == EngineStatus.PENDING) {
                current = current.transitionTo(EngineStatus.READY, now);
            }
            return current.status() == EngineStatus.READY
                    ? current.transitionTo(EngineStatus.RUNNING, now) : current;
        }
        if (!observed.isTerminal()) {
            return current;
        }
        if (observed == EngineStatus.SKIPPED || observed == EngineStatus.CANCELLED) {
            if (observed == EngineStatus.SKIPPED && current.status() == EngineStatus.RUNNING) {
                return current;
            }
            return current.transitionTo(observed, now, failure);
        }
        if (current.status() == EngineStatus.PENDING) {
            current = current.transitionTo(EngineStatus.READY, now);
        }
        if (current.status() == EngineStatus.READY) {
            current = current.transitionTo(EngineStatus.RUNNING, now);
        }
        return current.status() == EngineStatus.RUNNING
                ? current.transitionTo(observed, now, failure) : current;
    }

    private List<io.github.uprxiao.audit.finding.EngineCoverage> coverage(
            RuntimeScan runtime, ProjectContext project) {
        int modules = project.manifest().modules().size();
        List<io.github.uprxiao.audit.finding.EngineCoverage> result = new ArrayList<>();
        for (ScanEngine engine : runtime.plan.engines()) {
            NormalizationResult normalized = runtime.normalized.get(engine.id());
            if (normalized != null) {
                result.add(normalized.coverage());
                continue;
            }
            EngineTaskState state = runtime.engines.get(engine.id().value());
            ExecutionResult execution = runtime.executions.get(engine.id());
            result.add(new io.github.uprxiao.audit.finding.EngineCoverage(
                    engine.id().value(), state.status(), modules, modules, 0, 0,
                    execution == null ? Duration.ZERO : execution.duration(),
                    state.failure() == null ? state.status().name() : state.failure().code(),
                    rawArtifact(runtime.layout, engine.id().value())));
        }
        return List.copyOf(result);
    }

    private String rawArtifact(JobDirectoryLayout layout, String engineId) {
        Path root = layout.rawEngine(engineId);
        for (String name : List.of("report.json", "report.xml")) {
            if (Files.isRegularFile(root.resolve(name))) {
                return "raw/" + engineId + "/" + name;
            }
        }
        return "";
    }

    private void cancelRuntime(RuntimeScan runtime) {
        synchronized (runtime) {
            if (runtime.job.status().isTerminal()) {
                return;
            }
            Map<String, EngineTaskState> states = new LinkedHashMap<>();
            runtime.engines.forEach((id, engine) -> states.put(id, engine.status().isTerminal()
                    ? engine : engine.transitionTo(EngineStatus.CANCELLED, clock.instant())));
            runtime.engines = Map.copyOf(states);
            runtime.job = runtime.job.transitionTo(ScanStatus.CANCELLED, clock.instant());
            try {
                persist(runtime);
            } catch (IOException ignored) {
                // The in-memory terminal state remains queryable; startup recovery validates persisted state.
            }
            releaseSourceCredential(runtime);
        }
    }

    private void fail(RuntimeScan runtime, FailureDetails failure) {
        synchronized (runtime) {
            Map<String, EngineTaskState> states = new LinkedHashMap<>();
            runtime.engines.forEach((id, engine) -> {
                if (engine.status().isTerminal()) {
                    states.put(id, engine);
                } else if (engine.status() == EngineStatus.RUNNING) {
                    states.put(id, engine.transitionTo(EngineStatus.FAILED, clock.instant(), failure));
                } else {
                    states.put(id, engine.transitionTo(EngineStatus.SKIPPED, clock.instant(), failure));
                }
            });
            runtime.engines = Map.copyOf(states);
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

    private void requireProfile(ScanProfile profile) {
        if (scanners.available(profile)) {
            return;
        }
        throw new ApiException(HttpStatus.CONFLICT, ApiErrorCode.PROFILE_UNAVAILABLE,
                profile.name() + " 所需扫描器未完整通过版本和完整性检查。",
                Map.of("unavailable", scanners.unavailable(profile)));
    }

    private Map<String, EngineTaskState> initialEngineStates(ScanPlan plan, Instant now) {
        Map<String, EngineTaskState> states = new LinkedHashMap<>();
        for (ScanEngine engine : plan.engines()) {
            scanners.require(engine.id());
            states.put(engine.id().value(), EngineTaskState.pending(engine.id().value(), now));
        }
        return Map.copyOf(states);
    }

    private Map<String, String> persistedMavenProperties(Map<String, String> properties) {
        Map<String, String> persisted = new LinkedHashMap<>();
        properties.forEach((key, value) -> {
            if (!mavenArguments.isSensitiveProperty(key)) {
                persisted.put(key, value);
            }
        });
        return Map.copyOf(persisted);
    }

    private void rejectSvnRuntime(RuntimeScan runtime) {
        scans.remove(runtime.job.id(), runtime);
        releaseSourceCredential(runtime);
    }

    private Map<String, Object> reportSource(SourceDescriptor source) {
        if (source.type() == SourceType.SVN) {
            return Map.of(
                    "type", "SVN",
                    "displayName", source.displayName(),
                    "repositoryUrl", redactedSvnLocation(source.location()),
                    "repositoryUrlSha256", "sha256:" + sha256Text(source.location()),
                    "revision", source.revision(),
                    "sha256", source.contentSha256());
        }
        return Map.of(
                "type", "ZIP",
                "displayName", source.displayName(),
                "sha256", source.contentSha256());
    }

    private Map<String, Object> mavenBuildSummary(RuntimeScan runtime) {
        MavenBuildResult result = runtime.mavenBuild;
        if (result == null) {
            return Map.of(
                    "status", "NOT_REQUIRED",
                    "mavenProfiles", runtime.request.mavenProfiles());
        }
        return Map.of(
                "status", result.status().name(),
                "mavenProfiles", runtime.request.mavenProfiles(),
                "modules", result.modules().stream().map(module -> Map.of(
                        "module", module.module(),
                        "status", module.status().name())).toList(),
                "durationMillis", result.execution().duration().toMillis(),
                "artifact", "raw/maven-build/stdout.log");
    }

    private int modulesBuilt(RuntimeScan runtime, ProjectContext project) {
        if (runtime.mavenBuild == null || runtime.mavenBuild.status() != MavenBuildResult.Status.SUCCEEDED) {
            return 0;
        }
        if (runtime.mavenBuild.modules().isEmpty()) {
            // Maven may omit the Reactor Summary for a single module; success means that module built.
            return project.manifest().modules().size() == 1 ? 1 : 0;
        }
        long successful = runtime.mavenBuild.modules().stream()
                .filter(module -> module.status() == io.github.uprxiao.audit.process.MavenModuleResult.Status.SUCCESS)
                .count();
        // The root aggregator may be present in Maven's summary but is already one manifest module.
        return (int) Math.min(project.manifest().modules().size(), successful);
    }

    private Map<String, Object> finalizeSbom(RuntimeScan runtime, List<Finding> activeFindings) throws IOException {
        Path raw = runtime.layout.rawEngine("cyclonedx").resolve("sbom/bom.json");
        if (!Files.isRegularFile(raw)) {
            return Map.of(
                    "status", runtime.job.profile() == ScanProfile.QUICK ? "NOT_REQUIRED" : "UNAVAILABLE",
                    "components", 0,
                    "vulnerableComponents", 0);
        }
        Path target = runtime.layout.safeResolve("sbom/bom.json");
        if (Files.exists(target)) {
            throw new IOException("SBOM final target already exists");
        }
        byte[] bom = Files.readAllBytes(raw);
        Path temporary = runtime.layout.safeResolve("sbom/bom.json.tmp");
        Files.createDirectories(target.getParent());
        Files.write(temporary, bom, java.nio.file.StandardOpenOption.CREATE_NEW);
        try {
            Files.move(temporary, target, java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        } catch (java.nio.file.AtomicMoveNotSupportedException exception) {
            Files.move(temporary, target);
        }
        com.fasterxml.jackson.databind.JsonNode document = json.readTree(bom);
        int components = document.path("components").isArray() ? document.path("components").size() : 0;
        long vulnerableComponents = activeFindings.stream()
                .filter(finding -> finding.category() == io.github.uprxiao.audit.finding.IssueCategory.DEPENDENCY_VULNERABILITY)
                .map(Finding::component)
                .filter(java.util.Objects::nonNull)
                .map(io.github.uprxiao.audit.finding.ComponentEvidence::purl)
                .distinct()
                .count();
        return Map.of(
                "status", "AVAILABLE",
                "format", document.path("bomFormat").asText("CycloneDX"),
                "specVersion", document.path("specVersion").asText(""),
                "components", components,
                "vulnerableComponents", vulnerableComponents,
                "artifact", "sbom/bom.json");
    }

    private String redactedSvnLocation(String repositoryUrl) {
        java.net.URI uri = java.net.URI.create(repositoryUrl);
        StringBuilder origin = new StringBuilder(uri.getScheme()).append("://").append(uri.getHost());
        if (uri.getPort() >= 0) {
            origin.append(':').append(uri.getPort());
        }
        return origin.append("/***").toString();
    }

    private String sha256Text(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by Java 17", exception);
        }
    }

    private void releaseSourceCredential(RuntimeScan runtime) {
        synchronized (runtime) {
            if (runtime.sourceCredential != null) {
                runtime.sourceCredential.close();
                runtime.sourceCredential = null;
            }
        }
    }

    private void writeRequest(RuntimeScan runtime, PersistedScanRequest request) throws IOException {
        byte[] bytes = json.writerWithDefaultPrettyPrinter().writeValueAsBytes(request);
        Path target = runtime.layout.safeResolve("request.json");
        Path temporary = runtime.layout.safeResolve("request.json.tmp");
        Files.write(temporary, bytes);
        try {
            Files.move(temporary, target, java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        } catch (java.nio.file.AtomicMoveNotSupportedException exception) {
            Files.move(temporary, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private String configFingerprint() throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (Path rule : ruleFiles()) {
                digest.update(Files.readAllBytes(rule));
            }
            return "sha256:" + HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by Java 17", exception);
        }
    }

    private List<Map<String, Object>> ruleManifest() throws IOException {
        return List.of(
                ruleEntry("semgrep-java-audit", "config/rules/semgrep/java-audit.yaml", paths.semgrepRules()),
                ruleEntry("gitleaks-java-audit", "config/rules/gitleaks/gitleaks.toml", paths.gitleaksRules()),
                ruleEntry("pmd-java-audit", "config/rules/pmd/java-audit.xml", paths.pmdRules()),
                ruleEntry("checkstyle-java-audit", "config/rules/checkstyle/java-audit.xml", paths.checkstyleRules()),
                ruleEntry("spotbugs-exclude", "config/rules/spotbugs-exclude.xml", paths.spotbugsExcludeFilter()));
    }

    private Map<String, Object> ruleEntry(String id, String portablePath, Path rule) throws IOException {
        return Map.of("id", id, "path", portablePath, "sha256", "sha256:" + sha256(rule));
    }

    private List<Path> ruleFiles() {
        return List.of(
                paths.semgrepRules(), paths.gitleaksRules(), paths.pmdRules(), paths.checkstyleRules(),
                paths.spotbugsExcludeFilter());
    }

    private List<String> sensitiveRequestValues(ZipScanRequest request) {
        return request.mavenProperties().entrySet().stream()
                .filter(entry -> mavenArguments.isSensitiveProperty(entry.getKey()))
                .map(Map.Entry::getValue)
                .filter(value -> value != null && !value.isBlank())
                .toList();
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

    private String safeSvnDisplayName(String repositoryUrl) {
        String path = java.net.URI.create(repositoryUrl).getPath();
        if (path == null || path.isBlank() || "/".equals(path)) {
            return "svn-project";
        }
        int end = path.endsWith("/") ? path.length() - 1 : path.length();
        int separator = path.lastIndexOf('/', end - 1);
        String name = path.substring(separator + 1, end).replaceAll("[\\r\\n\\t]", "_");
        return name.isBlank() ? "svn-project" : name.substring(0, Math.min(200, name.length()));
    }

    private static final class RuntimeScan {
        private final JobDirectoryLayout layout;
        private final StagedUpload staged;
        private final ZipScanRequest request;
        private final ScanPlan plan;
        private final SvnRuntimeRequest svnRequest;
        private SourceCredential sourceCredential;
        private ScanJob job;
        private Map<String, EngineTaskState> engines;
        private List<Finding> findings = List.of();
        private ScanCoverage coverage;
        private ReportBundle bundle;
        private final AtomicBoolean cancelRequested = new AtomicBoolean();
        private final Map<EngineId, NormalizationResult> normalized = new ConcurrentHashMap<>();
        private final Map<EngineId, ExecutionResult> executions = new ConcurrentHashMap<>();
        private volatile MavenBuildResult mavenBuild;
        private Runnable workItem;
        private volatile ScanJobHandle schedulerHandle;
        private volatile IOException persistenceFailure;
        private volatile ProjectContext project;

        private RuntimeScan(
                JobDirectoryLayout layout,
                ScanJob job,
                Map<String, EngineTaskState> engines,
                StagedUpload staged,
                ZipScanRequest request,
                ScanPlan plan) {
            this.layout = layout;
            this.job = job;
            this.engines = engines;
            this.staged = staged;
            this.request = request;
            this.plan = plan;
            this.svnRequest = null;
        }

        private RuntimeScan(
                JobDirectoryLayout layout,
                ScanJob job,
                Map<String, EngineTaskState> engines,
                ZipScanRequest request,
                ScanPlan plan,
                SvnRuntimeRequest svnRequest,
                SourceCredential sourceCredential) {
            this.layout = layout;
            this.job = job;
            this.engines = engines;
            this.staged = null;
            this.request = request;
            this.plan = plan;
            this.svnRequest = svnRequest;
            this.sourceCredential = sourceCredential;
        }
    }

    private record SvnRuntimeRequest(String repositoryUrl, SvnRevision revision) {
    }
}
