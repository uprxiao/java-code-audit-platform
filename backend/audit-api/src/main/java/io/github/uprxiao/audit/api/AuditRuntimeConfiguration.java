package io.github.uprxiao.audit.api;

import io.github.uprxiao.audit.adapter.semgrep.SemgrepAdapter;
import io.github.uprxiao.audit.adapter.checkstyle.CheckstyleAdapter;
import io.github.uprxiao.audit.adapter.gitleaks.GitleaksAdapter;
import io.github.uprxiao.audit.adapter.pmd.PmdAdapter;
import io.github.uprxiao.audit.adapter.pmd.PmdCpdAdapter;
import io.github.uprxiao.audit.adapter.trivy.TrivyRepositoryAdapter;
import io.github.uprxiao.audit.finding.ScanIdGenerator;
import io.github.uprxiao.audit.intake.MavenProjectInspector;
import io.github.uprxiao.audit.intake.MavenArgumentValidator;
import io.github.uprxiao.audit.intake.SafeZipExtractor;
import io.github.uprxiao.audit.intake.SvnCheckoutLimits;
import io.github.uprxiao.audit.intake.SvnKitSourceCheckout;
import io.github.uprxiao.audit.intake.SvnRepositoryPolicy;
import io.github.uprxiao.audit.intake.SvnSourceCheckout;
import io.github.uprxiao.audit.intake.UploadStager;
import io.github.uprxiao.audit.intake.ZipExtractionLimits;
import io.github.uprxiao.audit.orchestrator.ScanJobQueueFullException;
import io.github.uprxiao.audit.orchestrator.FairDagScheduler;
import io.github.uprxiao.audit.orchestrator.SchedulerConfiguration;
import io.github.uprxiao.audit.process.LocalProcessExecutionBackend;
import io.github.uprxiao.audit.report.ReportGenerator;
import io.github.uprxiao.audit.storage.FileJobStore;
import io.github.uprxiao.audit.storage.AtomicFileWriter;
import io.github.uprxiao.audit.storage.JobStore;
import io.github.uprxiao.audit.storage.JobRetentionService;
import io.github.uprxiao.audit.storage.JobTemporaryFileCleaner;
import io.github.uprxiao.audit.storage.RetentionPolicy;
import io.github.uprxiao.audit.storage.SingleInstanceLock;
import io.github.uprxiao.audit.storage.NioAtomicFileWriter;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class AuditRuntimeConfiguration {

    @Bean
    AuditRuntimePaths runtimePaths(
            @Value("${audit.data-root:./data}") String dataRoot,
            @Value("${audit.tools.semgrep-executable:./tools/downloads/bin/semgrep}") String semgrepExecutable,
            @Value("${audit.tools.quick-root:}") String configuredQuickRoot,
            @Value("${audit.rules.semgrep:./config/rules/semgrep/java-audit.yaml}") String semgrepRules,
            @Value("${audit.rules.gitleaks:./config/rules/gitleaks/gitleaks.toml}") String gitleaksRules,
            @Value("${audit.rules.pmd:./config/rules/pmd/java-audit.xml}") String pmdRules,
            @Value("${audit.rules.checkstyle:./config/rules/checkstyle/java-audit.xml}") String checkstyleRules) {
        String quickRoot = configuredQuickRoot.isBlank()
                ? "./tools/downloads/tool-pack/" + currentPlatform() + "/quick"
                : configuredQuickRoot;
        return new AuditRuntimePaths(
                Path.of(dataRoot).toAbsolutePath().normalize(),
                Path.of(semgrepExecutable).toAbsolutePath().normalize(),
                Path.of(semgrepRules).toAbsolutePath().normalize(),
                Path.of(quickRoot).toAbsolutePath().normalize(),
                Path.of(gitleaksRules).toAbsolutePath().normalize(),
                Path.of(pmdRules).toAbsolutePath().normalize(),
                Path.of(checkstyleRules).toAbsolutePath().normalize());
    }

    @Bean(destroyMethod = "close")
    SingleInstanceLock instanceLock(AuditRuntimePaths paths) throws IOException {
        return SingleInstanceLock.acquire(paths.dataRoot());
    }

    @Bean
    JobStore jobStore(AuditRuntimePaths paths) {
        return new FileJobStore(paths.dataRoot());
    }

    @Bean
    AtomicFileWriter atomicFileWriter() {
        return new NioAtomicFileWriter();
    }

    @Bean
    StorageCapacityGuard storageCapacityGuard(
            AuditRuntimePaths paths,
            @Value("${audit.storage.minimum-free-bytes:53687091200}") long minimumDiskBytes) {
        return new StorageCapacityGuard(paths, minimumDiskBytes);
    }

    @Bean(destroyMethod = "shutdown")
    ThreadPoolExecutor scanExecutor(
            @Value("${audit.concurrency.max-concurrent-scan-jobs:2}") int workers,
            @Value("${audit.concurrency.max-queued-scan-jobs:20}") int queueCapacity,
            @Value("${audit.concurrency.retry-after-seconds:30}") long retryAfterSeconds) {
        if (workers < 1 || queueCapacity < 1 || retryAfterSeconds < 1) {
            throw new IllegalArgumentException("scan worker and queue limits must be positive");
        }
        AtomicInteger sequence = new AtomicInteger();
        return new ThreadPoolExecutor(
                workers, workers, 0, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(queueCapacity),
                runnable -> {
                    Thread thread = new Thread(runnable, "audit-scan-job-" + sequence.incrementAndGet());
                    thread.setDaemon(false);
                    return thread;
                },
                (task, executor) -> {
                    if (executor.isShutdown()) {
                        throw new java.util.concurrent.RejectedExecutionException("scan executor is shutting down");
                    }
                    throw new ScanJobQueueFullException(
                            executor.getQueue().size(), queueCapacity, Duration.ofSeconds(retryAfterSeconds));
                });
    }

    @Bean(destroyMethod = "close")
    FairDagScheduler engineScheduler(
            @Value("${audit.concurrency.max-queued-scan-jobs:20}") int queued,
            @Value("${audit.concurrency.max-concurrent-scan-jobs:2}") int jobs,
            @Value("${audit.concurrency.max-concurrent-engines:4}") int engines,
            @Value("${audit.concurrency.max-engines-per-scan:2}") int perScan,
            @Value("${audit.concurrency.weighted-permits:8}") int weighted,
            @Value("${audit.concurrency.tool-limits.maven:1}") int maven,
            @Value("${audit.concurrency.tool-limits.dependency-check:1}") int dependencyCheck,
            @Value("${audit.concurrency.tool-limits.codeql:1}") int codeql,
            @Value("${audit.concurrency.retry-after-seconds:30}") long retryAfterSeconds) {
        return new FairDagScheduler(new SchedulerConfiguration(
                queued, jobs, engines, perScan, weighted,
                Map.of(
                        new io.github.uprxiao.audit.scanner.EngineId("maven"), maven,
                        new io.github.uprxiao.audit.scanner.EngineId("dependency-check"), dependencyCheck,
                        new io.github.uprxiao.audit.scanner.EngineId("codeql"), codeql),
                Duration.ofSeconds(retryAfterSeconds)));
    }

    @Bean
    ZipExtractionLimits zipExtractionLimits(
            @Value("${audit.intake.max-archive-bytes:1073741824}") long maxArchiveBytes,
            @Value("${audit.intake.max-expanded-bytes:10737418240}") long maxExpandedBytes,
            @Value("${audit.intake.max-single-file-bytes:1073741824}") long maxSingleFileBytes,
            @Value("${audit.intake.max-entries:200000}") int maxEntries,
            @Value("${audit.intake.max-compression-ratio:100}") double maxCompressionRatio) {
        return new ZipExtractionLimits(maxArchiveBytes, maxExpandedBytes, maxSingleFileBytes,
                maxEntries, maxCompressionRatio);
    }

    @Bean
    SvnRepositoryPolicy svnRepositoryPolicy(
            @Value("${audit.intake.svn.max-url-characters:2048}") int maximumUrlCharacters,
            @Value("${audit.intake.svn.allowed-hosts:}") String allowedHosts) {
        Set<String> hosts = Arrays.stream(allowedHosts.split(","))
                .map(String::trim)
                .filter(host -> !host.isEmpty())
                .map(host -> host.toLowerCase(Locale.ROOT))
                .collect(Collectors.toUnmodifiableSet());
        return new SvnRepositoryPolicy(maximumUrlCharacters, hosts);
    }

    @Bean
    SvnCheckoutLimits svnCheckoutLimits(
            @Value("${audit.intake.svn.max-expanded-bytes:10737418240}") long maxExpandedBytes,
            @Value("${audit.intake.svn.max-single-file-bytes:1073741824}") long maxSingleFileBytes,
            @Value("${audit.intake.svn.max-entries:200000}") int maxEntries,
            @Value("${audit.intake.svn.max-path-characters:4096}") int maxPathCharacters,
            @Value("${audit.intake.svn.connect-timeout:15s}") Duration connectTimeout,
            @Value("${audit.intake.svn.read-timeout:5m}") Duration readTimeout) {
        return new SvnCheckoutLimits(maxExpandedBytes, maxSingleFileBytes, maxEntries,
                maxPathCharacters, connectTimeout, readTimeout);
    }

    @Bean
    SvnSourceCheckout svnSourceCheckout(SvnRepositoryPolicy repositoryPolicy, SvnCheckoutLimits checkoutLimits) {
        return new SvnKitSourceCheckout(repositoryPolicy, checkoutLimits);
    }

    @Bean
    Clock auditClock() {
        return Clock.systemUTC();
    }

    @Bean
    ScanIdGenerator scanIdGenerator() {
        return ScanIdGenerator.RANDOM;
    }

    @Bean
    UploadStager uploadStager() {
        return new UploadStager();
    }

    @Bean
    SafeZipExtractor safeZipExtractor() {
        return new SafeZipExtractor();
    }

    @Bean
    MavenProjectInspector mavenProjectInspector() {
        return new MavenProjectInspector();
    }

    @Bean
    MavenArgumentValidator mavenArgumentValidator() {
        return new MavenArgumentValidator();
    }

    @Bean
    LocalProcessExecutionBackend processExecutionBackend() {
        return new LocalProcessExecutionBackend();
    }

    @Bean
    StartupHealthSnapshot startupHealthSnapshot(
            AuditRuntimePaths paths,
            LocalProcessExecutionBackend processes,
            AtomicFileWriter files,
            Clock clock,
            SingleInstanceLock lock,
            QuickScannerRegistry scanners,
            @Value("${audit.maven.executable:mvn}") String mavenExecutable,
            @Value("${audit.storage.minimum-free-bytes:53687091200}") long minimumDiskBytes)
            throws IOException, InterruptedException {
        return new StartupPrerequisiteChecker(
                paths, processes, files, new ObjectMapper().findAndRegisterModules(), clock,
                mavenExecutable, minimumDiskBytes, scanners.health()).checkAndPersist();
    }

    @Bean
    ToolInstallationHealth semgrepHealth(
            AuditRuntimePaths paths,
            LocalProcessExecutionBackend processes,
            Clock clock,
            @Value("${audit.tools.semgrep-version:1.170.0}") String expectedVersion)
            throws IOException, InterruptedException {
        return new SemgrepIntegrityChecker(
                paths, processes, new ObjectMapper(), clock, expectedVersion).check();
    }

    @Bean
    SemgrepAdapter semgrepAdapter(AuditRuntimePaths paths) {
        return new SemgrepAdapter(paths.semgrepRules());
    }

    @Bean
    QuickScannerRegistry quickScannerRegistry(
            AuditRuntimePaths paths,
            LocalProcessExecutionBackend processes,
            Clock clock,
            SemgrepAdapter semgrep,
            ToolInstallationHealth semgrepHealth) throws IOException, InterruptedException {
        List<ToolInstallationHealth> health = new ArrayList<>();
        health.add(semgrepHealth);
        health.addAll(new QuickToolIntegrityChecker(
                paths, processes, new ObjectMapper(), clock).checkAll());
        List<io.github.uprxiao.audit.scanner.ScannerAdapter> adapters = List.of(
                new GitleaksAdapter(paths.gitleaksRules()),
                semgrep,
                new PmdAdapter(paths.pmdRules(), paths.pmdHome()),
                new PmdCpdAdapter(paths.pmdHome()),
                new CheckstyleAdapter(paths.checkstyleRules(), paths.checkstyleJar()),
                new TrivyRepositoryAdapter(paths.trivyCache()));
        return new QuickScannerRegistry(adapters, health, paths);
    }

    @Bean
    ReportGenerator reportGenerator() {
        return new ReportGenerator();
    }

    @Bean
    JobTemporaryFileCleaner temporaryFileCleaner() {
        return new JobTemporaryFileCleaner();
    }

    @Bean
    RetentionPolicy retentionPolicy(
            @Value("${audit.retention.successful-results:30d}") Duration successfulResults,
            @Value("${audit.retention.failed-results:7d}") Duration failedResults,
            @Value("${audit.retention.failed-workspace:24h}") Duration failedWorkspace,
            @Value("${audit.storage.minimum-free-bytes:53687091200}") long minimumDiskBytes) {
        return new RetentionPolicy(successfulResults, failedResults, failedWorkspace, minimumDiskBytes);
    }

    @Bean
    JobRetentionService jobRetentionService(AuditRuntimePaths paths, RetentionPolicy policy) {
        return new JobRetentionService(paths.dataRoot(), policy);
    }

    private static String currentPlatform() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        if (os.contains("mac") && (arch.equals("aarch64") || arch.equals("arm64"))) {
            return "darwin-arm64";
        }
        if (os.contains("linux") && (arch.equals("amd64") || arch.equals("x86_64"))) {
            return "linux-x86_64";
        }
        throw new IllegalStateException("unsupported V1 platform: " + os + "/" + arch);
    }
}
