package io.github.uprxiao.audit.api;

import io.github.uprxiao.audit.adapter.semgrep.SemgrepAdapter;
import io.github.uprxiao.audit.finding.ScanIdGenerator;
import io.github.uprxiao.audit.intake.MavenProjectInspector;
import io.github.uprxiao.audit.intake.MavenArgumentValidator;
import io.github.uprxiao.audit.intake.SafeZipExtractor;
import io.github.uprxiao.audit.intake.UploadStager;
import io.github.uprxiao.audit.intake.ZipExtractionLimits;
import io.github.uprxiao.audit.process.LocalProcessExecutionBackend;
import io.github.uprxiao.audit.report.ReportGenerator;
import io.github.uprxiao.audit.storage.FileJobStore;
import io.github.uprxiao.audit.storage.AtomicFileWriter;
import io.github.uprxiao.audit.storage.JobStore;
import io.github.uprxiao.audit.storage.JobTemporaryFileCleaner;
import io.github.uprxiao.audit.storage.SingleInstanceLock;
import io.github.uprxiao.audit.storage.NioAtomicFileWriter;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Clock;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class AuditRuntimeConfiguration {

    @Bean
    AuditRuntimePaths runtimePaths(
            @Value("${audit.data-root:./data}") String dataRoot,
            @Value("${audit.tools.semgrep-executable:./tools/downloads/bin/semgrep}") String semgrepExecutable,
            @Value("${audit.rules.semgrep:./config/rules/semgrep/java-audit.yaml}") String semgrepRules) {
        return new AuditRuntimePaths(
                Path.of(dataRoot).toAbsolutePath().normalize(),
                Path.of(semgrepExecutable).toAbsolutePath().normalize(),
                Path.of(semgrepRules).toAbsolutePath().normalize());
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

    @Bean(destroyMethod = "shutdown")
    ExecutorService scanExecutor(
            @Value("${audit.concurrency.max-concurrent-scan-jobs:2}") int workers,
            @Value("${audit.concurrency.max-queued-scan-jobs:20}") int queueCapacity) {
        if (workers < 1 || queueCapacity < 1) {
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
                new ThreadPoolExecutor.AbortPolicy());
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
            ToolInstallationHealth semgrepHealth,
            @Value("${audit.maven.executable:mvn}") String mavenExecutable,
            @Value("${audit.storage.minimum-free-bytes:53687091200}") long minimumDiskBytes)
            throws IOException, InterruptedException {
        return new StartupPrerequisiteChecker(
                paths, processes, files, new ObjectMapper().findAndRegisterModules(), clock,
                mavenExecutable, minimumDiskBytes, semgrepHealth).checkAndPersist();
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
    ReportGenerator reportGenerator() {
        return new ReportGenerator();
    }

    @Bean
    JobTemporaryFileCleaner temporaryFileCleaner() {
        return new JobTemporaryFileCleaner();
    }
}
