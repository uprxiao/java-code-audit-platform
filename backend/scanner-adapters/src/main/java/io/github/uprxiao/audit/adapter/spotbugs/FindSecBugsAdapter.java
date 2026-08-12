package io.github.uprxiao.audit.adapter.spotbugs;

import io.github.uprxiao.audit.intake.ProjectContext;
import io.github.uprxiao.audit.scanner.Applicability;
import io.github.uprxiao.audit.scanner.ArtifactValidation;
import io.github.uprxiao.audit.scanner.EngineDescriptor;
import io.github.uprxiao.audit.scanner.EngineId;
import io.github.uprxiao.audit.scanner.ExecutionSpec;
import io.github.uprxiao.audit.scanner.NormalizationResult;
import io.github.uprxiao.audit.scanner.RawArtifactSet;
import io.github.uprxiao.audit.scanner.ResourceClass;
import io.github.uprxiao.audit.scanner.ResourceRequest;
import io.github.uprxiao.audit.scanner.ScanContext;
import io.github.uprxiao.audit.scanner.ScannerAdapter;
import io.github.uprxiao.audit.scanner.ToolContext;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Objects;
import java.util.Set;

/**
 * Logical FindSecBugs engine. The orchestrator should execute the SpotBugs execution group once and pass the same
 * report/execution evidence to this adapter with engine id {@code findsecbugs}; {@link #prepare} exists for isolated
 * smoke tests and produces the identical fixed scan with an engine-local output path.
 */
public final class FindSecBugsAdapter implements ScannerAdapter {

    public static final EngineId ID = new EngineId("findsecbugs");
    public static final String TOOL_VERSION = "1.14.0";

    private final Path spotbugsHome;
    private final Path plugin;
    private final Path excludeFilter;
    private final SpotBugsReportNormalizer normalizer = new SpotBugsReportNormalizer(ID, true, TOOL_VERSION);

    public FindSecBugsAdapter(Path spotbugsHome, Path plugin, Path excludeFilter) {
        this.spotbugsHome = Objects.requireNonNull(spotbugsHome).toAbsolutePath().normalize();
        this.plugin = Objects.requireNonNull(plugin).toAbsolutePath().normalize();
        this.excludeFilter = excludeFilter == null ? null : excludeFilter.toAbsolutePath().normalize();
    }

    @Override
    public EngineDescriptor descriptor() {
        return new EngineDescriptor(ID, "FindSecBugs", true,
                new ResourceRequest(ResourceClass.MEDIUM, 2, 2048), Duration.ofMinutes(20), Set.of(SpotBugsAdapter.ID));
    }

    @Override
    public Applicability checkApplicability(ProjectContext project, ToolContext tools) {
        ToolContext.ToolInstallation installation = tools.installations().get(ID);
        if (installation == null || !installation.available()) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "TOOL_UNAVAILABLE", "Java launcher is unavailable");
        }
        if (!TOOL_VERSION.equals(installation.version())) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "TOOL_VERSION_MISMATCH", installation.version());
        }
        if (!Files.isRegularFile(spotbugsHome.resolve("lib/spotbugs.jar"))) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "SPOTBUGS_HOME_INVALID", spotbugsHome.toString());
        }
        if (!Files.isRegularFile(plugin)) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "FINDSECBUGS_PLUGIN_INVALID", plugin.toString());
        }
        return Applicability.applicable();
    }

    @Override
    public ExecutionSpec prepare(ScanContext context, ToolContext tools) throws IOException {
        return SpotBugsExecutionSupport.prepare(ID, descriptor(), context, tools,
                spotbugsHome, plugin, excludeFilter);
    }

    @Override
    public ArtifactValidation validate(RawArtifactSet artifacts) throws IOException {
        return normalizer.validate(artifacts);
    }

    @Override
    public NormalizationResult normalize(ScanContext context, RawArtifactSet artifacts) throws IOException {
        return normalizer.normalize(context, artifacts);
    }
}
