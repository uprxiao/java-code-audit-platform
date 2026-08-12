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

public final class SpotBugsAdapter implements ScannerAdapter {

    public static final EngineId ID = new EngineId("spotbugs");
    public static final String TOOL_VERSION = "4.9.3";

    private final Path spotbugsHome;
    private final Path findSecBugsPlugin;
    private final Path excludeFilter;
    private final SpotBugsReportNormalizer normalizer = new SpotBugsReportNormalizer(ID, false, TOOL_VERSION);

    public SpotBugsAdapter(Path spotbugsHome, Path findSecBugsPlugin, Path excludeFilter) {
        this.spotbugsHome = Objects.requireNonNull(spotbugsHome).toAbsolutePath().normalize();
        this.findSecBugsPlugin = Objects.requireNonNull(findSecBugsPlugin).toAbsolutePath().normalize();
        this.excludeFilter = excludeFilter == null ? null : excludeFilter.toAbsolutePath().normalize();
    }

    @Override
    public EngineDescriptor descriptor() {
        return new EngineDescriptor(ID, "SpotBugs", true,
                new ResourceRequest(ResourceClass.MEDIUM, 2, 2048), Duration.ofMinutes(20), Set.of());
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
        if (!Files.isRegularFile(findSecBugsPlugin)) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "FINDSECBUGS_PLUGIN_INVALID", findSecBugsPlugin.toString());
        }
        return Applicability.applicable();
    }

    @Override
    public ExecutionSpec prepare(ScanContext context, ToolContext tools) throws IOException {
        return SpotBugsExecutionSupport.prepare(ID, descriptor(), context, tools,
                spotbugsHome, findSecBugsPlugin, excludeFilter);
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
