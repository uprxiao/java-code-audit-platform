package io.github.uprxiao.audit.scanner;

import io.github.uprxiao.audit.intake.ProjectContext;
import java.io.IOException;

public interface ScannerAdapter {
    EngineDescriptor descriptor();

    Applicability checkApplicability(ProjectContext project, ToolContext tools);

    ExecutionSpec prepare(ScanContext context, ToolContext tools) throws IOException;

    ArtifactValidation validate(RawArtifactSet artifacts) throws IOException;

    NormalizationResult normalize(ScanContext context, RawArtifactSet artifacts) throws IOException;
}
