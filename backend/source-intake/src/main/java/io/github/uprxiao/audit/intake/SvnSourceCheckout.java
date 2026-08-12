package io.github.uprxiao.audit.intake;

import java.io.IOException;
import java.nio.file.Path;
import java.util.function.BooleanSupplier;

@FunctionalInterface
public interface SvnSourceCheckout {

    SvnCheckoutResult checkout(
            String repositoryUrl,
            SvnRevision revision,
            Path destination,
            SourceCredential credential,
            BooleanSupplier cancellationRequested) throws IOException;
}
