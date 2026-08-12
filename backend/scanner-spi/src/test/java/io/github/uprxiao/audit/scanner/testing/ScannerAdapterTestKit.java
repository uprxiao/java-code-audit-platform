package io.github.uprxiao.audit.scanner.testing;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.uprxiao.audit.scanner.EngineDescriptor;
import io.github.uprxiao.audit.scanner.ExecutionSpec;
import io.github.uprxiao.audit.scanner.ScannerAdapter;
import java.nio.file.Path;
import java.util.Set;

public final class ScannerAdapterTestKit {

    private static final Set<String> SHELLS = Set.of("sh", "bash", "zsh", "dash", "ksh", "csh", "fish");

    private ScannerAdapterTestKit() {
    }

    public static void assertDescriptorContract(ScannerAdapter adapter) {
        assertNotNull(adapter);
        EngineDescriptor descriptor = adapter.descriptor();
        assertNotNull(descriptor);
        assertFalse(descriptor.displayName().isBlank());
        assertTrue(!descriptor.defaultTimeout().isZero() && !descriptor.defaultTimeout().isNegative());
        assertFalse(descriptor.dependsOn().contains(descriptor.id()));
    }

    public static void assertSafeExecutionSpec(ExecutionSpec specification, Path taskRoot) {
        Path normalizedRoot = taskRoot.toAbsolutePath().normalize();
        assertTrue(specification.workingDirectory().startsWith(normalizedRoot),
                "working directory must remain within the task root");
        String executableName = Path.of(specification.command().get(0)).getFileName().toString();
        assertFalse(SHELLS.contains(executableName), "adapters must not execute through a shell");
        specification.expectedArtifacts().forEach(artifact -> {
            Path resolved = specification.workingDirectory().resolve(artifact.relativePath()).normalize();
            assertTrue(resolved.startsWith(specification.workingDirectory()),
                    "artifact path must remain within the engine output directory");
        });
    }
}
