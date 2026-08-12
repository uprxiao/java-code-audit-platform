package io.github.uprxiao.audit.intake;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.finding.SourceType;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MavenProjectInspectorTest {

    @TempDir
    Path temporaryDirectory;

    private final MavenProjectInspector inspector = new MavenProjectInspector();

    @Test
    void acceptsSingleJava17RootInsideOneWrapperDirectory() throws Exception {
        Path project = Files.createDirectories(temporaryDirectory.resolve("wrapper/app"));
        Files.writeString(project.resolve("pom.xml"), pom("app", "jar", "<maven.compiler.release>17</maven.compiler.release>", ""));

        ProjectContext result = inspector.inspect(temporaryDirectory, source(), ScanProfile.QUICK);

        assertEquals(project.toAbsolutePath(), result.workspaceRoot());
        assertEquals("wrapper/app", result.manifest().root());
        assertEquals(17, result.manifest().javaVersion());
        assertEquals(List.of("."), result.manifest().modules().stream().map(MavenModule::path).toList());
    }

    @Test
    void discoversDeclaredMultiModuleReactorAndIgnoresTargetPoms() throws Exception {
        Path project = Files.createDirectories(temporaryDirectory.resolve("reactor"));
        Files.writeString(project.resolve("pom.xml"), pom("root", "pom", "<java.version>17</java.version>",
                "<modules><module>api</module><module>service</module></modules>"));
        Files.createDirectories(project.resolve("api"));
        Files.writeString(project.resolve("api/pom.xml"), pom("api", "jar", "", ""));
        Files.createDirectories(project.resolve("service"));
        Files.writeString(project.resolve("service/pom.xml"), pom("service", "jar", "", ""));
        Files.createDirectories(project.resolve("target/generated"));
        Files.writeString(project.resolve("target/generated/pom.xml"), pom("ignored", "jar", "", ""));

        ProjectContext result = inspector.inspect(temporaryDirectory, source(), ScanProfile.STANDARD);

        assertEquals(3, result.manifest().modules().size());
        assertEquals(List.of(".", "api", "service"),
                result.manifest().modules().stream().map(MavenModule::path).toList());
    }

    @Test
    void reportsEveryIndependentRootAndRequiresRepackaging() throws Exception {
        Path first = Files.createDirectories(temporaryDirectory.resolve("first"));
        Path second = Files.createDirectories(temporaryDirectory.resolve("second"));
        Files.writeString(first.resolve("pom.xml"), pom("first", "jar", "<java.version>17</java.version>", ""));
        Files.writeString(second.resolve("pom.xml"), pom("second", "jar", "<java.version>17</java.version>", ""));

        SourceIntakeException error = assertThrows(SourceIntakeException.class,
                () -> inspector.inspect(temporaryDirectory, source(), ScanProfile.QUICK));

        assertEquals("MULTIPLE_MAVEN_ROOTS", error.code());
        assertEquals(List.of("first/pom.xml", "second/pom.xml"), error.details().get("candidates"));
    }

    @Test
    void rejectsNonJava17MissingJavaVersionModuleEscapeAndDoctype() throws Exception {
        Path non17 = Files.createDirectories(temporaryDirectory.resolve("non17"));
        Files.writeString(non17.resolve("pom.xml"), pom("non17", "jar", "<java.version>21</java.version>", ""));
        assertEquals("UNSUPPORTED_JAVA_VERSION", assertThrows(SourceIntakeException.class,
                () -> inspector.inspect(non17, source(), ScanProfile.QUICK)).code());

        Path missing = Files.createDirectories(temporaryDirectory.resolve("missing"));
        Files.writeString(missing.resolve("pom.xml"), pom("missing", "jar", "", ""));
        assertEquals("UNSUPPORTED_JAVA_VERSION", assertThrows(SourceIntakeException.class,
                () -> inspector.inspect(missing, source(), ScanProfile.QUICK)).code());

        Path escape = Files.createDirectories(temporaryDirectory.resolve("escape"));
        Files.writeString(escape.resolve("pom.xml"), pom("escape", "pom", "<java.version>17</java.version>",
                "<modules><module>../outside</module></modules>"));
        assertEquals("INVALID_MAVEN_REACTOR", assertThrows(SourceIntakeException.class,
                () -> inspector.inspect(escape, source(), ScanProfile.QUICK)).code());

        Path xxe = Files.createDirectories(temporaryDirectory.resolve("xxe"));
        Files.writeString(xxe.resolve("pom.xml"), """
                <?xml version="1.0"?>
                <!DOCTYPE project [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
                <project><modelVersion>4.0.0</modelVersion><artifactId>&xxe;</artifactId>
                  <properties><java.version>17</java.version></properties></project>
                """);
        SourceIntakeException xxeError = assertThrows(SourceIntakeException.class,
                () -> inspector.inspect(xxe, source(), ScanProfile.QUICK));
        assertEquals("INVALID_MAVEN_POM", xxeError.code());
        assertTrue(xxeError.getMessage().contains("securely parse"));
    }

    private SourceDescriptor source() {
        return new SourceDescriptor(SourceType.ZIP, "fixture", "upload.zip", "", "sha256");
    }

    private String pom(String artifactId, String packaging, String properties, String modules) {
        return """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>example</groupId>
                  <artifactId>%s</artifactId>
                  <version>1.0.0</version>
                  <packaging>%s</packaging>
                  <properties>%s</properties>
                  %s
                </project>
                """.formatted(artifactId, packaging, properties, modules);
    }
}
