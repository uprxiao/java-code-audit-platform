package io.github.uprxiao.audit.intake;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;

/** Optional operator smoke against a disposable http(s)/svn fixture URL. */
@EnabledIfSystemProperty(named = "audit.svn.smoke-url", matches = ".+")
class SvnKitRealSmokeTest {

    @TempDir
    Path temporary;

    @Test
    void downloadsConfiguredNetworkFixtureAtHead() throws Exception {
        String url = System.getProperty("audit.svn.smoke-url");
        String user = System.getProperty("audit.svn.smoke-username", "");
        char[] password = System.getProperty("audit.svn.smoke-password", "").toCharArray();
        try (SourceCredential credential = new SourceCredential(user, password)) {
            SvnCheckoutResult result;
            try {
                result = new SvnKitSourceCheckout(SvnRepositoryPolicy.defaults(), SvnCheckoutLimits.defaults())
                        .checkout(url, SvnRevision.head(), temporary.resolve("snapshot"), credential, () -> false);
            } catch (SourceIntakeException failure) {
                throw new AssertionError(failure.code() + ": " + failure.details(), failure);
            }
            assertTrue(result.revision() >= 0);
            assertTrue(result.entries() > 0);
            assertTrue(Files.isDirectory(result.root()));
            assertTrue(Files.notExists(result.root().resolve(".svn")));

            SvnCheckoutResult pinned = new SvnKitSourceCheckout(
                    SvnRepositoryPolicy.defaults(), SvnCheckoutLimits.defaults())
                    .checkout(url, new SvnRevision(java.util.OptionalLong.of(result.revision())),
                            temporary.resolve("pinned-snapshot"), credential, () -> false);
            assertEquals(result.revision(), pinned.revision());
            assertEquals(result.contentSha256(), pinned.contentSha256());
        } finally {
            java.util.Arrays.fill(password, '\0');
        }
    }
}
