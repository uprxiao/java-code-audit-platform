package io.github.uprxiao.audit.intake;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Set;
import org.junit.jupiter.api.Test;

class SvnRepositoryPolicyTest {

    private final SvnRepositoryPolicy policy = SvnRepositoryPolicy.defaults();

    @Test
    void acceptsOnlyNetworkSvnSnapshotProtocols() throws Exception {
        assertEquals("http://svn.example.test/repo/trunk", policy.validate("http://svn.example.test/repo/trunk").value());
        assertEquals("https://svn.example.test/repo/%E9%A1%B9%E7%9B%AE",
                policy.validate("https://svn.example.test/repo/%E9%A1%B9%E7%9B%AE").value());
        assertEquals("svn://svn.example.test/repo/trunk", policy.validate("svn://svn.example.test/repo/trunk").value());
    }

    @Test
    void rejectsLocalSshAndCredentialBearingUrls() {
        assertCode("UNSUPPORTED_SVN_PROTOCOL", "file:///tmp/repository");
        assertCode("UNSUPPORTED_SVN_PROTOCOL", "svn+ssh://svn.example.test/repository");
        assertCode("INVALID_SVN_URL", "https://alice:canary@svn.example.test/repository");
        assertCode("INVALID_SVN_URL", "https://svn.example.test/repository?password=canary");
        assertCode("INVALID_SVN_URL", "https://svn.example.test/repository#fragment");
        assertCode("INVALID_SVN_URL", "https://svn.example.test/%0aheader");
    }

    @Test
    void optionalAllowlistIsCaseInsensitiveAndFailClosed() throws Exception {
        SvnRepositoryPolicy restricted = new SvnRepositoryPolicy(2048, Set.of("SVN.EXAMPLE.TEST"));
        assertEquals("svn.example.test", restricted.validate("https://svn.example.test/repository").host());
        SourceIntakeException failure = assertThrows(SourceIntakeException.class,
                () -> restricted.validate("https://other.example.test/repository"));
        assertEquals("SVN_HOST_NOT_ALLOWED", failure.code());
    }

    private void assertCode(String expected, String value) {
        SourceIntakeException failure = assertThrows(SourceIntakeException.class, () -> policy.validate(value));
        assertEquals(expected, failure.code());
    }
}
