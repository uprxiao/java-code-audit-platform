package io.github.uprxiao.audit.api;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.intake.SourceCredential;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/** JSON request whose password storage can be explicitly cleared after ownership is transferred. */
public final class SvnScanRequest implements AutoCloseable {

    private final String repositoryUrl;
    private final String revision;
    private final String username;
    private final char[] password;
    private final String displayName;
    private final ScanProfile profile;
    private final List<String> mavenProfiles;
    private final Map<String, String> mavenProperties;
    private boolean closed;

    @JsonCreator
    public SvnScanRequest(
            @JsonProperty("repositoryUrl") String repositoryUrl,
            @JsonProperty("revision") String revision,
            @JsonProperty("username") String username,
            @JsonProperty("password") char[] password,
            @JsonProperty("displayName") String displayName,
            @JsonProperty("profile") ScanProfile profile,
            @JsonProperty("mavenProfiles") List<String> mavenProfiles,
            @JsonProperty("mavenProperties") Map<String, String> mavenProperties) {
        this.repositoryUrl = repositoryUrl == null ? "" : repositoryUrl;
        this.revision = revision == null ? "" : revision;
        this.username = username == null ? "" : username;
        this.password = password == null ? new char[0] : password.clone();
        this.displayName = displayName == null ? "" : displayName;
        this.profile = profile == null ? ScanProfile.QUICK : profile;
        this.mavenProfiles = mavenProfiles == null ? List.of() : List.copyOf(mavenProfiles);
        this.mavenProperties = mavenProperties == null ? Map.of() : Map.copyOf(mavenProperties);
    }

    public String repositoryUrl() {
        return repositoryUrl;
    }

    public String revision() {
        return revision;
    }

    public String username() {
        return username;
    }

    @JsonIgnore
    public char[] passwordCopy() {
        ensureOpen();
        return password.clone();
    }

    public String displayName() {
        return displayName;
    }

    public ScanProfile profile() {
        return profile;
    }

    public List<String> mavenProfiles() {
        return mavenProfiles;
    }

    public Map<String, String> mavenProperties() {
        return mavenProperties;
    }

    @JsonIgnore
    public SourceCredential transferCredential() {
        ensureOpen();
        try {
            return new SourceCredential(username, password);
        } finally {
            close();
        }
    }

    @Override
    public void close() {
        Arrays.fill(password, '\0');
        closed = true;
    }

    @JsonIgnore
    public boolean isClosed() {
        return closed;
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("SVN request credential has been cleared");
        }
    }

    @Override
    public String toString() {
        return "SvnScanRequest[repositoryUrl=<redacted>, revision=" + revision
                + ", username=<redacted>, password=***, displayName=" + displayName
                + ", profile=" + profile + "]";
    }
}
