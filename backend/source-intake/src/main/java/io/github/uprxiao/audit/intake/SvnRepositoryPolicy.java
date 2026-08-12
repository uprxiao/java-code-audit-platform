package io.github.uprxiao.audit.intake;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/** Validates an SVN endpoint before it is handed to a protocol implementation. */
public final class SvnRepositoryPolicy {

    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https", "svn");
    private static final Set<String> FORBIDDEN_ESCAPES = Set.of("%00", "%0a", "%0d", "%5c");

    private final int maximumUrlCharacters;
    private final Set<String> allowedHosts;

    public SvnRepositoryPolicy(int maximumUrlCharacters, Set<String> allowedHosts) {
        if (maximumUrlCharacters < 64) {
            throw new IllegalArgumentException("maximum SVN URL length must be at least 64 characters");
        }
        this.maximumUrlCharacters = maximumUrlCharacters;
        this.allowedHosts = allowedHosts == null ? Set.of() : allowedHosts.stream()
                .map(host -> host.toLowerCase(Locale.ROOT))
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
    }

    public static SvnRepositoryPolicy defaults() {
        return new SvnRepositoryPolicy(2048, Set.of());
    }

    public ValidatedSvnUrl validate(String value) throws SourceIntakeException {
        if (value == null || value.isBlank() || value.length() > maximumUrlCharacters
                || value.chars().anyMatch(character -> Character.isISOControl(character))) {
            throw invalid("SVN repository URL is missing or exceeds its configured limit");
        }
        URI uri;
        try {
            uri = new URI(value);
        } catch (URISyntaxException exception) {
            throw invalid("SVN repository URL is malformed");
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!ALLOWED_SCHEMES.contains(scheme)) {
            throw new SourceIntakeException("UNSUPPORTED_SVN_PROTOCOL",
                    "SVN repository URL must use http, https, or svn");
        }
        if (!uri.isAbsolute() || uri.getHost() == null || uri.getHost().isBlank()
                || uri.getRawUserInfo() != null || uri.getRawAuthority() == null
                || uri.getRawAuthority().indexOf('@') >= 0 || uri.getRawQuery() != null || uri.getRawFragment() != null) {
            throw invalid("SVN repository URL must contain a host and must not contain user-info, query, or fragment data");
        }
        String lower = value.toLowerCase(Locale.ROOT);
        if (FORBIDDEN_ESCAPES.stream().anyMatch(lower::contains)) {
            throw invalid("SVN repository URL contains a forbidden escaped character");
        }
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        if (!allowedHosts.isEmpty() && !allowedHosts.contains(host)) {
            throw new SourceIntakeException("SVN_HOST_NOT_ALLOWED", "SVN repository host is not allowed by deployment policy");
        }
        String normalized = uri.normalize().toASCIIString();
        if (!uri.getScheme().equals(scheme)) {
            normalized = scheme + normalized.substring(normalized.indexOf(':'));
        }
        return new ValidatedSvnUrl(normalized, host);
    }

    private SourceIntakeException invalid(String message) {
        return new SourceIntakeException("INVALID_SVN_URL", message);
    }

    public record ValidatedSvnUrl(String value, String host) {
        public ValidatedSvnUrl {
            Objects.requireNonNull(value, "value");
            Objects.requireNonNull(host, "host");
        }
    }
}
