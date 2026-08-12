package io.github.uprxiao.audit.intake;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.IDN;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.DigestOutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.Normalizer;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.BooleanSupplier;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import org.tmatesoft.svn.core.SVNCancelException;
import org.tmatesoft.svn.core.SVNDirEntry;
import org.tmatesoft.svn.core.SVNErrorCode;
import org.tmatesoft.svn.core.SVNErrorMessage;
import org.tmatesoft.svn.core.SVNException;
import org.tmatesoft.svn.core.SVNNodeKind;
import org.tmatesoft.svn.core.SVNProperties;
import org.tmatesoft.svn.core.SVNProperty;
import org.tmatesoft.svn.core.SVNURL;
import org.tmatesoft.svn.core.auth.BasicAuthenticationManager;
import org.tmatesoft.svn.core.auth.ISVNAuthenticationManager;
import org.tmatesoft.svn.core.auth.ISVNAuthenticationProvider;
import org.tmatesoft.svn.core.auth.ISVNProxyManager;
import org.tmatesoft.svn.core.auth.SVNAuthentication;
import org.tmatesoft.svn.core.auth.SVNPasswordAuthentication;
import org.tmatesoft.svn.core.auth.SVNUserNameAuthentication;
import org.tmatesoft.svn.core.internal.io.dav.DAVRepositoryFactory;
import org.tmatesoft.svn.core.internal.io.svn.SVNRepositoryFactoryImpl;
import org.tmatesoft.svn.core.io.SVNRepository;
import org.tmatesoft.svn.core.io.SVNRepositoryFactory;

/**
 * Fetches one SVN tree through SVNKit without invoking a native process or creating a working copy.
 * This deliberately ignores history and svn:externals and writes only regular files.
 */
public final class SvnKitSourceCheckout implements SvnSourceCheckout {

    static {
        DAVRepositoryFactory.setup();
        SVNRepositoryFactoryImpl.setup();
    }

    private final SvnRepositoryPolicy repositoryPolicy;
    private final SvnCheckoutLimits limits;

    public SvnKitSourceCheckout(SvnRepositoryPolicy repositoryPolicy, SvnCheckoutLimits limits) {
        this.repositoryPolicy = Objects.requireNonNull(repositoryPolicy, "repositoryPolicy");
        this.limits = Objects.requireNonNull(limits, "limits");
    }

    @Override
    public SvnCheckoutResult checkout(
            String repositoryUrl,
            SvnRevision requestedRevision,
            Path destination,
            SourceCredential credential,
            BooleanSupplier cancellationRequested) throws IOException {
        SvnRepositoryPolicy.ValidatedSvnUrl validated = repositoryPolicy.validate(repositoryUrl);
        Objects.requireNonNull(requestedRevision, "requestedRevision");
        Objects.requireNonNull(destination, "destination");
        Objects.requireNonNull(credential, "credential");
        Objects.requireNonNull(cancellationRequested, "cancellationRequested");
        Path target = destination.toAbsolutePath().normalize();
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            throw new SourceIntakeException("DESTINATION_NOT_EMPTY", "SVN destination must not already exist");
        }
        Path parent = target.getParent();
        if (parent == null) {
            throw new SourceIntakeException("UNSAFE_SVN_DESTINATION", "SVN destination must have a parent directory");
        }
        Files.createDirectories(parent);
        Path staging = parent.resolve("." + target.getFileName() + ".svn-" + UUID.randomUUID()).normalize();
        if (!staging.startsWith(parent) || Files.exists(staging, LinkOption.NOFOLLOW_LINKS)) {
            throw new SourceIntakeException("UNSAFE_SVN_DESTINATION", "SVN staging destination is unsafe");
        }

        char[] password = credential.passwordCopy();
        String username = credential.username();
        BasicAuthenticationManager inMemoryAuthentication = new BasicAuthenticationManager(new SVNAuthentication[]{
                SVNPasswordAuthentication.newInstance(username, password, false, null, false),
                SVNUserNameAuthentication.newInstance(username, false, null, false)
        });
        ISVNAuthenticationManager boundedAuthentication = new TimeoutAuthenticationManager(
                inMemoryAuthentication, validated.host(), systemTrustManager(validated.host()),
                (int) limits.connectTimeout().toMillis(), (int) limits.readTimeout().toMillis());
        SVNRepository repository = null;
        try {
            checkCancelled(cancellationRequested);
            SVNURL svnUrl = SVNURL.parseURIEncoded(validated.value());
            repository = SVNRepositoryFactory.create(svnUrl);
            repository.setAuthenticationManager(boundedAuthentication);
            repository.setCanceller(() -> checkCancelled(cancellationRequested));
            long revision = requestedRevision.number().isPresent()
                    ? requestedRevision.number().getAsLong()
                    : repository.getLatestRevision();
            ensureRedirectDidNotChangeHost(validated.host(), repository.getLocation());
            if (repository.checkPath("", revision) != SVNNodeKind.DIR) {
                throw new SourceIntakeException("SVN_NOT_DIRECTORY",
                        "SVN repository URL must point to a directory at the requested revision");
            }
            Files.createDirectory(staging);
            Counters counters = new Counters();
            MessageDigest snapshotDigest = sha256();
            fetchTree(repository, revision, staging, cancellationRequested, counters, snapshotDigest);
            ensureRedirectDidNotChangeHost(validated.host(), repository.getLocation());
            moveCompletedTree(staging, target);
            return new SvnCheckoutResult(target, revision, counters.entries, counters.files,
                    counters.expandedBytes, "sha256:" + HexFormat.of().formatHex(snapshotDigest.digest()));
        } catch (SVNCancelException exception) {
            throw new SourceIntakeException("SVN_CHECKOUT_CANCELLED", "SVN source acquisition was cancelled");
        } catch (SVNException exception) {
            SourceIntakeException intake = findIntakeCause(exception);
            if (intake != null) {
                throw intake;
            }
            String svnCode = exception.getErrorMessage() == null
                    ? "UNKNOWN" : exception.getErrorMessage().getErrorCode().toString();
            throw new SourceIntakeException("SVN_CHECKOUT_FAILED", "SVN source acquisition failed",
                    Map.of("svnErrorCode", svnCode,
                            "causeType", deepestCause(exception).getClass().getSimpleName()));
        } finally {
            Arrays.fill(password, '\0');
            inMemoryAuthentication.dismissSensitiveData();
            if (repository != null) {
                repository.closeSession();
            }
            deleteTree(staging);
        }
    }

    private void fetchTree(
            SVNRepository repository,
            long revision,
            Path root,
            BooleanSupplier cancellationRequested,
            Counters counters,
            MessageDigest snapshotDigest) throws SVNException, IOException {
        Deque<String> directories = new ArrayDeque<>();
        directories.add("");
        Set<String> portablePaths = new HashSet<>();
        while (!directories.isEmpty()) {
            checkCancelled(cancellationRequested);
            String directory = directories.removeFirst();
            List<SVNDirEntry> entries = new ArrayList<>();
            repository.getDir(directory, revision, null,
                    SVNDirEntry.DIRENT_KIND | SVNDirEntry.DIRENT_SIZE, entries);
            entries.sort(Comparator.comparing(SVNDirEntry::getName));
            for (SVNDirEntry entry : entries) {
                checkCancelled(cancellationRequested);
                String relative = directory.isEmpty() ? entry.getName() : directory + "/" + entry.getName();
                Path path = validateEntry(root, relative, entry.getName(), portablePaths, counters);
                if (entry.getKind() == SVNNodeKind.DIR) {
                    Files.createDirectory(path);
                    directories.addLast(relative);
                } else if (entry.getKind() == SVNNodeKind.FILE) {
                    fetchFile(repository, revision, relative, path, entry.getSize(), counters, snapshotDigest);
                } else {
                    throw new SourceIntakeException("UNSAFE_SVN_ENTRY", "SVN snapshot contains an unsupported node kind");
                }
            }
        }
    }

    private Path validateEntry(
            Path root,
            String relative,
            String name,
            Set<String> portablePaths,
            Counters counters) throws IOException {
        counters.entries++;
        if (counters.entries > limits.maxEntries()) {
            throw limit("SVN snapshot contains too many entries", counters);
        }
        if (name == null || name.isBlank() || ".".equals(name) || "..".equals(name)
                || name.indexOf('/') >= 0 || name.indexOf('\\') >= 0 || name.indexOf('\0') >= 0
                || relative.length() > limits.maxPathCharacters()) {
            throw new SourceIntakeException("UNSAFE_SVN_ENTRY", "SVN snapshot contains an unsafe path");
        }
        Path path = root.resolve(relative).normalize();
        if (!path.startsWith(root)) {
            throw new SourceIntakeException("UNSAFE_SVN_ENTRY", "SVN snapshot path escapes its workspace");
        }
        String collisionKey = Normalizer.normalize(relative, Normalizer.Form.NFC).toLowerCase(Locale.ROOT);
        if (!portablePaths.add(collisionKey)) {
            throw new SourceIntakeException("UNSAFE_SVN_ENTRY",
                    "SVN paths collide on a supported target file system");
        }
        return path;
    }

    private void fetchFile(
            SVNRepository repository,
            long revision,
            String relative,
            Path target,
            long declaredSize,
            Counters counters,
            MessageDigest snapshotDigest) throws IOException, SVNException {
        if (declaredSize > limits.maxSingleFileBytes()
                || declaredSize >= 0 && counters.expandedBytes > limits.maxExpandedBytes() - declaredSize) {
            throw limit("SVN snapshot exceeds configured byte limits", counters);
        }
        counters.files++;
        SVNProperties properties = new SVNProperties();
        MessageDigest fileDigest = sha256();
        Files.createDirectories(target.getParent());
        try (OutputStream file = new BufferedOutputStream(Files.newOutputStream(
                target, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE));
             OutputStream limited = new LimitedOutputStream(file, counters);
             OutputStream digest = new DigestOutputStream(limited, fileDigest)) {
            repository.getFile(relative, revision, properties, digest);
        }
        if (properties.containsName(SVNProperty.SPECIAL)) {
            throw new SourceIntakeException("UNSAFE_SVN_ENTRY", "SVN symbolic links and special files are forbidden");
        }
        snapshotDigest.update(relative.getBytes(StandardCharsets.UTF_8));
        snapshotDigest.update((byte) 0);
        snapshotDigest.update(fileDigest.digest());
    }

    private void ensureRedirectDidNotChangeHost(String expectedHost, SVNURL actual) throws SourceIntakeException {
        if (actual == null) {
            return;
        }
        String actualHost;
        try {
            actualHost = URI.create(actual.toString()).getHost();
        } catch (IllegalArgumentException exception) {
            throw new SourceIntakeException("UNSAFE_SVN_REDIRECT", "SVN endpoint redirected to an invalid URL");
        }
        if (actualHost == null || !actualHost.equalsIgnoreCase(expectedHost)) {
            throw new SourceIntakeException("UNSAFE_SVN_REDIRECT", "SVN endpoint redirected to a different host");
        }
    }

    private void checkCancelled(BooleanSupplier cancellationRequested) throws SVNCancelException {
        if (cancellationRequested.getAsBoolean()) {
            throw new SVNCancelException(SVNErrorMessage.create(SVNErrorCode.CANCELLED));
        }
    }

    private SourceIntakeException findIntakeCause(Throwable throwable) {
        Throwable current = throwable;
        while (current != null) {
            if (current instanceof SourceIntakeException intake) {
                return intake;
            }
            current = current.getCause();
        }
        if (throwable instanceof SVNException svn && svn.getErrorMessage() != null) {
            current = svn.getErrorMessage().getCause();
            while (current != null) {
                if (current instanceof SourceIntakeException intake) {
                    return intake;
                }
                current = current.getCause();
            }
        }
        return null;
    }

    private Throwable deepestCause(Throwable throwable) {
        Throwable current = throwable;
        while (current.getCause() != null) {
            current = current.getCause();
        }
        return current;
    }

    private SourceIntakeException limit(String message, Counters counters) {
        return new SourceIntakeException("SVN_LIMIT_EXCEEDED", message, Map.of(
                "entries", counters.entries,
                "files", counters.files,
                "expandedBytes", counters.expandedBytes));
    }

    private MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by Java 17", exception);
        }
    }

    private X509TrustManager systemTrustManager(String expectedHost) throws SourceIntakeException {
        try {
            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init((KeyStore) null);
            for (TrustManager manager : factory.getTrustManagers()) {
                if (manager instanceof X509TrustManager x509) {
                    return new HostnameCheckingTrustManager(x509, expectedHost);
                }
            }
        } catch (GeneralSecurityException exception) {
            throw new SourceIntakeException("SVN_TLS_CONFIGURATION_FAILED",
                    "JVM system truststore cannot be initialized");
        }
        throw new SourceIntakeException("SVN_TLS_CONFIGURATION_FAILED",
                "JVM system truststore does not provide an X.509 trust manager");
    }

    private void moveCompletedTree(Path source, Path destination) throws IOException {
        try {
            Files.move(source, destination, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException exception) {
            Files.move(source, destination);
        }
    }

    private void deleteTree(Path root) throws IOException {
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        try (var paths = Files.walk(root)) {
            for (Path path : paths.sorted(Comparator.comparingInt(Path::getNameCount).reversed()).toList()) {
                if (!path.normalize().startsWith(root)) {
                    throw new IOException("refusing to clean outside SVN staging root");
                }
                Files.deleteIfExists(path);
            }
        }
    }

    private final class LimitedOutputStream extends OutputStream {
        private final OutputStream delegate;
        private final Counters counters;
        private long fileBytes;

        private LimitedOutputStream(OutputStream delegate, Counters counters) {
            this.delegate = delegate;
            this.counters = counters;
        }

        @Override
        public void write(int value) throws IOException {
            ensureCapacity(1);
            delegate.write(value);
            fileBytes++;
            counters.expandedBytes++;
        }

        @Override
        public void write(byte[] buffer, int offset, int length) throws IOException {
            ensureCapacity(length);
            delegate.write(buffer, offset, length);
            fileBytes += length;
            counters.expandedBytes += length;
        }

        @Override
        public void flush() throws IOException {
            delegate.flush();
        }

        private void ensureCapacity(int additional) throws SourceIntakeException {
            if (fileBytes > limits.maxSingleFileBytes() - additional
                    || counters.expandedBytes > limits.maxExpandedBytes() - additional) {
                throw limit("SVN snapshot exceeds configured byte limits", counters);
            }
        }
    }

    private static final class Counters {
        private int entries;
        private int files;
        private long expandedBytes;
    }

    private record TimeoutAuthenticationManager(
            BasicAuthenticationManager delegate,
            String expectedHost,
            X509TrustManager trustManager,
            int connectTimeoutMillis,
            int readTimeoutMillis) implements ISVNAuthenticationManager {

        @Override
        public void setAuthenticationProvider(ISVNAuthenticationProvider provider) {
            delegate.setAuthenticationProvider(provider);
        }

        @Override
        public ISVNProxyManager getProxyManager(SVNURL url) throws SVNException {
            return delegate.getProxyManager(url);
        }

        @Override
        public TrustManager getTrustManager(SVNURL url) throws SVNException {
            assertAllowedHost(url);
            return trustManager;
        }

        @Override
        public SVNAuthentication getFirstAuthentication(String kind, String realm, SVNURL url) throws SVNException {
            assertAllowedHost(url);
            return delegate.getFirstAuthentication(kind, realm, url);
        }

        @Override
        public SVNAuthentication getNextAuthentication(String kind, String realm, SVNURL url) throws SVNException {
            assertAllowedHost(url);
            return delegate.getNextAuthentication(kind, realm, url);
        }

        @Override
        public void acknowledgeAuthentication(
                boolean accepted,
                String kind,
                String realm,
                SVNErrorMessage errorMessage,
                SVNAuthentication authentication) throws SVNException {
            delegate.acknowledgeAuthentication(accepted, kind, realm, errorMessage, authentication);
        }

        @Override
        public void acknowledgeTrustManager(TrustManager trustManager) {
            delegate.acknowledgeTrustManager(trustManager);
        }

        @Override
        public boolean isAuthenticationForced() {
            return delegate.isAuthenticationForced();
        }

        @Override
        public int getReadTimeout(SVNRepository repository) {
            return readTimeoutMillis;
        }

        @Override
        public int getConnectTimeout(SVNRepository repository) {
            return connectTimeoutMillis;
        }

        private void assertAllowedHost(SVNURL url) throws SVNException {
            if (url != null && (url.getHost() == null || !url.getHost().equalsIgnoreCase(expectedHost))) {
                throw new SVNException(SVNErrorMessage.create(
                        SVNErrorCode.RA_ILLEGAL_URL, "cross-host SVN authentication is forbidden"));
            }
        }
    }

    private static final class HostnameCheckingTrustManager extends X509ExtendedTrustManager {
        private final X509TrustManager delegate;
        private final String expectedHost;

        private HostnameCheckingTrustManager(X509TrustManager delegate, String expectedHost) {
            this.delegate = delegate;
            this.expectedHost = expectedHost;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            delegate.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            if (delegate instanceof X509ExtendedTrustManager extended) {
                extended.checkServerTrusted(chain, authType, socket);
            } else {
                delegate.checkServerTrusted(chain, authType);
            }
            verifyHostname(chain);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            delegate.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            if (delegate instanceof X509ExtendedTrustManager extended) {
                extended.checkServerTrusted(chain, authType, engine);
            } else {
                delegate.checkServerTrusted(chain, authType);
            }
            verifyHostname(chain);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            delegate.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            delegate.checkServerTrusted(chain, authType);
            verifyHostname(chain);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return delegate.getAcceptedIssuers();
        }

        private void verifyHostname(X509Certificate[] chain) throws CertificateException {
            if (chain == null || chain.length == 0 || chain[0] == null || !certificateMatches(chain[0])) {
                throw new CertificateException("SVN TLS certificate does not match the requested host");
            }
        }

        private boolean certificateMatches(X509Certificate certificate) throws CertificateException {
            String unwrappedHost = expectedHost.startsWith("[") && expectedHost.endsWith("]")
                    ? expectedHost.substring(1, expectedHost.length() - 1) : expectedHost;
            boolean ipAddress = isIpLiteral(unwrappedHost);
            String asciiHost = (ipAddress ? unwrappedHost : IDN.toASCII(unwrappedHost)).toLowerCase(Locale.ROOT);
            boolean relevantAlternativeName = false;
            var alternativeNames = certificate.getSubjectAlternativeNames();
            if (alternativeNames != null) {
                for (var name : alternativeNames) {
                    if (name == null || name.size() < 2 || !(name.get(0) instanceof Integer type)) {
                        continue;
                    }
                    if (ipAddress && type == 7) {
                        relevantAlternativeName = true;
                        if (ipEquals(asciiHost, name.get(1))) {
                            return true;
                        }
                    } else if (!ipAddress && type == 2) {
                        relevantAlternativeName = true;
                        if (dnsMatches(asciiHost, String.valueOf(name.get(1)))) {
                            return true;
                        }
                    }
                }
            }
            if (relevantAlternativeName || ipAddress) {
                return false;
            }
            try {
                LdapName subject = new LdapName(certificate.getSubjectX500Principal().getName());
                for (var rdn : subject.getRdns()) {
                    if ("CN".equalsIgnoreCase(rdn.getType()) && dnsMatches(asciiHost, String.valueOf(rdn.getValue()))) {
                        return true;
                    }
                }
            } catch (InvalidNameException exception) {
                throw new CertificateException("SVN TLS certificate subject cannot be parsed", exception);
            }
            return false;
        }

        private boolean dnsMatches(String host, String certificateName) {
            String pattern;
            try {
                boolean wildcard = certificateName.startsWith("*.");
                String name = wildcard ? certificateName.substring(2) : certificateName;
                pattern = (wildcard ? "*." : "") + IDN.toASCII(name).toLowerCase(Locale.ROOT);
            } catch (IllegalArgumentException exception) {
                return false;
            }
            if (!pattern.startsWith("*.")) {
                return host.equals(pattern);
            }
            String suffix = pattern.substring(2);
            if (!suffix.contains(".") || !host.endsWith("." + suffix)) {
                return false;
            }
            String firstLabel = host.substring(0, host.length() - suffix.length() - 1);
            return !firstLabel.isBlank() && firstLabel.indexOf('.') < 0;
        }

        private boolean isIpLiteral(String value) {
            return value.indexOf(':') >= 0 || value.matches("[0-9.]+");
        }

        private boolean ipEquals(String expected, Object actual) {
            try {
                byte[] actualAddress = actual instanceof byte[] bytes
                        ? bytes : InetAddress.getByName(String.valueOf(actual)).getAddress();
                return Arrays.equals(InetAddress.getByName(expected).getAddress(), actualAddress);
            } catch (UnknownHostException exception) {
                return false;
            }
        }
    }
}
