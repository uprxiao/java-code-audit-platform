package io.github.uprxiao.audit.intake;

import java.util.Arrays;

public final class SourceCredential implements AutoCloseable {

    private final String username;
    private final char[] password;
    private boolean closed;

    public SourceCredential(String username, char[] password) {
        this.username = username == null ? "" : username;
        this.password = password == null ? new char[0] : password.clone();
    }

    public String username() {
        ensureOpen();
        return username;
    }

    public char[] passwordCopy() {
        ensureOpen();
        return password.clone();
    }

    @Override
    public void close() {
        Arrays.fill(password, '\0');
        closed = true;
    }

    public boolean isClosed() {
        return closed;
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("source credential has been cleared");
        }
    }
}
