package io.github.uprxiao.audit.intake;

import java.util.Arrays;

public final class SourceCredential implements AutoCloseable {

    private static final int MAXIMUM_USERNAME_CHARACTERS = 512;
    private static final int MAXIMUM_PASSWORD_CHARACTERS = 4096;

    private final String username;
    private final char[] password;
    private boolean closed;

    public SourceCredential(String username, char[] password) {
        this.username = username == null ? "" : username;
        this.password = password == null ? new char[0] : password.clone();
        if (this.username.length() > MAXIMUM_USERNAME_CHARACTERS
                || this.username.chars().anyMatch(Character::isISOControl)) {
            Arrays.fill(this.password, '\0');
            throw new IllegalArgumentException("source credential username is invalid");
        }
        if (this.password.length > MAXIMUM_PASSWORD_CHARACTERS) {
            Arrays.fill(this.password, '\0');
            throw new IllegalArgumentException("source credential password exceeds its configured limit");
        }
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

    public boolean isPresent() {
        ensureOpen();
        return !username.isBlank() || password.length > 0;
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("source credential has been cleared");
        }
    }
}
