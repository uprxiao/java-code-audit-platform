package io.github.uprxiao.audit.orchestrator;

public final class ProfileConfigurationException extends RuntimeException {
    public ProfileConfigurationException(String message) {
        super(message);
    }

    public ProfileConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}
