package io.github.uprxiao.audit.finding;

public record RedactionResult(String text, boolean redacted, int replacementCount) {
}
