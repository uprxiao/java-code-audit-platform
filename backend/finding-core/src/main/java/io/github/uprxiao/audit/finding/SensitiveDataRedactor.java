package io.github.uprxiao.audit.finding;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Shared redaction policy for snippets, normalized findings, raw artifacts and logs. */
public final class SensitiveDataRedactor {

    private static final Pattern PRIVATE_KEY = Pattern.compile(
            "(?s)-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----.*?-----END \\1-----");
    private static final Pattern BEARER = Pattern.compile("(?i)(authorization\\s*[:=]\\s*bearer\\s+)([^\\s,;]+)");
    private static final Pattern URL_USER_INFO = Pattern.compile("(?i)(https?://)([^/@\\s:]+):([^/@\\s]+)@");
    private static final Pattern GENERIC_ASSIGNMENT = Pattern.compile(
            "(?i)(\\b(?:password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret)\\b\\s*[:=]\\s*[\"']?)([^\"'\\s,;}]+)");
    private static final Pattern AWS_ACCESS_KEY = Pattern.compile("\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b");
    private static final Pattern GITHUB_TOKEN = Pattern.compile("\\bgh[pousr]_[A-Za-z0-9]{20,255}\\b");
    private static final Pattern JWT = Pattern.compile("\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b");
    private static final Pattern CANARY = Pattern.compile("\\bAUDIT_CANARY_SECRET_[A-Za-z0-9_-]+\\b");

    private final List<String> exactSecrets;

    public SensitiveDataRedactor() {
        this(List.of());
    }

    public SensitiveDataRedactor(List<String> exactSecrets) {
        List<String> values = new ArrayList<>();
        if (exactSecrets != null) {
            exactSecrets.stream().filter(Objects::nonNull).filter(value -> !value.isBlank())
                    .distinct().sorted(Comparator.comparingInt(String::length).reversed()).forEach(values::add);
        }
        this.exactSecrets = List.copyOf(values);
    }

    public RedactionResult redact(String input) {
        Objects.requireNonNull(input, "input");
        Mutable value = new Mutable(input);
        for (String secret : exactSecrets) {
            int occurrences = count(value.text, secret);
            if (occurrences > 0) {
                value.text = value.text.replace(secret, mask(secret));
                value.count += occurrences;
            }
        }
        value = replacePrivateKeys(value);
        value = replaceGroup(value, BEARER, 2);
        value = replaceUrlUserInfo(value);
        value = replaceGroup(value, GENERIC_ASSIGNMENT, 2);
        value = replaceWhole(value, AWS_ACCESS_KEY);
        value = replaceWhole(value, GITHUB_TOKEN);
        value = replaceWhole(value, JWT);
        value = replaceWhole(value, CANARY);
        return new RedactionResult(value.text, value.count > 0, value.count);
    }

    public boolean containsSensitiveData(String input) {
        return redact(input).redacted();
    }

    public List<String> exactSecrets() {
        return exactSecrets;
    }

    private Mutable replacePrivateKeys(Mutable value) {
        Matcher matcher = PRIVATE_KEY.matcher(value.text);
        StringBuffer output = new StringBuffer();
        int count = 0;
        while (matcher.find()) {
            String replacement = "[REDACTED " + matcher.group(1) + " sha256:" + digest(matcher.group()).substring(0, 12) + "]";
            matcher.appendReplacement(output, Matcher.quoteReplacement(replacement));
            count++;
        }
        matcher.appendTail(output);
        return new Mutable(output.toString(), value.count + count);
    }

    private Mutable replaceUrlUserInfo(Mutable value) {
        Matcher matcher = URL_USER_INFO.matcher(value.text);
        StringBuffer output = new StringBuffer();
        int count = 0;
        while (matcher.find()) {
            matcher.appendReplacement(output, Matcher.quoteReplacement(matcher.group(1) + "[REDACTED]@"));
            count++;
        }
        matcher.appendTail(output);
        return new Mutable(output.toString(), value.count + count);
    }

    private Mutable replaceGroup(Mutable value, Pattern pattern, int secretGroup) {
        Matcher matcher = pattern.matcher(value.text);
        StringBuffer output = new StringBuffer();
        int count = 0;
        while (matcher.find()) {
            String secret = matcher.group(secretGroup);
            String replacement = matcher.group().substring(0, matcher.start(secretGroup) - matcher.start()) + mask(secret);
            matcher.appendReplacement(output, Matcher.quoteReplacement(replacement));
            count++;
        }
        matcher.appendTail(output);
        return new Mutable(output.toString(), value.count + count);
    }

    private Mutable replaceWhole(Mutable value, Pattern pattern) {
        Matcher matcher = pattern.matcher(value.text);
        StringBuffer output = new StringBuffer();
        int count = 0;
        while (matcher.find()) {
            matcher.appendReplacement(output, Matcher.quoteReplacement(mask(matcher.group())));
            count++;
        }
        matcher.appendTail(output);
        return new Mutable(output.toString(), value.count + count);
    }

    private int count(String text, String value) {
        int count = 0;
        int offset = 0;
        while ((offset = text.indexOf(value, offset)) >= 0) {
            count++;
            offset += value.length();
        }
        return count;
    }

    private String mask(String value) {
        if (value.length() <= 4) {
            return "*".repeat(Math.max(4, value.length()));
        }
        return value.substring(0, 2) + "*".repeat(Math.min(32, value.length() - 4))
                + value.substring(value.length() - 2);
    }

    private String digest(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by Java 17", exception);
        }
    }

    private static final class Mutable {
        private String text;
        private int count;

        private Mutable(String text) {
            this(text, 0);
        }

        private Mutable(String text, int count) {
            this.text = text;
            this.count = count;
        }
    }
}
