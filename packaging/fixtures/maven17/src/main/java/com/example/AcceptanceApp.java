package com.example;

public final class AcceptanceApp {
    private AcceptanceApp() {
    }

    public static String message(String candidate) {
        return candidate == null ? "acceptance" : candidate.strip();
    }
}
