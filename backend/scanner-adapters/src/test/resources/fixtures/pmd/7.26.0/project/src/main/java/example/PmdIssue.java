package example;

import java.io.FileInputStream;

public final class PmdIssue {
    private PmdIssue() {
    }

    public static int read(String file) throws Exception {
        FileInputStream input = new FileInputStream(file);
        return input.read();
    }
}
