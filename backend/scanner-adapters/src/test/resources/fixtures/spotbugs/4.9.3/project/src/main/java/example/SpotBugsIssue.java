package example;

public final class SpotBugsIssue {
    public String dereference(Object value) {
        value = null;
        return value.toString();
    }
}
