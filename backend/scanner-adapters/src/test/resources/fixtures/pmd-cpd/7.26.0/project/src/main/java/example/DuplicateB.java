package example;

public final class DuplicateB {
    int calculate(int[] values) {
        int total = 0;
        for (int value : values) {
            if (value > 0) { total += value; } else { total -= value; }
        }
        return total;
    }
}
