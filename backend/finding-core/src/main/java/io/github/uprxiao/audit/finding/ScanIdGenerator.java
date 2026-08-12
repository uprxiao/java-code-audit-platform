package io.github.uprxiao.audit.finding;

import java.util.UUID;

@FunctionalInterface
public interface ScanIdGenerator {
    ScanIdGenerator RANDOM = UUID::randomUUID;

    UUID nextId();
}
