package io.github.uprxiao.audit.storage;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Objects;
import java.util.UUID;

public final class NioAtomicFileWriter implements AtomicFileWriter {

    @Override
    public void write(Path target, byte[] content) throws IOException {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(content, "content");
        Path absoluteTarget = target.toAbsolutePath().normalize();
        Path parent = absoluteTarget.getParent();
        if (parent == null) {
            throw new IllegalArgumentException("target must have a parent directory");
        }
        Files.createDirectories(parent);
        Path temporary = parent.resolve(absoluteTarget.getFileName() + ".tmp-" + UUID.randomUUID());
        try {
            try (FileChannel channel = FileChannel.open(temporary,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                ByteBuffer buffer = ByteBuffer.wrap(content);
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }
                channel.force(true);
            }
            move(temporary, absoluteTarget);
            syncDirectory(parent);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private void move(Path source, Path target) throws IOException {
        try {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException exception) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private void syncDirectory(Path directory) {
        try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        } catch (IOException | UnsupportedOperationException ignored) {
            // Directory fsync is not supported on every V1 target file system.
        }
    }
}
