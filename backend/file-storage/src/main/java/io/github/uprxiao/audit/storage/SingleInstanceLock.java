package io.github.uprxiao.audit.storage;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Objects;

public final class SingleInstanceLock implements AutoCloseable {

    private final FileChannel channel;
    private final FileLock lock;

    private SingleInstanceLock(FileChannel channel, FileLock lock) {
        this.channel = channel;
        this.lock = lock;
    }

    public static SingleInstanceLock acquire(Path dataRoot) throws IOException {
        Objects.requireNonNull(dataRoot, "dataRoot");
        Path root = dataRoot.toAbsolutePath().normalize();
        Files.createDirectories(root);
        Path lockFile = root.resolve("instance.lock");
        FileChannel channel = FileChannel.open(lockFile, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        try {
            FileLock lock = channel.tryLock();
            if (lock == null) {
                channel.close();
                throw new InstanceAlreadyRunningException(lockFile);
            }
            return new SingleInstanceLock(channel, lock);
        } catch (OverlappingFileLockException exception) {
            channel.close();
            throw new InstanceAlreadyRunningException(lockFile);
        } catch (IOException | RuntimeException exception) {
            channel.close();
            throw exception;
        }
    }

    @Override
    public void close() throws IOException {
        try {
            lock.release();
        } finally {
            channel.close();
        }
    }
}
