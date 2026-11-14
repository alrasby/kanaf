#pragma once
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace kanaf {

enum class SnapshotStatus { Complete, Unreadable, InvalidFile, TooLarge, Changed };

struct FileSnapshot {
    SnapshotStatus status = SnapshotStatus::Unreadable;
    std::vector<uint8_t> bytes;
};

/** Compare metadata across one fd, not two path lookups (defends against truncation
 * or rewriting during reads). The bytes are read into a bounded private buffer. */
inline bool sameFileSnapshot(const struct stat& before, const struct stat& after) {
    return before.st_dev == after.st_dev &&
           before.st_ino == after.st_ino &&
           before.st_size == after.st_size &&
           before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
           before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
           before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
           before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
}

inline FileSnapshot readStableFile(const char* path, size_t maximumBytes) {
    if (!path || !*path || maximumBytes == 0) {
        return {SnapshotStatus::InvalidFile, {}};
    }
    // Avoid symlinks and never block on a FIFO masquerading as a file.
    const int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return {SnapshotStatus::Unreadable, {}};

    struct stat before{};
    if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) || before.st_size < 0) {
        close(fd);
        return {SnapshotStatus::InvalidFile, {}};
    }
    if (static_cast<uint64_t>(before.st_size) > maximumBytes) {
        close(fd);
        return {SnapshotStatus::TooLarge, {}};
    }
    FileSnapshot snapshot{SnapshotStatus::Unreadable, {}};
    snapshot.bytes.resize(static_cast<size_t>(before.st_size));
    size_t offset = 0;
    while (offset < snapshot.bytes.size()) {
        const ssize_t count = read(fd, snapshot.bytes.data() + offset, snapshot.bytes.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            close(fd);
            return {SnapshotStatus::Changed, {}};
        }
        offset += static_cast<size_t>(count);
    }

    // A file which was appended after fstat must NOT be reported as fully scanned.
    uint8_t trailingByte = 0;
    ssize_t trailing;
    do {
        trailing = read(fd, &trailingByte, 1);
    } while (trailing < 0 && errno == EINTR);

    struct stat after{};
    const bool stable = trailing == 0 && fstat(fd, &after) == 0 &&
                        sameFileSnapshot(before, after);
    close(fd);
    if (!stable) return {SnapshotStatus::Changed, {}};
    snapshot.status = SnapshotStatus::Complete;
    return snapshot;
}

inline const char* snapshotFailureReason(SnapshotStatus status) {
    switch (status) {
        case SnapshotStatus::TooLarge: return "yara-file-too-large";
        case SnapshotStatus::Changed: return "yara-file-changed";
        case SnapshotStatus::InvalidFile: return "yara-file-invalid";
        case SnapshotStatus::Unreadable: return "yara-file-unreadable";
        case SnapshotStatus::Complete: return "";
    }
    return "yara-file-invalid";
}
} // namespace kanaf
