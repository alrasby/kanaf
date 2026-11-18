#include "../app/src/main/cpp/file_snapshot.h"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int main() {
    using namespace kanaf;
    char path[] = "/tmp/kanaf-native-snapshot-XXXXXX";
    const int fd = mkstemp(path);
    assert(fd >= 0);
    constexpr char data[] = "safe-test-bytes";
    assert(write(fd, data, sizeof(data) - 1) == sizeof(data) - 1);
    auto good = readStableFile(path, 1024);
    assert(good.status == SnapshotStatus::Complete);
    assert(good.bytes.size() == sizeof(data) - 1);
    assert(std::memcmp(good.bytes.data(), data, sizeof(data) - 1) == 0);
    assert(readStableFile(path, 1).status == SnapshotStatus::TooLarge);
    assert(readStableFile(nullptr, 100).status == SnapshotStatus::InvalidFile);
    assert(readStableFile(path, 0).status == SnapshotStatus::InvalidFile);
    assert(readStableFile("/tmp/kanaf-nonexistent-12345", 100).status ==
           SnapshotStatus::Unreadable);
    assert(readStableFile("/tmp", 100).status == SnapshotStatus::InvalidFile);

    char symlinkName[sizeof(path) + 8];
    std::snprintf(symlinkName, sizeof(symlinkName), "%s-link", path);
    assert(symlink(path, symlinkName) == 0);
    assert(readStableFile(symlinkName, 100).status == SnapshotStatus::Unreadable);
    unlink(symlinkName);

    char fifoName[sizeof(path) + 8];
    std::snprintf(fifoName, sizeof(fifoName), "%s-fifo", path);
    assert(mkfifo(fifoName, 0600) == 0);
    assert(readStableFile(fifoName, 100).status == SnapshotStatus::InvalidFile);
    unlink(fifoName);

    struct stat before{}, after{};
    assert(fstat(fd, &before) == 0);
    assert(write(fd, "z", 1) == 1);
    assert(fstat(fd, &after) == 0);
    assert(!sameFileSnapshot(before, after));
    assert(readStableFile(path, 1024).status == SnapshotStatus::Complete);

    assert(ftruncate(fd, 0) == 0);
    const auto empty = readStableFile(path, 1024);
    assert(empty.status == SnapshotStatus::Complete && empty.bytes.empty());

    assert(std::strcmp(snapshotFailureReason(SnapshotStatus::Changed), "yara-file-changed") == 0);
    constexpr size_t largeSize = 20U * 1024U * 1024U;
    assert(ftruncate(fd, largeSize) == 0);
    const auto large = readStableFile(path, 64U * 1024U * 1024U);
    assert(large.status == SnapshotStatus::Complete && large.bytes.size() == largeSize);
    assert(readStableFile(path, 16U * 1024U * 1024U).status == SnapshotStatus::TooLarge);
    close(fd);
    unlink(path);
    return 0;
}
