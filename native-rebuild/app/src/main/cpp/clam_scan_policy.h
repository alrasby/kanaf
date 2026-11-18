#pragma once

#include <array>
#include <cstddef>
#include <cstring>
#include <string>

// ClamAV 1.4.6 (clamav-1.4.6/libclamav/clamav.h) ABI ordinal values.
// Do NOT reuse with a different ClamAV version without rechecking the header.
namespace kanaf {
// Only the exact audited libclamav C ABI may be called via dlsym.
inline bool isPinnedClamRuntime(const char* version) {
    return version != nullptr && std::strcmp(version, "1.4.6") == 0;
}

// Treat unnamed, malformed or oversized native detections as incomplete.
// The worker must never invent a generic threat identifier.
inline bool validClamThreatName(const char* name) {
    if (!name) return false;
    std::size_t length = 0;
    for (; length < 128 && name[length] != '\0'; ++length) {
        const unsigned char c = static_cast<unsigned char>(name[length]);
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' ||
              c == ':' || c == '+' || c == '-')) return false;
    }
    return length > 0 && length <= 128 && name[length] == '\0';
}

// ClamAV 1.4.6: CL_ENGINE_AC_ONLY=10. Configure before cl_load because
// cli_initroots builds the matcher while the database is being loaded.
inline constexpr int kClamAcOnlyField = 10;
// Verified against the pinned ClamAV 1.4.6 clamav.h enum.
inline constexpr int kClamTmpDirField = 13;

/** Force a caller-owned writable temporary directory before cl_load/compile.
 * On Android, a default /tmp may not exist or be accessible. */
template <typename Engine>
bool configureClamTempDirectory(
    Engine* engine, int (*setString)(Engine*, int, const char*), const char* directory) {
    return engine && setString && directory && directory[0] == '/' &&
        directory[1] != '\0' && setString(engine, kClamTmpDirField, directory) == 0;
}

inline constexpr int kClamDisableCacheField = 25;
// A fresh engine on each scan does not need the internal clean-cache. Keep it
// disabled to rule out stale or ARM64-translator cache false negatives.
template <typename Engine>
bool disableClamCleanCache(Engine* engine, int (*setNum)(Engine*, int, long long)) {
    return engine && setNum && setNum(engine, kClamDisableCacheField, 1) == 0;
}
template <typename Engine>
bool configureClamAcOnly(Engine* engine, int (*setNum)(Engine*, int, long long)) {
    return engine && setNum && setNum(engine, kClamAcOnlyField, 1) == 0;
}
struct ClamLimit {
    int field;
    long long value;
};
inline constexpr long long MiB = 1024LL * 1024;
inline constexpr std::array<ClamLimit, 5> kClamLimits{{
    {0, 128 * MiB},  // CL_ENGINE_MAX_SCANSIZE: aggregate decompressed bytes
    {1, 64 * MiB},  // CL_ENGINE_MAX_FILESIZE: per contained file
    {2, 8},         // CL_ENGINE_MAX_RECURSION
    {3, 512},       // CL_ENGINE_MAX_FILES
    {31, 20000},    // CL_ENGINE_MAX_SCANTIME, milliseconds
}};
static_assert(kClamLimits[0].value >= kClamLimits[1].value);
static_assert(kClamLimits[4].value > 0 && kClamLimits[4].value < 90000);

template <typename Engine>
bool configureClamLimits(Engine* engine, int (*setNum)(Engine*, int, long long)) {
    if (!engine || !setNum) return false;
    for (const auto& limit : kClamLimits) {
        if (setNum(engine, limit.field, limit.value) != 0) return false;
    }
    return true;
}

/** The libclamav "limit exceeded" heuristic means NOT FULLY SCANNED, not malware. */
inline bool isIncompleteLimitAlert(const char* name) {
    if (!name) return false;
    constexpr char kLimitName[] = "Heuristics.Limits.Exceeded";
    constexpr size_t len = sizeof(kLimitName) - 1;
    return std::strncmp(name, kLimitName, len) == 0 &&
           (name[len] == '\0' || name[len] == '.');
}
// ClamAV 1.4.6: CL_CLEAN=0 and CL_VIRUS=1. Other codes are errors.
inline std::string classifyClamScan(int code, const char* name) {
    if (code == 0) {
        // A contradictory name on CL_CLEAN cannot be trusted.
        return name && name[0] != '\0' ? "INCOMPLETE:clamav-contradictory-result" : "NO_MATCH";
    }
    if (code != 1) return "INCOMPLETE:clamav-scan-failed";
    if (isIncompleteLimitAlert(name)) return "INCOMPLETE:clamav-resource-limit";
    if (!validClamThreatName(name)) return "INCOMPLETE:clamav-invalid-threat-name";
    return std::string("DETECTED:") + name;
}
} // namespace kanaf
