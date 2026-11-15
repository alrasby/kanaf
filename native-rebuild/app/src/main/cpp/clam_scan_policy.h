#pragma once

#include <array>
#include <cstddef>
#include <cstring>

// ClamAV 1.4.3 (clamav-1.4.3/libclamav/clamav.h) ABI ordinal values.
// Do NOT reuse with a different ClamAV version without rechecking the header.
namespace kanaf {
struct ClamLimit {
    int field;
    long long value;
};
inline constexpr long long MiB = 1024LL * 1024;
inline constexpr std::array<ClamLimit, 6> kClamLimits{{
    {0, 32 * MiB},  // CL_ENGINE_MAX_SCANSIZE: aggregate decompressed bytes
    {1, 16 * MiB},  // CL_ENGINE_MAX_FILESIZE: per contained file
    {2, 8},         // CL_ENGINE_MAX_RECURSION
    {3, 512},       // CL_ENGINE_MAX_FILES
    {31, 20000},    // CL_ENGINE_MAX_SCANTIME, milliseconds
    {25, 1},         // CL_ENGINE_DISABLE_CACHE (1.4.3): bypass MD5/cache early return
}};
static_assert(kClamLimits[0].value >= kClamLimits[1].value);
static_assert(kClamLimits[4].value > 0 && kClamLimits[4].value < 90000);
static_assert(kClamLimits[5].field == 25 && kClamLimits[5].value == 1);

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
} // namespace kanaf
