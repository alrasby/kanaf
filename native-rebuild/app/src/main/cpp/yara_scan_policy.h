#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

namespace kanaf {
// YARA-X 0.13.0 supports yrx_scanner_set_timeout(scanner, seconds).
// The Android subprocess watchdog remains a separate hard stop for blocked JNI.
inline constexpr uint64_t kYaraTimeoutSeconds = 20;
inline constexpr size_t kMaxRuleIdentifierBytes = 128;

struct YaraMatchState {
    std::string firstRuleName;
    bool observedMatch = false;
    bool invalidIdentifier = false;
};

// A callback occurred: an unreadable identifier can never be treated as NO_MATCH.
// The rule identifier from the YARA-X C API is valid only during the callback.
inline void observeYaraMatch(YaraMatchState& state, int status,
                            const uint8_t* identifier, size_t length) {
    state.observedMatch = true;
    if (status != 0 || !identifier || length == 0 ||
        length > kMaxRuleIdentifierBytes ||
        std::memchr(identifier, '\0', length) != nullptr) {
        state.invalidIdentifier = true;
        return;
    }
    if (state.firstRuleName.empty()) {
        state.firstRuleName.assign(reinterpret_cast<const char*>(identifier), length);
    }
}

inline std::string classifyYaraMatches(const YaraMatchState& state) {
    if (state.invalidIdentifier ||
        (state.observedMatch && state.firstRuleName.empty())) {
        return "INCOMPLETE:yara-rule-identifier-unavailable";
    }
    if (state.observedMatch) return "DETECTED:" + state.firstRuleName;
    return "NO_MATCH";
}
}  // namespace kanaf
