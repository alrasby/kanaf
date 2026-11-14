#include "../app/src/main/cpp/yara_scan_policy.h"

#include <cassert>
#include <cstdint>
#include <string>

int main() {
    static_assert(kanaf::kYaraTimeoutSeconds > 0 &&
                  kanaf::kYaraTimeoutSeconds < 90);
    kanaf::YaraMatchState empty;
    assert(kanaf::classifyYaraMatches(empty) == "NO_MATCH");

    constexpr uint8_t id[] = {'K', 'a', 'n', 'a', 'f', '_', 'E', 'I', 'C', 'A', 'R'};
    kanaf::YaraMatchState detected;
    kanaf::observeYaraMatch(detected, 0, id, sizeof(id));
    assert(kanaf::classifyYaraMatches(detected) == "DETECTED:Kanaf_EICAR");
    // Multiple callbacks preserve the first valid identifier.
    kanaf::observeYaraMatch(detected, 0, id, sizeof(id));
    assert(kanaf::classifyYaraMatches(detected) == "DETECTED:Kanaf_EICAR");

    kanaf::YaraMatchState invalidStatus;
    kanaf::observeYaraMatch(invalidStatus, 2, id, sizeof(id));
    assert(kanaf::classifyYaraMatches(invalidStatus) ==
           "INCOMPLETE:yara-rule-identifier-unavailable");

    kanaf::YaraMatchState nullName;
    kanaf::observeYaraMatch(nullName, 0, nullptr, sizeof(id));
    assert(kanaf::classifyYaraMatches(nullName).rfind("INCOMPLETE:", 0) == 0);

    kanaf::YaraMatchState emptyName;
    kanaf::observeYaraMatch(emptyName, 0, id, 0);
    assert(kanaf::classifyYaraMatches(emptyName).rfind("INCOMPLETE:", 0) == 0);

    kanaf::YaraMatchState oversizedName;
    kanaf::observeYaraMatch(oversizedName, 0, id, kanaf::kMaxRuleIdentifierBytes + 1);
    assert(kanaf::classifyYaraMatches(oversizedName).rfind("INCOMPLETE:", 0) == 0);

    constexpr uint8_t embeddedNul[] = {'B', 'A', 'D', 0, 'I', 'D'};
    kanaf::YaraMatchState nulName;
    kanaf::observeYaraMatch(nulName, 0, embeddedNul, sizeof(embeddedNul));
    assert(kanaf::classifyYaraMatches(nulName).rfind("INCOMPLETE:", 0) == 0);

    // Even if a different matching rule has a valid name, an invalid callback
    // must not be hidden behind a successful detection.
    kanaf::observeYaraMatch(detected, 1, id, sizeof(id));
    assert(kanaf::classifyYaraMatches(detected).rfind("INCOMPLETE:", 0) == 0);
    return 0;
}
