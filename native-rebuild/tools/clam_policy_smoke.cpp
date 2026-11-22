#include "../app/src/main/cpp/clam_scan_policy.h"

#include <cassert>
#include <cstring>

struct FakeEngine {
    int calls = 0;
    int failAt = -1;
};
static int setNumber(FakeEngine* engine, int, long long) {
    return (++engine->calls == engine->failAt) ? 1 : 0;
}

int main() {
    static_assert(kanaf::kClamLimits.size() == 5);
    static_assert(kanaf::kClamLimits[0].field == 0);
    static_assert(kanaf::kClamLimits[1].field == 1);
    static_assert(kanaf::kClamLimits[2].field == 2);
    static_assert(kanaf::kClamLimits[3].field == 3);
    static_assert(kanaf::kClamLimits[4].field == 31);
    static_assert(kanaf::kClamTmpDirField == 13);
    constexpr unsigned char zip[]{'P', 'K', 3, 4};
    constexpr unsigned char nonZip[]{'P', 'K', 3, 6};
    static_assert(kanaf::isZipHeader(zip));
    static_assert(!kanaf::isZipHeader(nonZip));
    static_assert(kanaf::officialScanBudgetMs(kanaf::MiB, false) == 20'000);
    static_assert(kanaf::officialScanBudgetMs(kanaf::MiB, true) == 55'000);
    static_assert(kanaf::officialScanBudgetMs(65 * kanaf::MiB, true) == 90'000);
    FakeEngine tmpEngine;
    auto setString = +[](FakeEngine* engine, int field, const char*) -> int {
        assert(field == 13);
        ++engine->calls;
        return 0;
    };
    assert(kanaf::configureClamTempDirectory(&tmpEngine, setString, "/data/user/0/cache"));
    assert(tmpEngine.calls == 1);
    assert(!kanaf::configureClamTempDirectory(&tmpEngine, setString, "relative/path"));
    assert(!kanaf::configureClamTempDirectory<FakeEngine>(nullptr, setString, "/data/cache"));
    assert(!kanaf::configureClamTempDirectory<FakeEngine>(&tmpEngine, nullptr, "/data/cache"));
    assert(!kanaf::configureClamTempDirectory(&tmpEngine, setString, nullptr));
    auto badString = +[](FakeEngine*, int, const char*) -> int { return -1; };
    assert(!kanaf::configureClamTempDirectory(&tmpEngine, badString, "/data/cache"));
    FakeEngine matcher;
    static_assert(kanaf::kClamAcOnlyField == 10);
    assert(kanaf::configureClamAcOnly(&matcher, &setNumber));
    assert(matcher.calls == 1);
    FakeEngine invalidMatcher;
    invalidMatcher.failAt = 1;
    assert(!kanaf::configureClamAcOnly(&invalidMatcher, &setNumber));
    assert(!kanaf::configureClamAcOnly<FakeEngine>(nullptr, &setNumber));
    assert(!kanaf::configureClamAcOnly<FakeEngine>(&matcher, nullptr));
    FakeEngine cache;
    static_assert(kanaf::kClamDisableCacheField == 25);
    assert(kanaf::disableClamCleanCache(&cache, &setNumber));
    assert(cache.calls == 1);
    FakeEngine invalidCache;
    invalidCache.failAt = 1;
    assert(!kanaf::disableClamCleanCache(&invalidCache, &setNumber));
    assert(!kanaf::disableClamCleanCache<FakeEngine>(nullptr, &setNumber));
    assert(!kanaf::disableClamCleanCache<FakeEngine>(&cache, nullptr));
    FakeEngine ready;
    assert(kanaf::configureClamLimits(&ready, &setNumber));
    assert(ready.calls == 5);
    FakeEngine fails;
    fails.failAt = 3;
    assert(!kanaf::configureClamLimits(&fails, &setNumber));
    assert(fails.calls == 3);
    assert(!kanaf::configureClamLimits<FakeEngine>(nullptr, &setNumber));
    assert(!kanaf::configureClamLimits<FakeEngine>(&ready, nullptr));
    assert(kanaf::isIncompleteLimitAlert("Heuristics.Limits.Exceeded"));
    assert(kanaf::isIncompleteLimitAlert("Heuristics.Limits.Exceeded.MaxScanSize"));
    assert(!kanaf::isIncompleteLimitAlert(nullptr));
    assert(!kanaf::isIncompleteLimitAlert("Eicar-Test-Signature"));
    assert(!kanaf::isIncompleteLimitAlert("Heuristics.Limits.ExceededFake"));
    assert(kanaf::isPinnedClamRuntime("1.4.6"));
    assert(!kanaf::isPinnedClamRuntime(nullptr));
    assert(!kanaf::isPinnedClamRuntime("1.4.3"));
    assert(!kanaf::isPinnedClamRuntime("1.4.6-patched"));
    assert(!kanaf::validClamThreatName(nullptr));
    assert(!kanaf::validClamThreatName(""));
    assert(kanaf::validClamThreatName("Kanaf.EICAR.Test.UNOFFICIAL"));
    assert(kanaf::validClamThreatName("Win.Trojan.Agent-3"));
    assert(!kanaf::validClamThreatName("Fake threat"));
    assert(!kanaf::validClamThreatName("newline\\ncontrol"));
    assert(!kanaf::validClamThreatName(std::string(129, 'X').c_str()));
    assert(kanaf::classifyClamScan(0, nullptr) == "NO_MATCH");
    assert(kanaf::classifyClamScan(0, "") == "NO_MATCH");
    assert(kanaf::classifyClamScan(0, "Fake.Rule") ==
        "INCOMPLETE:clamav-contradictory-result");
    assert(kanaf::classifyClamScan(1, "Kanaf.EICAR.Test.UNOFFICIAL") ==
        "DETECTED:Kanaf.EICAR.Test.UNOFFICIAL");
    assert(kanaf::classifyClamScan(1, nullptr) ==
        "INCOMPLETE:clamav-invalid-threat-name");
    assert(kanaf::classifyClamScan(1, "") ==
        "INCOMPLETE:clamav-invalid-threat-name");
    assert(kanaf::classifyClamScan(1, "Threat\\nInjected") ==
        "INCOMPLETE:clamav-invalid-threat-name");
    assert(kanaf::classifyClamScan(1, "Heuristics.Limits.Exceeded.MaxScanSize") ==
        "INCOMPLETE:clamav-resource-limit");
    assert(kanaf::classifyClamScan(13, "Fake.Rule") ==
        "INCOMPLETE:clamav-scan-failed");
    return 0;
}
