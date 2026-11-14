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
    FakeEngine ready;
    assert(kanaf::configureClamLimits(&ready, &setNumber));
    assert(ready.calls == 5);
    FakeEngine fails;
    fails.failAt = 3;
    assert(!kanaf::configureClamLimits(&fails, &setNumber));
    assert(fails.calls == 3);
    assert(!kanaf::configureClamLimits<FakeEngine>(nullptr, &setNumber));
    assert(!kanaf::configureClamLimits(&ready, nullptr));
    assert(kanaf::isIncompleteLimitAlert("Heuristics.Limits.Exceeded"));
    assert(kanaf::isIncompleteLimitAlert("Heuristics.Limits.Exceeded.MaxScanSize"));
    assert(!kanaf::isIncompleteLimitAlert(nullptr));
    assert(!kanaf::isIncompleteLimitAlert("Eicar-Test-Signature"));
    assert(!kanaf::isIncompleteLimitAlert("Heuristics.Limits.ExceededFake"));
    return 0;
}
