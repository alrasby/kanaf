#include <jni.h>
#include <android/log.h>
#include "clam_scan_policy.h"
#include "yara_scan_policy.h"
#include "file_snapshot.h"
#include <dlfcn.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string>
#include <vector>

namespace {
struct ClEngine;
struct ClScanOptions {
    uint32_t general;
    uint32_t parse;
    uint32_t heuristic;
    uint32_t mail;
    uint32_t dev;
};
static_assert(sizeof(ClScanOptions) == 20, "ClamAV 1.4 scan options ABI");

template <typename T> T symbol(void* library, const char* name) {
    return reinterpret_cast<T>(dlsym(library, name));
}
std::string incomplete(const char* why) { return std::string("INCOMPLETE:") + why; }
jstring result(JNIEnv* env, const std::string& value) { return env->NewStringUTF(value.c_str()); }

class UtfChars {
public:
    UtfChars(JNIEnv* env, jstring value) : env_(env), value_(value),
        chars_(value ? env->GetStringUTFChars(value, nullptr) : nullptr) {}
    ~UtfChars() { if (chars_) env_->ReleaseStringUTFChars(value_, chars_); }
    const char* get() const { return chars_; }
private:
    JNIEnv* env_;
    jstring value_;
    const char* chars_;
};

std::string clamScan(const char* file, const char* database) {
    if (!file || !database) return incomplete("missing-path");
    void* lib = dlopen("libclamav.so", RTLD_NOW | RTLD_LOCAL);
    if (!lib) return incomplete("clamav-load-failed");

    auto init = symbol<int (*)(unsigned int)>(lib, "cl_init");
    auto create = symbol<ClEngine* (*)()>(lib, "cl_engine_new");
    auto freeEngine = symbol<int (*)(ClEngine*)>(lib, "cl_engine_free");
    auto load = symbol<int (*)(const char*, ClEngine*, unsigned int*, unsigned int)>(lib, "cl_load");
    auto compile = symbol<int (*)(ClEngine*)>(lib, "cl_engine_compile");
    auto setNum = symbol<int (*)(ClEngine*, int, long long)>(lib, "cl_engine_set_num");
    auto scan = symbol<int (*)(const char*, const char**, unsigned long*, const ClEngine*, ClScanOptions*)>(lib, "cl_scanfile");
    if (!init || !create || !freeEngine || !load || !compile || !setNum || !scan) {
        dlclose(lib);
        return incomplete("clamav-api-unavailable");
    }
    std::string answer = incomplete("clamav-init-failed");
    ClEngine* engine = nullptr;
    if (init(0) == 0 && (engine = create()) != nullptr) {
        unsigned int count = 0;
        int loading = load(database, engine, &count, 0);
#ifndef NDEBUG
        // Diagnostic counters only. Never log any user-selected path or file bytes.
        __android_log_print(ANDROID_LOG_INFO, "KanafClamNative",
            "ClamAV database load result=%d signatures=%u", loading, count);
#endif
        if (loading != 0 || count == 0) {
            answer = incomplete("clamav-rules-load-failed");
        } else if (!kanaf::configureClamLimits(engine, setNum)) {
            answer = incomplete("clamav-limits-unavailable");
        } else if (compile(engine) != 0) {
            answer = incomplete("clamav-compile-failed");
        } else {
            const char* name = nullptr;
            unsigned long scanned = 0;
            ClScanOptions options{};
            // ClamAV 1.4.3 parsers: archive, ELF, PDF, HTML, PE.
            // Alert on engine resource limit exhaustion; never label it malware or clean.
            options.parse = 0x1 | 0x2 | 0x4 | 0x100 | 0x200;
            options.general = 0x4;   // CL_SCAN_GENERAL_HEURISTICS
            options.heuristic = 0x4; // CL_SCAN_HEURISTIC_EXCEEDS_MAX
            int verdict = scan(file, &name, &scanned, engine, &options);
#ifndef NDEBUG
            __android_log_print(ANDROID_LOG_INFO, "KanafClamNative",
                "ClamAV scan code=%d scannedUnits=%lu", verdict, scanned);
            // A diagnostic on the harmless built-in EICAR vector only.
            // ClamAV 1.4.3's cli_magic_scan has a direct raw-pattern path
            // when no parse or heuristic options are enabled. Check whether
            // the options, rather than the database, suppress matching.
            // This result is NEVER returned as the verdict or a readiness gate.
            if (verdict == 0 && file &&
                std::strstr(file, "/kanaf-eicar-") != nullptr) {
                // ClamAV's raw matcher invokes MD5/SHA-1/SHA-256 through
                // OpenSSL. Missing digest providers can suppress matching.
                // Probe only the app-generated harmless EICAR vector; never
                // log user content or treat this as a scan verdict.
                auto hashInit = symbol<void* (*)(const char*)>(lib, "cl_hash_init");
                auto hashDestroy = symbol<void (*)(void*)>(lib, "cl_hash_destroy");
                if (hashInit && hashDestroy) {
                    for (const char* algorithm : {"md5", "sha1", "sha256"}) {
                        void* hashContext = hashInit(algorithm);
                        __android_log_print(ANDROID_LOG_INFO, "KanafClamNative",
                            "Built-in EICAR crypto %s available=%d",
                            algorithm, hashContext != nullptr ? 1 : 0);
                        if (hashContext) hashDestroy(hashContext);
                    }
                } else {
                    __android_log_print(ANDROID_LOG_INFO, "KanafClamNative",
                        "Built-in EICAR crypto APIs unavailable");
                }
                ClScanOptions rawOptions{};
                const char* rawName = nullptr;
                unsigned long rawScanned = 0;
                const int rawCode = scan(file, &rawName, &rawScanned, engine, &rawOptions);
                __android_log_print(ANDROID_LOG_INFO, "KanafClamNative",
                    "Built-in EICAR raw-only scan code=%d scannedUnits=%lu named=%d",
                    rawCode, rawScanned, rawName != nullptr ? 1 : 0);
                // Compare the same harmless fixture in memory to isolate
                // Android file-mapping/descriptor behavior from signature matching.
                // Never use this diagnostic result for any security verdict.
                auto fixture = kanaf::readStableFile(file, 16U * 1024U * 1024U);
                auto openMemory = symbol<void* (*)(const void*, size_t)>(
                    lib, "cl_fmap_open_memory");
                auto closeMemory = symbol<void (*)(void*)>(lib, "cl_fmap_close");
                auto scanMemory = symbol<int (*)(void*, const char*, const char**,
                    unsigned long*, const ClEngine*, ClScanOptions*, void*)>(
                    lib, "cl_scanmap_callback");
                if (fixture.status == kanaf::SnapshotStatus::Complete &&
                    !fixture.bytes.empty() && openMemory && closeMemory && scanMemory) {
                    void* map = openMemory(fixture.bytes.data(), fixture.bytes.size());
                    if (map) {
                        const char* mappedName = nullptr;
                        unsigned long mappedScanned = 0;
                        ClScanOptions noOptions{};
                        int memoryCode = scanMemory(map, nullptr, &mappedName,
                            &mappedScanned, engine, &noOptions, nullptr);
                        __android_log_print(ANDROID_LOG_INFO, "KanafClamNative",
                            "Built-in EICAR memory scan code=%d scannedUnits=%lu named=%d",
                            memoryCode, mappedScanned, mappedName != nullptr ? 1 : 0);
                        closeMemory(map);
                    } else {
                        __android_log_print(ANDROID_LOG_INFO, "KanafClamNative",
                            "Built-in EICAR memory map unavailable");
                    }
                } else {
                    __android_log_print(ANDROID_LOG_INFO, "KanafClamNative",
                        "Built-in EICAR memory scan API unavailable");
                }
            }
#endif
            if (verdict == 1 && kanaf::isIncompleteLimitAlert(name)) {
                answer = incomplete("clamav-resource-limit");
            } else if (verdict == 1) {
                answer = std::string("DETECTED:") + (name ? name : "ClamAV.Rule");
            } else if (verdict == 0) {
                answer = "NO_MATCH";
            }
            else answer = incomplete("clamav-scan-failed");
        }
        freeEngine(engine);
    }
    dlclose(lib);
    return answer;
}

struct YaraMatch {
    kanaf::YaraMatchState state;
    int (*identifier)(const void*, const uint8_t**, size_t*);
};
void onYaraMatch(const void* rule, void* userData) {
    auto* ctx = static_cast<YaraMatch*>(userData);
    if (!ctx) return;
    const uint8_t* name = nullptr;
    size_t length = 0;
    const int status = ctx->identifier ? ctx->identifier(rule, &name, &length) : -1;
    kanaf::observeYaraMatch(ctx->state, status, name, length);
}

std::string yaraScan(const char* file, const char* rulesSource) {
    if (!file || !rulesSource || !*rulesSource) return incomplete("missing-rules");
    // Always scan a complete, stable file snapshot. A growing, truncated,
    // substituted or non-regular file must never yield NO_MATCH.
    auto snapshot = kanaf::readStableFile(file, 16U * 1024U * 1024U);
    if (snapshot.status != kanaf::SnapshotStatus::Complete) {
        return incomplete(kanaf::snapshotFailureReason(snapshot.status));
    }
    const auto& bytes = snapshot.bytes;
    void* lib = dlopen("libyara_x_capi.so", RTLD_NOW | RTLD_LOCAL);
    if (!lib) return incomplete("yara-load-failed");
    auto compile = symbol<int (*)(const char*, void**)>(lib, "yrx_compile");
    auto destroyRules = symbol<void (*)(void*)>(lib, "yrx_rules_destroy");
    auto createScanner = symbol<int (*)(const void*, void**)>(lib, "yrx_scanner_create");
    auto destroyScanner = symbol<void (*)(void*)>(lib, "yrx_scanner_destroy");
    auto onMatch = symbol<int (*)(void*, void (*)(const void*, void*), void*)>(lib, "yrx_scanner_on_matching_rule");
    auto scan = symbol<int (*)(void*, const uint8_t*, size_t)>(lib, "yrx_scanner_scan");
    auto identifier = symbol<int (*)(const void*, const uint8_t**, size_t*)>(lib, "yrx_rule_identifier");
    auto setTimeout = symbol<int (*)(void*, uint64_t)>(lib, "yrx_scanner_set_timeout");
    if (!compile || !destroyRules || !createScanner || !destroyScanner || !onMatch || !scan || !identifier || !setTimeout) {
        dlclose(lib);
        return incomplete("yara-api-unavailable");
    }
    std::string answer = incomplete("yara-compile-failed");
    void* rules = nullptr;
    if (compile(rulesSource, &rules) == 0 && rules) {
        void* scanner = nullptr;
        if (createScanner(rules, &scanner) == 0 && scanner) {
            YaraMatch match{{}, identifier};
            // YARA-X 0.13.0 supplies a cooperative timeout in seconds.
            // The scanner process watchdog still handles a hung native parser.
            if (setTimeout(scanner, kanaf::kYaraTimeoutSeconds) != 0) {
                answer = incomplete("yara-timeout-unavailable");
            } else if (onMatch(scanner, onYaraMatch, &match) != 0) {
                answer = incomplete("yara-callback-failed");
            } else if (scan(scanner, bytes.empty() ? reinterpret_cast<const uint8_t*>("") : bytes.data(), bytes.size()) != 0) {
                answer = incomplete("yara-scan-failed-or-timeout");
            } else {
                answer = kanaf::classifyYaraMatches(match.state);
            }
            destroyScanner(scanner);
        } else {
            answer = incomplete("yara-scanner-failed");
        }
        destroyRules(rules);
    }
    dlclose(lib);
    return answer;
}
}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_kanaf_alrasby_engine_NativeScannerBridge_clamScanNative(
    JNIEnv* env, jobject, jstring filePath, jstring databasePath) {
    UtfChars file(env, filePath);
    UtfChars database(env, databasePath);
    return result(env, clamScan(file.get(), database.get()));
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_kanaf_alrasby_engine_NativeScannerBridge_yaraScanNative(
    JNIEnv* env, jobject, jstring filePath, jstring ruleSource) {
    UtfChars file(env, filePath);
    UtfChars rules(env, ruleSource);
    return result(env, yaraScan(file.get(), rules.get()));
}
