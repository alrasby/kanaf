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

// Diagnostic mode is only invoked on the app-generated harmless EICAR fixture.
// Production scans still use the previously pinned configuration and fail closed.
std::string clamScan(const char* file, const char* database, bool useDefaultMatcher = false, bool exactFileOnly = false) {
    if (!file || !database) return incomplete("missing-path");
    void* lib = dlopen("libclamav.so", RTLD_NOW | RTLD_LOCAL);
    if (!lib) return incomplete("clamav-load-failed");

    auto getVersion = symbol<const char* (*)()>(lib, "cl_retver");
    // The ClamAV function-pointer ABI, scan flags and field ordinals below
    // are pinned to 1.4.6. Refuse another runtime even if its .so loads.
    if (!getVersion || !kanaf::isPinnedClamRuntime(getVersion())) {
        dlclose(lib);
        return incomplete("clamav-version-mismatch");
    }
    auto init = symbol<int (*)(unsigned int)>(lib, "cl_init");
    auto create = symbol<ClEngine* (*)()>(lib, "cl_engine_new");
    auto freeEngine = symbol<int (*)(ClEngine*)>(lib, "cl_engine_free");
    auto load = symbol<int (*)(const char*, ClEngine*, unsigned int*, unsigned int)>(lib, "cl_load");
    auto compile = symbol<int (*)(ClEngine*)>(lib, "cl_engine_compile");
    auto setNum = symbol<int (*)(ClEngine*, int, long long)>(lib, "cl_engine_set_num");
    auto setString = symbol<int (*)(ClEngine*, int, const char*)>(
        lib, "cl_engine_set_str");
    auto scan = symbol<int (*)(const char*, const char**, unsigned long*, const ClEngine*, ClScanOptions*)>(lib, "cl_scanfile");
    if (!init || !create || !freeEngine || !load || !compile ||
        !setNum || !setString || !scan) {
        dlclose(lib);
        return incomplete("clamav-api-unavailable");
    }
    std::string answer = incomplete("clamav-init-failed");
    ClEngine* engine = nullptr;
    if (init(0) == 0 && (engine = create()) != nullptr) {
        // The bundled .ndb is staged in the app-private cache directory.
        // Use that existing directory for ClamAV temporary extraction rather
        // than Android's potentially absent or inaccessible global /tmp.
        const std::string databasePath(database);
        const auto slash = databasePath.find_last_of('/');
        const std::string privateTemp = slash == std::string::npos ?
            std::string() : databasePath.substr(0, slash);
        struct stat tempInfo {};
        if (privateTemp.empty() ||
            lstat(privateTemp.c_str(), &tempInfo) != 0 ||
            !S_ISDIR(tempInfo.st_mode) ||
            access(privateTemp.c_str(), W_OK | X_OK) != 0 ||
            !kanaf::configureClamTempDirectory(
                engine, setString, privateTemp.c_str())) {
            freeEngine(engine);
            dlclose(lib);
            return incomplete("clamav-private-tempdir-unavailable");
        }
        // Use supported Aho–Corasick path for the tiny prototype signature
        // database. This must happen before cl_load initializes root matchers.
        // Reject scans if matcher configuration fails; do not pretend clean.
        if (!useDefaultMatcher &&
            (!kanaf::configureClamAcOnly(engine, setNum) ||
                !kanaf::disableClamCleanCache(engine, setNum))) {
            freeEngine(engine);
            dlclose(lib);
            return incomplete("clamav-matcher-or-cache-config-failed");
        }
        unsigned int count = 0;
        int loading = load(database, engine, &count, 0);
#ifndef NDEBUG
        // Diagnostic counters only. Never log any user-selected path or file bytes.
        __android_log_print(ANDROID_LOG_INFO, "KanafClamNative",
            "ClamAV database load result=%d signatures=%u", loading, count);
#endif
        if (loading != 0 || count == 0) {
            answer = incomplete("clamav-rules-load-failed");
        } else if (!kanaf::configureClamLimits(engine, setNum) ||
                   (exactFileOnly && (setNum(engine, 0, 256 * kanaf::MiB) != 0 ||
                                      setNum(engine, 1, 256 * kanaf::MiB) != 0))) {
            answer = incomplete("clamav-limits-unavailable");
        } else if (compile(engine) != 0) {
            answer = incomplete("clamav-compile-failed");
        } else {
            const char* name = nullptr;
            unsigned long scanned = 0;
            ClScanOptions options{};
            // ClamAV 1.4.6 parsers: archive, ELF, PDF, HTML, PE.
            // Alert on engine resource limit exhaustion; never label it malware or clean.
            if (!exactFileOnly) {
                options.parse = 0x1 | 0x2 | 0x4 | 0x100 | 0x200;
                options.general = 0x4;   // CL_SCAN_GENERAL_HEURISTICS
                options.heuristic = 0x4; // CL_SCAN_HEURISTIC_EXCEEDS_MAX
            }
            int verdict = scan(file, &name, &scanned, engine, &options);
#ifndef NDEBUG
            __android_log_print(ANDROID_LOG_INFO, "KanafClamNative",
                "ClamAV scan code=%d scannedUnits=%lu", verdict, scanned);
            // A diagnostic on the harmless built-in EICAR vector only.
            // ClamAV 1.4.6's cli_magic_scan has a direct raw-pattern path
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
                auto fixture = kanaf::readStableFile(file, 64U * 1024U * 1024U);
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
            answer = kanaf::classifyClamScan(verdict, name);
        }
        freeEngine(engine);
    }
    dlclose(lib);
    return answer;
}

// The scanner Service serializes requests. Retain the compiled official database
// for that process lifetime so an inventory scan does not compile it per file.
class OfficialClamEngine {
public:
    ~OfficialClamEngine() {
        if (engine_) release_(engine_);
        if (library_) dlclose(library_);
    }

    std::string scan(const char* file, const char* directory, const char* temp) {
        if (!file || !directory || !temp) return incomplete("clamav-official-missing-path");
        if (!initialized_) {
            initialized_ = true;
            error_ = initialize(directory, temp);
        }
        if (error_) return incomplete(error_);
        const char* name = nullptr;
        unsigned long scanned = 0;
        ClScanOptions options{};
        options.parse = 0x1fff;  // All standard 1.4.6 parsers.
        options.general = 0x4;
        options.heuristic = 0x4;
        const int status = scan_(file, &name, &scanned, engine_, &options);
        if (status == 1 && kanaf::isIncompleteLimitAlert(name)) {
            constexpr const char* prefix = "Heuristics.Limits.Exceeded.";
            if (std::strncmp(name, prefix, std::strlen(prefix)) == 0) {
                const char* limit = name + std::strlen(prefix);
                if (std::strcmp(limit, "MaxScanTime") == 0) return incomplete("clamav-scan-time-limit");
                if (std::strcmp(limit, "MaxFiles") == 0) return incomplete("clamav-archive-entry-limit");
                if (std::strcmp(limit, "MaxRecursion") == 0) return incomplete("clamav-archive-depth-limit");
                if (std::strcmp(limit, "MaxScanSize") == 0 || std::strcmp(limit, "MaxFileSize") == 0)
                    return incomplete("clamav-expanded-size-limit");
            }
        }
        return kanaf::classifyClamScan(status, name);
    }

private:
    const char* initialize(const char* directory, const char* temp) {
        library_ = dlopen("libclamav.so", RTLD_NOW | RTLD_LOCAL);
        if (!library_) return "clamav-official-library-unavailable";
        auto version = symbol<const char* (*)()>(library_, "cl_retver");
        if (!version || !kanaf::isPinnedClamRuntime(version())) return "clamav-version-mismatch";
        auto init = symbol<int (*)(unsigned int)>(library_, "cl_init");
        auto create = symbol<ClEngine* (*)()>(library_, "cl_engine_new");
        auto verify = symbol<int (*)(const char*)>(library_, "cl_cvdverify");
        auto load = symbol<int (*)(const char*, ClEngine*, unsigned int*, unsigned int)>(
            library_, "cl_load");
        auto compile = symbol<int (*)(ClEngine*)>(library_, "cl_engine_compile");
        auto configure = symbol<int (*)(ClEngine*, int, long long)>(library_, "cl_engine_set_num");
        auto configureString = symbol<int (*)(ClEngine*, int, const char*)>(
            library_, "cl_engine_set_str");
        release_ = symbol<int (*)(ClEngine*)>(library_, "cl_engine_free");
        scan_ = symbol<Scan>(library_, "cl_scanfile");
        if (!init || !create || !verify || !load || !compile || !configure ||
            !configureString || !release_ || !scan_) return "clamav-official-api-unavailable";
        if (init(0) != 0 || !(engine_ = create())) return "clamav-official-init-failed";
        const char* failure = loadRules(directory, temp, verify, load, compile,
            configure, configureString);
        if (failure) {
            release_(engine_);
            engine_ = nullptr;
        }
        return failure;
    }

    const char* loadRules(const char* directory, const char* temp,
        int (*verify)(const char*), int (*load)(const char*, ClEngine*, unsigned int*, unsigned int),
        int (*compile)(ClEngine*), int (*configure)(ClEngine*, int, long long),
        int (*configureString)(ClEngine*, int, const char*)) {
        if (!kanaf::configureClamTempDirectory(engine_, configureString, temp) ||
            !kanaf::configureClamLimits(engine_, configure) ||
            !kanaf::disableClamCleanCache(engine_, configure) ||
            configure(engine_, 0, 384 * kanaf::MiB) != 0 ||
            configure(engine_, 1, 256 * kanaf::MiB) != 0 ||
            configure(engine_, 3, 2048) != 0) return "clamav-official-limits-unavailable";

        // CL_DB_STDOPT | CL_DB_OFFICIAL_ONLY. Never enable unsigned bytecode.
        constexpr unsigned int flags = 0x200a | 0x1000;
        unsigned int count = 0;
        for (const char* name : {"main.cvd", "daily.cvd", "bytecode.cvd"}) {
            std::string path = std::string(directory) + "/" + name;
            if (verify(path.c_str()) != 0) return "clamav-official-cvd-signature-invalid";
        }
        // Directory loading preserves ClamAV's normal database ordering.
        if (load(directory, engine_, &count, flags) != 0 || count == 0)
            return "clamav-official-database-load-failed";
        if (compile(engine_) != 0) return "clamav-official-database-compile-failed";
        __android_log_print(ANDROID_LOG_INFO, "KanafScanner", "Official ClamAV signatures=%u", count);
        return nullptr;
    }

    using Scan = int (*)(const char*, const char**, unsigned long*, const ClEngine*, ClScanOptions*);
    void* library_ = nullptr;
    ClEngine* engine_ = nullptr;
    int (*release_)(ClEngine*) = nullptr;
    Scan scan_ = nullptr;
    bool initialized_ = false;
    const char* error_ = nullptr;
};

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
    auto snapshot = kanaf::readStableFile(file, 64U * 1024U * 1024U);
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
    JNIEnv* env, jobject, jstring filePath, jstring databasePath, jboolean exactFileOnly) {
    UtfChars file(env, filePath);
    UtfChars database(env, databasePath);
    return result(env, clamScan(file.get(), database.get(), false, exactFileOnly));
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_kanaf_alrasby_engine_NativeScannerBridge_clamOfficialScanNative(
    JNIEnv* env, jobject, jstring filePath, jstring databasePath, jstring temporaryDirectory) {
    UtfChars file(env, filePath);
    UtfChars database(env, databasePath);
    UtfChars temp(env, temporaryDirectory);
    static OfficialClamEngine official;
    return result(env, official.scan(file.get(), database.get(), temp.get()));
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_kanaf_alrasby_engine_NativeScannerBridge_yaraScanNative(
    JNIEnv* env, jobject, jstring filePath, jstring ruleSource) {
    UtfChars file(env, filePath);
    UtfChars rules(env, ruleSource);
    return result(env, yaraScan(file.get(), rules.get()));
}

/**
 * Debug-only EICAR comparison. Caller enforces FLAG_DEBUGGABLE and always ignores
 * this result for antivirus readiness. It does NOT disable or replace self-tests.
 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_kanaf_alrasby_engine_NativeScannerBridge_clamDefaultMatcherDiagnosticNative(
    JNIEnv* env, jobject, jstring filePath, jstring databasePath) {
    UtfChars file(env, filePath);
    UtfChars database(env, databasePath);
    return result(env, clamScan(file.get(), database.get(), true));
}
