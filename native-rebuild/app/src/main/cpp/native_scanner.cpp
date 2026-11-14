#include <jni.h>
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
    auto freeEngine = symbol<void (*)(ClEngine*)>(lib, "cl_engine_free");
    auto load = symbol<int (*)(const char*, ClEngine*, unsigned int*, unsigned int)>(lib, "cl_load");
    auto compile = symbol<int (*)(ClEngine*)>(lib, "cl_engine_compile");
    auto scan = symbol<int (*)(const char*, const char**, unsigned long*, const ClEngine*, ClScanOptions*)>(lib, "cl_scanfile");
    if (!init || !create || !freeEngine || !load || !compile || !scan) {
        dlclose(lib);
        return incomplete("clamav-api-unavailable");
    }
    std::string answer = incomplete("clamav-init-failed");
    ClEngine* engine = nullptr;
    if (init(0) == 0 && (engine = create()) != nullptr) {
        unsigned int count = 0;
        int loading = load(database, engine, &count, 0);
        if (loading != 0 || count == 0) {
            answer = incomplete("clamav-rules-load-failed");
        } else if (compile(engine) != 0) {
            answer = incomplete("clamav-compile-failed");
        } else {
            const char* name = nullptr;
            unsigned long scanned = 0;
            ClScanOptions options{};
            // Archive and basic executable parsers; bounds are set by the Android file-copy layer.
            options.parse = 0x1 | 0x2 | 0x4 | 0x100 | 0x200;
            int verdict = scan(file, &name, &scanned, engine, &options);
            if (verdict == 1) answer = std::string("DETECTED:") + (name ? name : "ClamAV.Rule");
            else if (verdict == 0) answer = "NO_MATCH";
            else answer = incomplete("clamav-scan-failed");
        }
        freeEngine(engine);
    }
    dlclose(lib);
    return answer;
}

struct YaraMatch {
    std::string name;
    int (*identifier)(const void*, const uint8_t**, size_t*);
};
void onYaraMatch(const void* rule, void* userData) {
    auto* ctx = static_cast<YaraMatch*>(userData);
    if (!ctx || !ctx->name.empty() || !ctx->identifier) return;
    const uint8_t* name = nullptr;
    size_t length = 0;
    if (ctx->identifier(rule, &name, &length) == 0 && name && length > 0 && length <= 128) {
        ctx->name.assign(reinterpret_cast<const char*>(name), length);
    }
}

std::string yaraScan(const char* file, const char* rulesSource) {
    if (!file || !rulesSource || !*rulesSource) return incomplete("missing-rules");
    // Entire-file scanning is deliberate: do not give a partial-scan CLEAN verdict.
    constexpr off_t MAX_BYTES = 16 * 1024 * 1024;
    int fd = open(file, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return incomplete("file-open-failed");
    struct stat st{};
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 || st.st_size > MAX_BYTES) {
        close(fd);
        return incomplete("yara-file-too-large-or-invalid");
    }
    std::vector<uint8_t> bytes(static_cast<size_t>(st.st_size));
    size_t offset = 0;
    while (offset < bytes.size()) {
        ssize_t n = read(fd, bytes.data() + offset, bytes.size() - offset);
        if (n <= 0) {
            close(fd);
            return incomplete("file-read-failed");
        }
        offset += static_cast<size_t>(n);
    }
    close(fd);
    void* lib = dlopen("libyara_x_capi.so", RTLD_NOW | RTLD_LOCAL);
    if (!lib) return incomplete("yara-load-failed");
    auto compile = symbol<int (*)(const char*, void**)>(lib, "yrx_compile");
    auto destroyRules = symbol<void (*)(void*)>(lib, "yrx_rules_destroy");
    auto createScanner = symbol<int (*)(const void*, void**)>(lib, "yrx_scanner_create");
    auto destroyScanner = symbol<void (*)(void*)>(lib, "yrx_scanner_destroy");
    auto onMatch = symbol<int (*)(void*, void (*)(const void*, void*), void*)>(lib, "yrx_scanner_on_matching_rule");
    auto scan = symbol<int (*)(void*, const uint8_t*, size_t)>(lib, "yrx_scanner_scan");
    auto identifier = symbol<int (*)(const void*, const uint8_t**, size_t*)>(lib, "yrx_rule_identifier");
    if (!compile || !destroyRules || !createScanner || !destroyScanner || !onMatch || !scan || !identifier) {
        dlclose(lib);
        return incomplete("yara-api-unavailable");
    }
    std::string answer = incomplete("yara-compile-failed");
    void* rules = nullptr;
    if (compile(rulesSource, &rules) == 0 && rules) {
        void* scanner = nullptr;
        if (createScanner(rules, &scanner) == 0 && scanner) {
            YaraMatch match{"", identifier};
            if (onMatch(scanner, onYaraMatch, &match) != 0) {
                answer = incomplete("yara-callback-failed");
            } else if (scan(scanner, bytes.empty() ? nullptr : bytes.data(), bytes.size()) != 0) {
                answer = incomplete("yara-scan-failed");
            } else {
                answer = match.name.empty() ? "NO_MATCH" : "DETECTED:" + match.name;
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
