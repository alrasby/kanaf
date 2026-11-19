// Offline host probe of the app's exact pinned ClamAV C API and policy.
// No samples are executed. Network and exec syscalls are denied before parsing.
#include "../../native-rebuild/app/src/main/cpp/clam_scan_policy.h"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <dlfcn.h>
#include <cerrno>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

struct Engine;
struct Options { uint32_t general, parse, heuristic, mail, dev; };
static_assert(sizeof(Options) == 20);
template<typename T> T sym(void* lib, const char* name) { return reinterpret_cast<T>(dlsym(lib, name)); }

bool restrictParser() {
    // x86_64 host-only helper, never an Android app component.
    sock_filter filters[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
    sock_fprog program{static_cast<unsigned short>(sizeof(filters) / sizeof(filters[0])), filters};
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 &&
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0;
}

int main(int argc, char** argv) {
    if (argc != 5) return 2;
    void* lib = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!lib) { std::puts("INCOMPLETE:library-unavailable"); return 0; }
    auto version = sym<const char* (*)()>(lib, "cl_retver");
    auto init = sym<int (*)(unsigned int)>(lib, "cl_init");
    auto create = sym<Engine* (*)()>(lib, "cl_engine_new");
    auto release = sym<int (*)(Engine*)>(lib, "cl_engine_free");
    auto load = sym<int (*)(const char*, Engine*, unsigned int*, unsigned int)>(lib, "cl_load");
    auto compile = sym<int (*)(Engine*)>(lib, "cl_engine_compile");
    auto number = sym<int (*)(Engine*, int, long long)>(lib, "cl_engine_set_num");
    auto string = sym<int (*)(Engine*, int, const char*)>(lib, "cl_engine_set_str");
    auto scan = sym<int (*)(const char*, const char**, unsigned long*, const Engine*, Options*)>(lib, "cl_scanfile");
    if (!version || !kanaf::isPinnedClamRuntime(version()) || !init || !create || !release ||
        !load || !compile || !number || !string || !scan || !restrictParser()) {
        std::puts("INCOMPLETE:runtime-api-or-sandbox-unavailable"); return 0;
    }
    if (init(0) != 0) { std::puts("INCOMPLETE:initialization-failed"); return 0; }
    Engine* engine = create();
    if (!engine) { std::puts("INCOMPLETE:engine-unavailable"); return 0; }
    unsigned int count = 0;
    if (!kanaf::configureClamAcOnly(engine, number) || !kanaf::disableClamCleanCache(engine, number) ||
        !kanaf::configureClamTempDirectory(engine, string, argv[4]) ||
        load(argv[2], engine, &count, 0) != 0 || count == 0 ||
        !kanaf::configureClamLimits(engine, number) || compile(engine) != 0) {
        release(engine); std::puts("INCOMPLETE:database-or-policy-failed"); return 0;
    }
    Options options{};
    options.parse = 0x1 | 0x2 | 0x4 | 0x100 | 0x200;
    options.general = 0x4;
    options.heuristic = 0x4;
    const char* name = nullptr;
    unsigned long scanned = 0;
    const int code = scan(argv[3], &name, &scanned, engine, &options);
    const auto result = kanaf::classifyClamScan(code, name);
    std::puts(result.c_str());
    release(engine);
    dlclose(lib);
    return 0;
}
