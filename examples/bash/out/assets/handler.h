#pragma once

// Definitions for some useful registers
// Let's add some of useful registers!
#if defined(__i386)
#define PC eip
#define SP esp
typedef unsigned long addrint;
typedef signed long addrdiff;
typedef unsigned long u32;
typedef unsigned long long u64;
typedef struct {
	u32 eflags, edi, esi, ebp, edx, ecx, ebx, eax, esp, eip;
} context;
#elif defined(__x86_64)
#define PC rip
#define SP rsp
typedef unsigned long long addrint;
typedef signed long long addrdiff;
typedef unsigned long u32;
typedef unsigned long long u64;
typedef struct {
	u64 rflags, r8, r9, r10, r11, r12, r13, r14, r15, rdi, rsi, rbp, rdx, rcx, rbx, rax, rsp, rip;
} context;
#elif defined(__arm__)
#define PC arm_pc
#define SP arm_sp
typedef unsigned long addrint;
typedef signed long addrdiff;
#endif

typedef struct _lib {
    char *name;
    addrint base;
    struct _lib *next;
} lib;

void logger(int level, char *format, ...);
void install_one_trampoline(char *library, addrint where, addrint function_ptr);
lib *query_lib(char *name);

// Expanding __COUNTER__ via expanding macros
#define CONCAT1(x, y) x##y
#define CONCAT(x, y) CONCAT1(x, y)
#define HOOK_WITH_LIB(lib, addr, func) __attribute__((constructor)) void CONCAT(install_##func##_, __COUNTER__)() { \
    logger(1, "Hooking "#addr" with "#func"\n"); \
    install_one_trampoline(lib, addr, (addrint)func); \
}
#define HOOK_WITH_NOLIB(addr, func) HOOK_WITH_LIB("", addr, func)

#define SELECTOR(_1, _2, _3, NAME, ...) NAME
#define HOOK(...) SELECTOR(__VA_ARGS__, HOOK_WITH_LIB, HOOK_WITH_NOLIB)(__VA_ARGS__)

#define SYMHOOK_WITH_LIB(lib, name, func) __attribute__((constructor)) void CONCAT(install_##func##_, __COUNTER__)() { \
    logger(1, "Hooking "#name" with "#func"\n"); \
    install_trampoline_by_name(lib, name, (addrint)func); \
}

#define SYMHOOK_WITH_NOLIB(name, func) SYMHOOK_WITH_LIB("", name, func)

#define SYMHOOK(...) SELECTOR(__VA_ARGS__, SYMHOOK_WITH_LIB, SYMHOOK_WITH_NOLIB)(__VA_ARGS__)

// LOGLEVEL
// 0: error
// 1: hooking log
#define LOGLEVEL 1

