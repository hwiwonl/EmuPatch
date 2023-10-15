:loudspeaker: *All of the codes in this repository were developed by me and brilliant members of DEFKOR for DEFCON23-24*

# <span style="font-family: 'Georgia';">EmuPatch</span>: An Efficient Binary Patch Framework
Make patches for compiled binary in C.

## Dependency 

* [CPython 2.7](http://www.python.org)
* [latest pyelftools](https://github.com/eliben/pyelftools)
* GCC + GCC Assembler(AS) (for ARM, x86/x64, and you can modify bpatch.py to change GCC binary)

## Usage 

### scripts/bpatch.py: binary patch writable in C

```
scripts/bpatch.py [1:original binary] [2:patch file] [3:output path]
```

This patches the original binary by patch file written in C.

### Patch file format

Basically it's a C source code, but with additional lines at the end.

#### 1. Hooking by address

```c
HOOK("library name", [offset to hook], handler)
HOOK([offset to hook], handler)
```

- If library name is omitted or "", it will hook main binary.
- Actual hooked address is [library base] + [offset].
- It supports PIE binary.

Patch example:

```c
void my_patch_1(context *ctx) {
	ctx->eax = 100;
	PC = 0x40056c;
}

HOOK(0x400550, my_patch_1);
```

For PIE main executable, it's same.

```c
void main_hook(context *ctx) {
	puts("main hook!");
}

HOOK(0x4c60, main_hook);
```

#### 2. Hooking by exported function name

```c
SYMHOOK("library name", "function name", handler);
SYMHOOK("function name", handler);
```

Same as above, if library name is omitted, it'll search every library.
Then the resolved symbol will be same as binary's resolved one.

### Callback:

The `handler` used above has format:

```c
void handler(context *ctx) { ... }
```

The `context` has registers, and you can get/modify it.

```c
typedef struct {
    addrint r8, r9, ..., rsp, rip;
} context;

```

##### Example:

```c
// PC, SP is macro: rip, rsp
#include <handler.h>

void fwrite_check(context *ctx) {
    printf("fwrite: %s(%p)", ctx->rdi, ctx->rdi);
    ctx->rax = ctx->rsi * ctx->rdx;
    ctx->PC = *((addrint *)ctx->SP + 1);
}

void system_hook(context *ctx) {
    puts("system is not allowed!");
    ctx->PC = 0x41414141;
    return;
}

HOOK(0x41f420, fwrite_check) // fwrite plt
SYMHOOK("libc.so", "system", system_hook)
```

### ./build_examples.sh

It builds a upper-cased bash. Check examples/bash for the patched code. examples/bash/out/ is build directory.

## Supported platforms ##

* x86/x64 ELF
* ~~ARM little, big endian ELF~~
