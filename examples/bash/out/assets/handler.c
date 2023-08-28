#define _GNU_SOURCE

#include <sys/mman.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <link.h>
#include <stdarg.h>

void *stack;

// Do not modify this or put header after this. This includes tramp file.
#include "handler.h"

// lib_tail is garanteed to have the executable base
lib *lib_head = NULL, *lib_tail = NULL;

void trampoline();
void trampoline_end();

char map_exists(addrint address) {
    int r = msync((void *)address, 1, 0);
    return r == 0;
}

addrint make_trampoline(addrint target, addrint preferred_address) {
    addrint  trampoline_size = (addrint)&trampoline_end - (addrint)&trampoline;
    addrint  target_p = target;
    addrint  preferred_address_ = preferred_address; // backup
    char    *code;

    preferred_address &= ~0xfff;
    while(map_exists(preferred_address)) preferred_address -= 0x1000;
    code = (char *)mmap((void *)preferred_address, 0x1000, 7, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    code += 0x1000 - (trampoline_size + sizeof(addrint));
    memcpy(code, &trampoline, trampoline_size);
    memcpy(code + trampoline_size, &target_p, sizeof(addrint));
    return (addrint)code;
}

void install_trampoline(addrint where, addrint function_ptr) {
    void *page = (void *)(where & ~0xfff); // this is safe way between 32/64
    mprotect(page, 0x1000, 7);
    // Patch code
    addrint preferred_address = where;
    addrint new_trampoline = make_trampoline(function_ptr, preferred_address);
    logger(1, "patching %p with %p...\n", (void *)where, (void *)new_trampoline);
    *(unsigned int *)(where) = 0xe8;
    *(unsigned long *)(where + 1) = (addrint)new_trampoline - ((addrint)where + 5);
    mprotect(page, 0x1000, 5);
}

void install_one_trampoline(char *library, addrint where, addrint function_ptr) {
    lib *lib_ = query_lib(library);
    if(!lib_) {
        logger(0, "library not found: %s\n", library);
    }
    else {
        where += lib_->base;
        install_trampoline(where, function_ptr);
    }
}

void install_trampoline_by_name(char *library, char *name, addrint function_ptr) {
    addrint where = 0;
    void *handle = RTLD_DEFAULT;
    lib *lib_ = NULL;
    if(strlen(library)) {
        lib_ = query_lib(library);
        if(lib_)
            handle = dlopen(lib_->name, RTLD_NOLOAD | RTLD_NOW);
        if(!lib_ || !handle) {
            logger(0, "library not found: %s\n", library);
            handle = RTLD_DEFAULT;
        }
    }
    where = (addrint)dlsym(handle, name);
    if(!where) {
        logger(0, "function %s on %s is not found\n", library, name);
    } else {
        install_trampoline(where, function_ptr);
    }
}

lib *query_lib(char *library) {
    if(strlen(library) == 0)
        return lib_head;
    lib *cur = lib_head;
    while(cur) {
        if(strstr(cur->name, library))
            return cur;
        cur = cur->next;
    }
    return NULL;
}

static int
fetch_lib_addr(struct dl_phdr_info *info, size_t size, void *data) {
    lib *new_lib = (lib *)malloc(sizeof(lib));
    new_lib->base = (addrint)info->dlpi_addr;
    new_lib->name = strdup(info->dlpi_name);
    new_lib->next = NULL;
    // Add to linked list
    if(lib_tail) {
        lib_tail->next = new_lib;
        lib_tail = new_lib;
    } else {
        lib_head = lib_tail = new_lib;
    }
	return 1;
}

int init() {
	char buf;
	struct sigaction act;
	memset(&act, 0, sizeof(act));
	dl_iterate_phdr(fetch_lib_addr, NULL);
}

void logger(int level, char *format, ...) {
    if(level <= LOGLEVEL) {
        va_list args;
        va_start(args, format);
        vfprintf(stderr, format, args);
    }
}
