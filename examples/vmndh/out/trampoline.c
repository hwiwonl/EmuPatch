#include <handler.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/shm.h>
#include <stdlib.h>

#define SHM_ENV_VAR "__AFL_SHM_ID"
#define FORKSRV_FD 198

char *afl_area_ptr = NULL;
int afl_setup_failure = 0;

// binary base
char *base = NULL;

typedef struct {
    int op;
    void (*handler)();
} handler;

char *vm_flags = NULL;
char **vm_base = NULL;
unsigned short *vm_pc = NULL;
handler *handlers = NULL;

unsigned short prev_location;

void die() { _exit(0); }

void close_fds() {
    close(FORKSRV_FD);
    close(FORKSRV_FD + 1);
}

void afl_abort() {
    afl_setup_failure += 1;
}

__attribute__((constructor))
void afl_setup() {
    if(afl_setup_failure) return;
    char *env = getenv(SHM_ENV_VAR);
    if(env == NULL) {
        afl_abort();
        return;
    }
    int shmid = atoi(env);
    char *shm = shmat(shmid, 0, 0);
    if(shm == (void *)-1) {
        afl_abort();
        return;
    }
    afl_area_ptr = shm;
    int32_t buf = 0, pid;
    // Check if this program is under afl-fuzz
    if(write(FORKSRV_FD + 1, &buf, 4) == 4) {
        if(read(FORKSRV_FD, &buf, 4) != 4) {
            die();
        }
        pid = fork();
        if(pid < 0) die();
        if(pid == 0) {
            // Then resume it
            close_fds();
            return;
        } else {
            write(FORKSRV_FD + 1, &pid, 4);
            if(waitpid(pid, &buf, 0) < 0) {
                die();
            }
            write(FORKSRV_FD + 1, &buf, 4);
        }
    }
    else {
        // Then resume it
        close_fds();
        return;
    }
}

__attribute__((constructor))
void obtain_bases() {
    base = (char *)query_lib("")->base;
    vm_flags = base + 0x20f8d0;
    vm_pc = (unsigned short *)(base + 0x20f8ae);
    vm_base = (char **)(base + 0x20f8b8);
    handlers = (handler *)(base + 0x20f020);
}

void afl_store() {
    // Sends coverage to afl
    unsigned short cur_location = *vm_pc;
//    printf("branch: %p\n", cur_location);
    if(!afl_area_ptr) return;
    afl_area_ptr[cur_location ^ prev_location]++;
    prev_location = cur_location >> 1;
}

void segfault_handler(context *ctx) {
//    printf("segfault at %p\n", *vm_pc);
    char *code = (char *)(ctx->rdi & 0xffffffff);
    code[0] = 1;
}

HOOK(0x5d38, segfault_handler);

void _return(context *ctx) {
    ctx->rsp += 8;
}

unsigned short uint16_at(uint16_t where) {
    uint16_t *ptr = (uint16_t *)((*vm_base) + where);
    return *ptr;
}

void trace_branch_handler(context *ctx) {
    addrint op = ctx->rdx;
    int trace = 0;
//    printf("op: %d\n", op);
    switch(op) {
        case 0x16: // jmps
        case 0x1b: // jmpl
        case 0x19: // call
        case 0x10: // jz
        case 0x11: // jnz
        case 0x1e: // ja
        case 0x1f: // jb
        case 0x1a: // ret
            trace = 1;
            break;
    }
    handlers[ctx->rax].handler();
    if(trace) afl_store();
    ctx->PC = base + 0x3e3d;
}

HOOK(0x3e29, trace_branch_handler);
