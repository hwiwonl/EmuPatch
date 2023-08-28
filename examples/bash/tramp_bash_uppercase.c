#include <ctype.h>
#include <stdio.h>
#include <handler.h>

void fwrite_check(context *ctx) {
    char *s = (char *)ctx->rdi;
    addrint remain = ctx->rsi * ctx->rdx;
    while(remain--) {
        char c = *s++;
        if(islower(c)) c -= 32;
        fputc(c, stderr);
    }
    fflush(stderr);
    ctx->rip = ((addrint *)ctx->rsp)[1];
    ctx->rsp += 8;
}

void exit_handler(context *ctx) {
    puts("exit!");
    return _exit(0);
}

HOOK(0x41f420, fwrite_check)
SYMHOOK("exit", exit_handler);
