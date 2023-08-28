.intel_syntax noprefix
.globl trampoline, trampoline_end

trampoline:
	pushad
	pushfd
	push esp
	call [trampoline_end]
	add esp, 4
	popfd
	popad
	ret

trampoline_end:
.long 0
