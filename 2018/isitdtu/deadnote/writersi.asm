BITS 64

start:
	push rdx
	pop rdi
	push rdx
	pop rax
        mov dl, 0xff
	syscall
