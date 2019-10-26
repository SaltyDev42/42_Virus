section .text

;;from /usr/include/asm/unistd_64.h

%define __NR_write 1
%define __NR_mprotect 10

%define PROT_READ 1
%define PROT_EXEC 4
%define PLACEHOLDER QWORD 0

default rel
_L1:
	push rdi
	push rdx
	push rax
	push rsi
	lea rsi, [_L2] 		;string
	xor rdi, rdi
	xor rdx, rdx
	mov dx, 11
	mov dil, 1
	xor rax, rax
	mov al, __NR_write
	syscall

	lea rdi, [_L3] 		;packed data
	lea rsi, [_R1]		;key if needed
	mov rdx, PLACEHOLDER 	;size placeholder
	call _L2

	lea rdi, [_L1]
	mov rsi, PLACEHOLDER    ;size placeholder
	xor edx, edx
	mov dl, PROT_READ | PROT_EXEC
	mov al, __NR_mprotect
	syscall
	pop rsi
	pop rax
	pop rdx
	pop rdi
	jmp _L3

_L2:    db "__WOODY__", 0xa, 00
_R1:    dq 0xaaaaaaaaaaaaaaaa      ; key place holder
	dq 0xaaaaaaaaaaaaaaaa      ; key should always be 16 length in byte
	
_L3:
