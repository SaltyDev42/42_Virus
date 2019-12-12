section .text

;;from /usr/include/asm/unistd_64.h

%define __NR_write 1
%define __NR_mprotect 10


%define PROT_READ	0x1	;;	/* Page can be read.  */
%define PROT_WRITE	0x2	;;	/* Page can be written.  */
%define PROT_EXEC	0x4	;;	/* Page can be executed.  */
%define PROT_NONE	0x0	;;	/* Page can not be accessed.  */

%define PLACEHOLDER 0x11223344

default rel
_L1:
	lea rsi, [_L2] 		;string
	xor rdi, rdi
	xor rdx, rdx
	mov dx, 11
	mov dil, 1
	xor rax, rax
	mov al, __NR_write
	syscall

;; put WRITE mode on PT_LOAD exec
	lea rdi, [_L1]
	mov rsi, PLACEHOLDER    ;size placeholder
	xor edx, edx
	mov dl, PROT_READ | PROT_EXEC | PROT_WRITE
	mov al, __NR_mprotect

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
	ret

_L2:    db "__WOODY__", 0xa, 00
_R1:    dq 0xaaaaaaaaaaaaaaaa      ; key place holder
	dq 0xaaaaaaaaaaaaaaaa      ; key should always be 16 length in byte
	
_L3:
