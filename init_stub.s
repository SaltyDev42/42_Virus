section .text

%define __NR_write 1
%define __NR_mprotect 10

%define PROT_READ	0x1	;;	/* Page can be read.  */
%define PROT_WRITE	0x2	;;	/* Page can be written.  */
%define PROT_EXEC	0x4	;;	/* Page can be executed.  */
%define PROT_NONE	0x0	;;	/* Page can not be accessed.  */


%define QWORD_PLACERHOLDER 0x1122334455667788
%define PLACEHOLDER 0

default rel
stub:
;; context saving
	push rdi
	push rdx
	push rax
	push rsi
;; resets register
	xor rdi, rdi
	xor edx, edx
	xor rsi, rsi
	xor rax, rax

;; saving space
	sub rsp, 0x10
;;mprotect
	lea rdi, [_REL]				 ; address
	mov [rsp + 0x8], rdi			 ; save rel
	mov DWORD [rsp], PLACEHOLDER		 ; save size
	mov esi, [rsp]				 ; payload size
	mov dl, PROT_READ | PROT_WRITE | PROT_EXEC ; prot
	mov al, __NR_mprotect
	syscall

	call [rsp + 0x8]		; real function

;; reset bss
	mov rdi, [rsp + 0x8]
	mov ecx, [rsp]
	rep stosq
;;mprotect removes exection on bss
	pop rsi			;size
	pop rdi			;address
	mov dl, PROT_READ | PROT_WRITE ; prot
	mov al, __NR_mprotect
	syscall
;; context restoring
	pop rsi
	pop rax
	pop rdx
	pop rdi
	jmp 1
;; PLACEHOLDER for bss
_REL:
