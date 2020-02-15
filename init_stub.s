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
	push rdx
	push rax
;; resets register
	xor edx, edx

;; saving space
	sub rsp, 0x10
;;mprotect
	lea r8,  [_REL]				 ; address jump
	lea rdi, [_REL]				 ; aligned address mapping
	mov [rsp + 0x8], rdi			 ; save rel
	mov DWORD [rsp], PLACEHOLDER		 ; save size
	mov esi, [rsp]				 ; payload size
	mov dl, PROT_READ | PROT_WRITE | PROT_EXEC ; prot
	mov al, __NR_mprotect
	syscall

	call r8					; real function

;; reset bss
	mov rdi, r8
	mov ecx, eax
	xor eax, eax
	rep stosq
;;mprotect removes exection on bss
	pop rsi			;size
	pop rdi			;address
	mov dl, PROT_READ | PROT_WRITE ; prot
	mov al, __NR_mprotect
	syscall
;; context restoring
	pop rax
	pop rdx
	jmp 1
;; PLACEHOLDER for bss
_REL:
