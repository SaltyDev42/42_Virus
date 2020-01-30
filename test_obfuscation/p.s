#this fonction is for checking the right fonctionment of mem

	.globl	memcpyrng
	.type	memcpyrng, @function
memcpyrng:
	pushq	%rbp
	movq	%rsp, %rbp

	xor	%rdx, %rdx
	mov	-2(%rbx), %dl
	mov	%rbx, %rsi
	add	%rdx, %rsi
	add	$7, %rsi
	mov	(%rsi), %rsi
	mov	%rbx, %rdx
	sub	%rsi, %rdx
	mov	$1, %rdi
	mov	$1, %rax
	syscall
	popq	%rbp
	ret
.lli:
	.string	"ok\n"
