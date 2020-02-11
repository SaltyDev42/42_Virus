#void aes128_enc(__m128i *key_schedule, uint8_t *plainText,uint8_t *cipherText);
#void aes128_dec(__m128i *key_schedule, uint8_t *cipherText,uint8_t *plainText);
	.file	"aes.c"
	.intel_syntax noprefix
	.text
	.type	aes_128_key_expansion, @function
aes_128_key_expansion:
.LFB510:
	.cfi_startproc
        pshufd xmm1, xmm1, 0xff

        shufps xmm2, xmm0, 0x10
        pxor   xmm0, xmm2
        shufps xmm2, xmm0, 0x8c
        pxor   xmm0, xmm2
        pxor   xmm0, xmm1

	ret
	.cfi_endproc
.LFE510:
	.size	aes_128_key_expansion, .-aes_128_key_expansion
	.type	aes128_load_key_enc_only, @function
aes128_load_key_enc_only:
.LFB511:
	.cfi_startproc
        pxor xmm2, xmm2
	movaps	xmm0, [rdi]

	aeskeygenassist	xmm1, xmm0, 1
	call	aes_128_key_expansion
	movaps	xmm3, xmm0

	aeskeygenassist	xmm1, xmm0, 2
	call	aes_128_key_expansion
	movaps	xmm4, xmm0

	aeskeygenassist	xmm1, xmm0, 4
	call	aes_128_key_expansion
	movaps	xmm5, xmm0

	aeskeygenassist	xmm1, xmm0, 8
	call	aes_128_key_expansion
	movaps	xmm6, xmm0

	aeskeygenassist	xmm1, xmm0, 0x10
	call	aes_128_key_expansion
	movaps	xmm7, xmm0

	aeskeygenassist	xmm1, xmm0, 0x20
	call	aes_128_key_expansion
	movaps	xmm8, xmm0

	aeskeygenassist	xmm1, xmm0, 0x40
	call	aes_128_key_expansion
	movaps	xmm9, xmm0

	aeskeygenassist	xmm1, xmm0, 0x80
	call	aes_128_key_expansion
	movaps	xmm10, xmm0

	aeskeygenassist	xmm1, xmm0, 0x1b
	call	aes_128_key_expansion
	movaps	xmm11, xmm0

	aeskeygenassist	xmm1, xmm0, 0x36
	call	aes_128_key_expansion
	movaps	xmm12, xmm0

	ret
	.cfi_endproc
.LFE511:
	.size	aes128_load_key_enc_only, .-aes128_load_key_enc_only
	.type	aes128_enc, @function
aes128_enc:
.LFB513:
	.cfi_startproc

	call	aes128_load_key_enc_only
	movdqa		xmm1, XMMWORD PTR [rsi]

	pxor		xmm1, [rdi]
	aesenc		xmm1, xmm3
	aesenc		xmm1, xmm4
	aesenc		xmm1, xmm5
	aesenc		xmm1, xmm6
	aesenc		xmm1, xmm7
	aesenc		xmm1, xmm8
	aesenc		xmm1, xmm9
	aesenc		xmm1, xmm10
	aesenc		xmm1, xmm11
	aesenclast	xmm1, xmm12

	movups	XMMWORD PTR [rdx], xmm1

	ret
	.cfi_endproc
.LFE513:
	.size	aes128_enc, .-aes128_enc


	.type	aes128_dec, @function
aes128_dec:
.LFB514:
	.cfi_startproc

	call	aes128_load_key_enc_only

	movdqu		xmm1, XMMWORD PTR [rsi]
	pxor		xmm1, xmm12

	aesimc		xmm11, xmm11
	aesdec		xmm1, xmm11
	aesimc		xmm10, xmm10
	aesdec		xmm1, xmm10
	aesimc		xmm9, xmm9
	aesdec		xmm1, xmm9
	aesimc		xmm8, xmm8
	aesdec		xmm1, xmm8
	aesimc		xmm7, xmm7
	aesdec		xmm1, xmm7
	aesimc		xmm6, xmm6
	aesdec		xmm1, xmm6
	aesimc		xmm5, xmm5
	aesdec		xmm1, xmm5
	aesimc		xmm4, xmm4
	aesdec		xmm1, xmm4
	aesimc		xmm3, xmm3
	aesdec		xmm1, xmm3

	aesdeclast	xmm1, [rdi]

	movups	XMMWORD PTR [rdx], xmm1

	ret
	.cfi_endproc
.LFE514:
	.size	aes128_dec, .-aes128_dec
	.globl	main
	.type	main, @function
main:
.LFB515:
	.cfi_startproc
	push	rbp
	mov	rbp, rsp

	sub	rsp, 432

	movabs	rax, -8272457234482837714
	movabs	rdx, 3749026652749312305
	mov	QWORD PTR -96[rbp], rax
	mov	QWORD PTR -88[rbp], rdx

	movabs	rax, -6425882231111844309
	movabs	rdx, 4345919805280614315
	mov	QWORD PTR -80[rbp], rax
	mov	QWORD PTR -72[rbp], rdx
	mov	DWORD PTR -420[rbp], 0

	lea	rdx, -48[rbp]
	lea	rsi, -96[rbp]
	lea	rdi, -80[rbp]
	call	aes128_enc

	lea	rdx, -32[rbp]
	lea	rsi, -48[rbp]
	lea	rdi, -80[rbp]
	call	aes128_dec

	mov	edx, 16
	lea	rsi, -32[rbp]
	lea	rdi, -96[rbp]
	call	memcmp@PLT
	leave
	ret
	.cfi_endproc
.LFE515:
	.size	main, .-main
	.ident	"GCC: (GNU) 9.1.0"
	.section	.note.GNU-stack,"",@progbits
