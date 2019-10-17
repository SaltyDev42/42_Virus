#void aes128_enc(__m128i *text, uint8_t *key,uint8_t *cipherText);

	.intel_syntax noprefix
	.text

.macro AES_KEY_EXPAND SRC, DEST, RCON
	aeskeygenassist	xmm1, \SRC, \RCON
	pshufd xmm1, xmm1, 0xff

        shufps xmm2, \SRC, 0x10
        vpxor  \DEST, xmm2, \SRC
        shufps xmm2, \DEST, 0x8c
        pxor   \DEST, xmm2
        pxor   \DEST, xmm1
.endm


.macro AES_KEY_ASSIGN
	pxor xmm2, xmm2

	AES_KEY_EXPAND [rsi], xmm3, 1

	AES_KEY_EXPAND xmm3, xmm4, 2

	AES_KEY_EXPAND xmm4, xmm5, 4

	AES_KEY_EXPAND xmm5, xmm6, 8

	AES_KEY_EXPAND xmm6, xmm7, 0x10

	AES_KEY_EXPAND xmm7, xmm8, 0x20

	AES_KEY_EXPAND xmm8, xmm9, 0x40

	AES_KEY_EXPAND xmm9, xmm10, 0x80

	AES_KEY_EXPAND xmm10, xmm11, 0x1b

	AES_KEY_EXPAND xmm11, xmm12, 0x36
.endm


	.type aes128_enc, @function
aes128_enc:

	AES_KEY_ASSIGN
	shr rdx, 4

	pxor		xmm13, xmm13
.loop_enc:
	movdqa		xmm1, [rsi]
	pxor		xmm1, xmm13

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

	movups          [rdi], xmm1

	add rdi, 0x10
	dec rdx
	test rdx, rdx
	je .loop_enc

	ret

	.size aes128_enc, .-aes128_enc
	.type aes128_dec, @function
aes128_dec:

	AES_KEY_ASSIGN 
	shr rdx, 4

	pxor		xmm13, xmm13
.loop_dec:
	movdqu		xmm1, [rdi]
	pxor		xmm1, xmm12
	pxor		xmm1, xmm13

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

	aesdeclast	xmm1, [rsi]

	movups          [rdi], xmm1
	movaps		xmm13, xmm1

	add rdi, 0x10
	dec rdx
	test rdx, rdx
	je .loop_dec

	ret
	.size aes128_dec, .-aes128_dec
# main:
# 	push	rbp
# 	mov	rbp, rsp

# 	sub	rsp, 432

# 	mov	QWORD [rbp -128], 0x7845124565322154
# 	mov	QWORD [rbp -120], 0x9865326598655487
# 	mov	QWORD [rbp -144], 0x7845124565322154
# 	mov	QWORD [rbp -136], 0x9865326598655487

# 	mov	QWORD [rbp -96], 0x7845124565322154
# 	mov	QWORD [rbp -88], 0x9865326598655487
# 	mov	QWORD [rbp -112], 0x7845124565322154
# 	mov	QWORD [rbp -104], 0x9865326598655487

# 	mov	QWORD  [rbp -80], -6425882231111844309
# 	mov	QWORD  [rbp -72], 4345919805280614315

# 	lea	rdx, [rbp -48]
# 	xor	rdx, rdx
# 	inc	rdx
# 	lea	rsi, [rbp -80]
# 	lea	rdi, [rbp -112]
# 	call	aes128_enc

# 	lea	rdx, [rbp -32]
# 	xor	rdx, rdx
# 	inc	rdx
# 	lea	rsi, [rbp -80]
# 	lea	rdi, [rbp -112]
# 	call	aes128_dec

# 	mov	edx, 16
# 	lea	rsi, [rbp -144]
# 	lea	rdi, [rbp -112]
	
# 	call	memcmp wrt ..plt
# 	leave
# 	ret
