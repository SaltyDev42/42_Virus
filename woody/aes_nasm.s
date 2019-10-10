;void aes128_enc(__m128i *key_schedule, uint8_t *plainText,uint8_t *cipherText);
;void aes128_dec(__m128i *key_schedule, uint8_t *cipherText,uint8_t *plainText);

section .text

%macro AES_KEY_EXPAND 0
	pshufd xmm1, xmm1, 0xff

        shufps xmm2, xmm0, 0x10
        pxor   xmm0, xmm2
        shufps xmm2, xmm0, 0x8c
        pxor   xmm0, xmm2
        pxor   xmm0, xmm1
%endmacro

%macro AES_KEY_ASSIGN 0
	pxor xmm2, xmm2
	movaps	xmm0, [rdi]

	aeskeygenassist	xmm1, xmm0, 1
	AES_KEY_EXPAND
	movaps	xmm3, xmm0

	aeskeygenassist	xmm1, xmm0, 2
	AES_KEY_EXPAND
	movaps	xmm4, xmm0

	aeskeygenassist	xmm1, xmm0, 4
	AES_KEY_EXPAND
	movaps	xmm5, xmm0

	aeskeygenassist	xmm1, xmm0, 8
	AES_KEY_EXPAND
	movaps	xmm6, xmm0

	aeskeygenassist	xmm1, xmm0, 0x10
	AES_KEY_EXPAND
	movaps	xmm7, xmm0

	aeskeygenassist	xmm1, xmm0, 0x20
	AES_KEY_EXPAND
	movaps	xmm8, xmm0

	aeskeygenassist	xmm1, xmm0, 0x40
	AES_KEY_EXPAND
	movaps	xmm9, xmm0

	aeskeygenassist	xmm1, xmm0, 0x80
	AES_KEY_EXPAND
	movaps	xmm10, xmm0

	aeskeygenassist	xmm1, xmm0, 0x1b
	AES_KEY_EXPAND
	movaps	xmm11, xmm0

	aeskeygenassist	xmm1, xmm0, 0x36
	AES_KEY_EXPAND
	movaps	xmm12, xmm0
%endmacro


aes128_enc:
	push rbp
	mov rbp, rsp

	AES_KEY_ASSIGN

	movdqa		xmm1, [rsi]

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

	movups          [rdx], xmm1

	leave
	ret

aes128_dec:
	push rbp
	mov rbp, rsp

	AES_KEY_ASSIGN 

	movdqu		xmm1, [rsi]
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

	movups          [rdx], xmm1

	leave
	ret
