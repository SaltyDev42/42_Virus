/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memcmp.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/04 17:34:30 by jye               #+#    #+#             */
/*   Updated: 2017/12/21 04:45:55 by jye              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdint.h>

static int	ft_memcmp8(uint64_t s1p, uint64_t s2p, size_t n)
{
	register uint8_t	s1c;
	register uint8_t	s2c;

	while (n--)
	{
		s1c = ((uint8_t *)s1p++)[0];
		s2c = ((uint8_t *)s2p++)[0];
		if (s2c != s1c)
			return (s1c - s2c);
	}
	return (0);
}

static int	ft_unaligned_word_cmp(uint64_t s1p, uint64_t s2p, size_t m8)
{
	uint64_t			val;
	size_t				xlen;
	uint64_t			w[2];
	int					sh[2];

	xlen = m8 >> 1;
	sh[0] = (s2p & 7) * 8;
	sh[1] = 64 - sh[0];
	w[0] = ((uint64_t *)s2p)[0];
	while (xlen--)
	{
		w[1] = ((uint64_t *)s2p)[1];
		if ((val = MERGE(w[0], sh[0], w[1], sh[1])) ^ ((uint64_t *)s1p)[0])
			return (ft_memcmp8(s1p, (uint64_t)&val, 8));
		s2p += 16;
		w[0] = ((uint64_t *)s2p)[0];
		if ((val = MERGE(w[1], sh[0], w[0], sh[1])) ^ ((uint64_t *)s1p)[1])
			return (ft_memcmp8(s1p + 8, (uint64_t)&val, 8));
		s1p += 16;
	}
	w[1] = ((uint64_t *)s2p)[1];
	if (m8 & 1)
		if ((val = MERGE(w[0], sh[0], w[1], sh[1])) ^ ((uint64_t *)s1p)[0])
			return (ft_memcmp8(s1p, (uint64_t)&val, 8));
	return (0);
}

static int	ft_aligned_word_cmp(uint64_t s1p, uint64_t s2p, size_t m8)
{
	size_t				xlen;

	xlen = m8 >> 3;
	while (xlen--)
	{
		if (((uint64_t *)s2p)[0] ^ ((uint64_t *)s1p)[0])
			return (ft_memcmp8(s1p, s2p, 8));
		if (((uint64_t *)s2p)[1] ^ ((uint64_t *)s1p)[1])
			return (ft_memcmp8(s1p + 8, s2p + 8, 8));
		if (((uint64_t *)s2p)[2] ^ ((uint64_t *)s1p)[2])
			return (ft_memcmp8(s1p + 16, s2p + 16, 8));
		if (((uint64_t *)s2p)[3] ^ ((uint64_t *)s1p)[3])
			return (ft_memcmp8(s1p + 24, s2p + 24, 8));
		s1p += 32;
		s2p += 32;
	}
	m8 &= 3;
	while (m8--)
	{
		if (((uint64_t *)s2p)[0] ^ ((uint64_t *)s1p)[0])
			return (ft_memcmp8(s1p, s2p, 8));
		s1p += 8;
		s2p += 8;
	}
	return (0);
}

int			ft_memcmp(const void *s1, const void *s2, size_t n)
{
	uint64_t	s1p;
	uint64_t	s2p;
	size_t		xlen;
	int			diff;

	s1p = (uint64_t)s1;
	s2p = (uint64_t)s2;
	if (n >= 16)
	{
		xlen = -s1p & 7;
		if ((diff = ft_memcmp8(s1p, s2p, xlen)))
			return (diff);
		n -= xlen;
		s1p += xlen;
		s2p += xlen;
		xlen = n >> 3;
		diff = s2p & 7 ? ft_unaligned_word_cmp(s1p, s2p & ~7, xlen) :
			ft_aligned_word_cmp(s1p, s2p, xlen);
		if (diff)
			return (diff);
		s1p += (xlen << 3);
		s2p += (xlen << 3);
		n &= 7;
	}
	return (ft_memcmp8(s1p, s2p, n));
}
