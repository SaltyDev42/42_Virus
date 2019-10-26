/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memmove.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/04 15:49:06 by jye               #+#    #+#             */
/*   Updated: 2017/12/21 04:45:00 by jye              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdint.h>

static void	ft_word_copy_dest_aligned(uint64_t dstp, uint64_t srcp, size_t m8)
{
	uint64_t	w[2];
	size_t		xlen;
	int			sh[2];

	xlen = m8 >> 1;
	sh[0] = (srcp & 7) * 8;
	sh[1] = 64 - sh[0];
	srcp -= 8;
	dstp -= 16;
	srcp &= ~7;
	w[1] = ((uint64_t *)srcp)[1];
	while (xlen--)
	{
		w[0] = ((uint64_t *)srcp)[0];
		((uint64_t *)dstp)[1] = MERGE(w[0], sh[0], w[1], sh[1]);
		srcp -= 16;
		w[1] = ((uint64_t *)srcp)[1];
		((uint64_t *)dstp)[0] = MERGE(w[1], sh[0], w[0], sh[1]);
		dstp -= 16;
	}
	if (m8 & 1)
	{
		w[0] = ((uint64_t *)srcp)[0];
		((uint64_t *)dstp)[1] = MERGE(w[0], sh[0], w[1], sh[1]);
	}
}

static void	ft_word_copy_aligned(uint64_t dstp, uint64_t srcp, size_t m8)
{
	uint64_t	w;
	size_t		xlen;

	xlen = m8 >> 2;
	while (xlen--)
	{
		dstp -= 32;
		srcp -= 32;
		w = ((uint64_t *)srcp)[3];
		((uint64_t *)dstp)[3] = w;
		w = ((uint64_t *)srcp)[2];
		((uint64_t *)dstp)[2] = w;
		w = ((uint64_t *)srcp)[1];
		((uint64_t *)dstp)[1] = w;
		w = ((uint64_t *)srcp)[0];
		((uint64_t *)dstp)[0] = w;
	}
	m8 &= 3;
	while (m8--)
	{
		dstp -= 8;
		srcp -= 8;
		w = ((uint64_t *)srcp)[0];
		((uint64_t *)dstp)[0] = w;
	}
}

static void	ft_byte_copy_bwd(uint64_t dst, uint64_t src, size_t n)
{
	while (n--)
		((uint8_t *)--dst)[0] = ((uint8_t *)--src)[0];
}

static void	ft_memcpy_bwd(uint64_t dstp, uint64_t srcp, size_t n)
{
	size_t		xlen;

	dstp += n;
	srcp += n;
	if (n >= 16)
	{
		xlen = dstp & 7;
		ft_byte_copy_bwd(dstp, srcp, xlen);
		dstp -= xlen;
		srcp -= xlen;
		n -= xlen;
		xlen = n >> 3;
		if (srcp & 7)
			ft_word_copy_dest_aligned(dstp, srcp, xlen);
		else
			ft_word_copy_aligned(dstp, srcp, xlen);
		dstp -= (xlen << 3);
		srcp -= (xlen << 3);
		n &= 7;
	}
	ft_byte_copy_bwd(dstp, srcp, n);
}

void		*ft_memmove(void *dst, const void *src, size_t n)
{
	uint64_t	dstp;
	uint64_t	srcp;

	dstp = (uint64_t)dst;
	srcp = (uint64_t)src;
	if (dstp - srcp >= n)
		ft_memcpy(dst, src, n);
	else
		ft_memcpy_bwd(dstp, srcp, n);
	return (dst);
}
