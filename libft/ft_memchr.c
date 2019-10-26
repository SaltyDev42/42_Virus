/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/04 16:57:12 by jye               #+#    #+#             */
/*   Updated: 2017/12/02 03:04:28 by jye              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdint.h>

static inline void	*ft_memchr8(uint64_t dstp, int c, size_t n)
{
	register uint8_t	dstc;

	while (n--)
	{
		dstc = ((uint8_t *)dstp)[0];
		if (dstc == c)
			return ((void *)dstp);
		++dstp;
	}
	return (0);
}

static void			*ft_memchr64(uint64_t dstp, int c, size_t n)
{
	register size_t		xlen;
	register uint64_t	mask_set;
	register uint64_t	lo_magic;
	register uint64_t	hi_magic;
	uint64_t			dstpp;

	lo_magic = QWORD_LBITS;
	hi_magic = QWORD_HBITS;
	mask_set = c << 8 | c;
	mask_set = (mask_set << 16) | mask_set;
	mask_set = ((mask_set << 16) << 16) | mask_set;
	xlen = n >> 3;
	while (xlen--)
	{
		if ((((((uint64_t *)dstp)[0] ^ mask_set) - lo_magic) & hi_magic))
			if ((dstpp = (uint64_t)ft_memchr8(dstp, c, 8)))
				return ((void *)dstpp);
		dstp += 8;
	}
	return (ft_memchr8(dstp, c, n & 7));
}

void				*ft_memchr(const void *mem, int c, size_t n)
{
	uint64_t	dstp;
	size_t		xlen;
	void		*ret;

	dstp = (uint64_t)mem;
	c &= 0xff;
	if (n >= 16)
	{
		xlen = -dstp & 7;
		if ((ret = ft_memchr8(dstp, c, xlen)))
			return (ret);
		dstp += xlen;
		n -= xlen;
		return (ft_memchr64(dstp, c, n));
	}
	return (ft_memchr8(dstp, c, n));
}
