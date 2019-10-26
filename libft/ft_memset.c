/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memset.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/03 19:47:40 by jye               #+#    #+#             */
/*   Updated: 2019/02/01 21:35:41 by jye              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdint.h>

static inline void	ft_memset64(uint64_t dstp, int c, size_t m8)
{
	register size_t		xlen;
	register uint64_t	mask_set;

	mask_set = c << 8 | c;
	mask_set = (mask_set << 16) | mask_set;
	mask_set = ((mask_set << 16) << 16) | mask_set;
	xlen = m8 >> 3;
	while (xlen--)
	{
		((uint64_t *)dstp)[0] = mask_set;
		((uint64_t *)dstp)[1] = mask_set;
		((uint64_t *)dstp)[2] = mask_set;
		((uint64_t *)dstp)[3] = mask_set;
		((uint64_t *)dstp)[4] = mask_set;
		((uint64_t *)dstp)[5] = mask_set;
		((uint64_t *)dstp)[6] = mask_set;
		((uint64_t *)dstp)[7] = mask_set;
		dstp += 64;
	}
	m8 &= 7;
	while (m8--)
	{
		((uint64_t *)dstp)[0] = mask_set;
		dstp += 8;
	}
}

static inline void	ft_memset8(uint64_t dstp, int c, size_t len)
{
	while (len--)
		((uint8_t *)dstp++)[0] = c;
}

void				*ft_memset(void *mem, int c, size_t mlen)
{
	uint64_t	dstp;
	size_t		xlen;

	dstp = (uint64_t)mem;
	c &= 0xff;
	if (mlen >= 16)
	{
		xlen = -dstp & 7;
		ft_memset8(dstp, c, xlen);
		mlen -= xlen;
		dstp += xlen;
		xlen = mlen >> 3;
		ft_memset64(dstp, c, xlen);
		dstp += (xlen << 3);
		mlen &= 7;
	}
	ft_memset8(dstp, c, mlen);
	return (mem);
}
