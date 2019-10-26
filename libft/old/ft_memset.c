/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memset.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/03 19:47:40 by jye               #+#    #+#             */
/*   Updated: 2017/03/15 19:02:34 by jye              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static unsigned long	init__(unsigned long **magic, void *cp, int c)
{
	unsigned long bmagic;

	*magic = (unsigned long *)cp;
	if (c == 0)
		return (0);
	bmagic = 0xff & c;
	bmagic = (bmagic << 8) | bmagic;
	bmagic = (bmagic << 16) | bmagic;
	bmagic = ((bmagic << 16) << 16) | bmagic;
	return (bmagic);
}

void					*ft_memset(void *mem, int c, size_t mlen)
{
	unsigned long bmagic;
	unsigned long *magic;
	unsigned char *cp;

	magic = NULL;
	cp = (unsigned char *)mem;
	while (((unsigned long)cp & (sizeof(bmagic) - 1)) && mlen)
	{
		*cp++ = c;
		--mlen;
	}
	if (mlen >= 8)
	{
		bmagic = init__(&magic, cp, c);
		while (mlen >= 8)
		{
			*magic++ = bmagic;
			mlen -= 8;
		}
	}
	if (magic != NULL)
		cp = (unsigned char *)magic;
	while (mlen--)
		*cp++ = c;
	return (mem);
}
