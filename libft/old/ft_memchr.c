/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/04 16:57:12 by jye               #+#    #+#             */
/*   Updated: 2017/03/15 19:15:04 by jye              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static unsigned long	init__(unsigned long **magic, void *cp,
									const unsigned char c)
{
	unsigned long mask;

	mask = c;
	mask = (mask << 8) | mask;
	mask = (mask << 16) | mask;
	mask = ((mask << 16) << 16) | mask;
	*magic = (unsigned long *)cp;
	return (mask);
}

static unsigned char	*test__(void *mem, const unsigned char c)
{
	unsigned char *cp;

	cp = (unsigned char *)mem;
	if (*cp == c)
		return (cp);
	if (*++cp == c)
		return (cp);
	if (*++cp == c)
		return (cp);
	if (*++cp == c)
		return (cp);
	if (*++cp == c)
		return (cp);
	if (*++cp == c)
		return (cp);
	if (*++cp == c)
		return (cp);
	if (*++cp == c)
		return (cp);
	return (NULL);
}

static void				*last_bytes__(unsigned char *cp, void *magic,
							const unsigned char c, size_t n)
{
	if (magic)
		cp = (unsigned char *)magic;
	while (n--)
	{
		if (*cp == c)
			return ((void *)cp);
		else
			++cp;
	}
	return (NULL);
}

void					*ft_memchr(const void *mem, const unsigned char c,
									size_t n)
{
	unsigned long	mask;
	unsigned long	*magic;
	unsigned char	*cp;

	cp = (unsigned char *)mem;
	magic = NULL;
	while (((sizeof(unsigned long) - 1) & (unsigned long)cp) && n)
	{
		if (*cp++ == c)
			return (cp - 1);
		--n;
	}
	if (n >= 8)
	{
		mask = init__(&magic, cp, c);
		while (n >= 8)
		{
			if ((((*magic ^ mask) - LBITS) & HBITS))
				if ((cp = test__(magic, c)))
					return ((void *)cp);
			++magic;
			n -= 8;
		}
	}
	return (last_bytes__(cp, magic, c, n));
}
