/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/05 14:22:09 by jye               #+#    #+#             */
/*   Updated: 2017/03/29 15:22:52 by root             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

static unsigned long	init__(unsigned long **magic, void *cp, unsigned char c)
{
	unsigned long mask;

	mask = c;
	mask = (mask << 8) | mask;
	mask = (mask << 16) | mask;
	mask = ((mask << 16) << 16) | mask;
	*magic = (unsigned long *)cp;
	return (mask);
}

static unsigned char	*test__(unsigned long *long_ptr, unsigned char c)
{
	unsigned char	*str;
	unsigned int	i;

	str = (unsigned char *)long_ptr;
	i = 0;
	while (i < sizeof(unsigned long))
	{
		if (*str == c)
			return (str);
		else if (*str == 0)
			return (NULL);
		++str;
		++i;
	}
	return ((unsigned char *)1);
}

char					*ft_strchr(const char *str, unsigned char c)
{
	unsigned long	mask;
	unsigned long	*long_ptr;
	unsigned long	val;
	unsigned char	*cp;

	cp = (unsigned char *)str;
	while ((sizeof(unsigned long) - 1) & (unsigned long)cp)
	{
		if (*cp == c || *cp == 0)
			return (*cp == c ? (char *)cp : NULL);
		++cp;
	}
	mask = init__(&long_ptr, cp, c);
	while (42)
	{
		val = *long_ptr;
		if (((val - LBITS) & HBITS) || (((val ^ mask) - LBITS) & HBITS))
			if ((long)(cp = test__(long_ptr, c)) != 1L)
				return ((char *)cp);
		++long_ptr;
	}
}
