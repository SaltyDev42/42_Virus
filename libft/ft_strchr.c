/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/05 14:22:09 by jye               #+#    #+#             */
/*   Updated: 2017/11/30 16:27:15 by root             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdint.h>

static uint64_t	init__(uint64_t **magic, void *cp, int c)
{
	uint64_t mask;

	mask = c & 0xff;
	mask = (mask << 8) | mask;
	mask = (mask << 16) | mask;
	mask = ((mask << 16) << 16) | mask;
	*magic = (uint64_t *)cp;
	return (mask);
}

static uint8_t	*test__(uint64_t *long_ptr, uint8_t c)
{
	uint8_t		*str;
	uint32_t	i;

	str = (uint8_t *)long_ptr;
	i = 0;
	while (i < 8)
	{
		if (*str == c)
			return (str);
		else if (*str == 0)
			return (0);
		++str;
		++i;
	}
	return ((uint8_t *)1);
}

char			*ft_strchr(const char *str, int c)
{
	uint64_t	mask;
	uint64_t	*long_ptr;
	uint64_t	val;
	uint8_t		*cp;

	cp = (uint8_t *)str;
	while ((sizeof(uint64_t) - 1) & (uint64_t)cp)
	{
		if (*cp == c || *cp == 0)
			return (*cp == c ? (char *)cp : NULL);
		++cp;
	}
	mask = init__(&long_ptr, cp, c);
	while (42)
	{
		val = *long_ptr;
		if (((val - QWORD_LBITS) & QWORD_HBITS) ||
			(((val ^ mask) - QWORD_LBITS) & QWORD_HBITS))
			if ((cp = test__(long_ptr, c)) != (uint8_t *)1)
				return ((char *)cp);
		++long_ptr;
	}
}
