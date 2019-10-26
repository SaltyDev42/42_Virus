/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strlen.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/12/05 00:00:00 by jye               #+#    #+#             */
/*   Updated: 2017/12/21 04:47:47 by jye              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdint.h>

static char	*maybe(uint64_t *long_ptr)
{
	char *cp;

	cp = (char *)long_ptr;
	if (*cp == 0)
		return (cp);
	if (*++cp == 0)
		return (cp);
	if (*++cp == 0)
		return (cp);
	if (*++cp == 0)
		return (cp);
	if (*++cp == 0)
		return (cp);
	if (*++cp == 0)
		return (cp);
	if (*++cp == 0)
		return (cp);
	if (*++cp == 0)
		return (cp);
	return (NULL);
}

size_t		ft_strlen(const char *str)
{
	uint64_t		*long_ptr;
	uint64_t		val;
	const char		*cp;

	cp = str;
	while ((uint64_t)cp & (sizeof(*long_ptr) - 1))
	{
		if (*cp == 0)
			return (cp - str);
		++cp;
	}
	long_ptr = (uint64_t *)cp;
	while (1)
	{
		val = *long_ptr;
		if ((val - QWORD_LBITS) & QWORD_HBITS)
			if ((cp = maybe(long_ptr)))
				return (cp - str);
		++long_ptr;
	}
}
