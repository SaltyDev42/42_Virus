/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strlen.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/12/05 00:00:00 by jye               #+#    #+#             */
/*   Updated: 2017/03/15 18:58:40 by jye              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static char	*test__(unsigned long *long_ptr)
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
	unsigned long	*long_ptr;
	unsigned long	val;
	const char		*cp;

	cp = str;
	while ((unsigned long)cp & (sizeof(*long_ptr) - 1))
	{
		if (*cp == 0)
			return (cp - str);
		++cp;
	}
	long_ptr = (unsigned long *)cp;
	while (1)
	{
		val = *long_ptr;
		if ((val - LBITS) & HBITS)
			if ((cp = test__(long_ptr)))
				return (cp - str);
		++long_ptr;
	}
}
