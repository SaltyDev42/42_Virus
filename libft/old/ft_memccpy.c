/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memccpy.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/04 14:45:53 by jye               #+#    #+#             */
/*   Updated: 2016/11/09 17:08:42 by jye              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memccpy(void *dest, const void *src, int c, size_t n)
{
	unsigned char		uc;
	unsigned char		*t;
	const unsigned char	*p;

	if (n)
	{
		t = (unsigned char *)dest;
		p = (const unsigned char *)src;
		uc = (unsigned char)c;
		while (n--)
			if ((*t++ = *p++) == uc)
				return (t);
	}
	return (NULL);
}
