/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memmove.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/04 15:49:06 by jye               #+#    #+#             */
/*   Updated: 2016/11/09 16:38:18 by jye              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memmove(void *dest, const void *src, size_t n)
{
	unsigned char		*dc;
	const unsigned char	*sc;

	sc = (const unsigned char *)src;
	dc = (unsigned char *)dest;
	if (sc > dc)
		while (n--)
			*dc++ = *sc++;
	else
	{
		dc += n;
		sc += n;
		while (n--)
			*--dc = *--sc;
	}
	return (dest);
}
