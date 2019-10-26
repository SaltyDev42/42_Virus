/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strlcat.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/05 14:22:09 by jye               #+#    #+#             */
/*   Updated: 2016/11/11 20:15:46 by jye              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

size_t	ft_strlcat(char *dst, const char *src, size_t sz)
{
	char		*d;
	const char	*s;
	size_t		dlen;
	size_t		clen;
	size_t		slen;

	d = dst;
	s = src;
	dlen = ft_strlen(dst);
	slen = ft_strlen(src);
	d += dlen;
	if (dlen >= sz)
		return (sz + slen);
	clen = sz - dlen - 1;
	if (clen > slen)
		clen = slen;
	ft_strncpy(d, s, clen);
	dst[dlen + clen] = 0;
	return (slen + dlen);
}
