/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strncat.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/05 14:22:09 by jye               #+#    #+#             */
/*   Updated: 2016/11/06 14:51:00 by jye              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strncat(char *dst, const char *src, size_t n)
{
	size_t dlen;
	size_t slen;
	size_t clen;

	dlen = ft_strlen(dst);
	slen = ft_strlen(src);
	clen = slen < n ? slen : n;
	ft_memcpy(dst + dlen, src, clen);
	dst[dlen + clen] = '\0';
	return (dst);
}
