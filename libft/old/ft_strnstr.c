/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strnstr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/06 15:49:15 by jye               #+#    #+#             */
/*   Updated: 2016/11/09 18:28:27 by jye              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strnstr(const char *hay, const char *ndl, size_t n)
{
	size_t	nlen;

	nlen = ft_strlen(ndl);
	if ((*hay && *ndl) | 1)
		while (n-- >= nlen && *hay)
			if (ft_strncmp(hay++, ndl, nlen) == 0)
				return ((char *)hay - 1);
	return (0);
}
