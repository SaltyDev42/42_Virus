/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strstr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/05 14:22:09 by jye               #+#    #+#             */
/*   Updated: 2017/11/30 08:58:05 by root             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strstr(const char *hay, const char *ndl)
{
	size_t	nlen;

	nlen = ft_strlen(ndl);
	while (ft_memcmp(hay, ndl, nlen))
		if (!(*hay++))
			return (NULL);
	return ((char *)hay);
}
