/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strstr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/05 14:22:09 by jye               #+#    #+#             */
/*   Updated: 2016/11/06 15:38:12 by jye              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strstr(const char *hay, const char *ndl)
{
	size_t	nlen;

	nlen = ft_strlen(ndl);
	if (*ndl)
	{
		while (ft_strncmp(hay, ndl, nlen))
			if (!(*hay++))
				return (NULL);
	}
	return ((char *)hay);
}
