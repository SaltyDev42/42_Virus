/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strdup.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/02 18:54:14 by jye               #+#    #+#             */
/*   Updated: 2017/11/30 08:43:20 by root             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

char	*ft_strdup(const char *src)
{
	size_t	len;
	char	*cpy;

	len = ft_strlen(src);
	if (!(cpy = (char *)malloc(len + 1)))
		return (NULL);
	cpy[len] = 0;
	ft_memcpy(cpy, src, len);
	return (cpy);
}
