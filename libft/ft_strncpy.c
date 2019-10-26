/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strncpy.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/05 14:22:09 by jye               #+#    #+#             */
/*   Updated: 2017/12/02 02:50:41 by jye              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strncpy(char *dest, const char *src, size_t n)
{
	size_t	len;

	len = ft_strlen(src);
	if (n > len)
	{
		ft_memset(dest + len, 0, n - len);
		return (ft_memcpy(dest, src, len));
	}
	return (ft_memcpy(dest, src, n));
}
