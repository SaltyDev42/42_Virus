/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strsub.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/06 00:00:00 by jye               #+#    #+#             */
/*   Updated: 2016/11/07 15:11:51 by jye              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strsub(const char *s, unsigned int i, size_t len)
{
	char	*fresh;
	char	*d;

	if (!s)
		return (NULL);
	if (!(fresh = ft_strnew(len)))
		return (NULL);
	s += i;
	d = fresh;
	while (len--)
		*d++ = *s++;
	return (fresh);
}
