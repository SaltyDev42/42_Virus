/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strcmp.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/05 14:22:09 by jye               #+#    #+#             */
/*   Updated: 2017/11/30 09:03:43 by root             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int		ft_strcmp(const char *s1, const char *s2)
{
	const unsigned char *ss1;
	const unsigned char *ss2;
	unsigned char		c1;
	unsigned char		c2;

	ss1 = (const unsigned char *)s1;
	ss2 = (const unsigned char *)s2;
	c1 = *ss1;
	c2 = *ss2;
	while (c1 == c2)
	{
		if (c1 == 0)
			return (c1 - c2);
		c1 = *++ss1;
		c2 = *++ss2;
	}
	return (c1 - c2);
}
