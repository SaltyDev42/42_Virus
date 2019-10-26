/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strncmp.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/05 14:22:09 by jye               #+#    #+#             */
/*   Updated: 2017/12/21 04:48:18 by jye              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int		ft_strncmp(const char *s1, const char *s2, size_t n)
{
	const unsigned char *ss1;
	const unsigned char *ss2;
	unsigned char		c1;
	unsigned char		c2;

	ss1 = (const unsigned char *)s1;
	ss2 = (const unsigned char *)s2;
	c1 = 0;
	c2 = 0;
	while (n--)
	{
		c1 = *ss1++;
		c2 = *ss2++;
		if (c1 == 0 || c1 != c2)
			return (c1 - c2);
	}
	return (c1 - c2);
}
