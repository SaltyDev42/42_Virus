/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/06 00:00:00 by jye               #+#    #+#             */
/*   Updated: 2016/11/08 16:24:29 by jye              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

static int	h_szint(int z)
{
	int n;

	n = 1;
	if (z < 0)
		while (z < -9)
		{
			z /= 10;
			n++;
		}
	else
		while (z > 9)
		{
			z /= 10;
			n++;
		}
	return (n);
}

static char	*h_cpy(char *fresh, int z, int n)
{
	char	*t;

	if (z < 0)
	{
		t = fresh + n + 1;
		while (t != fresh)
		{
			*--t = 0x30 - (z % 10);
			z = z / 10;
		}
		*t = '-';
	}
	else
	{
		t = fresh + n;
		while (t >= fresh)
		{
			*--t = 0x30 + (z % 10);
			z = z / 10;
		}
	}
	return (fresh);
}

char		*ft_itoa(int z)
{
	int		n;
	char	*fresh;

	n = h_szint(z);
	if (z < 0)
	{
		if ((fresh = ft_strnew(n + 1)) == NULL)
			return (NULL);
		fresh = h_cpy(fresh, z, n);
	}
	else
	{
		if ((fresh = ft_strnew(n)) == NULL)
			return (NULL);
		fresh = h_cpy(fresh, z, n);
	}
	return (fresh);
}
