/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strdup.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/02 18:54:14 by jye               #+#    #+#             */
/*   Updated: 2016/11/03 13:06:43 by jye              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

char	*ft_strdup(const char *src)
{
	int		l;
	char	*a;

	l = ft_strlen(src);
	if (!(a = (char *)malloc(l * sizeof(char) + 1)))
		return (NULL);
	a[l] = 0;
	l = -1;
	while (*src)
		a[++l] = *src++;
	return (a);
}
