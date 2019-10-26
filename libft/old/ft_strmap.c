/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strmap.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/06 00:00:00 by jye               #+#    #+#             */
/*   Updated: 2016/11/07 15:01:01 by jye              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strmap(const char *s, char (*f)(char))
{
	char	*fresh;
	char	*t;

	if (!s || !f)
		return (NULL);
	if (!(fresh = ft_strnew(ft_strlen(s))))
		return (NULL);
	t = fresh;
	while (*s)
		*t++ = f(*s++);
	return (fresh);
}
