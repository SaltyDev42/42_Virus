/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strmapi.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/06 00:00:00 by jye               #+#    #+#             */
/*   Updated: 2016/11/07 15:03:32 by jye              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strmapi(const char *s, char (*f)(unsigned int, char))
{
	char	*fresh;
	char	*t;
	size_t	n;

	if (!s || !f)
		return (NULL);
	n = 0;
	if (!(fresh = ft_strnew(ft_strlen(s))))
		return (NULL);
	t = fresh;
	while (*s)
		*t++ = f(n++, *s++);
	return (fresh);
}
