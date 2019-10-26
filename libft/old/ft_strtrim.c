/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strtrim.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/06 00:00:00 by jye               #+#    #+#             */
/*   Updated: 2016/11/07 18:27:56 by jye              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

static int	h_end(const char *s)
{
	int		n;
	int		i;

	n = 0;
	i = 0;
	while (s[i])
	{
		if (s[i] != ' ' && s[i] != '\t' && s[i] != '\n')
			n = i;
		i++;
	}
	return (n);
}

static int	h_head(const char *s)
{
	int		n;

	n = 0;
	while (s[n] == ' ' || s[n] == '\t' || s[n] == '\n')
		n++;
	return (n);
}

char		*ft_strtrim(const char *s)
{
	char	*fresh;
	char	*t;
	int		head;
	int		end;
	size_t	clen;

	if (s == NULL)
		return (NULL);
	head = h_head(s);
	end = h_end(s);
	clen = end - head < 0 ? 0 : end - head + 1;
	if ((fresh = ft_strnew(clen)) == NULL)
		return (NULL);
	t = fresh;
	while (head <= end)
		*t++ = s[head++];
	return (fresh);
}
