/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strsplit.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/06 00:00:00 by jye               #+#    #+#             */
/*   Updated: 2016/11/11 19:51:11 by jye              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

static int		h_count(const char *s, char c)
{
	int		n;

	n = 0;
	if (!s)
		return (-1);
	while (*s)
	{
		while (*s && *s == c)
			++s;
		if (*s != 0x00)
			++n;
		while (*s && *s != c)
			++s;
	}
	return (n);
}

static size_t	h_len(const char *s, char c)
{
	size_t n;

	n = 0;
	while (*s && *s != c)
	{
		++s;
		++n;
	}
	return (n);
}

static void		h_abort(char ***s, size_t n)
{
	char **todel;

	todel = *s;
	while (*todel && n--)
	{
		free(*todel++);
	}
	free(*s);
	*s = NULL;
}

char			**ft_strsplit(const char *s, char c)
{
	char	**fresh;
	char	**start;
	int		n;
	size_t	wlen;
	size_t	abort;

	if ((n = h_count(s, c)) == -1)
		return (NULL);
	wlen = 0;
	if (!(fresh = (char **)malloc(sizeof(char *) * n + 1)))
		return (NULL);
	fresh[n] = NULL;
	start = fresh;
	abort = n;
	while (start && n-- && (s += wlen))
	{
		while (*s && *s == c)
			++s;
		wlen = h_len(s, c);
		if (!(*fresh = ft_strnew(wlen + 1)))
			h_abort(&start, abort - n);
		if (start)
			ft_strncpy(*fresh++, s, wlen);
	}
	return (start);
}
