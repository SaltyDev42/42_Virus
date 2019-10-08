/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_getopt_long.h                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: root <marvin@42.fr>                        +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/09/14 11:56:09 by root              #+#    #+#             */
/*   Updated: 2019/10/07 20:19:10 by virus            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_GETOPT_LONG_H
# define FT_GETOPT_LONG_H 1

enum	e_arg
{
	no_arg,
	req_arg,
	opt_arg
};

struct	options_s
{
	char	*s;
	int	has_arg;
	int	*f;
	int	val;
};

extern int	_optind;
extern char	*_optarg;
extern int	_opterr;

int
ft_getopt_long(int ac, char **av, char *optstring, struct s_options *longopt);

#endif
