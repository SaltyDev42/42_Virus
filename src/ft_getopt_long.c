#include <stdio.h>
#include "ft_getopt_long.h"
#include "libft.h"

#define OPT_ISOPT(opt) ((opt)[0] == '-' && (opt)[1])
#define OPT_ISLONG(opt) (!ft_strncmp((opt), "--", 2) && (opt)[2] != 0)
#define OPT_ISEND(opt) (!ft_strcmp((opt), "--"))

int	_optind;
char	*_optarg;
int	_opterr = 1;

static int
ft_getopt_long_long_no_arg(struct options_s *lopt, char *pname)
{
	if (_optarg)
	{
		if (_opterr)
			dprintf(2, "%s: '--%s' doesn't allow an argument\n",
				pname, lopt->s);
		return ('?');
	}
	if (lopt->f)
		*lopt->f = lopt->val;
	return (lopt->f ? 0 : lopt->val);
}

static int
ft_getopt_long_long_req_arg(struct options_s *lopt, char **av, char *pname)
{
	if (!_optarg)
		_optarg = av[_optind++];
	if (!_optarg)
	{
		if (_opterr)
			dprintf(2, "%s: '--%s' options requires an argument\n",
				pname, lopt->s);
		return ('?');
	}
	if (lopt->f)
		*lopt->f = lopt->val;
	return (lopt->f ? 0 : lopt->val);
}

static int
ft_getopt_long_long_opt_arg(struct options_s *lopt, char *pname)
{
	(void)pname;
	if (lopt->f)
		*lopt->f = lopt->val;
	return (lopt->f ? 0 : lopt->val);
}

static int
ft_getopt_long_long(struct options_s *lopt, char **av, char *pname)
{
	_optind += 1;
	if (lopt == NULL)
		return ('?');
	else if (lopt->has_arg == no_arg)
		return (ft_getopt_long_long_no_arg(lopt, pname));
	else if (lopt->has_arg == req_arg)
		return (ft_getopt_long_long_req_arg(lopt, av, pname));
	else
		return (ft_getopt_long_long_opt_arg(lopt, pname));
}

static void
ft_getopt_init(char **pname, char **nextchar, char *s)
{
	_optind = 1;
	*pname = s;
	*nextchar = "";
}

struct options_s
*ft_opt_getstruct_long(char *s,	struct options_s *longopt, char *pname)
{
	char	*has_arg;
	size_t	ncmp;

	has_arg = ft_strchr(s, '=');
	if (has_arg)
		_optarg = has_arg + 1;
	ncmp = (size_t)has_arg ? (size_t)(has_arg - s) : ft_strlen(s);
	while (longopt->s != NULL || longopt->has_arg != 0 || \
	       longopt->f != 0 || longopt->val != 0)
	{
		if (ncmp == ft_strlen(longopt->s) &&
		    !ft_strncmp(s, longopt->s, ncmp))
			break ;
		longopt++;
	}
	if (longopt->s == NULL && longopt->has_arg == 0 && \
	    longopt->f == 0 && longopt->val == 0)
	{
		if (_opterr)
			dprintf(2, "%s: unrecognized options '--%.*s'\n", pname,
				(int)ncmp, s);
		return (NULL);
	}
	return (longopt);
}

struct options_s
*ft_opt_getstruct(char s, struct options_s *longopt)
{
	while (longopt->s != NULL || longopt->has_arg != 0 || \
	       longopt->f != 0 || longopt->val != 0)
	{
		if (s == longopt->val)
			break ;
		longopt++;
	}
	return (longopt->s ? longopt : NULL);
}

static int
ft_getopt_(char **nextchar, char **av, struct options_s *lopt)
{
	if (lopt->has_arg == opt_arg ||
	    lopt->has_arg == req_arg)
	{
		if ((*nextchar)[1])
			_optarg = *nextchar + 1;
		else
			_optarg = av[_optind++];
		*nextchar = "";
	}
	else
		(*nextchar)++;
	if (lopt->f)
		*lopt->f = lopt->val;
	return (lopt->f ? 0 : lopt->val);
}

int
ft_getopt_long(int ac, char **av, char *optstr, struct options_s *lopt)
{
	static char	*nextchar;
	static char	*pname;

	_optarg = 0;
	if (_optind == 0)
		ft_getopt_init(&pname, &nextchar, av[0]);
	if (nextchar == NULL)
		return (-1);
	if (*nextchar == 0 &&
	    (_optind >= ac || av[_optind] == 0 || OPT_ISEND(av[_optind]))) {
		nextchar = 0;
		return (-1);
	}
	else if (*nextchar == 0 && OPT_ISLONG(av[_optind]))
		return (ft_getopt_long_long(
				ft_opt_getstruct_long(av[_optind] + 2, lopt, pname),
				av, pname));
	else if (*nextchar == 0 && OPT_ISOPT(av[_optind]))
		nextchar = av[_optind++] + 1;
	else if (*nextchar == 0) {
		nextchar = 0;
		return (-1);
	}
	if (ft_strchr(optstr, *nextchar))
		return (ft_getopt_(&nextchar, av, ft_opt_getstruct(*nextchar, lopt)));
	if (_opterr)
		dprintf(2, "%s: unrecognized option '%c'\n", pname, *nextchar++);
	return ('?');
}
