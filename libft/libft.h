/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libft.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jye <marvin@42.fr>                         +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/03 19:43:06 by jye               #+#    #+#             */
/*   Updated: 2019/10/23 11:41:24 by virus            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_H
# define LIBFT_H
# include <string.h>

# define QWORD_LBITS 0x101010101010101L
# define QWORD_HBITS 0x8080808080808080L

# if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  define MERGE(x1, sh1, x2, sh2) (((x1) << (sh1)) | ((x2) >> (sh2)))
# else
#  define MERGE(x1, sh1, x2, sh2) (((x1) >> (sh1)) | ((x2) << (sh2)))
# endif

void			*ft_memset(void *str, int c, size_t n);
void			*ft_memcpy(void *dest, const void *src, size_t n);
void			*ft_memmove(void *dest, const void *src, size_t n);
void			*ft_memchr(const void *s, int c, size_t n);
int			ft_memcmp(const void *s1, const void *s2, size_t n);
size_t			ft_strlen(const char *str);
char			*ft_strdup(const char *str);
char			*ft_strcpy(char *dest, const char *src);
char			*ft_strncpy(char *dest, const char *src, size_t n);
char			*ft_strcat(char *dest, const char *src);
char			*ft_strchr(const char *s, int c);
char			*ft_strstr(const char *s1, const char *s2);
int			ft_strcmp(const char *s1, const char *s2);
int			ft_strncmp(const char *s1, const char *s2, size_t n);
int			ft_atoi(const char *str);
int			ft_isdigit(int c);
int			ft_isalpha(int c);
int			ft_isalnum(int c);
int			ft_isascii(int c);
int			ft_isprint(int c);
int			ft_toupper(int c);
int			ft_tolower(int c);

#endif
