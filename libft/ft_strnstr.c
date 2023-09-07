/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strnstr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ugreyiro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/11/01 14:17:50 by ugreyiro          #+#    #+#             */
/*   Updated: 2020/11/04 12:33:51 by ugreyiro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int	issub(const char *hayst, const char *needle, size_t i, size_t nlen)
{
	size_t	j;
	int		eq;

	eq = 1;
	j = 0;
	while (j < nlen)
	{
		if (hayst[i] != needle[j])
		{
			eq = 0;
			break ;
		}
		++i;
		++j;
	}
	return (eq);
}

char		*ft_strnstr(const char *hayst, const char *needle, size_t len)
{
	size_t	i;
	size_t	n_len;

	n_len = ft_strlen(needle);
	if (!needle || ft_strlen(hayst) < n_len)
		return (NULL);
	if (!n_len)
		return ((char *)hayst);
	i = 0;
	while (hayst[i] && ((i + n_len - 1) < len))
	{
		if (hayst[i] == needle[0])
		{
			if (issub(hayst, needle, i, n_len))
				return ((char *)&(hayst[i]));
		}
		++i;
	}
	return (NULL);
}
