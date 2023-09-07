/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strtrim.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ugreyiro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/28 16:29:58 by ugreyiro          #+#    #+#             */
/*   Updated: 2020/10/30 18:50:06 by ugreyiro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stddef.h>
#include <stdlib.h>
#include "libft.h"

static int		symb_in_set(char symb, const char *set)
{
	int j;

	j = 0;
	while (set[j])
	{
		if (symb == set[j])
			return (1);
		j++;
	}
	return (0);
}

static char		*allocate(int from, int to)
{
	char	*trimed;

	if (from > to)
		trimed = (char *)malloc(sizeof(char));
	else
		trimed = (char *)malloc(sizeof(char) * (to - from + 2));
	return (trimed);
}

char			*ft_strtrim(char const *s1, char const *set)
{
	char	*trimed;
	int		from;
	int		to;
	int		j;

	if (!s1 || !set)
		return (NULL);
	to = ft_strlen(s1) - 1;
	from = 0;
	while (s1[from] && symb_in_set(s1[from], set))
		from++;
	while (to >= 0 && symb_in_set(s1[to], set))
		to--;
	trimed = allocate(from, to);
	if (!trimed)
		return (NULL);
	j = 0;
	while (from <= to)
	{
		trimed[j] = s1[from];
		j++;
		from++;
	}
	trimed[j] = '\0';
	return (trimed);
}
