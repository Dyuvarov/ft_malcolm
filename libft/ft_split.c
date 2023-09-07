/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_slpit.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ugreyiro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/29 10:52:06 by ugreyiro          #+#    #+#             */
/*   Updated: 2020/11/04 17:06:43 by ugreyiro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int	next_begin(char const *s, char c, int j)
{
	while (s[j] == c)
		j++;
	return (j);
}

static void	free_array(char **arr, int k)
{
	while (k >= 0)
	{
		free(arr[k]);
		--k;
	}
	free(arr);
	exit(1);
}

static int	delimiters_count(char const *s, char c)
{
	int i;
	int count;

	if (!s)
		return (0);
	i = 0;
	count = 0;
	while (s[i])
	{
		if (s[i] == c && s[i + 1] != c)
			count++;
		i++;
	}
	return ((count == 0) ? 0 : (count + 1));
}

static int	cut_str(char **arr, char const *s, char c)
{
	int	begin;
	int	j;
	int k;

	j = 0;
	k = 0;
	begin = 0;
	if (*s == '\0')
		return (0);
	while (1)
	{
		if ((s[j] == c && s[j - 1] != c && begin < j) || s[j] == '\0')
		{
			arr[k] = ft_substr(s, begin, j - begin);
			if (!arr[k])
				free_array(arr, k - 1);
			begin = next_begin(s, c, j);
			k++;
			if (s[j] == '\0')
				break ;
		}
		j++;
	}
	return (k);
}

char		**ft_split(char const *s, char c)
{
	char	**arr;
	char	*trimed_s;
	int		begin;
	int		k;
	char	set[2];

	if (!s)
	{
		arr = (char **)malloc(sizeof(char *));
		arr[0] = NULL;
		return (arr);
	}
	begin = 0;
	k = 0;
	set[0] = c;
	set[1] = '\0';
	trimed_s = ft_strtrim(s, set);
	arr = (char **)malloc(sizeof(char *) * (delimiters_count(trimed_s, c) + 1));
	if (!arr)
		return (NULL);
	k = cut_str(arr, trimed_s, c);
	free(trimed_s);
	arr[k] = NULL;
	return (arr);
}
