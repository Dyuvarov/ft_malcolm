/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strjoin.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ugreyiro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/28 12:33:10 by ugreyiro          #+#    #+#             */
/*   Updated: 2020/11/03 15:15:26 by ugreyiro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stddef.h>
#include <stdlib.h>
#include "libft.h"

static int	add_str(char *result, char const *s, int k)
{
	int j;

	j = 0;
	while (s[j])
	{
		result[k] = s[j];
		j++;
		k++;
	}
	return (k);
}

char		*ft_strjoin(char const *s1, char const *s2)
{
	char			*result;
	int				j;
	int				k;

	if (!s1 || !s2)
		return (NULL);
	j = 0;
	k = 0;
	result = (char *)malloc(sizeof(char) * (ft_strlen(s1) + ft_strlen(s2) + 1));
	if (result)
	{
		k = add_str(result, s1, k);
		k = add_str(result, s2, k);
		result[k] = '\0';
	}
	return (result);
}
