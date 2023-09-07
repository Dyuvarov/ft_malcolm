/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_substr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ugreyiro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/28 11:48:49 by ugreyiro          #+#    #+#             */
/*   Updated: 2020/10/31 12:29:45 by ugreyiro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>
#include <stddef.h>
#include "libft.h"

char	*ft_substr(char const *s, unsigned int start, size_t len)
{
	char				*result;
	unsigned int		j;

	if (!s)
		return (NULL);
	if (start >= ft_strlen(s))
	{
		result = (char *)malloc(sizeof(char));
		result[0] = '\0';
		return (result);
	}
	j = 0;
	result = (char *)malloc(sizeof(char) * (len + 1));
	if (result != NULL)
	{
		while (j < len)
		{
			result[j] = s[start];
			start++;
			j++;
		}
		result[j] = '\0';
	}
	return (result);
}
