/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ugreyiro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/11/01 10:20:07 by ugreyiro          #+#    #+#             */
/*   Updated: 2020/11/01 10:29:07 by ugreyiro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memchr(const void *s, int c, size_t n)
{
	unsigned char	*s_temp;
	size_t			i;
	unsigned char	c_temp;

	s_temp = (unsigned char *)s;
	c_temp = (unsigned char)c;
	i = 0;
	while (i < n)
	{
		if (s_temp[i] == c_temp)
			return (&(s_temp[i]));
		i++;
	}
	return (NULL);
}
