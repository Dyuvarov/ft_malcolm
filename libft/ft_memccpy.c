/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memccpy.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ugreyiro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/31 13:43:03 by ugreyiro          #+#    #+#             */
/*   Updated: 2020/11/02 13:27:11 by ugreyiro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memccpy(void *dst, const void *src, int c, size_t n)
{
	unsigned char	*dst_temp;
	unsigned char	*src_temp;
	unsigned char	c_temp;
	size_t			i;

	c_temp = (unsigned char)c;
	dst_temp = (unsigned char *)dst;
	src_temp = (unsigned char*)src;
	i = 0;
	while (i < n)
	{
		dst_temp[i] = src_temp[i];
		if (dst_temp[i] == c_temp)
		{
			return (&(dst_temp[i + 1]));
		}
		i++;
	}
	return (NULL);
}
