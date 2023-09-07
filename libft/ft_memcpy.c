/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memcpy.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ugreyiro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/31 13:31:25 by ugreyiro          #+#    #+#             */
/*   Updated: 2020/11/04 15:46:03 by ugreyiro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memcpy(void *dst, const void *src, size_t n)
{
	size_t			i;
	unsigned char	*dst_temp;
	unsigned char	*src_temp;

	if (!dst && !src)
		return (NULL);
	dst_temp = (unsigned char*)dst;
	src_temp = (unsigned char*)src;
	i = 0;
	while (i < n)
	{
		dst_temp[i] = src_temp[i];
		i++;
	}
	return (dst_temp);
}
