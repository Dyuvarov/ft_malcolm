/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memmove.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ugreyiro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/31 15:14:55 by ugreyiro          #+#    #+#             */
/*   Updated: 2020/11/05 10:37:21 by ugreyiro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void		*ft_memmove(void *dest, const void *src, size_t n)
{
	unsigned char	*dest_temp;
	unsigned char	*src_temp;
	size_t			i;

	if (src < dest)
	{
		dest_temp = (unsigned char *)dest;
		src_temp = (unsigned char *)src;
		i = 1;
		while (i <= n)
		{
			dest_temp[n - i] = src_temp[n - i];
			i++;
		}
	}
	else
		dest_temp = ft_memcpy(dest, src, n);
	return (dest);
}
