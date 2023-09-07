/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memset.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ugreyiro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/30 17:46:50 by ugreyiro          #+#    #+#             */
/*   Updated: 2020/11/04 11:53:27 by ugreyiro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memset(void *s, int c, size_t n)
{
	size_t			i;
	unsigned char	*scpy;

	scpy = (unsigned char*)s;
	i = 0;
	while (i < n)
	{
		scpy[i] = c;
		i++;
	}
	return (scpy);
}
