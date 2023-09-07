/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_bzero.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ugreyiro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/31 13:05:57 by ugreyiro          #+#    #+#             */
/*   Updated: 2020/11/02 13:25:50 by ugreyiro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_bzero(void *s, size_t n)
{
	size_t			i;
	unsigned char	*temp;

	if (n > 0)
	{
		i = 0;
		temp = (unsigned char*)s;
		while (i < n)
		{
			temp[i] = '\x0';
			i++;
		}
		s = temp;
	}
}
