/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strrchr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ugreyiro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/11/01 13:51:35 by ugreyiro          #+#    #+#             */
/*   Updated: 2020/11/02 13:30:44 by ugreyiro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strrchr(const char *s, int c)
{
	char	*mark;
	char	*s_temp;
	int		i;
	int		len;

	len = ft_strlen(s);
	i = 0;
	mark = NULL;
	s_temp = (char *)s;
	while (i <= len)
	{
		if (s_temp[i] == c)
			mark = &(s_temp[i]);
		i++;
	}
	return (mark);
}
