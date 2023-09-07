/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ugreyiro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/29 14:56:04 by ugreyiro          #+#    #+#             */
/*   Updated: 2020/11/03 14:45:40 by ugreyiro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int	nlen(int n)
{
	int		i;
	long	ncpy;

	if (n == 0)
		return (1);
	if (n < 0)
		ncpy = (long)n * (-1);
	else
		ncpy = n;
	i = 0;
	while (ncpy > 0)
	{
		ncpy /= 10;
		i++;
	}
	return (i);
}

static void	reverse_string(char *s, int len)
{
	int		i;
	int		j;
	char	tmp;

	i = 0;
	j = len - 1;
	while (i < j)
	{
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
		i++;
		j--;
	}
}

static void	create_string(char *str, long ncpy, int n)
{
	int	i;

	i = 0;
	while (ncpy > 0)
	{
		str[i] = (ncpy % 10) + '0';
		ncpy /= 10;
		i++;
	}
	if (n < 0)
	{
		str[i] = '-';
		i++;
	}
	str[i] = '\0';
}

char		*ft_itoa(int n)
{
	char	*str;
	int		len;
	long	ncpy;

	len = nlen(n);
	if (n < 0)
	{
		ncpy = (long)n * (-1);
		len += 1;
	}
	else if (n > 0)
		ncpy = n;
	else
	{
		str = (char *)malloc(sizeof(char) * 2);
		str[0] = '0';
		str[1] = '\0';
		return (str);
	}
	str = (char *)malloc(sizeof(char) * (len + 1));
	if (str == NULL)
		return (NULL);
	create_string(str, ncpy, n);
	reverse_string(str, len);
	return (str);
}
