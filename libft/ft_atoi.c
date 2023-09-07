/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_atoi.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ugreyiro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/11/01 15:08:39 by ugreyiro          #+#    #+#             */
/*   Updated: 2020/11/04 15:10:35 by ugreyiro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int	ft_isspace(char c)
{
	if (c == '\t' || c == '\v' || c == '\f' || c == '\n' ||
			c == ' ' || c == '\r')
		return (1);
	else
		return (0);
}

static int	skip_start(const char *str, int *negative)
{
	int	i;

	i = 0;
	while (ft_isspace(str[i]))
		i++;
	if (str[i] == '-')
	{
		*negative = -1;
		++i;
	}
	else if (str[i] == '+')
		++i;
	return (i);
}

int			ft_atoi(const char *str)
{
	long	result;
	int		negative;
	int		i;

	result = 0;
	negative = 1;
	i = skip_start(str, &negative);
	while (str[i] >= '0' && str[i] <= '9')
	{
		result = result * 10 + (str[i] - '0');
		i++;
	}
	if (result < 0 && negative < 0)
		return (0);
	else if (result < 0 && negative > 0)
		return (-1);
	else
		return (result * negative);
}
