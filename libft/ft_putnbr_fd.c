/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_putnbr_fd.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ugreyiro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/10/30 16:10:35 by ugreyiro          #+#    #+#             */
/*   Updated: 2020/10/30 17:04:35 by ugreyiro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static void	recursive_putnbr_fd(long ncpy, int fd, char tmp)
{
	tmp = (ncpy % 10 + '0');
	if (ncpy < 10)
		write(fd, &tmp, 1);
	else
	{
		ncpy /= 10;
		recursive_putnbr_fd(ncpy, fd, tmp);
		write(fd, &tmp, 1);
	}
}

void		ft_putnbr_fd(int n, int fd)
{
	long	ncpy;
	char	tmp;

	tmp = ' ';
	if (fd < 0)
		return ;
	if (n < 0)
	{
		ncpy = (long)n * (-1);
		write(fd, "-", 1);
	}
	else
		ncpy = n;
	recursive_putnbr_fd(ncpy, fd, tmp);
}
