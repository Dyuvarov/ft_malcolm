/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstclear.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ugreyiro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/11/02 16:06:26 by ugreyiro          #+#    #+#             */
/*   Updated: 2020/11/04 17:38:03 by ugreyiro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static void	recursive_clear(t_list *lst, void (*del)(void*))
{
	if (lst->next)
		recursive_clear(lst->next, del);
	del(lst->content);
	free(lst);
}

void		ft_lstclear(t_list **lst, void (*del)(void*))
{
	t_list	*tmp;

	if (del)
	{
		tmp = *lst;
		recursive_clear(tmp, del);
	}
	*lst = NULL;
}
