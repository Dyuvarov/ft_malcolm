/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstmap.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ugreyiro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/11/02 16:24:06 by ugreyiro          #+#    #+#             */
/*   Updated: 2020/11/02 17:06:36 by ugreyiro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

t_list	*ft_lstmap(t_list *l, void *(*f)(void *), void (*del)(void *))
{
	t_list	*result;
	t_list	*rtmp;
	t_list	*tmp;

	if (!l || !f)
		return (NULL);
	result = ft_lstnew(f(l->content));
	if (!result)
		return (NULL);
	tmp = l->next;
	while (tmp)
	{
		rtmp = ft_lstnew(f(tmp));
		if (!rtmp)
			ft_lstclear(&result, del);
		ft_lstadd_back(&result, rtmp);
		tmp = tmp->next;
	}
	return (result);
}
