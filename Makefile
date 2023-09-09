NAME		= ft_malcolm
INC_DIR		= ./includes
SRC_DIR		= ./src
CC			= gcc
TEMP		= main.c malcolm_validator.c
			  
SRCS		= $(addprefix $(SRC_DIR)/, $(TEMP))
OBJS		= $(SRCS:.c=.o)
LIBFT_DIR	= libft
LIBS		= -L$(LIBFT_DIR) -lft
CFLAGS		= -I $(INC_DIR) -I $(LIBFT_DIR)
SMAKE		= make -s

.c.o:		
			$(CC) $(CFLAGS) -c  $< -o ${<:.c=.o}

all:		$(NAME)

libft:
			make -C $(LIBFT_DIR)

$(NAME):	$(OBJS)
			$(SMAKE) libft
			$(CC) $(CFLAGS) -I $(INC_DIR) $(OBJS) $(LIBS) -o $(NAME)

clean:
			rm -rf $(OBJS)
			$(SMAKE) clean -C $(LIBFT_DIR)

fclean:		clean
			rm -rf $(NAME)
			$(SMAKE) fclean -C $(LIBFT_DIR)

re:			fclean all

.PHONY:		all clean fclean re libft