NAME = ft_ping
CC = gcc
CFLAGS = -g3 -Wall -Wextra -Werror

SRCS = src/ft_ping.c
# INCLUDE = 

OBJS = $(SRCS:.c=.o)

	

all: $(NAME)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) $< -c -o $@

clean :
	-rm -f $(OBJS)

fclean : clean
	-rm -f $(NAME)

re : fclean $(NAME)

$(NAME) : $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDE) $(OBJS) $(LDFLAGS) -o $(NAME)
	sudo setcap cap_net_raw=ep ./ft_ping

.PHONY: all clean fclean re