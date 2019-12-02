CC = gcc
CFLAGS = -Wall -Wextra

SOURCE = main.c ft_getopt_long.c
OBJECT = $(patsubst %.c, obj/%.o, $(SOURCE))
PACKER = aes_masm.s

STATIC_LIB = libft/libft.a

NAME = woody_woodpacker

all: $(NAME)


$(NAME): $(OBJECT) $(STATIC_LIB) $(PACKER:.s=.o)
	$(CC) $(OBJECT) -Llibft -lft -Ilibft -o $(NAME)

$(PACKER:.s=.o): $(PACKER)
	$(CC) -c $(PACKER)

$(STATIC_LIB):
	make -C libft

obj/%.o: src/%.c
	@mkdir -p $(shell dirname $@)
	$(CC) $(CFLAGS) -c -o $@ $< -Ilibft -Isrc

clean:
	make -C libft clean
	rm -rf obj $(PACKER:.s=.o)

fclean: clean
	make -C libft fclean
	rm -rf $(NAME)

re: fclean all

test:
	runtest --srcdir testsuite

.PHONY: all clean fclean re test
