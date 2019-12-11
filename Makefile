CC = gcc
CFLAGS = -Wall -Wextra -fno-stack-protector -nostartfiles
ASM = nasm
ASMFLAGS = -f elf64

SOURCE = main.c syscall.s
OBJECT = $(patsubst %.c, obj/%.o, $(SOURCE))
OBJECT = obj/main.o obj/syscall.o

STATIC_LIB = libfts/libfts.a

NAME = famine

all: $(NAME)


$(NAME): $(OBJECT) $(STATIC_LIB) $(PACKER:.s=.o)
	$(CC) $(OBJECT) -Ilibfts/include -o $(NAME) $(STATIC_LIB)

$(PACKER:.s=.o): $(PACKER)
	$(CC) -c $(PACKER)

$(STATIC_LIB):
	make -C libfts

obj/%.o: src/%.s
	@mkdir -p $(shell dirname $@)
	$(ASM) $(ASMFLAGS) -o $@ $<

obj/%.o: src/%.c
	@mkdir -p $(shell dirname $@)
	$(CC) $(CFLAGS) -c -o $@ $< -Ilibfts/include -Isrc

clean:
	make -C libfts clean
	rm -rf obj $(PACKER:.s=.o)

fclean: clean
	make -C libfts fclean
	rm -rf $(NAME)

re: fclean all

test:
	runtest --srcdir testsuite

.PHONY: all clean fclean re test
