#ifndef __WOODY_H__
# define __WOODY_H__ 1

# include <elf.h>

# define WVICTIM(x) x##_victim
# define ELF32_E(x) ((Elf32_Ehdr *)(x))
# define ELF64_E(x) ((Elf64_Ehdr *)(x))
# define ELF32_S(x) ((Elf32_Shdr *)(x))
# define ELF64_S(x) ((Elf64_Shdr *)(x))
# define ELF32_P(x) ((Elf32_Phdr *)(x))
# define ELF64_P(x) ((Elf64_Phdr *)(x))

typedef struct
{
	int fd;
	int WVICIM(fd);
	void *map;
	void *WVICTIM(map);
	void *bottom;
	void *WVICTIM(bottom);

	unsigned char *ident;
	void *ehdr;
	void *phdr;
	void *shdr;

	int ntext;
	int ndata;
	int nrodata;
} WOODFILE;

#endif
