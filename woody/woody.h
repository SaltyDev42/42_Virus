#ifndef __WOODY_H__
# define __WOODY_H__ 1

# include <elf.h>

# define WVICTIM(x) x##_victim
# define ELF32_E(x) ((Elf32_Ehdr *)(x))
# define ELF32_S(x) ((Elf32_Shdr *)(x))
# define ELF32_P(x) ((Elf32_Phdr *)(x))

# define SELF32_E sizeof(Elf32_Ehdr)
# define SELF32_S sizeof(Elf32_Shdr)
# define SELF32_P sizeof(Elf32_Phdr)


# define ELF64_E(x) ((Elf64_Ehdr *)(x))
# define ELF64_S(x) ((Elf64_Shdr *)(x))
# define ELF64_P(x) ((Elf64_Phdr *)(x))

# define SELF64_E sizeof(Elf64_Ehdr)
# define SELF64_S sizeof(Elf64_Shdr)
# define SELF64_P sizeof(Elf64_Phdr)

typedef struct
{
	int fd;
	int WVICTIM(fd);
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
