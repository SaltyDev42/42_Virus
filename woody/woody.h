#ifndef __WOODY_H__
# define __WOODY_H__ 1

# include <elf.h>
# include <sys/stat.h>

# define ELF32_E(x)    ((Elf32_Ehdr *)(x))
# define ELF32_S(x)    ((Elf32_Shdr *)(x))
# define ELF32_P(x)    ((Elf32_Phdr *)(x))
# define ELF32_ST(x)   ((Elf32_Sym *)(x))
# define ELF32_RELA(x) ((Elf64_Rela *)(x))

# define SELF32_E    sizeof(Elf32_Ehdr)
# define SELF32_S    sizeof(Elf32_Shdr)
# define SELF32_P    sizeof(Elf32_Phdr)
# define SELF32_ST   sizeof(Elf32_Sym)
# define SELF64_RELA sizeof(Elf64_Rela)

# define ELF64_E(x)    ((Elf64_Ehdr *)(x))
# define ELF64_S(x)    ((Elf64_Shdr *)(x))
# define ELF64_P(x)    ((Elf64_Phdr *)(x))
# define ELF64_ST(x)   ((Elf64_Sym *)(x))
# define ELF64_RELA(x) ((Elf64_Rela *)(x))

# define SELF64_E    sizeof(Elf64_Ehdr)
# define SELF64_S    sizeof(Elf64_Shdr)
# define SELF64_P    sizeof(Elf64_Phdr)
# define SELF64_ST   sizeof(Elf64_Sym)
# define SELF64_RELA sizeof(Elf64_Rela)

# define WPACKER_TSIZE 0x80

typedef struct
{
	const char *name;

	int fd;
	void *map;
	struct stat stat;

	unsigned char *ident;
	void *ehdr;
	void *phdr;
	void *shdr;
} WFILE;

typedef struct
{
	WFILE wfile;
	Elf64_Off pack_off;
	Elf64_Xword pack_sz;

	Elf64_Off unpack_off;
	Elf64_Xword unpack_sz;

} WPAYLOAD;

#endif
