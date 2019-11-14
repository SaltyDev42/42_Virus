#ifndef __WOODY_H__
# define __WOODY_H__ 1

# include <elf.h>
# include <sys/stat.h>

# define ELF32_E(x)    ((volatile Elf32_Ehdr *)(x))
# define ELF32_S(x)    ((volatile Elf32_Shdr *)(x))
# define ELF32_P(x)    ((volatile Elf32_Phdr *)(x))
# define ELF32_ST(x)   ((volatile Elf32_Sym *)(x))
# define ELF32_RELA(x) ((volatile Elf32_Rela *)(x))
# define ELF32_DYN(x)  ((volatile Elf32_Dyn *)(x))

# define SELF32_E    sizeof(Elf32_Ehdr)
# define SELF32_S    sizeof(Elf32_Shdr)
# define SELF32_P    sizeof(Elf32_Phdr)
# define SELF32_ST   sizeof(Elf32_Sym)
# define SELF32_RELA sizeof(Elf32_Rela)
# define SELF32_DYN  sizeof(Elf32_Dyn)

# define ELF64_E(x)    ((volatile Elf64_Ehdr *)(x))
# define ELF64_S(x)    ((volatile Elf64_Shdr *)(x))
# define ELF64_P(x)    ((volatile Elf64_Phdr *)(x))
# define ELF64_ST(x)   ((volatile Elf64_Sym *)(x))
# define ELF64_RELA(x) ((volatile Elf64_Rela *)(x))
# define ELF64_DYN(x)  ((volatile Elf64_Dyn *)(x))

# define SELF64_E    sizeof(Elf64_Ehdr)
# define SELF64_S    sizeof(Elf64_Shdr)
# define SELF64_P    sizeof(Elf64_Phdr)
# define SELF64_ST   sizeof(Elf64_Sym)
# define SELF64_RELA sizeof(Elf64_Rela)
# define SELF64_DYN  sizeof(Elf64_Dyn)

#define FSIGN_TSIZE 7
#define FSIGN_STR "<sign>\n"
#define DIR_CIBLE "test"

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
