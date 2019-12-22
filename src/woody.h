#ifndef __WOODY_H__
# define __WOODY_H__ 1

# include <elf.h>
# include <sys/stat.h>

# define ELF32_E(x)    ((Elf32_Ehdr *)(x))
# define ELF32_S(x)    ((Elf32_Shdr *)(x))
# define ELF32_P(x)    ((Elf32_Phdr *)(x))
# define ELF32_ST(x)   ((Elf32_Sym *)(x))
# define ELF32_RELA(x) ((Elf32_Rela *)(x))
# define ELF32_DYN(x)  ((Elf32_Dyn *)(x))

# define SELF32_E    sizeof(Elf32_Ehdr)
# define SELF32_S    sizeof(Elf32_Shdr)
# define SELF32_P    sizeof(Elf32_Phdr)
# define SELF32_ST   sizeof(Elf32_Sym)
# define SELF32_RELA sizeof(Elf32_Rela)
# define SELF32_DYN  sizeof(Elf32_Dyn)

# define ELF64_E(x)    ((Elf64_Ehdr *)(x))
# define ELF64_S(x)    ((Elf64_Shdr *)(x))
# define ELF64_P(x)    ((Elf64_Phdr *)(x))
# define ELF64_ST(x)   ((Elf64_Sym *)(x))
# define ELF64_RELA(x) ((Elf64_Rela *)(x))
# define ELF64_DYN(x)  ((Elf64_Dyn *)(x))

# define SELF64_E    sizeof(Elf64_Ehdr)
# define SELF64_S    sizeof(Elf64_Shdr)
# define SELF64_P    sizeof(Elf64_Phdr)
# define SELF64_ST   sizeof(Elf64_Sym)
# define SELF64_RELA sizeof(Elf64_Rela)
# define SELF64_DYN  sizeof(Elf64_Dyn)

# define WSTUB_SIZE    0x48
# define WWRAPPER_SIZE 0x80

typedef struct
{
	char	*name;

	void	*map,
		*ehdr,
		*phdr,
		*shdr,
		*shstrp;

	struct stat stat;
	int	fd;
} WFILE;

typedef struct
{
	WFILE	*wfile;
#define _vmap    wfile->map
#define _vehdr   wfile->ehdr
#define _vphdr   wfile->phdr
#define _vshdr   wfile->shdr
#define _vshstrp wfile->shstrp
	void	*wmap;

	__UINT_LEAST64_TYPE__
		phd_fix,
		added,
		entry,
		vaddr_payload,
		upac_filesz,
		upac_align;

	__INT_LEAST32_TYPE__
		*stub_bss,
		*stub_dat,
		*stub_dsz,
		*stub_jmp;

	__INT_LEAST32_TYPE__
		*pload_phx[2],
		*pload_pxs[2],
		*pload_txt,
		*pload_txs;

#define NDX(x) x##_ndx
	int	NDX(phd),
		NDX(phx),
		NDX(txt),
		NDX(bss),
		NDX(shx);

	int	phd_align;
} WVICTIM;

typedef struct
{
	WFILE		wfile;

	Elf64_Off	pack_off;
	Elf64_Xword	pack_sz;

	Elf64_Off	unpack_off;
	Elf64_Xword	unpack_sz;

} WPAYLOAD;

#undef NDX
#endif
