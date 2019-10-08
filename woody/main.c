#include <sys/mman.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include <stdio.h>
#include <stdint.h>
/* GOD FORBIDS */
#include <string.h>

#include "woody.h"

#define WMAP(fd, size, prot, flag) mmap(0, size, prot, flag, fd, 0)

#define VICTIM_MAPFLAG (MAP_PRIVATE)
#define VICTIM_MAPPROT (PROT_READ)
#define WVMAP(fd, size) WMAP(fd, size, VICTIM_MAPPROT, VICTIM_MAPFLAG)

#define WOOD_MAPFLAG (MAP_SHARED)
#define WOOD_MAPPROT (PROT_READ | PROT_WRITE)
#define WWMAP(fd, size) WMAP(fd, size, WOOD_MAPPROT, WOOD_MAPFLAG)

/* checking elf headers integrity */
#define	WELF_CHECK(ELF_HDR, ptr, sphdr, sshdr, filesize, jump, shdr, phdr) \
	if (ELF_HDR(ptr)->e_machine != EM_386 &&			\
	    ELF_HDR(ptr)->e_machine != EM_X86_64) {			\
		dprintf(STDERR_FILENO, "Architecture unsupported\n");	\
		goto jump;						\
	}								\
	if (ELF_HDR(ptr)->e_phoff >= (filesize)	||			\
	    ELF_HDR(ptr)->e_phoff + ELF_HDR(ptr)->e_phentsize		\
	    * ELF_HDR(ptr)->e_phnum > (filesize) ||			\
	    ELF_HDR(ptr)->e_phentsize != (sphdr) ||			\
	    /* section headers */					\
	    ELF_HDR(ptr)->e_shoff >= (filesize) ||			\
	    ELF_HDR(ptr)->e_shoff + ELF_HDR(ptr)->e_shentsize		\
	    * ELF_HDR(ptr)->e_shnum > (filesize) ||			\
	    ELF_HDR(ptr)->e_shentsize != (sshdr) ||			\
	    ELF_HDR(ptr)->e_shstrndx >= ELF_HDR(ptr)->e_shnum) {	\
		dprintf(STDERR_FILENO, "Elf is corrupted\n");		\
		goto jump;						\
	}								\
	(phdr) = ELF_HDR(ptr)->e_phoff + (char *)ptr;			\
	(shdr) = ELF_HDR(ptr)->e_shoff + (char *)ptr;

/* checking section headers integrity */
#define WELF_SCHECK(ELF_HDR, ptr, filesize, jump)			\
	if ((ELF_HDR(ptr)->sh_name & SHN_LORESERVE) == SHN_LORESERVE)	\
		continue;						\
	if (ELF_HDR(ptr)->sh_offset >= (filesize) ||			\
	    ELF_HDR(ptr)->sh_offset + ELF_HDR(ptr)->sh_size >= (filesize)) { \
		dprintf(STDERR_FILENO, "Elf is corrupted\n");		\
		goto jump;						\
	}

/* checking program headers integrity*/
#define WELF_PCHECK(ELF_HDR, ptr, filesize, jump)			\
	if (ELF_HDR(ptr)->p_offset >= (filesize) ||			\
	    ELF_HDR(ptr)->p_offset + ELF_HDR(ptr)->p_filesz >= (filesize)) { \
		dprintf(STDERR_FILENO, "Elf is corrupted\n");		\
		goto jump;						\
	}


#define NEXT_HDR(hdr, s)           (hdr) = (((char *)(hdr)) + (s))

#define DEFAULT_PAYLOAD_PATH           "./BUILD/payload.o"

#define DEFAULT_PAYLOAD_PACK_SYMNAME   "pack"
#define DEFAULT_PAYLOAD_UNPACK_SYMNAME "unpack"

/* probably unsafe if symbol has no trailing '\0' to mark the end */
#if 0
typedef uint32_t hashval_t;

static hashval_t
hash_string(const char *str)
{
	uint32_t hash;

	hash = 85206151;
	while (*str)
	{
		hash ^= *str++ * 85206151;
		hash += 85206151;
	}
	return (hash);
}
#endif

int
woody_open(const char *victim, WOODYFILE *buf)
{
	struct stat   *_stat;
	WOODYFILE     *new = buf;
	void          *mapv;
	void          *shstr, *phdr, *shdr;
	void	      *nshdr, *nphdr;
	void          *shdx;
	unsigned char *ident;
	int           fdv;

	fdv = open(victim, O_RDONLY);
	if (0 > fdv) {
		dprintf(STDERR_FILENO, "fatal: open fail\n");
		goto fail_open;
	}

	if (0 > fstat(fdv, &new->stat)) {
		dprintf(STDERR_FILENO, "fatal: could not stat %s\n", victim);
		goto fail_vmap;
	}

	_stat = &new->stat;
	if ((__off_t)sizeof(Elf32_Ehdr) > _stat->st_size) {
		dprintf(STDERR_FILENO, "unsupported file\n");
		goto fail_vmap;
	}

	mapv = WVMAP(fdv, _stat->st_size);
	if (MAP_FAILED == mapv) {
		dprintf(STDERR_FILENO, "fatal: mmap fail\n");
		goto fail_vmap;
	}

	ident = mapv;
	/* GOD FORBIDS */
	if (0 != memcmp(ident, ELFMAG, SELFMAG)) {
		dprintf(STDERR_FILENO, "File is not an elf\n");
		goto fail_corrupt;
	}

	if (0 == ident[EI_CLASS] ||
	    3 <= ident[EI_CLASS]) {
		dprintf(STDERR_FILENO, "unsupported file\n");
		goto fail_corrupt;
	}

	/* This program only supports little endian */
	if (ELFDATA2LSB != ident[EI_DATA]) {
		dprintf(STDERR_FILENO, "unsupported fail\n");
		goto fail_corrupt;
	}

	/* checking if any segment is past size of file */
	switch (ident[EI_CLASS]) {
	case ELFCLASS32:
		WELF_CHECK(ELF32_E, mapv,
			   sizeof(Elf32_Phdr),                /*sphdr*/
			   sizeof(Elf32_Shdr),                /*sshdr*/
			   (long unsigned int)_stat->st_size, /*filesize*/
			   fail_corrupt,                      /*jump*/
			   shdr, phdr);
		shstr = &ELF32_S(shdr)[ELF32_E(mapv)->e_shstrndx];
		shdx = ELF32_S(shstr)->sh_offset + (char *)mapv;
		nshdr = shdr;
		
		for (int i = ELF32_E(mapv)->e_shnum; i;
		     i--, NEXT_HDR(nshdr, SELF32_S)) {
			WELF_SCHECK(ELF32_S, nshdr, (long unsigned int)_stat->st_size, fail_corrupt);
		}
		
		nphdr = phdr;
		for (int i = ELF32_E(mapv)->e_phnum; i;
		     i--, NEXT_HDR(nphdr, SELF32_P)) {
			WELF_PCHECK(ELF32_P, nphdr, (long unsigned int)_stat->st_size, fail_corrupt);
		}
		break ;

	/* same as above for 64 bits */
	case ELFCLASS64: 
		WELF_CHECK(ELF64_E, mapv,
			   sizeof(Elf64_Phdr),                /*sphdr*/
			   sizeof(Elf64_Shdr),                /*sshdr*/
			   (long unsigned int)_stat->st_size, /*filesize*/
			   fail_corrupt,                      /*jump*/
			   shdr, phdr);

		shstr = &ELF64_S(shdr)[ELF64_E(mapv)->e_shstrndx];
		shdx = ELF64_S(shstr)->sh_offset + (char *)mapv;
		nshdr = shdr;

		for (int i = ELF64_E(mapv)->e_shnum; i;
		     i--, NEXT_HDR(nshdr, SELF64_S)) {
			WELF_SCHECK(ELF64_S, nshdr, (long unsigned int)_stat->st_size, fail_corrupt);
		}

		nphdr = phdr;
		for (int i = ELF64_E(mapv)->e_phnum; i;
		     i--, NEXT_HDR(nphdr, SELF64_P)) {
			WELF_PCHECK(ELF64_P, nphdr, (long unsigned int)_stat->st_size, fail_corrupt);
		}
		break ;
	default:
		dprintf(STDERR_FILENO, "Unsupported elf class\n");
		goto fail_corrupt;
	}

	new->name = victim;
	new->fd = fdv;
	new->map = mapv;
	new->ident = ident;

	new->ehdr = mapv;
	new->phdr = phdr;
	new->shdr = shdr;

	return 0;

fail_corrupt:
	munmap(mapv, _stat->st_size);
fail_vmap:
	close(fdv);
fail_open:
	return -1;
}

void
wood_close(WOODYFILE *w)
{
	munmap(w->map, w->stat.st_size);
	close(w->fd);
}

int
woody_open_pl(const char *pl_path, WOODYPAYLOAD *pl,
	const char *packsym, const char *unpacksym)
{
	WOODYFILE   *wfile;
	void        *ehdr, *shdr;
	void        *shndr;
	void        *symtab = 0;
	void        *stpack = 0, *stupack = 0;
	Elf64_Xword symtabn;
	char        *shstr, *strtab;

	/* there's no sym to unpack */
	if (0 == packsym ||
	    0 == unpacksym ||
	    woody_open(pl_path, &pl->wfile))
		goto fail_wopen;

	wfile = &pl->wfile;

	ehdr = wfile->ehdr;
	shdr = wfile->shdr;

#define PL_GETPACKER(ELF)						\
	do {								\
		shstr = ELF##_S(shdr)[ELF##_E(ehdr)->e_shstrndx].sh_offset + \
			(char *)wfile->map;				\
		shndr = shdr;						\
		for (int i = ELF##_E(ehdr)->e_shnum; i;			\
		     i--, NEXT_HDR(shndr, SELF##_S)) {			\
			/* GOD FORBIDS */				\
			if (!symtab &&					\
			    0 == strcmp(".symtab", shstr + ELF##_S(shndr)->sh_name)) { \
				symtabn = ELF##_S(shndr)->sh_size / S##ELF##_ST; \
				symtab = ELF##_S(shndr)->sh_offset + (char *)wfile->map; \
			}						\
			/* GOD FORBIDS */				\
			if (0 == strcmp(".strtab", shstr + ELF##_S(shndr)->sh_name)) \
				symstr = ELF##_S(shndr)->sh_offset + (char *)wfile->map; \
		}							\
									\
		if (0 == symtab) {					\
			dprintf(STDERR_FILENO, "elf section symtab not"	\
				" found in payload '%s'\n",		\
				pl_path);				\
			goto fail;					\
		}							\
		if (0 == strtab) {					\
			dprintf(STDERR_FILENO, "elf section strtab not"	\
				" found in payload '%s'\n",		\
				pl_path);				\
			goto fail;					\
		}							\
									\
		for (Elf64_Xword i = symtabn;				\
		     i ||  0 == stpack || 0 == stupack;			\
		     i--, NEXT_HDR(symtab, S##ELF##_ST)) {		\
			/* GOD FORBIDS */				\
			if (!stpack &&					\
			    0 == strcmp(packsym, strtab + ELF##_ST(symtab)->st_name)) \
				stpack = symtab;			\
			if (!stupack &&					\
			    0 == strcmp(unpacksym, strtab + ELF##_ST(symtab)->st_name)) \
				stupack = symtab;			\
		}							\
									\
		if (0 == stpack ||					\
		    0 == stupack) {					\
			dprintf(STDERR_FILENO,				\
				"could not find symbol '%s'"		\
				" in payload '%s' symtab\n",		\
				!stpack ? packsym : unpacksym,		\
				pl_path);				\
			goto fail;					\
		}							\
									\
		pl->pack_off = ELF##_ST(stpack)->st_value;		\
		pl->unpack_off = ELF##_ST(stupack)->st_value;		\
		pl->pack_sz = ELF##_ST(stpack)->st_size;		\
		pl->unpack_sz = ELF##_ST(stupack)->st_size;		\
	} while(0);


	switch (wfile->ident[EI_CLASS]) {
	case ELFCLASS32:
		PL_GETPACKER(ELF32);
		break ;
	case ELFCLASS64:
		PL_GETPACKER(ELF64);
	}

	return 0;

fail:
	wood_close(&pl->wfile);
fail_wopen:
	return -1;
}

int
woody_prepare(WOODYFILE *wfil, WOODYPAYLOAD *plfil, const char *sect)
{
	WOODYFILE *wfile = wfil;
	WOODYPAYLOAD *plfile = plfil;

	if (wfile->ident[EI_CLASS] != plfile->ident[EI_CLASS])
		goto class_mismatch;

	return 0;
class_mismatch:
	return -1;
}

int
main(int ac, char **av)
{
	WOODYFILE w;
	WOODYPAYLOAD pl;

	if (woody_open(av[1], &w))
		goto fail;

	return 0;
fail:
	return 1;
}
