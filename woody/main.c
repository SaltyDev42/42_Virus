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

#define	WELF_CHECK(ELF_HDR, ptr, sphdr, sshdr, filesize, jump, shdr, phdr) \
	if (ELF_HDR(ptr)->e_machine != EM_386 &&			\
	    ELF_HDR(ptr)->e_machine != EM_X86_64) {			\
		dprintf(STDERR_FILENO, "Architecture unsupported\n");	\
		goto jump;						\
	}								\
	if (ELF_HDR(ptr)->e_phoff >= (filesize)	||			\
	    ELF_HDR(ptr)->e_phoff + ELF_HDR(ptr)->e_phentsize >= (filesize) || \
	    ELF_HDR(ptr)->e_phentsize != (sphdr) * ELF_HDR(ptr)->e_phnum || \
	    ELF_HDR(ptr)->e_shoff >= (filesize) ||			\
	    ELF_HDR(ptr)->e_shoff + ELF_HDR(ptr)->e_shentsize >= (filesize) || \
	    ELF_HDR(ptr)->e_shentsize != (sshdr) * ELF_HDR(ptr)->e_shnum) { \
		dprintf(STDERR_FILENO, "Elf is corrupted\n");		\
		goto jump;						\
	}								\
	(phdr) = ELF_HDR(ptr)->e_phoff + (char *)ptr;			\
	(shdr) = ELF_HDR(ptr)->e_shoff + (char *)ptr;

#define NEXT_HDR(hdr, s)           (hdr) = (((char *)(hdr)) + s)

#define WELF_SCHECK(ELF_HDR, ptr, filesize, jump)			\
	if ((ELF_HDR(ptr)->sh_name & SHN_LORESERVE) == SHN_LORESERVE)	\
		continue;						\
	if (ELF_HDR(ptr)->sh_offset >= (filesize) ||			\
	    ELF_HDR(ptr)->sh_offset + ELF_HDR(ptr)->sh_size >= (filesize)) { \
		dprintf(STDERR_FILENO, "Elf is corrupted\n");		\
		goto jump;						\
	}

#define WELF_PCHECK(ELF_HDR, ptr, filesize, jump)			\
	if (ELF_HDR(ptr)->p_offset >= (filesize) ||			\
	    ELF_HDR(ptr)->p_offset + ELF_HDR(ptr)->p_filesz >= (filesize)) { \
		dprintf(STDERR_FILENO, "Elf is corrupted\n");		\
		goto jump;						\
	}
		

#define HASH_DTEXT
#define HASH_DDATA

/*#define HASH_DRODATA*/

typedef uint32_t hashval_t;

static hashval_t hash_string(char *str)
{
	uint32_t	hash;

	hash = 85206151;
	while (*str)
	{
		hash ^= *str++ * 85206151;
		hash += 85206151;
	}
	return (hash);
}

WOODFILE *wood_open(char *victim)
{
	struct stat   _stat;
	WOODFILE      *new;
	void          *mapv, *mapw;
	void          *shstr, *phdr, *shdr;
	void	      *nshdr, *nphdr;
	void          *shdx;
	unsigned char *ident;
	int           fdv, fdw;
	int           ntext = -1,
		      ndata = -1,
		      nrodata = -1;

	new = malloc(sizeof *new);
	if (0 == new) {
		dprintf(STDERR_FILENO, "fatal: malloc fail\n");
		goto fail_alloc;
	}

	fdv = open(victim, O_RDONLY);
	if (0 > fdv) {
		dprintf(STDERR_FILENO, "fatal: open fail\n");
		goto fail_open;
	}

	fstat(fdv, &_stat);
	if ((__off_t)sizeof(Elf32_Ehdr) > _stat.st_size) {
		dprintf(STDERR_FILENO, "unsupported file\n");
		goto fail_vmap;
	}

	mapv = WVMAP(fdv, _stat.st_size);
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
	if (ident[EI_CLASS] == ELFCLASS32) {
		WELF_CHECK(ELF32_E, mapv,
			   sizeof(Elf32_Phdr),               /*sphdr*/
			   sizeof(Elf32_Shdr),               /*sshdr*/
			   (long unsigned int)_stat.st_size, /*filesize*/
			   fail_corrupt,                     /*jump*/
			   shdr, phdr);
		shstr = &ELF32_S(shdr)[ELF32_E(mapv)->e_shstrndx];
		shdx = ELF32_S(shstr)->sh_offset + (char *)mapv;
		nshdr = shdr;

		for (int i = ELF32_E(mapv)->e_shnum; i;
		     i--, NEXT_HDR(nshdr, SELF32_S)) {
			WELF_SCHECK(ELF32_S, nshdr, (long unsigned int)_stat.st_size, fail_corrupt);
		}

		nphdr = phdr;
		for (int i = ELF32_E(mapv)->e_phnum; i;
		     i--, NEXT_HDR(nphdr, SELF32_P)) {
			WELF_PCHECK(ELF32_P, nphdr, (long unsigned int)_stat.st_size, fail_corrupt);
		}
	}

	/* same as above for 64 bits */
	if (ident[EI_CLASS] == ELFCLASS64) {
		WELF_CHECK(ELF64_E, mapv,
			   sizeof(Elf64_Phdr),               /*sphdr*/
			   sizeof(Elf64_Shdr),               /*sshdr*/
			   (long unsigned int)_stat.st_size, /*filesize*/
			   fail_corrupt,                     /*jump*/
			   shdr, phdr);

		shstr = &ELF64_S(shdr)[ELF64_E(mapv)->e_shstrndx];
		shdx = ELF64_S(shstr)->sh_offset + (char *)mapv;
		nshdr = shdr;

		for (int i = ELF64_E(mapv)->e_shnum; i;
		     i--, NEXT_HDR(nshdr, SELF64_S)) {
			WELF_SCHECK(ELF64_S, nshdr, (long unsigned int)_stat.st_size, fail_corrupt);
		}

		nphdr = phdr;
		for (int i = ELF64_E(mapv)->e_phnum; i;
		     i--, NEXT_HDR(nphdr, SELF64_P)) {
			WELF_PCHECK(ELF64_P, nphdr, (long unsigned int)_stat.st_size, fail_corrupt);
		}
	}

	new->fd = fdv;
	new->map = mapv;
	new->bottom = (char *)mapv + _stat.st_size;
	new->ehdr = mapv;
	new->ident = ident;

	return new;

fail_corrupt:
	munmap(mapv, _stat.st_size);
fail_vmap:
	close(fdv);
fail_open:
	free(new);
fail_alloc:
	return 0;
}

int
main(int ac, char **av)
{
	return 0;
}
