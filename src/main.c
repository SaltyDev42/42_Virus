#include <sys/mman.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include <stdio.h>
#include <stdint.h>

#include "libft.h"
#include "woody.h"

#define WMAP(fd, size, prot, flag) mmap(0, size, prot, flag, fd, 0)

#define VICTIM_MAPFLAG (MAP_SHARED)
#define VICTIM_MAPPROT (PROT_READ | PROT_WRITE)
#define WVMAP(fd, size) WMAP(fd, size, VICTIM_MAPPROT, VICTIM_MAPFLAG)

/* checking elf headers integrity */
#define	WELF_CHECK(ELF, ptr, filesize, jump, shdr, phdr)		\
	if (ELF##_E(ptr)->e_machine != EM_386 &&			\
	    ELF##_E(ptr)->e_machine != EM_X86_64) {			\
		dprintf(STDERR_FILENO, "Architecture unsupported\n");	\
		goto jump;						\
	}								\
	if ((ELF##_E(ptr)->e_phnum &&					\
	     (ELF##_E(ptr)->e_phoff != S##ELF##_E ||			\
	      ELF##_E(ptr)->e_phoff + ELF##_E(ptr)->e_phentsize		\
	      * ELF##_E(ptr)->e_phnum > (filesize) ||			\
	      ELF##_E(ptr)->e_phentsize != S##ELF##_P))			\
	    /* */							\
	    ||								\
	    /* section headers */					\
	    (ELF##_E(ptr)->e_shnum &&					\
	     (ELF##_E(ptr)->e_shoff >= (filesize) ||			\
	      ELF##_E(ptr)->e_shoff + ELF##_E(ptr)->e_shentsize		\
	      * ELF##_E(ptr)->e_shnum > (filesize) ||			\
	      ELF##_E(ptr)->e_shentsize != S##ELF##_S ||		\
	      ELF##_E(ptr)->e_shstrndx >= ELF##_E(ptr)->e_shnum))) {	\
		dprintf(STDERR_FILENO, "Elf is corrupted\n");		\
		goto jump;						\
	}								\
	(phdr) = ELF##_E(ptr)->e_phoff + (char *)ptr;			\
	(shdr) = ELF##_E(ptr)->e_shoff + (char *)ptr;

/* checking section headers integrity */
#define WELF_SCHECK(ELF_HDR, ptr, filesize, jump)			\
	if ((ELF_HDR(ptr)->sh_name & SHN_LORESERVE) == SHN_LORESERVE)	\
		continue;						\
	if (ELF_HDR(ptr)->sh_type != SHT_NOBITS	&&			\
	    (ELF_HDR(ptr)->sh_offset >= (filesize) ||			\
	     ELF_HDR(ptr)->sh_offset + ELF_HDR(ptr)->sh_size >= (filesize))) { \
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

int
wopen(const char *victim, WFILE *buf)
{
	struct stat   *_stat;
	WFILE         *new = buf;
	void          *mapv;
	void          *phdr, *shdr;
	void	      *nshdr, *nphdr;
	unsigned char *ident;
	int           fdv;

	if (0 == buf)
		goto fail_open;

	fdv = open(victim, O_RDWR);
	if (0 > fdv) {
		dprintf(STDERR_FILENO, "fatal: failed to open '%s'\n", victim);
		goto fail_open;
	}

	if (0 > fstat(fdv, &new->stat)) {
		dprintf(STDERR_FILENO, "fatal: could not stat '%s'\n", victim);
		goto fail_vmap;
	}

	_stat = &new->stat;
	if ((__off_t)SELF64_E > _stat->st_size) {
		dprintf(STDERR_FILENO, "Unsupported file '%s'\n", victim);
		goto fail_vmap;
	}

	mapv = WVMAP(fdv, _stat->st_size);
	if (MAP_FAILED == mapv) {
		dprintf(STDERR_FILENO, "fatal: mmap fail '%s'\n", victim);
		goto fail_vmap;
	}

	ident = mapv;
	/* GOD FORBIDS */
	if (0 != ft_memcmp(ident, ELFMAG, SELFMAG)) {
		dprintf(STDERR_FILENO, "'%s' is not an elf\n", victim);
		goto fail_corrupt;
	}

	if (0 == ident[EI_CLASS] ||
	    3 <= ident[EI_CLASS]) {
		dprintf(STDERR_FILENO, "Unsupported file '%s'\n", victim);
		goto fail_corrupt;
	}

	/* This program only supports little endian */
	if (ELFDATA2LSB != ident[EI_DATA]) {
		dprintf(STDERR_FILENO, "Unsupported endianess '%s'\n", victim);
		goto fail_corrupt;
	}

	/* checking if any segment is past size of file */

	if (ident[EI_CLASS] != ELFCLASS64) {
		dprintf(STDERR_FILENO, "Unsupported architecture '%s'\n", victim);
		goto fail_corrupt;
	}

	WELF_CHECK(ELF64, mapv,
		   (long unsigned int)_stat->st_size, /*filesize*/
		   fail_corrupt,                      /*jump*/
		   shdr, phdr);
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
wclose(WFILE *w)
{
	munmap(w->map, w->stat.st_size);
	close(w->fd);
}


int
winject(WFILE const *wfil)
{
	void *ehdr, *shdr;


	size_t filsz, added;
	int  nasec = -1;
	int64_t addr_sign;

	if (0 == wfil)
		goto fail;

	ehdr = wfil->ehdr;
	shdr = wfil->shdr;
	int dx;
	
#define LF_SECTION(condition, inst)					\
	for (dx = 0; dx < ELF64_E(ehdr)->e_shnum; dx++){		\
		if (condition)						\
			inst;						\
	}

	/* search the first no alloc section */
	LF_SECTION(!(ELF64_S(shdr)[dx].sh_flags & SHF_ALLOC) && dx,
		{ nasec = dx; break ; });


	/* addr inject signature */
	if (nasec == -1)//"write in end of file");
		addr_sign = wfil->stat.st_size;
	else
		addr_sign = ELF64_S(shdr)[nasec].sh_offset;

	/* size signature + align */
	added = FSIGN_TSIZE;
#if 0
	/* ?? */
	added += 0xfff;
	added &= ~0xfff; /* align */
	/* ... */
#else
	added += 0xf;
	added &= ~0xf;
#endif

	/* is sign ? */
	if(!memcmp(wfil->map + addr_sign - added, FSIGN_STR, FSIGN_TSIZE))
		return (1);

	/* grow file */
	filsz = wfil->stat.st_size;
	filsz += added;
	if (ftruncate(wfil->fd, filsz)) {
		dprintf(STDERR_FILENO, "fatal ftruncate error\n");
		goto fail;
	}

	/* write sign */
	if (nasec != -1)
	{
		ELF64_E(ehdr)->e_shoff += added;
		for (int dx = nasec; dx < ELF64_E(ehdr)->e_shnum; dx++)
			(ELF64_S(shdr)[dx].sh_offset) += added;
		memcpy(wfil->map + addr_sign + added,
			wfil->map + addr_sign,
			filsz - addr_sign);
	}
	memcpy(wfil->map + addr_sign, FSIGN_STR, FSIGN_TSIZE);

	munmap(wfil->map, filsz);
	return 0;
fail:
	return -1;
}

int
main(int ac, char **av)
{
	(void)ac;


	WFILE w;
	if (wopen(av[1], &w))
		goto fail;

	int ret = winject(&w);
	printf((!ret)?"SUCCESS\n" : (ret == 1) ? "OK\n" : "ERROR\n");

	return 0;
fail:
	return 1;
}
