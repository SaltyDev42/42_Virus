#include <sys/mman.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include "woody.h"

#define WMAP(fd, size, prot, flag) mmap(0, size, prot, flag, fd, 0)

#define VICTIM_MAPFLAG (MAP_PRIVATE)
#define VICTIM_MAPPROT (PROT_READ)
#define WVMAP(fd, size) WMAP(fd, size, VICTIM_MAPPROT, VICTIM_MAPFLAG)

#define WOOD_MAPFLAG (MAP_SHARED)
#define WOOD_MAPPROT (PROT_READ | PROT_WRITE)
#define WWMAP(fd, size) WMAP(fd, size, WOOD_MAPPROT, WOOD_MAPFLAG)

#define	WELF_CHECK(ELF_HDR, ptr, sphdr, sshdr, filesize, jump)		\
	if (ELF_HDR(ptr)->e_machine != EM_386 &&			\
	    ELF_HDR(ptr)->e_machine != EM_X86_64) {			\
		dprintf(STDERR_FILENO, "Architecture unsupported\n");	\
		goto jump;						\
	}								\
	if (ELF_HDR(ptr)->e_phoff + ELF_HDR(ptr)->e_phentsize >= (filesize) || \
	    ELF_HDR(ptr)->e_phentsize != (sphdr) * ELF_HDR(ptr)->e_phnum || \
	    ELF_HDR(ptr)->e_shoff + ELF_HDR(ptr)->e_shentsize >= (filesize) || \
	    ELF_HDR(ptr)->e_shentsize != (sshdr) * ELF_HDR(ptr)->e_shnum) { \
		dprintf(STDERR_FILENO, "Elf is corrupted\n");		\
		goto jump;						\
	}								\
	new->phdr = ELF_HDR(ptr)->e_phoff + (char *)ptr;		\
	new->shdr = ELF_HDR(ptr)->e_shoff + (char *)ptr;		\


WOODFILE *wood_open(char *victim)
{
	struct stat _stat;
	WOODFILE    *new;
	void        *mapv, mapw;
	char        *ident;
	int         fdv, fdw;

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
	if (sizeof(Elf32_Ehdr) > _stat.st_size) {
		dprintf(STDERR_FILENO, "unsupported file\n")
		goto fail_vmap;
	}

	mapv = WVMAP(fdv, _stat.st_size);
	if (MAP_FAILED == map) {
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
			   sizeof(Elf32_Phdr), /*sphdr*/
			   sizeof(Elf32_Shdr), /*sshdr*/
			   _stat.st_size,      /*filesize*/
			   fail_corrupt);      /*jump*/
	}

	/* same as above for 64 bits */
	if (ident[EI_CLASS] == ELFCLASS64) {
		WELF_CHECK(ELF64_E, mapv,
			   sizeof(Elf64_Phdr), /*sphdr*/   
			   sizeof(Elf64_Shdr), /*sshdr*/   
			   _stat.st_size,      /*filesize*/
			   fail_corrupt);      /*jump*/
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
	close(fd);
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
