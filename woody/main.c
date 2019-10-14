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
#define VICTIM_MAPPROT (PROT_READ | PROT_WRITE)
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
	if ((ELF_HDR(ptr)->e_phnum &&					\
	     (ELF_HDR(ptr)->e_phoff >= (filesize) ||			\
	      ELF_HDR(ptr)->e_phoff + ELF_HDR(ptr)->e_phentsize		\
	      * ELF_HDR(ptr)->e_phnum > (filesize) ||			\
	      ELF_HDR(ptr)->e_phentsize != (sphdr)))			\
	    /* */							\
	    ||								\
	    /* section headers */					\
	    (ELF_HDR(ptr)->e_shnum &&					\
	     (ELF_HDR(ptr)->e_shoff >= (filesize) ||			\
	      ELF_HDR(ptr)->e_shoff + ELF_HDR(ptr)->e_shentsize		\
	      * ELF_HDR(ptr)->e_shnum > (filesize) ||			\
	      ELF_HDR(ptr)->e_shentsize != (sshdr) ||			\
	      ELF_HDR(ptr)->e_shstrndx >= ELF_HDR(ptr)->e_shnum))) {	\
		dprintf(STDERR_FILENO, "1Elf is corrupted\n");		\
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
			   SELF64_P,                /*sphdr*/
			   SELF64_S,                /*sshdr*/
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
wclose(WFILE *w)
{
	munmap(w->map, w->stat.st_size);
	close(w->fd);
}

int
wopen_pl(const char *pl_path, WPAYLOAD *pl,
	const char *packsym, const char *unpacksym)
{
	WFILE       *wfile;
	void        *ehdr, *shdr;
	void        *shndr;
	void        *symtab = 0;
	void        *stpack = 0, *stupack = 0;
	char        *shstr, *strtab = 0;
	Elf64_Xword symtabn;
	Elf64_Xword toffset = 0;

	/* there's no sym to unpack */
	if (0 == pl_path ||
	    0 == pl ||
	    0 == packsym ||
	    0 == unpacksym ||
	    wopen(pl_path, &pl->wfile))
		goto fail_wopen;

	wfile = &pl->wfile;

	ehdr = wfile->ehdr;
	shdr = wfile->shdr;

#define PL_GETPACKER(ELF)						\
	do {								\
		shstr = ELF##_S(shdr)[ELF##_E(ehdr)->e_shstrndx].sh_offset + \
			(char *)wfile->map;				\
		shndr = shdr;						\
		for (int i = ELF##_E(ehdr)->e_shnum;			\
		     i || !symtab || !strtab || !toffset;		\
		     i--, NEXT_HDR(shndr, S##ELF##_S)) {		\
			/* GOD FORBIDS */				\
			if (!symtab &&					\
			    0 == strcmp(".symtab", shstr + ELF##_S(shndr)->sh_name)) { \
				symtabn = ELF##_S(shndr)->sh_size / S##ELF##_ST; \
				symtab = ELF##_S(shndr)->sh_offset + (char *)wfile->map; \
			}						\
			/* GOD FORBIDS */				\
			if (!strtab &&					\
			    0 == strcmp(".strtab", shstr + ELF##_S(shndr)->sh_name)) \
				strtab = ELF##_S(shndr)->sh_offset + (char *)wfile->map; \
									\
			if (!toffset &&					\
			    0 == strcmp(".text", shstr + ELF##_S(shndr)->sh_name)) \
				toffset = ELF##_S(shndr)->sh_offset;	\
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
		if (0 == toffset) {					\
			dprintf(STDERR_FILENO, "elf section text not"	\
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
		pl->pack_off = ELF##_ST(stpack)->st_value + toffset;	\
		pl->unpack_off = ELF##_ST(stupack)->st_value + toffset;	\
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

	if (mprotect(wfile->map,
		     pl->wfile.stat.st_size,
		     PROT_READ | PROT_EXEC)) {
		dprintf(STDERR_FILENO, "fatal: mprotect error\n");
		perror("");
		goto fail;
	}
	return 0;

fail:
	wclose(&pl->wfile);
fail_wopen:
	return -1;
}

int
winject(WFILE const *wfil, WPAYLOAD const *wpfil)
{
	void (*packer)(void *, void *, size_t) = wpfil->wfile.map + wpfil->pack_off;
	void *tmap;
	void *ehdr, *phdr;
	void *wehdr, *wphdr;
	size_t filsz, added;
	size_t offp;
	size_t szcp;
	unsigned char *_exec;
	int  tfd;
	int  rfd;
	int  xseg = -1;

	if (0 == wfil ||
	    0 == wpfil)
		goto fail;

#define WTARGET "woody"

	tfd = open(WTARGET, O_TRUNC | O_CREAT | O_RDWR, wfil->stat.st_mode);
	if (-1 == tfd) {
		dprintf(STDERR_FILENO, "failed to open '%s'\n", WTARGET);
		goto fail;
	}
#undef WTARGET
	rfd = open("/dev/urandom", O_RDONLY);
	if (-1 == rfd) {
		dprintf(STDERR_FILENO, "failed to generate key\n");
		goto fail_l1;
	}


	ehdr = wfil->ehdr;
	phdr = wfil->phdr;

	switch (wfil->ident[EI_CLASS]) {
	case ELFCLASS64:
		/* get the corresponding program header where .text resides */
		/* assumes that program header is ascending order by vaddr */
		for (int i = 0; i < ELF64_E(ehdr)->e_phnum; i++) {
			if (ELF64_P(phdr)[i].p_flags & PF_X) {
				xseg = i;
				break ;
			}
		}
		if (xseg == -1) {
			dprintf(STDERR_FILENO, "Executable segment not found\n");
			goto fail_l2;
		}
		break ;

	default:
		break;
	}
	/* assumes data is after rodata and rodata is after text */

	filsz = wfil->stat.st_size;
	/* unpacker size */
	added = wpfil->unpack_sz; /* unpacker sz */
	added += WPACKER_TSIZE; /* packer header size */
#if 0 
	/* ?? */
	added += 0xfff;
	added &= ~0xfff; /* align */
	/* ... */
#else
	added += 0xf;
	added &= ~0xf;
#endif

	filsz += added;
	if (ftruncate(tfd, filsz)) {
		dprintf(STDERR_FILENO, "fatal ftruncate error\n");
		goto fail;
	}

	tmap = WWMAP(tfd, filsz);
	if (MAP_FAILED == tmap) {
		dprintf(STDERR_FILENO, "fatal: mmap error\n");
		goto fail;
	}
	// unpack(char *map, void *key, size_t n) 
	switch (wfil->ident[EI_CLASS]) {
	case ELFCLASS64:
		/* copy elf headers*/
		wehdr = memcpy(tmap, ehdr, SELF64_E);
		offp = SELF64_E;
		/* copy program headers */
		szcp = ELF64_E(ehdr)->e_phnum * ELF64_E(ehdr)->e_phentsize;
		wphdr = memcpy(tmap + offp, phdr, szcp);
		offp += szcp;
		/* copy everything that's behind exec segment offset */
		szcp = ELF64_P(phdr)[xseg].p_offset - offp;
		memcpy(tmap + offp, wfil->map + offp, szcp);
		offp += szcp;

		_exec = memcpy(tmap + offp,
			       /* sequence to copy in byte for header */
			       "\x48\x8d\x35\x4f\x00\x00\x00"
			       /* 0x7 */
			       "\x48\x31\xff"
			       "\x48\x31\xd2"
			       "\x66\xba\x0b\x00"
			       "\x40\xb7\x01"
			       "\x48\x31\xc0"
			       "\xb0\x01"
			       /* --------------- ---------- */
			       /* 0x19 syscall */
			       "\x0f\x05"
			       /* 0x1b  (0x1e load .text rel) // to do dyn */
			       "\x48\x8d\x3d\x42""\x00\x00\x00"
			       /* 0x22 load key address rip rel addr // ok */
			       "\x48\x8d\x35\x47""\x00\x00\x00"
			       /* 0x29 mov rdx, size // to do dyn */
			       "\x48\xba""\x00\x00\x00\x00""\x00\x00\x00\x00"
			       /* 0x33 packer call // ok */
			       "\xe8\x48\x00\x00""\x00"
			       /* 0x38 lea rsi, rip - 0x3f (_init sym) // ok */
			       "\x48\x8d\x3d\xc1""\xff\xff\xff"
			       /* 0x3f mov rsi, PLACE HOLDER // dyn */
			       "\x48\xbe""\x00\x00\x00\x00""\x00\x00\x00\x00"
			       /* 0x49 */
			       "\x31\xd2\xb2\x05""\xb0\x0a\x0f\x05"
			       /* 0x51 jmp near rel addr + 0x26 // dyn jump unpack */
			       "\xe8\x26\x00\x00""\x00"
			       /* 0x56 ____________ should jump over*/
			       /*__WOOODY__ , 0xa 0 STRING*/
			       "\x5f\x5f\x57\x4f\x4f\x44\x59\x5f"
			       "\x5f\x0a\x00\x90\x90\x90\x90\x90"
			       "\x90\x90\x90\x90\x90\x90\x90\x90"
			       "\x90\x90"/* alignment for SSE */
			       /* 0x70 */
			       /* ... 16 random bytes */
			       /* 0x80 */
			       , 0x70);

		/* urandom key */
		read(rfd, &0x70[_exec], 16);
		/* copy the unpacker */
		memcpy(_exec + 0x80,
		       wpfil->wfile.map + wpfil->unpack_off,
		       wpfil->unpack_sz);

		ELF64_P(phdr)[xseg].p_filesz = (ELF64_P(phdr)[xseg].p_filesz + 0xf) & ~0xf;
		offp += ELF64_P(phdr)[xseg].p_filesz;

		/* copy the .text */
		memcpy(_exec + added,
		       wfil->map + ELF64_P(phdr)[xseg].p_offset,
		       ELF64_P(phdr)[xseg].p_filesz);

		/* call packer to encrypt .text*/
		packer(_exec + added, &0x70[_exec], ELF64_P(phdr)[xseg].p_filesz);
		memcpy(tmap + added + offp,
		       wfil->map + offp,
		       wfil->stat.st_size - offp);

		/*
		 *TODO
		 * 1. before calling packer copy .text into shared map // ok
		 * 2. call packer // ok
		 * 3. copy unpacker into binary // ok
		 * 4. copy the rest
		 * 5. test the shit
		 */
		/* offset to the real section .text */
		*((__UINT_LEAST32_TYPE__ *)(&0x1e[_exec])) = added - 0x22;
		/* size to unpack */
		*((__UINT_LEAST64_TYPE__ *)(&0x2b[_exec])) = ELF64_P(phdr)[xseg].p_filesz;
		/* segment size for mprotect */
		*((__UINT_LEAST64_TYPE__ *)(&0x48[_exec])) = ELF64_P(phdr)[xseg].p_filesz + added;
		/* jump to .text init */
		*((__INT_LEAST32_TYPE__ *)(&0x52[_exec])) = added - 0x56;


		ELF64_P(wphdr)[xseg].p_filesz = ELF64_P(phdr)[xseg].p_filesz + added;
		ELF64_P(wphdr)[xseg].p_memsz = ELF64_P(wphdr)[xseg].p_filesz;
		ELF64_P(wphdr)[xseg].p_flags |= PF_W;
		/* 
		 * offsets them so the original program does not segfaults 
		 * when using relative address 
		 */
		for (int i = xseg + 1; i < ELF64_E(wehdr)->e_phnum; i++) {
			ELF64_P(wphdr)[i].p_offset += added;
			ELF64_P(wphdr)[i].p_vaddr  += added;
			ELF64_P(wphdr)[i].p_paddr  += added;
		}

		ELF64_E(wehdr)->e_shoff += added;
	default:
		break;
	}

	munmap(tmap, filsz);
	close(tfd);
	close(rfd);
	return 0;
fail_l2:
	close(rfd);
fail_l1:
	close(tfd);
fail:
	return -1;
}

int
main(int ac, char **av)
{
	WFILE w;
	WPAYLOAD pl;

	if (wopen(av[1], &w))
		goto fail;

#define DEFAULT_PAYLOAD_PATH           "./aes_masm.o"

#define DEFAULT_PAYLOAD_PACKSYM   "aes128_enc"
#define DEFAULT_PAYLOAD_UNPACKSYM "aes128_dec"

	if (wopen_pl(DEFAULT_PAYLOAD_PATH, &pl,
		     DEFAULT_PAYLOAD_PACKSYM,
		     DEFAULT_PAYLOAD_UNPACKSYM))
		goto fail;
	winject(&w, &pl);
	return 0;
fail:
	return 1;
}
