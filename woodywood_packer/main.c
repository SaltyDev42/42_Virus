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
		dprintf(STDERR_FILENO, "1Elf is corrupted\n");		\
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
		dprintf(STDERR_FILENO, "iciElf is corrupted\n");		\
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
		dprintf(STDERR_FILENO, "unsupported endianess\n");
		goto fail_corrupt;
	}

	/* checking if any segment is past size of file */

	if (ident[EI_CLASS] != ELFCLASS64) {
		dprintf(STDERR_FILENO, "unsupported architecture");
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
		     i && (!symtab || !strtab || !toffset);		\
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


	PL_GETPACKER(ELF64);

	if (mprotect(wfile->map,
		     pl->wfile.stat.st_size,
		     PROT_READ | PROT_EXEC)) {
		dprintf(STDERR_FILENO, "fatal: mprotect error\n");
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
	void *ehdr, *phdr, *shdr;
	void *wehdr, *wphdr, *wshdr;

	void *st, *rela, *dyn = 0;

	Elf64_Sxword gdiff = -1;

	char *shstroff;
	size_t filsz, added;
	size_t align = 0;
	size_t offp, xsz = 0;
	unsigned char *_exec;
	int  tfd, rfd;
	int  flag = 0;
	int  xseg = -1,
	     xsec = -1,
	     esec = -1;
	
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
	shdr = wfil->shdr;

	/* assumes that program header is ascending order by vaddr */
	for (int i = 0; i < ELF64_E(ehdr)->e_phnum; i++) {
		/* get executable segment */
		if (ELF64_P(phdr)[i].p_flags & PF_X &&
		    ELF64_P(phdr)[i].p_type == PT_LOAD)
			xseg = i;
	}

	if (xseg == -1) {
		dprintf(STDERR_FILENO, "Text or Data segment not found\n");
		goto fail_l2;
	}

	if (ELF64_P(phdr)[xseg].p_offset) {
		flag |= 0x4;
	}
	/* get the necessary segments */
#define LF_SECTION(condition, inst)					\
	for (int dx = 0; dx < ELF64_E(ehdr)->e_shnum; dx++){		\
		if (condition)						\
			inst;						\
	}

	shstroff = ELF64_S(shdr)[ELF64_E(ehdr)->e_shstrndx].sh_offset + (char *)wfil->map;
	/* finding the corresponding section of executable segment*/
	LF_SECTION(strcmp(".init", ELF64_S(shdr)[dx].sh_name + shstroff) == 0,
		{ xsec = dx; break ; });
		
	LF_SECTION(strcmp(".got", ELF64_S(shdr)[dx].sh_name + shstroff) == 0,
		{ gdiff = ELF64_S(shdr)[dx].sh_addr - ELF64_S(shdr)[dx].sh_offset;
			break ;});
	if (!(flag & 0x4))
		LF_SECTION(ELF64_S(shdr)[dx].sh_offset + ELF64_S(shdr)[dx].sh_size == ELF64_P(phdr)[xseg].p_filesz,
			{ esec = dx + 1; break ;});
		
	if (xsec == -1 ||
	    gdiff == -1 ||
	    (!(flag & 0x4) && esec == -1)) {
		dprintf(STDERR_FILENO, "Critical section header not found\n");
		goto fail_l2;
	}

	/* assumes data is after rodata and rodata is after text */
	filsz = wfil->stat.st_size;
	/* unpacker size */
	added = wpfil->unpack_sz; /* unpacker sz */
	added += WPACKER_TSIZE; /* packer header size */
#if 1
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

	if (ELF64_S(shdr)[xsec].sh_addr & 0xf) {
		align = ELF64_S(shdr)[xsec].sh_addr & 0xf;
	}


	/* copy everything that's behind exec segment offset */
	offp = flag & 0x4 ?
		ELF64_P(phdr)[xseg].p_offset : /* << GCC 8 and higher */
		ELF64_P(phdr)[xseg].p_filesz + 0xf & ~0xf; /* << GCC 7 and lower */

	printf("COPY OFFSET %#lx\n", offp);

	wehdr = memcpy(tmap, ehdr, offp);
	wphdr = SELF64_E + tmap;

	/* injection start */
	_exec = memcpy(tmap + offp,
		       /*0x0*/
		       "\x57\x52\x50\x56"
		       /* 0x4 sequence to copy in byte for header */
		       "\x48\x8d\x35\x53""\x00\x00\x00"
		       /* 0xb */
		       "\x48\x31\xff"
		       "\x48\x31\xd2"
		       "\x66\xba\x0b\x00"
		       "\x40\xb7\x01"
		       "\x48\x31\xc0"
		       "\xb0\x01"
		       /* --------------- ---------- */
		       /* 0x1d syscall */
		       "\x0f\x05"
		       /* 0x1f  (0x1e load .text rel) // to do dyn */
		       "\x48\x8d\x3d\x42""\x00\x00\x00"
		       /* 0x26 load key address rip rel addr // ok */
		       "\x48\x8d\x35\x43""\x00\x00\x00"
		       /* 0x2d mov rdx, size // to do dyn */
		       "\x48\xba""\x00\x00\x00\x00""\x00\x00\x00\x00"
		       /* 0x37 packer call // ok */
		       "\xe8\x44\x00\x00""\x00"
		       /* 0x3c lea rsi, rip - 0x43 (_init sym) // to do dyn */
		       "\x48\x8d\x3d\x00""\xff\xff\xff"
		       /* 0x43 mov rsi, PLACE HOLDER // dyn */
		       "\x48\xbe""\x00\x00\x00\x00""\x00\x00\x00\x00"
		       /* 0x4d */
		       "\x31\xd2\xb2\x05""\xb0\x0a\x0f\x05"
		       /* 0x55 restore register */
		       "\x5e\x58\x5a\x5f"
		       /* 0x59 jmp near rel addr + 0x26 // dyn jump unpack */
		       "\xe9\x26\x00\x00""\x00"
		       /* 0x5e ____________ should jump over*/
		       /*__WOOODY__ , 0xa 0 STRING*/
		       "\x5f\x5f\x57\x4f\x4f\x44\x59\x5f"
		       "\x5f\x0a\x00\x90\x90\x90\x90\x90"
		       "\x90\x90" /* alignment for SSE */
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
	/* injection end */

	/* align size */
	ELF64_P(wphdr)[xseg].p_filesz = (ELF64_P(wphdr)[xseg].p_filesz + 0xf) & ~0xf;

	/* copy the rest */
	memcpy(_exec + added,
	       wfil->map + offp,
	       wfil->stat.st_size - offp);

	ELF64_P(wphdr)[xseg].p_filesz += added;
	ELF64_P(wphdr)[xseg].p_memsz = ELF64_P(wphdr)[xseg].p_filesz;
	ELF64_P(wphdr)[xseg].p_flags |= PF_W;
	/* 
	 * offsets them so the original program does not segfaults 
	 * when using relative address 
	 */
	/* patch segment offset */
	for (int i = xseg + 1; i < ELF64_E(wehdr)->e_phnum; i++) {
		if (ELF64_P(wphdr)[i].p_offset > ELF64_P(wphdr)[xseg].p_offset) {
			ELF64_P(wphdr)[i].p_offset += added;
			if (flag & 0x4) {
				ELF64_P(wphdr)[i].p_vaddr  += added;
				ELF64_P(wphdr)[i].p_paddr  += added;
			}
		}
	}

	/* patch section offset */
	ELF64_E(wehdr)->e_shoff += added;
	wshdr = ELF64_E(wehdr)->e_shoff + tmap;

#define FIX_SECT_OFFSET(x)			\
	do {					\
		if ((x).sh_addr)		\
			(x).sh_addr += added;	\
		(x).sh_offset += added;		\
	} while(0);

	if (flag & 0x4) {
		for (int i = xsec; i < ELF64_E(wehdr)->e_shnum; i++)
			FIX_SECT_OFFSET(ELF64_S(wshdr)[i]);
	} else {
		for (int i = esec; i < ELF64_E(wehdr)->e_shnum; i++)
			ELF64_S(wshdr)[i].sh_offset += added;
	}

	/* 
	 * If we inserted on top, we must fix dynamic section 
	 * otherwise ignore it, since offset has not changed.
	 */
	if (flag & 0x4) {
		if (ELF64_E(wehdr)->e_type == ET_DYN) {
			LF_SECTION(strcmp(ELF64_S(wshdr)[dx].sh_name + shstroff, ".dynamic") == 0,
				{dyn = ELF64_S(wshdr)[dx].sh_offset + tmap; break ;});
			if (0 == dyn) {
				dprintf(STDERR_FILENO, "dynamic section is missing\n");
				goto fail_l3;
			}
			for (;DT_NULL != ELF64_DYN(dyn)->d_tag; NEXT_HDR(dyn, SELF64_DYN)) {
				switch (ELF64_DYN(dyn)->d_tag) {
				case DT_PLTGOT:
				case DT_FINI:
				case DT_INIT:
				case DT_FINI_ARRAY:
				case DT_INIT_ARRAY:
					ELF64_DYN(dyn)->d_un.d_ptr += added;
				default: break ;
				}
			}
		}

		if (0 == strcmp(".plt", shstroff + ELF64_S(wshdr)[xsec + 1].sh_name))
			flag |= 0x1;
		/* 
		 * patching some section content
		 */
		for (int i = 0; i < ELF64_E(wehdr)->e_shnum; i++) {
			if (ELF64_S(wshdr)[i].sh_type == SHT_RELA) {
				if (ELF64_S(wshdr)[i].sh_offset == 0 ||
				    ELF64_S(wshdr)[i].sh_entsize != SELF64_RELA)
					continue ;

				rela = ELF64_S(wshdr)[i].sh_offset + tmap;
				if ((flag & 0x1) && strcmp(".rela.plt", shstroff + ELF64_S(wshdr)[i].sh_name))
					flag |= 0x2;

				for (int n = ELF64_S(wshdr)[i].sh_size /
					     ELF64_S(wshdr)[i].sh_entsize - 1;
				     n > -1; n--) {
					ELF64_RELA(rela)[n].r_offset += added;
					if (flag & 0x4) {
						switch (ELF64_R_TYPE(ELF64_RELA(rela)[n].r_info)) {
						case R_X86_64_RELATIVE:
						case R_X86_64_RELATIVE64:
						case R_X86_64_IRELATIVE:
							ELF64_RELA(rela)[n].r_addend += added;
						default: break ;
						}
					}

					/* got patch */
					if (flag & 0x2)
						*((__UINT_LEAST64_TYPE__ *)
						  (tmap + ELF64_RELA(rela)[n].r_offset -
						   gdiff)) += added;
				}
			}
			if (ELF64_S(wshdr)[i].sh_type == SHT_DYNSYM ||
			    ELF64_S(wshdr)[i].sh_type == SHT_SYMTAB) {
				if (ELF64_S(wshdr)[i].sh_entsize != SELF64_ST)
					continue ;
				st = ELF64_S(wshdr)[i].sh_offset + tmap;
				for (int n = ELF64_S(wshdr)[i].sh_size / ELF64_S(wshdr)[i].sh_entsize - 1;
				     n > -1; n--) {
					if (ELF64_ST(st)[n].st_value)
						ELF64_ST(st)[n].st_value += added;
				}
			}
		}
	}

	for (int i = xsec; ELF64_S(shdr)[i].sh_flags & SHF_EXECINSTR; i++)
		xsz += ELF64_S(shdr)[i].sh_size;
	xsz &= ~0xf;

	/* size to unpack */
	*((__UINT_LEAST64_TYPE__ *)(&0x2f[_exec])) = xsz;

	/* patch entry point to our packer */
	if (flag & 0x4) {
		/* packer is at topside of the map */
		/* offset to the real section .text */
		*((__INT_LEAST32_TYPE__ *)(&0x22[_exec])) = added - 0x26;
		/* point to the start of the segment */
		*((__INT_LEAST32_TYPE__ *)(&0x3f[_exec])) = -0x43;
		/* segment size for mprotect */
		*((__UINT_LEAST64_TYPE__ *)(&0x45[_exec])) = xsz;
		/* patch the jmp so it goes to _start@.text*/
		*((__INT_LEAST32_TYPE__ *)(&0x5a[_exec])) = (added * 2) + ELF64_E(wehdr)->e_entry -
			ELF64_S(wshdr)[xsec].sh_addr -
			0x5e;

		/* patch entry point */
		ELF64_E(wehdr)->e_entry = ELF64_S(wshdr)[xsec].sh_addr - added;
		packer(_exec + added, &0x70[_exec], xsz);
	} else {
		/* packer is at the bottomside of the map */
		/* offset to the real section .text */
		*((__INT_LEAST32_TYPE__ *)(&0x22[_exec])) = -offp + ELF64_S(wshdr)[xsec].sh_addr - 0x26 + align;
		/* point to the start of the segment */
		*((__INT_LEAST32_TYPE__ *)(&0x3f[_exec])) = -offp - 0x43;
		/* segment size for mprotect */
		*((__UINT_LEAST64_TYPE__ *)(&0x45[_exec])) = ELF64_P(wphdr)[xseg].p_memsz;
		/* patch the jmp so it goes to _start@.text*/
		*((__INT_LEAST32_TYPE__ *)(&0x5a[_exec])) = -offp + ELF64_E(wehdr)->e_entry - 0x5e;
		/* patch entry point */
		ELF64_E(wehdr)->e_entry = ELF64_P(wphdr)[xseg].p_filesz - added;
		printf("__sec offset:%#lx align:%#lx\n", ELF64_S(wshdr)[xsec].sh_offset, align);
		packer(tmap + ELF64_S(wshdr)[xsec].sh_offset + align, &0x70[_exec], xsz);
	}

	/* pack the .text by calling the object function */
	printf("seg vaddr:%#lx\n", ELF64_P(wphdr)[xseg].p_vaddr);
	printf("sec vaddr:%#lx\n", ELF64_S(wshdr)[xsec].sh_addr);

	printf("%lu\n", added);
	printf("packed :%lx bytes\n", xsz);
	printf("jmp:%#lx\n", *((__INT_LEAST32_TYPE__ *)(&0x5a[_exec])));
	printf("value:%lx\n", *((__UINT_LEAST64_TYPE__ *)(&0x2f[_exec])));

	munmap(tmap, filsz);
	close(tfd);
	close(rfd);
	return 0;
fail_l3:
	munmap(tmap, filsz);
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

#define DEFAULT_PAYLOAD_PATH      "./aes_masm.o"

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
