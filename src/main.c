#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/file.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include <stdio.h>
#include <stdint.h>

#include "libft.h"
#include "woody.h"
#include "ft_getopt_long.h"

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

#define WASSERT(expr, jmp, fmt, ...)			\
	if (expr) {					\
		dprintf(STDERR_FILENO, fmt __VA_OPT__(,) __VA_ARGS__);	\
		goto jmp;				\
	}

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
	WASSERT(0 > fdv, fail_open,
		     "fatal: failed to open '%s'\n", victim);
	WASSERT(0 > fstat(fdv, &new->stat), fail_vmap,
		     "fatal: could not stat '%s'\n", victim);

	_stat = &new->stat;
	WASSERT((__off_t)SELF64_E > _stat->st_size, fail_vmap,
		     "Unsupported file '%s'\n", victim);

	mapv = WVMAP(fdv, _stat->st_size);
	WASSERT(MAP_FAILED == mapv, fail_vmap,
		     "fatal: mmap fail '%s'\n", victim);

	ident = mapv;
	WASSERT(0 != ft_memcmp(ident, ELFMAG, SELFMAG), fail_corrupt,
		     "'%s' is not an elf\n", victim);

	WASSERT(ELFCLASSNONE == ident[EI_CLASS] || ELFCLASSNUM <= ident[EI_CLASS],
		     fail_corrupt,
		     "Unsupported file '%s'\n", victim);

	/* This program only supports little endian */
	WASSERT(ELFDATA2LSB != ident[EI_DATA],
		     fail_corrupt,
		     "Unsupported endianess '%s'\n", victim);

	/* checking if any segment is past size of file */

	WASSERT(ident[EI_CLASS] != ELFCLASS64,
		     fail_corrupt,
		     "Unsupported architecture '%s'\n", victim);

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
	new->shstrp = ELF64_S(shdr)[ELF64_E(ehdr)->e_shstrndx].sh_offset + mapv;

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
			    0 == ft_strcmp(".symtab", shstr + ELF##_S(shndr)->sh_name)) { \
				symtabn = ELF##_S(shndr)->sh_size / S##ELF##_ST; \
				symtab = ELF##_S(shndr)->sh_offset + (char *)wfile->map; \
			}						\
			/* GOD FORBIDS */				\
			if (!strtab &&					\
			    0 == ft_strcmp(".strtab", shstr + ELF##_S(shndr)->sh_name)) \
				strtab = ELF##_S(shndr)->sh_offset + (char *)wfile->map; \
									\
			if (!toffset &&					\
			    0 == ft_strcmp(".text", shstr + ELF##_S(shndr)->sh_name)) \
				toffset = ELF##_S(shndr)->sh_offset;	\
		}							\
									\
		WASSERT(0 == symtab,					\
			fail,						\
			"elf section symtab not found in payload '%s'\n", \
			pl_path);					\
									\
		WASSERT(0 == strtab,					\
			fail,						\
			"elf section strtab not found in payload '%s'\n", \
			pl_path);					\
									\
		WASSERT(0 == toffset,					\
			fail,						\
			"elf section text not found in payload '%s'\n",	\
			pl_path);					\
									\
		for (Elf64_Xword i = symtabn;				\
		     i ||  0 == stpack || 0 == stupack;			\
		     i--, NEXT_HDR(symtab, S##ELF##_ST)) {		\
			/* GOD FORBIDS */				\
			if (!stpack &&					\
			    0 == ft_strcmp(packsym, strtab + ELF##_ST(symtab)->st_name)) \
				stpack = symtab;			\
			if (!stupack &&					\
			    0 == ft_strcmp(unpacksym, strtab + ELF##_ST(symtab)->st_name)) \
				stupack = symtab;			\
		}							\
									\
		WASSERT(0 == stpack || 0 == stupack,			\
			fail,						\
				"could not find symbol '%s'"		\
				" in payload '%s' symtab\n",		\
				!stpack ? packsym : unpacksym,		\
			pl_path);					\
									\
		pl->pack_off = ELF##_ST(stpack)->st_value + toffset;	\
		pl->unpack_off = ELF##_ST(stupack)->st_value + toffset;	\
		pl->pack_sz = ELF##_ST(stpack)->st_size;		\
		pl->unpack_sz = ELF##_ST(stupack)->st_size;		\
		WASSERT(0 == pl->unpack_sz,				\
			fail,						\
			"Symbol '%s' has size 0\n", unpacksym);		\
	} while(0);

	PL_GETPACKER(ELF64);

	WASSERT(mprotect(wfile->map,
			 pl->wfile.stat.st_size,
			 PROT_READ | PROT_EXEC),
		fail,
		"fatal: mprotect error\n");
	return 0;

fail:
	wclose(&pl->wfile);
fail_wopen:
	return -1;
}

static int
_seed_packer(void *buf, size_t size)
{
	int rfd;
	int ret = -1;

	rfd = open("/dev/urandom", O_RDONLY);
	/* fallback if urandom is not available or missing */
	if (0 > rfd)
		rfd = open("/dev/random", O_RDONLY);

	WASSERT(0 > rfd,
		fail,
		"Failed to generate a key\n");
	ret = read(rfd, buf, size);
	close(rfd);
fail:
	return -(0 => ret);
}

static int
_inject_stub(void *ehdr, void *phx, void *bss, size_t plsz)
{
	void *stubp = ehdr + ELF64_P(phx)->p_offset + ELF64_P(phx)->p_filesz;

	__UINT_LEAST64_TYPE__
		vaddr_entry = ELF64_E(ehdr)->e_entry,
		vaddr_patched = ELF64_P(phx)->p_vaddr + ELF64_P(phx)->p_filesz,
		vaddr_bss = ELF64_P(bss)->sh_addr;

	if (ELF64_P(phx)->p_filesz != ELF64_P(phx)->p_memsz)
		goto fail;

	ft_memcpy(stubp,
		  "\x57\x52\x50\x56"
		  "\x48\x31\xff"
		  "\x31\xd2"
		  "\x48\x31\xf6"
		  "\x48\x31\xc0"
		  "\x48\x83\xec\x10"
	/*13*/	  "\x48\x8d\x3d\x35\x00\x00\x00"
		  /*            ^^^ 0x16*/
	/*1a*/	  "\x48\x89\x7c\x24\x08"
	/*1f*/	  "\xc7\x04\x24\x00\x00\x00\x00"
		  /*            ^^^ 0x22*/
		  "\x8b\x34\x24"
		  "\xb2\x07"
		  "\xb0\x0a"
		  "\x0f\x05"
		  "\xff\x54\x24\x08"
		  "\x48\x8b\x7c\x24\x08"
		  "\x8b\x0c\x24"
		  "\xf3\x48\xab"
		  "\x5e\x5f"
		  "\xb2\x03"
		  "\xb0\x0a"
		  "\x0f\x05"
		  "\x5e\x58\x5a\x5f"
	/*4a*/	  "\xe9\xfd\xff\xff\xff",
		  /*    ^^^ 0x4b*/
	/*4f*/
		  WSTUB_SIZE);
#define BSS_OFFSET 0x16
#define BSZ_OFFSET 0x22
#define JMP_OFFSET 0x4b
	*((__INT_LEAST32_TYPE__ *)(stubp + BSS_OFFSET)) =
		vaddr_bss - vaddr_patched - 0x1a;
	*((__INT_LEAST32_TYPE__ *)(stubp + BSZ_OFFSET)) =
		plsz + 0xfff & ~0xfff;
	*((__INT_LEAST32_TYPE__ *)(stubp + JMP_OFFSET)) =
		-(vaddr_patched - vaddr_entry)- 0x4f;

	ELF64P(phx)->p_filesz += WSTUB_SIZE;
	ELF64P(phx)->p_memsz  += WSTUB_SIZE;
	return 0;
#undef BSS_OFFSET
#undef BSZ_OFFSET
#undef JMP_OFFSET
fail:
	return -1;
}

static int
_inject_payload(void *map, void *phx, void *phd, void *bss,
		WPAYLOAD const *wpfil)
{
	__UINT_LEAST64_TYPE__
		text_vaddr,
		bss_vaddr;

	ft_memcpy
		"\x48\x8d\x35\x53\x00\x00\x00"
		"\x48\x31\xff"
		"\x48\x31\xd2"
		"\x66\xba\x0b\x00"
		"\x40\xb7\x01"
		"\x48\x31\xc0"
		"\xb0\x01"
		"\x0f\x05"
		"\x48\x8d\x3d\xde\xff\xff\xff"
		"\xbe\x44\x33\x22\x11"
		"\x31\xd2"
		"\xb2\x07"
		"\xb0\x0a"
		"\x48\x8d\x3d\x41\x00\x00\x00"
		"\x48\x8d\x35\x2a\x00\x00\x00"
		"\xba\x44\x33\x22\x11"
		"\xe8\x15\x00\x00\x00"
		"\x48\x8d\x3d\xb4\xff\xff\xff"
		"\xbe\x44\x33\x22\x11"
		"\x31\xd2"
		"\xb2\x05"
		"\xb0\x0a"
		"\x0f\x05"
		"\xc3"
	/*5a*/
		"\x5f\x5f\x57\x4f\x4f\x44\x59\x5f\x5f"

}


int
winject(WFILE const *wfil, WPAYLOAD const *wpfil, const void *key)
{
	void    (*packer)(void *, void *, size_t) = wpfil->wfile.map + wpfil->pack_off;
	void    *ehdr = wfil->ehdr,
	        *phdr = wfil->phdr,
	        *shdr = wfil->shdr,
		*shstrp = wfil->shstrp,
		*wehdr, *wphdr, *wshdr,
		*wmap;
	size_t  filsz,
		added,
		offp, voff;
	int     phx_dx = -1,
	        phd_dx = -1,
		shx_dx = -1,
		wfd,
		i;

	if (0 == wfil ||
	    0 == wpfil)
		goto fail;

#define WTARGET "woody"
	/* 
	 * triggers copy on write on all page allocated
	 * this prevents error from happening if the victim file 
	 * is the same as the target one
	 */
	read(wfil->fd, wfil->map, wfil->stat.st_size);
	/* ^^ worst hack */
	tfd = open(WTARGET, O_CREAT | O_RDWR, wfil->stat.st_mode);
	WASSERT(0 > tfd,
		fail,
		"failed to open '%s'\n", WTARGET);
#undef WTARGET
	/* get executable segments */
	for (i = 0; i < ELF64_E(ehdr)->e_phnum; i++) {
		if (ELF64_P(phdr)[i].p_flags & PF_X) {
			phx_dx = i;
			break ;
		}
	}
	/* get data segment */
	for (; i < ELF64_E(ehdr)->e_phnum; i++) {
		if (ELF64_P(phdr)[i].p_flags == (PF_R | PF_W)) {
			phd_dx = i;
			break ;
		}
	}
	/* get section init */
	for (i = 0; i < ELF64_E(ehdr)->e_shnum; i++) {
		if (0 == ft_strcmp(ELF64_S(shdr)[i].sh_name + shstrp, ".bss"))
			bss_dx = i;
	}

	WASSERT(shx_dx == -1
		|| phd_dx == -1
		|| phx_dx == -1,
		fail_l1,
		"Executable program header or .init or .bss not found\n");
	/* checking requirement for injection */
	WASSERT(ELF64_P(phdr)[phx_dx + 1].p_vaddr - 
		ELF64_P(phdr)[phx_dx].p_vaddr + ELF64_P(phdr)[phx_dx].p_memsz
		< WSTUB_SIZE,
		fail_l1,
		"Segment executable cannot append stub, aborting\n");
	

	added = wpfil->unpack_sz;
	added += WWRAPPER_SIZE;
	added += 0x1f;
	added &= ~0xf;

	WASSERT(-1 == ftruncate(wfd, wfil->stat.st_size + added),
		fail_l1,
		"Fatal, Could not truncate file\n");

	wmap = WWMAP(wfd, wfil->stat.st_size + added);
	WASSERT(MAP_FAILED == wmap,
		fail_l1,
		"Fatal, mmap error\n");

	offp = ELF64_P(phdr)[phd_dx].p_offset + ELF64_P(phdr)[phd_dx].p_filesz;
	ft_memcpy(wmap, wfil->tmap, offp);

	_inject_stub();
	_inject_payload();

	/* patching time */
	wehdr;
	wshdr;
	wphdr;

	munmap(wmap, filsz);
	close(wfd);
	return 0;

fail_l2:
	munmap(wmap, filsz);
fail_l1:
	close(tfd);
fail:
	return -1;
}

#define DEFAULT_PAYLOAD_PATH "./aes_masm.o"

#define DEFAULT_PAYLOAD_PSYM "aes128_enc"
#define DEFAULT_PAYLOAD_USYM "aes128_dec"

void
wusage(void)
{
	dprintf(STDERR_FILENO, "usage: ./woodywood_packer [-dpe] binary\n"
		"\t-d Specify a symbol name for the unpacker (default: "DEFAULT_PAYLOAD_USYM")\n"
		"\t-e Specify a symbol name for the packer (default: "DEFAULT_PAYLOAD_PSYM")\n"
		"\t-p Specify a path to a non stripped loadable object (default: "DEFAULT_PAYLOAD_PATH")\n");
}

int
main(int ac, char **av)
{
	WFILE w;
	WPAYLOAD pl;
	char *pl_path = DEFAULT_PAYLOAD_PATH;
	char *pl_psym = DEFAULT_PAYLOAD_PSYM;
	char *pl_usym = DEFAULT_PAYLOAD_USYM;
	static struct options_s opts[] = {
		{"payload", req_arg, 0, 'p'},
		{"usym", req_arg, 0, 'd'},
		{"psym", req_arg, 0, 'e'},
		{0, 0, 0, 0}
	};
	int  opt;

	if (ac == 1) {
		wusage();
		goto fail;
	}
	while (-1 != (opt = ft_getopt_long(ac, av, "pde", opts))) {
		switch (opt) {
		case 'p':
			pl_path = _optarg;
			break ;
		case 'd':
			pl_usym = _optarg;
			break ;
		case 'e':
			pl_psym = _optarg;
			break ;
		default :
			wusage();
			goto fail;
		}
	}

	if (wopen(av[_optind], &w))
		goto fail;

	if (wopen_pl(pl_path, &pl,
		     pl_psym,
		     pl_usym))
		goto fail;
	if (winject(&w, &pl))
		goto fail;
	printf("SUCCESS\n");
	return 0;
fail:
	return 1;
}
