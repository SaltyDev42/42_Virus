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

	new->name = (char *)victim;
	new->fd = fdv;
	new->map = mapv;

	new->ehdr = mapv;
	new->phdr = phdr;
	new->shdr = shdr;
	new->shstrp = ELF64_S(shdr)[ELF64_E(mapv)->e_shstrndx].sh_offset + mapv;

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
	return -(0 >= ret);
}

static int
_inject_stub(WVICTIM *v)
{
	void	*phdr = v->_vphdr;

	void	*phx  = &ELF64_P(phdr)[v->phx_ndx],
		*stubp = v->wmap
			+ ELF64_P(phx)->p_offset
			+ ELF64_P(phx)->p_filesz;

	__UINT_LEAST64_TYPE__
		vaddr_patched = ELF64_P(phx)->p_vaddr + ELF64_P(phx)->p_filesz;

	if (ELF64_P(phx)->p_filesz != ELF64_P(phx)->p_memsz)
		goto fail;
	ft_memcpy(stubp,
		  "\x52\x50"
		  "\x31\xd2"
		  "\x48\x83\xec\x10"
	/*8*/	  "\x48\x8d\x3d\x35\x00\x00\x00"
		  /*            ^^^ 0xb*/
	/*f*/	  "\x4c\x8d\x05\x00\x00\x00\x00"
		  /*            ^^^ 0x12*/
	/*16*/	  "\x48\x89\x7c\x24\x08"
	/*1b*/	  "\xc7\x04\x24\x00\x00\x00\x00"
		  /*            ^^^ 0x1e*/
		  "\x8b\x34\x24"
		  "\xb2\x07"
		  "\xb0\x0a"
		  "\x0f\x05"
		  "\x41\xff\xd0"

		  "\x4c\x89\xc7"
		  "\x89\xc1"
		  "\x31\xc0"
		  "\xf3\x48\xab"

		  "\x5e\x5f"
		  "\xb2\x03"
		  "\xb0\x0a"
		  "\x0f\x05"
		  "\x58\x5a"
	/*42*/	  "\xe9\xfd\xff\xff\xff"
		  /*    ^^^ 0x43*/
	/*4d*/	  "\x90",
		  WSTUB_SIZE);
#define DAT_OFFSET 0xb
#define BSS_OFFSET 0x12
#define DSZ_OFFSET 0x1e
#define JMP_OFFSET 0x43

	/* setting pointers for patching */
	v->stub_bss = stubp + BSS_OFFSET;
	v->stub_dat = stubp + DAT_OFFSET;
	v->stub_dsz = stubp + DSZ_OFFSET;
	v->stub_jmp = stubp + JMP_OFFSET;
	/* setting values for patching */
	v->entry    = vaddr_patched;

	return 0;
#undef BSS_OFFSET
#undef DAT_OFFSET
#undef DSZ_OFFSET
#undef JMP_OFFSET
fail:
	return -1;
}

static ssize_t
_inject_payload(WVICTIM *v, WPAYLOAD const *wpfil)
{
	void    (*packer)(void *, void *, size_t)
		= wpfil->wfile.map + wpfil->pack_off;

	/* using the original mapping, 
	   we don't patch headers here, only injecting payload */
	void	*vphdr	= v->_vphdr,
		*vshdr	= v->_vshdr;

	void	*phd	= &ELF64_P(vphdr)[v->phd_ndx],
		*init	= &ELF64_S(vshdr)[v->shx_ndx],
		*root;

	size_t	packsz = v->added,
		data_memsz  = ELF64_P(phd)->p_memsz,
		data_filesz = ELF64_P(phd)->p_filesz,
		text_filesz = 0,
		toadd = 0;

	__UINT_LEAST64_TYPE__
		phd_off    = ELF64_P(phd)->p_offset + data_filesz,
		text_off;

	int	text_align,
		i;

	/* grow phd mem size if space is lower than required */
	if (data_memsz - data_filesz < packsz)
		toadd = packsz - (data_memsz - data_filesz);

	v->phd_fix   = toadd;

	phd_off     += v->phd_align;

#define KEYSIZE 0x10
	root = v->wmap + phd_off;
	printf("phd_off = %#lx\n", phd_off);
	ft_memcpy(root,
		  "\x48\x8d\x35\x5a\x00\x00\x00" /* << string */
		  "\x48\x31\xff"
		  "\x48\x31\xd2"
		  "\x66\xba\x0c\x00"
		  "\x40\xb7\x01"
		  "\x48\x31\xc0"
		  "\xb0\x01"
		  "\x0f\x05"                     /* << write syscall */

		  "\x48\x8d\x3d\xde\xff\xff\xff" /* << efffective address with rip rel */
		  /*            ^^^ 0x1e       */
		  "\xbe\x44\x33\x22\x11"         /* << size */
		  /*    ^^^ 0x23      */
		  "\x31\xd2"
		  "\xb2\x07"
		  "\xb0\x0a"
		  "\x0f\x05"
		  "\x48\x8d\x3d\x41\x00\x00\x00"
		  /*             ^^^ 0x32 */
		  "\x48\x8d\x35\x33\x00\x00\x00"
		  "\xba\x44\x33\x22\x11"
		  /*    ^^^^ 0x3e */
		  "\xe8\x39\x00\x00\x00"        /* << function call */

		  "\x48\x8d\x3d\xb4\xff\xff\xff"
		  /*            ^^^ 0x4a   */
		  "\xbe\x44\x33\x22\x11"
		  /*    ^^^ 0x4f      */
		  "\x31\xd2"
		  "\xb2\x05"
		  "\xb0\x0a"
		  "\x0f\x05"
		  "\xb8\x11\x22\x33\x44"
		  /*    ^^^0x5c        */
		  "\xc3"
		  /*END OF OPCODE*/
	/*61*/	  "\x2e\x2e\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x2e\x0a"
		  /*...WOODY...n*/
		  "\x90\x90\x90\x90",
		  /*ALIGN OPCODE FOR KEY*/
		  /*70*/
		  WWRAPPER_SIZE - KEYSIZE);

	_seed_packer(root + (WWRAPPER_SIZE - KEYSIZE), KEYSIZE);

	ft_memcpy(root + WWRAPPER_SIZE,
		  wpfil->wfile.map + wpfil->unpack_off,
		  wpfil->unpack_sz);

#define MAX_SECTION 4
	/* Search for text section, cannot pack plt */
	for (i = 0; i < MAX_SECTION; i++) {
		if (0 == ft_strcmp(ELF64_S(init)[i].sh_name + v->_vshstrp, ".text"))
			break ;
	}

	text_filesz = ELF64_S(init)[i].sh_size;
	text_off    = ELF64_S(init)[i].sh_offset;
	text_align  = text_off & 0xf;

	/* if no executable section found. abort */
	if (0 == text_filesz) {
		packsz = -1;
		goto end;
	}

	/* text_align based on offset, need to be aligned 2^4 */
	text_filesz -= text_align;
	/* remove trailing, bytes */
	text_filesz &= ~0xf;

	/* obfuscate the 4 executable section using AES-128 
	   (replaceable with any other type of symmetric encryption) 
	   object must be compiled with gcc, nasm does not provide enough
	   info to extract the unpacker */
	packer(v->wmap + text_off + text_align,
	       root + WWRAPPER_SIZE - KEYSIZE,
	       text_filesz);
#define PHX1_OFFSET 0x1e
#define PXS1_OFFSET 0x23

#define TXT_OFFSET  0x32
#define TXS_OFFSET  0x3e

#define PHX2_OFFSET 0x4a
#define PXS2_OFFSET 0x4f

#define PLSZ_OFFSET 0x5c

	/* setting pointers for patching*/
	v->pload_phx[0] = root + PHX1_OFFSET;
	v->pload_phx[1] = root + PHX2_OFFSET;
	v->pload_pxs[0] = root + PXS1_OFFSET;
	v->pload_pxs[1] = root + PXS2_OFFSET;
	v->pload_txt    = root + TXT_OFFSET;
	v->pload_txs    = root + TXS_OFFSET;
	/* setting addend for patching */
	v->upac_align   = text_align;
	v->upac_filesz  = text_filesz;
	v->txt_ndx      = i + v->shx_ndx;

	/*gimmick to give size of the payload in the bss for our stub */
	*((__UINT_LEAST32_TYPE__ *)(root + PLSZ_OFFSET))
		= (wpfil->unpack_sz + WWRAPPER_SIZE) / 8 + 1;

#undef KEYSIZE
#undef PLSZ_OFFSET
#undef PHX1_OFFSET
#undef PXS1_OFFSET
#undef PHX2_OFFSET
#undef PXS2_OFFSET
#undef TXT_OFFSET
#undef TXS_OFFSET
end:
	return packsz;
}

static void
_patch_binary(WVICTIM *v)
{
	__UINT_LEAST64_TYPE__
		offset        = v->added,
		text_filesz   = v->upac_filesz,
		text_align    = v->upac_align,
		phd_fix       = v->phd_fix,
		align;

	void	*wehdr = v->wmap,
		*wphdr = v->wmap + ELF64_E(wehdr)->e_phoff,
		*wshdr = v->wmap + ELF64_E(wehdr)->e_shoff + offset;

	int	phx_ndx = v->phx_ndx,
		phd_ndx = v->phd_ndx,
		txt_ndx = v->txt_ndx,
		bss_ndx = v->bss_ndx;

	__UINT_LEAST64_TYPE__
		vaddr_patched = v->entry,
		vaddr_entry   = ELF64_E(wehdr)->e_entry,
		vaddr_phx     = ELF64_P(wphdr)[phx_ndx].p_vaddr,
		memsz_phx     ,
		vaddr_data    = ELF64_P(wphdr)[phd_ndx].p_vaddr,
		memsz_data    = ELF64_P(wphdr)[phd_ndx].p_memsz,
		vaddr_payload = vaddr_data
		+ ELF64_P(wphdr)[phd_ndx].p_filesz
		+ v->phd_align,
		vaddr_text    = ELF64_S(wshdr)[txt_ndx].sh_addr;


	ELF64_E(wehdr)->e_shoff += offset;
	ELF64_E(wehdr)->e_entry  = v->entry;

	/* this assumes section are ascending order by offset in file */
	for (int i = bss_ndx; i < ELF64_E(wehdr)->e_shnum; i++) {
		if (ELF64_S(wshdr)[i].sh_flags == SHT_NOBITS)
			continue ;
		ELF64_S(wshdr)[i].sh_offset += offset;
	}

	ELF64_S(wshdr)[bss_ndx].sh_size += phd_fix;
	ELF64_P(wphdr)[phd_ndx].p_memsz += phd_fix;
	ELF64_P(wphdr)[phd_ndx].p_filesz += offset;

	ELF64_P(wphdr)[phx_ndx].p_filesz += WSTUB_SIZE;
	ELF64_P(wphdr)[phx_ndx].p_memsz  += WSTUB_SIZE;
	/* patching the text section is only relevant if we could inject it
	   before the rodata */
	if (ELF64_P(wphdr)[phx_ndx+1].p_flags == PF_R)
		ELF64_S(wshdr)[txt_ndx].sh_size  += WSTUB_SIZE;

	memsz_phx = ELF64_P(wphdr)[phx_ndx].p_filesz;

	/*stub*/
	align = vaddr_data & 0xfff;
	/* mprotect rdi + rsi */
	*v->stub_dat = (vaddr_data & ~0xfff) - vaddr_patched - 0xf;
	*v->stub_dsz = memsz_data + align;
	/* rel $rip call to our packer (lea r8, [$rip + ???]) */
	*v->stub_bss = vaddr_payload - vaddr_patched - 0x16;
	/* virtual address of _start */
	*v->stub_jmp = vaddr_entry - vaddr_patched - 0x47;

	/*payload*/
	*v->pload_phx[0] = vaddr_phx - vaddr_payload - 0x22;
	*v->pload_pxs[0] = memsz_phx;
	*v->pload_phx[1] = vaddr_phx - vaddr_payload - 0x4e;
	*v->pload_pxs[1] = memsz_phx;
	*v->pload_txt    = vaddr_text - vaddr_payload - 0x36 + text_align;
	*v->pload_txs    = text_filesz;
}

static int
_safe_bss_inject(
	void *map,
	void *dynsym,
	void *bss,
	__UINT_LEAST64_TYPE__ __top_phd_vaddr)
{
	__UINT_LEAST64_TYPE__
		_topmost_safe_bss = ELF64_S(bss)->sh_addr,
		st_value;
	void	*dynsym_p = map + ELF64_S(dynsym)->sh_offset;

	printf("_topmost_safe_bss: %#lx\n", _topmost_safe_bss);
	if (ELF64_S(dynsym)->sh_type != SHT_DYNSYM ||
	    ELF64_S(dynsym)->sh_entsize != SELF64_ST)
		goto result;
	/* bss top address can be unaligned, align it to 16 */
	_topmost_safe_bss += -_topmost_safe_bss & 0xf;
	for (int n = 0, max = ELF64_S(dynsym)->sh_size / SELF64_ST;
	     n < max;
	     n++) {
		st_value = ELF64_ST(dynsym_p)[n].st_value
			+ ELF64_ST(dynsym_p)[n].st_size;
		/* align it to 2^16, since size can be random*/
		st_value += -st_value & 0xf;
		if (st_value > _topmost_safe_bss)
			_topmost_safe_bss = st_value;
	}
result:
	printf("_topmost_safe_bss: %#lx\n", _topmost_safe_bss);
	return _topmost_safe_bss - __top_phd_vaddr;
}


int
winject(WFILE const *wfil, WPAYLOAD const *wpfil)
{
	void    *ehdr = wfil->ehdr,
	        *phdr = wfil->phdr,
	        *shdr = wfil->shdr,
		*shstrp = wfil->shstrp,
		*wmap;

	__UINT_LEAST64_TYPE__
		phd_vaddr,
		filesz,
		offp;

	int     phx_dx = -1,
	        phd_dx = -1,
		shx_dx = -1,
		bss_dx = -1,
		dyn_dx = 0,
		phd_align,
		wfd,
		i;
	WVICTIM victim;

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
	wfd = open(WTARGET, O_CREAT | O_RDWR, wfil->stat.st_mode);
	WASSERT(0 > wfd,
		fail,
		"failed to open '%s'\n", WTARGET);
#undef WTARGET
	/* get executable segments */
	for (i = 0; i < ELF64_E(ehdr)->e_phnum; i++) {
		if ((ELF64_P(phdr)[i].p_flags & PF_X) &&
		    ELF64_P(phdr)[i].p_type == PT_LOAD) {
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

	/* we can't know when there will be a dynsym */
	for (i = 0; i < ELF64_E(ehdr)->e_shnum; i++) {
		if (0 == ft_strcmp( ELF64_S(shdr)[i].sh_name + shstrp, ".dynsym")) {
			dyn_dx = i;
			break ;
		}
	}

	/* get section init */
	for (i = 0; i < ELF64_E(ehdr)->e_shnum; i++) {
		if (0 == ft_strcmp(ELF64_S(shdr)[i].sh_name + shstrp, ".init")) {
			shx_dx = i;
			break ;
		}
	}
	/* get section bss */
	for (; i < ELF64_E(ehdr)->e_shnum; i++) {
		if (0 == ft_strcmp(ELF64_S(shdr)[i].sh_name + shstrp, ".bss")) {
			bss_dx = i;
			break;
		}
	}

	WASSERT(shx_dx == -1
		|| phd_dx == -1
		|| phx_dx == -1
		|| bss_dx == -1,
		fail_l1,
		"Executable program header or .init or .bss not found\n");
	/* checking requirement for injection */
	WASSERT(ELF64_P(phdr)[phx_dx + 1].p_vaddr - 
		ELF64_P(phdr)[phx_dx].p_vaddr + ELF64_P(phdr)[phx_dx].p_memsz
		< WSTUB_SIZE,
		fail_l1,
		"Segment executable cannot append stub, aborting\n");

	phd_vaddr     = ELF64_P(phdr)[phd_dx].p_vaddr
		+ ELF64_P(phdr)[phd_dx].p_filesz;
	/* bss is not right after data, there is some padding */
	phd_align     = _safe_bss_inject(wfil->map,
					 &ELF64_S(shdr)[dyn_dx],
					 &ELF64_S(shdr)[bss_dx],
					 phd_vaddr);

	victim.added  = wpfil->unpack_sz;
	victim.added += WWRAPPER_SIZE;
	/* There is an offset between the start of the .bss and the end of the .data
	   and it varies from 0x8 ~ 0x18 */
	victim.added += phd_align;
	victim.added += 0xf;
	victim.added &= ~0xf;

	victim.phd_align = phd_align;

	filesz = wfil->stat.st_size + victim.added;

	WASSERT(-1 == ftruncate(wfd, filesz),
		fail_l1,
		"Fatal, Could not truncate file\n");

	wmap = WWMAP(wfd, filesz);
	WASSERT(MAP_FAILED == wmap,
		fail_l1,
		"Fatal, mmap error\n");

	offp = ELF64_P(phdr)[phd_dx].p_offset + ELF64_P(phdr)[phd_dx].p_filesz;

	ft_memcpy(wmap, wfil->map, offp);

	victim.wfile = (WFILE *)wfil;
	victim.wmap = wmap;
	victim.phd_ndx = phd_dx;
	victim.phx_ndx = phx_dx;
	victim.bss_ndx = bss_dx;
	victim.shx_ndx = shx_dx;

	WASSERT(-1 == _inject_stub(&victim),
		fail_l2,
		"Program Header memsz and filesz does not match\n");

	WASSERT(0 > _inject_payload(&victim, wpfil),
		fail_l2,
		"smthsmth happened, probably bad (injection fail, should not)\n");

	printf("added %#lx\n", victim.added);
	ft_memcpy(wmap + offp + victim.added,
		  wfil->map + offp,
		  wfil->stat.st_size - offp);
	/* patching time */
	_patch_binary(&victim);

	munmap(wmap, filesz);
	close(wfd);
	return 0;

fail_l2:
	munmap(wmap, filesz);
fail_l1:
	close(wfd);
fail:
	return -1;
}

#define DEFAULT_PAYLOAD_PATH "./aes_masm.o"

#define DEFAULT_PAYLOAD_PSYM "aes128_enc"
#define DEFAULT_PAYLOAD_USYM "aes128_dec"

void
wusage(void)
{
	dprintf(STDERR_FILENO, "usage: ./woody_woodpacker [-dpe] binary\n"
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
