#include <elf.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#define __MMAP_PROT (PROT_READ)
#define __MMAP_FLAGS (MAP_PRIVATE | MAP_FILE)
#define __MMAP_CPROT (PROT_READ | PROT_WRITE)
#define __MMAP_CFLAGS (MAP_SHARED | MAP_FILE)
int
main(int ac, char **av)
{
	Elf64_Ehdr *ehdr;
	Elf64_Shdr *shdr;
	Elf64_Phdr *phdr;
	Elf64_Sym  *sym;
	Elf64_Xword symsize;
	struct stat _stat;
	void *map;
	char *shstr;
	int fd;
#if __CORRUPT == 1
	char buf[4096];
	long unsigned int randval;
	int fdc;
	void *mapc;
	int rand = open("/dev/urandom", O_RDONLY);
	char opt;
#endif

	assert(ac > 1);
	fd = open(av[1], O_RDONLY);
	assert(fd > -1);

	fstat(fd, &_stat);

	map = mmap(0, _stat.st_size, __MMAP_PROT, __MMAP_FLAGS, fd, 0);
	assert(map != MAP_FAILED);

	ehdr = map;
#if __CORRUPT == 1
	assert(3072 > strlen(av[1]));
	/***************************************/
	snprintf(buf, 4096, "%s_%s", av[1], "elf_prog_bad_offset");
	fdc = open(buf, O_RDWR| O_CREAT | O_TRUNC, 0744);
	assert(-1 < fdc);
	assert(0 == ftruncate(fdc, _stat.st_size));

	mapc = mmap(0, _stat.st_size, __MMAP_CPROT, __MMAP_CFLAGS, fdc, 0);
	assert(MAP_FAILED != mapc);

	memcpy(mapc, map, _stat.st_size);
	ehdr = mapc;
	ehdr->e_phoff += 1;
	munmap(mapc, _stat.st_size);
	close(fdc);
	/***************************************/
	snprintf(buf, 4096, "%s_%s", av[1], "elf_sect_bad_offset");
	fdc = open(buf, O_RDWR| O_CREAT | O_TRUNC, 0744);
	assert(-1 < fdc);
	assert(0 == ftruncate(fdc, _stat.st_size));

	mapc = mmap(0, _stat.st_size, __MMAP_CPROT, __MMAP_CFLAGS, fdc, 0);
	assert(MAP_FAILED != mapc);

	memcpy(mapc, map, _stat.st_size);
	ehdr = mapc;
	ehdr->e_shoff += 1;
	munmap(mapc, _stat.st_size);
	close(fdc);
	/***************************************/
	snprintf(buf, 4096, "%s_%s", av[1], "elf_prog_rand_offset");
	fdc = open(buf, O_RDWR| O_CREAT | O_TRUNC, 0744);
	assert(-1 < fdc);
	assert(0 == ftruncate(fdc, _stat.st_size));
	assert(-1 < read(rand, &randval, sizeof randval));

	mapc = mmap(0, _stat.st_size, __MMAP_CPROT, __MMAP_CFLAGS, fdc, 0);
	assert(MAP_FAILED != mapc);

	memcpy(mapc, map, _stat.st_size);
	ehdr = mapc;
	ehdr->e_phoff = randval;
	munmap(mapc, _stat.st_size);
	close(fdc);
	/*************************************/
	snprintf(buf, 4096, "%s_%s", av[1], "elf_sect_rand_offset");
	fdc = open(buf, O_RDWR| O_CREAT | O_TRUNC, 0744);
	assert(-1 < fdc);
	assert(0 == ftruncate(fdc, _stat.st_size));
	assert(-1 < read(rand, &randval, sizeof randval));

	mapc = mmap(0, _stat.st_size, __MMAP_CPROT, __MMAP_CFLAGS, fdc, 0);
	assert(MAP_FAILED != mapc);

	memcpy(mapc, map, _stat.st_size);
	ehdr = mapc;
	ehdr->e_shoff = randval;
	munmap(mapc, _stat.st_size);
	close(fdc);
	/*************************************/
	snprintf(buf, 4096, "%s_%s", av[1], "elf_truncated_truncated");
	fdc = open(buf, O_RDWR| O_CREAT | O_TRUNC, 0744);
	assert(-1 < fdc);
	assert(-1 < read(rand, &randval, sizeof randval));
	randval =  randval % _stat.st_size;
	assert(0 == ftruncate(fdc, randval));

	mapc = mmap(0, randval, __MMAP_CPROT, __MMAP_CFLAGS, fdc, 0);
	assert(MAP_FAILED != mapc);

	memcpy(mapc, map, randval);
	ehdr = mapc;
	ehdr->e_shoff = randval;
	munmap(mapc, randval);
	close(fdc);

#else
	printf("e.e_type      == %#lx\n",ehdr->e_type);
	printf("e.e_machine   == %#lx\n",ehdr->e_machine);
	printf("e.e_version   == %#lx\n",ehdr->e_version);
	printf("e.e_entry     == %#lx\n",ehdr->e_entry);
	printf("e.e_phoff     == %#lx\n",ehdr->e_phoff);
	printf("e.e_shoff     == %#lx\n",ehdr->e_shoff);
	printf("e.e_flags     == %#lx\n",ehdr->e_flags);
	printf("e.e_ehsize    == %#lx\n",ehdr->e_ehsize);
	printf("e.e_phentsize == %#lx\n",ehdr->e_phentsize);
	printf("e.e_phnum     == %#lx\n",ehdr->e_phnum);
	printf("e.e_shentsize == %#lx\n",ehdr->e_shentsize);
	printf("e.e_shnum     == %#lx\n",ehdr->e_shnum);
	printf("e.e_shstrndx  == %#lx\n\n",ehdr->e_shstrndx);
	/* Segment */
	phdr = map + ehdr->e_phoff;
	for (size_t n = ehdr->e_phnum; n; n--, phdr++) {
		printf("p.p_type   == %#llx\n", phdr->p_type);
		printf("p.p_flags  == %#llx\n", phdr->p_flags);
		printf("p.p_offset == %#llx\n", phdr->p_offset);
		printf("p.p_vaddr  == %#llx\n", phdr->p_vaddr);
		printf("p.p_paddr  == %#llx\n", phdr->p_paddr);
		printf("p.p_filesz == %#llx\n", phdr->p_filesz);
		printf("p.p_memsz  == %#llx\n", phdr->p_memsz);
		printf("p.p_align  == %#llx\n\n", phdr->p_align);
	}

	/* Section */
	shdr = map + ehdr->e_shoff;
	shstr = map + shdr[ehdr->e_shstrndx].sh_offset;
	for (size_t n = ehdr->e_shnum; n; n--, shdr++) {
		if (memcmp(".symtab", shstr + shdr->sh_name, 7) == 0) {
			sym = (Elf64_Sym *)((char *)map + shdr->sh_offset);
			printf("map = %p\nsym = %p\n", map, sym);
			symsize = shdr->sh_size;
		}
		printf("s.sh_name       == %s\n", shstr + shdr->sh_name);
		printf("s.sh_type       == %#llx\n", shdr->sh_type);
		printf("s.sh_flags      == %#llx\n", shdr->sh_flags);
		printf("s.sh_addr       == %#llx\n", shdr->sh_addr);
		printf("s.sh_offset     == %#llx\n", shdr->sh_offset);
		printf("s.sh_size       == %#llx\n", shdr->sh_size);
		printf("s.sh_link       == %#llx\n", shdr->sh_link);
		printf("s.sh_info       == %#llx\n", shdr->sh_info);
		printf("s.sh_addralign  == %#llx\n", shdr->sh_addralign);
		printf("s.sh_entsize    == %#llx\n\n", shdr->sh_entsize);
	}
# if __WITH_SYMTAB == 1
	for (Elf64_Xword n = 0; n < symsize; n += sizeof *sym, sym++) {
		printf("symtab.st_name  == %#lx\n", sym->st_name);
		printf("symtab.st_info  == %#lx\n", sym->st_info);
		printf("symtab.st_other == %#lx\n", sym->st_other);
		printf("symtab.st_shndx == %#lx\n", sym->st_shndx);
		printf("symtab.st_value == %#lx\n", sym->st_value);
		printf("symtab.st_size  == %#lx\n\n", sym->st_size);
	}
# endif
#endif
	return (0);
}
