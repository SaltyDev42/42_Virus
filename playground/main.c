#include <elf.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>

#include <sys/mman.h>
#include <sys/stat.h>

#define __MMAP_PROT (PROT_READ)
#define __MMAP_FLAGS (MAP_PRIVATE | MAP_FILE)

int
main(int ac, char **av)
{
	Elf64_Ehdr *ehdr;
	Elf64_Shdr *shdr;
	Elf64_Phdr *phdr;
	struct stat _stat;
	void *map;
	char *shstr;
	int fd;

	assert(ac > 1);
	fd = open(av[1], O_RDONLY);
	assert(fd > -1);

	fstat(fd, &_stat);

	map = mmap(0, _stat.st_size, __MMAP_PROT, __MMAP_FLAGS, fd, 0);
	assert(map != MAP_FAILED);

	ehdr = map;

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
		printf("s.sh_name       == %s\n", shstr + shdr->sh_name);
		printf("s.sh_type       == %#llx\n", shdr->sh_type);
		printf("s.sh_flags      == %#llx\n", shdr->sh_flags);
		printf("s.sh_addr       == %#llx\n", shdr->sh_addr);
		printf("s.sh_offset     == %#llx\n", shdr->sh_offset);
		printf("s.sh_size       == %#llx\n", shdr->sh_size);
		printf("s.sh_line       == %#llx\n", shdr->sh_link);
		printf("s.sh_info       == %#llx\n", shdr->sh_info);
		printf("s.sh_addralign  == %#llx\n", shdr->sh_addralign);
		printf("s.sh_entsize    == %#llx\n\n", shdr->sh_entsize);
	}
}
