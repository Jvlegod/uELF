#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include "uELF.h"
#include "uELf_log.h"

// open file and read ELF header
static int Elf64_open(const char *name, uElf64_File *elf_file) {
  int fd = open(name, O_RDWR);
  if (fd < 0) {
    uELF_ERROR("Failed to open file: %s", name);
    return -1;
  }

  elf_file->fd = fd;

  // Read ELF header
  if (read(fd, &elf_file->elf_header, sizeof(elf_file->elf_header)) != sizeof(elf_file->elf_header)) {
    uELF_ERROR("Failed to read ELF header");
    close(fd);
    return -1;
  }

  if (memcmp(elf_file->elf_header.e_ident, "\x7f""ELF", 4) != 0) {
	uELF_ERROR("Not a valid ELF file");
	close(fd);
	return -1;
  }

  return fd;
}

static int Elf64_close(uElf64_File *elf_file) {
  if (elf_file->fd >= 0) {
	close(elf_file->fd);
	elf_file->fd = -1;
  }
  return 0;
}

static void uELF64_print_Header(uElf64_File *elf_file) {
  uElf64_Ehdr *ehdr = &elf_file->elf_header;

  uELF_INFO("ELF Header:");
  uELF_INFO("  Entry point: 0x%lx", ehdr->e_entry);
  uELF_INFO("  Program Header Offset: %lu", ehdr->e_phoff);
  uELF_INFO("  Section Header Offset: %lu", ehdr->e_shoff);
  uELF_INFO("  Number of Program Headers: %u", ehdr->e_phnum);
  uELF_INFO("  Number of Section Headers: %u", ehdr->e_shnum);
}

int main(int argc, char **argv) {
  if (argc < 2) {
    uELF_ERROR("error argument");
    return -1;
  }

  const char *path = argv[1];

  if (memcmp((void*)path, "-h", 2) == 0 || memcmp((void*)path, "--help", 6) == 0) {
	  printf("Usage: %s <elf-file>\n", argv[0]);
	  return 0;
  }

  uElf64_File elf_file;
  memset(&elf_file, 0, sizeof(elf_file));

  if (Elf64_open(path, &elf_file) < 0) {
	  uELF_ERROR("Failed to open ELF file: %s", path);
	  return -1;
  }
  uELF64_print_Header(&elf_file);

close:
  Elf64_close(&elf_file);

  return 0;
}
