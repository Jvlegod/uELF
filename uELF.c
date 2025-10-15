#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
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

static void uELF64_print_header(uElf64_File *elf_file) {
    uElf64_Ehdr *ehdr = &elf_file->elf_header;

    uELF_INFO("ELF Header:");
    uELF_INFO("  Magic: %02x %02x %02x %02x",
              ehdr->e_ident[0], ehdr->e_ident[1],
              ehdr->e_ident[2], ehdr->e_ident[3]);
    uELF_INFO("  Class: %s", uelf_class_name(ehdr->e_ident[4]));
    uELF_INFO("  Data encoding: %s", uelf_data_encoding(ehdr->e_ident[5]));
    uELF_INFO("  Version: %d", ehdr->e_ident[6]);
    uELF_INFO("  OS/ABI: %s", uelf_osabi_name(ehdr->e_ident[7]));
    uELF_INFO("  ABI Version: %d", ehdr->e_ident[8]);
    uELF_INFO("  Type: %s", uelf_type_name(ehdr->e_type));
    uELF_INFO("  Machine: %s (0x%x)", uelf_machine_name(ehdr->e_machine), ehdr->e_machine);
    uELF_INFO("  ELF Version: %u", ehdr->e_version);
    uELF_INFO("  Entry point: 0x%lx", ehdr->e_entry);
    uELF_INFO("  Program Header Offset: %lu", ehdr->e_phoff);
    uELF_INFO("  Section Header Offset: %lu", ehdr->e_shoff);
    uELF_INFO("  Flags: 0x%x", ehdr->e_flags);
    uELF_INFO("  ELF Header Size: %u bytes", ehdr->e_ehsize);
    uELF_INFO("  Program Header Entry Size: %u bytes", ehdr->e_phentsize);
    uELF_INFO("  Number of Program Headers: %u", ehdr->e_phnum);
    uELF_INFO("  Section Header Entry Size: %u bytes", ehdr->e_shentsize);
    uELF_INFO("  Number of Section Headers: %u", ehdr->e_shnum);
    uELF_INFO("  Section Header String Table Index: %u", ehdr->e_shstrndx);
}

static void uELF64_print_sections(uElf64_File *elf_file) {
    uElf64_Ehdr *ehdr = &elf_file->elf_header;
    uElf64_Shdr *shdrs = elf_file->section_headers;
    char *shstrtab = elf_file->shstrtab;

    uELF_INFO("Section Headers (all %d):", ehdr->e_shnum);
    uELF_INFO("  [Idx] Name              Type            Addr      Off    Size    EntSz  Flags Link Info Align");

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *name = shstrtab ? &shstrtab[shdrs[i].sh_name] : "(null)";
        const char *type_name;

        switch (shdrs[i].sh_type) {
            case UELF_SHT_NULL:    type_name = "NULL"; break;
            case UELF_SHT_PROGBITS:type_name = "PROGBITS"; break;
            case UELF_SHT_SYMTAB:  type_name = "SYMTAB"; break;
            case UELF_SHT_STRTAB:  type_name = "STRTAB"; break;
            case UELF_SHT_RELA:    type_name = "RELA"; break;
            case UELF_SHT_HASH:    type_name = "HASH"; break;
            case UELF_SHT_DYNAMIC: type_name = "DYNAMIC"; break;
            case UELF_SHT_NOTE:    type_name = "NOTE"; break;
            case UELF_SHT_NOBITS:  type_name = "NOBITS"; break;
            case UELF_SHT_REL:     type_name = "REL"; break;
            case UELF_SHT_SHLIB:   type_name = "SHLIB"; break;
            case UELF_SHT_DYNSYM:  type_name = "DYNSYM"; break;
            default:          type_name = "OTHER"; break;
        }

        uELF_INFO("  [%2d] %-17s %-12s %08lx %06lx %06lx %06lx %5lx %4u %4u %5lu",
            i,
            name,
            type_name,
            shdrs[i].sh_addr,
            shdrs[i].sh_offset,
            shdrs[i].sh_size,
            shdrs[i].sh_entsize,
            shdrs[i].sh_flags,
            shdrs[i].sh_link,
            shdrs[i].sh_info,
            shdrs[i].sh_addralign
        );
    }
}

static int uELF64_parse_sections(uElf64_File *elf_file) {
  uElf64_Ehdr *ehdr = &elf_file->elf_header;
  int fd = elf_file->fd;

  // Allocate memory for section headers
  elf_file->section_headers = malloc(ehdr->e_shnum * sizeof(uElf64_Shdr));
  if (!elf_file->section_headers) {
    uELF_ERROR("Failed to allocate memory for section headers");
    return -1;
  }

  // Read section headers
  lseek(fd, ehdr->e_shoff, SEEK_SET);
  if (read(fd, elf_file->section_headers, ehdr->e_shnum * sizeof(uElf64_Shdr)) !=
      ehdr->e_shnum * sizeof(uElf64_Shdr)) {
    uELF_ERROR("Failed to read section headers");
    free(elf_file->section_headers);
    return -1;
  }

  // parse section header string table
  elf_file->shstrtab_section = &elf_file->section_headers[ehdr->e_shstrndx];
  elf_file->shstrtab = malloc(elf_file->shstrtab_section->sh_size);
  if (!elf_file->shstrtab) {
    uELF_ERROR("Failed to allocate memory for section header string table");
    free(elf_file->section_headers);
    return -1;
  }

  if (lseek(fd, elf_file->shstrtab_section->sh_offset, SEEK_SET) < 0) {
      uELF_ERROR("lseek failed when reading .shstrtab");
      return -1;
  }

  if (read(fd, elf_file->shstrtab, elf_file->shstrtab_section->sh_size) !=
      (ssize_t)elf_file->shstrtab_section->sh_size) {
      uELF_ERROR("read failed when reading .shstrtab");
      return -1;
  }

  return 0;
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
  uELF64_print_header(&elf_file);
  
  uELF64_parse_sections(&elf_file);
  uELF64_print_sections(&elf_file);

close:
  Elf64_close(&elf_file);

  return 0;
}
