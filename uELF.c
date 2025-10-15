#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "uELF.h"
#include "uELf_log.h"

// open file and read ELF header
static int uElf64_open(const char *name, uElf64_File *elf_file) {
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

static int uElf64_close(uElf64_File *elf_file) {
  if (elf_file->fd >= 0) {
	  close(elf_file->fd);
	  elf_file->fd = -1;
  }

  for (int i = 0; i < elf_file->elf_header.e_shnum; i++) {
    if (elf_file->section_headers) {
      free(elf_file->section_headers);
      elf_file->section_headers = NULL;
    }
  }

  free(elf_file->shstrtab);
  elf_file->shstrtab = NULL;
  free(elf_file->symtab);
  elf_file->symtab = NULL;
  free(elf_file->dynsym);
  elf_file->dynsym = NULL;

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

  //parse symbol table if exists
  for (int i = 0; i < elf_file->elf_header.e_shnum; i++) {
    if (elf_file->section_headers[i].sh_type == UELF_SHT_SYMTAB) {
      elf_file->symtab_section = &elf_file->section_headers[i];
      elf_file->symtab = malloc(elf_file->section_headers[i].sh_size);
      if (!elf_file->symtab) {
        uELF_ERROR("Failed to allocate memory for symbol table");
        return -1;
      }

      lseek(fd, elf_file->symtab_section->sh_offset, SEEK_SET);
      if (read(fd, elf_file->symtab, elf_file->section_headers[i].sh_size) !=
          (ssize_t)elf_file->section_headers[i].sh_size) {
        uELF_ERROR("Failed to read symbol table");
        free(elf_file->symtab);
        return -1;
      }
    } else if (elf_file->section_headers[i].sh_type == UELF_SHT_DYNSYM) {
      elf_file->dynsym_section = &elf_file->section_headers[i];
      elf_file->dynsym = malloc(elf_file->section_headers[i].sh_size);
      if (!elf_file->dynsym) {
        uELF_ERROR("Failed to allocate memory for dynamic symbol table");
        return -1;
      }

      lseek(fd, elf_file->dynsym_section->sh_offset, SEEK_SET);
      if (read(fd, elf_file->dynsym, elf_file->section_headers[i].sh_size) !=
          (ssize_t)elf_file->section_headers[i].sh_size) {
        uELF_ERROR("Failed to read dynamic symbol table");
        free(elf_file->dynsym);
        return -1;
      }
    }
  }

  // parse static symbol table if exists
  if (elf_file->symtab_section) {
    elf_file->strtab_section = &elf_file->section_headers[elf_file->symtab_section->sh_link];
    elf_file->strtab = malloc(elf_file->strtab_section->sh_size);
    if (!elf_file->strtab) {
      uELF_ERROR("Failed to allocate memory for string table");
      return -1;
    }
  
    if (lseek(fd, elf_file->strtab_section->sh_offset, SEEK_SET) < 0) {
      uELF_ERROR("lseek failed when reading .strtab");
      return -1;
    }
  
    if (read(fd, elf_file->strtab, elf_file->strtab_section->sh_size) !=
      (ssize_t)elf_file->strtab_section->sh_size) {
      uELF_ERROR("read failed when reading .strtab");
      return -1;
    }
  }

  // parse dynamic symbol table if exists
  if (elf_file->dynsym_section) {
    elf_file->dynstr_section = &elf_file->section_headers[elf_file->dynsym_section->sh_link];
    elf_file->dynstr = malloc(elf_file->dynstr_section->sh_size);
    if (!elf_file->dynstr) {
      uELF_ERROR("Failed to allocate memory for dynamic string table");
      return -1;
    }
  
    if (lseek(fd, elf_file->dynstr_section->sh_offset, SEEK_SET) < 0) {
      uELF_ERROR("lseek failed when reading .dynstr");
      return -1;
    }
  
    if (read(fd, elf_file->dynstr, elf_file->dynstr_section->sh_size) !=
      (ssize_t)elf_file->dynstr_section->sh_size) {
      uELF_ERROR("read failed when reading .dynstr");
      return -1;
    }
  }


  return 0;
}

static int uELF64_print_symbols(uElf64_File *elf_file) {
  uElf64_Shdr *symtab_section = elf_file->symtab_section;
  uElf64_Shdr *dynsym_section = elf_file->dynsym_section;
  uElf64_Shdr *section_headers = elf_file->section_headers;

  if (symtab_section && symtab_section->sh_size > 0) {
    uElf64_Shdr *strtab_section = &section_headers[symtab_section->sh_link];
    char *strtab = elf_file->strtab;

    uELF_INFO("Symbol table '.symtab' contains %lu entries:",
              symtab_section->sh_size / symtab_section->sh_entsize);
    for (int i = 0; i < symtab_section->sh_size / symtab_section->sh_entsize; i++) {
      uElf64_Sym *sym = (uElf64_Sym *)(elf_file->symtab + i * sizeof(uElf64_Sym));
      const char *name = sym->st_name ? &strtab[sym->st_name] : "";
      uELF_INFO("  [%2d] Value: %016lx Size: %lu Info: %02x Other: %02x Shndx: %04x Name: %s",
                i, sym->st_value, sym->st_size, sym->st_info,
                sym->st_other, sym->st_shndx, name);
    }
  } else {
    uELF_INFO("No .symtab section found.");
  }

  if (dynsym_section && dynsym_section->sh_size > 0) {
    uElf64_Shdr *dynstr_section = &section_headers[dynsym_section->sh_link];
    char *dynstr = elf_file->dynstr;
    uELF_INFO("Symbol table '.dynsym' contains %lu entries:",
              dynsym_section->sh_size / dynsym_section->sh_entsize);
    for (int i = 0; i < dynsym_section->sh_size / dynsym_section->sh_entsize; i++) {
      uElf64_Sym *sym = (uElf64_Sym *)(elf_file->dynsym + i * sizeof(uElf64_Sym));
      const char *name = sym->st_name ? &dynstr[sym->st_name] : "";
      uELF_INFO("  [%2d] Value: %016lx Size: %lu Info: %02x Other: %02x Shndx: %04x Name: %s",
                i, sym->st_value, sym->st_size, sym->st_info,
                sym->st_other, sym->st_shndx, name);
    }
  } else {
    uELF_INFO("No .dynsym section found.");
  }

  return 0;
}

static int uELF64_parse_programs(uElf64_File *elf_file) {
  uElf64_Ehdr *ehdr = &elf_file->elf_header;
  int fd = elf_file->fd;

  if (ehdr->e_phnum == 0) {
    uELF_INFO("No program headers.");
    return 0;
  }

  // Allocate memory for program headers
  elf_file->program_headers = malloc(ehdr->e_phnum * sizeof(uElf64_Phdr));
  if (!elf_file->program_headers) {
    uELF_ERROR("Failed to allocate memory for program headers");
    return -1;
  }

  // Read program headers
  lseek(fd, ehdr->e_phoff, SEEK_SET);
  if (read(fd, elf_file->program_headers, ehdr->e_phnum * sizeof(uElf64_Phdr)) !=
      ehdr->e_phnum * sizeof(uElf64_Phdr)) {
    uELF_ERROR("Failed to read program headers");
    free(elf_file->program_headers);
    return -1;
  }

  return 0;
}

// 如果某个 section 的文件范围 [sh_offset, sh_offset + sh_size)
// 完全在某个 segment 的范围 [p_offset, p_offset + p_filesz)** 内，
// 那么这个 section 属于该 segment.
static int uELF64_print_map_sections_to_segments(uElf64_File *elf_file) {
    uElf64_Ehdr *ehdr = &elf_file->elf_header;
    uElf64_Shdr *shdrs = elf_file->section_headers;
    uElf64_Phdr *phdrs = elf_file->program_headers;
    const char *shstrtab = (const char *)elf_file->shstrtab;

    uELF_INFO("Section to Segment mapping:");

    for (int i = 0; i < ehdr->e_phnum; i++) {
        uElf64_Phdr *ph = &phdrs[i];

        uELF_INFO("   %02d     ", i);
        int found = 0;

        for (int j = 0; j < ehdr->e_shnum; j++) {
            uElf64_Shdr *sh = &shdrs[j];

            if (sh->sh_size == 0 || sh->sh_type == 0)
                continue;
          
            if (sh->sh_offset >= ph->p_offset &&
                (sh->sh_offset + sh->sh_size) <= (ph->p_offset + ph->p_filesz)) {

                const char *sec_name = shstrtab + sh->sh_name;
                uELF_INFO("%s ", sec_name);
                found = 1;
            }
        }

        if (!found)
            uELF_INFO(" ");
    }

    return 0;
}

static void uELF64_print_programs(uElf64_File *elf_file) {
    uElf64_Ehdr *ehdr = &elf_file->elf_header;
    uElf64_Phdr *phdrs = elf_file->program_headers;

    if (ehdr->e_phnum == 0) {
      uELF_INFO("No program headers.");
      return;
    }

    uELF_INFO("Program Headers (all %d):", ehdr->e_phnum);
    uELF_INFO("  [Idx] Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align");

    for (int i = 0; i < ehdr->e_phnum; i++) {
        const char *type_name;

        switch (phdrs[i].p_type) {
            case UELF_PT_NULL:    type_name = "NULL"; break;
            case UELF_PT_LOAD:    type_name = "LOAD"; break;
            case UELF_PT_DYNAMIC: type_name = "DYNAMIC"; break;
            case UELF_PT_INTERP:  type_name = "INTERP"; break;
            case UELF_PT_NOTE:    type_name = "NOTE"; break;
            case UELF_PT_SHLIB:   type_name = "SHLIB"; break;
            case UELF_PT_PHDR:    type_name = "PHDR"; break;
            case UELF_PT_TLS:     type_name = "TLS"; break;
            default:          type_name = "OTHER"; break;
        }

        uELF_INFO("  [%2d] %-14s %06lx %08lx %08lx %06lx %06lx %3x %5lu",
            i,
            type_name,
            phdrs[i].p_offset,
            phdrs[i].p_vaddr,
            phdrs[i].p_paddr,
            phdrs[i].p_filesz,
            phdrs[i].p_memsz,
            phdrs[i].p_flags,
            phdrs[i].p_align
        );
    }
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

  if (uElf64_open(path, &elf_file) < 0) {
	  uELF_ERROR("Failed to open ELF file: %s", path);
	  return -1;
  }
  uELF64_print_header(&elf_file);
  
  uELF64_parse_sections(&elf_file);
  uELF64_print_sections(&elf_file);

  uELF64_print_symbols(&elf_file);

  uELF64_parse_programs(&elf_file);
  uELF64_print_programs(&elf_file);
  uELF64_print_map_sections_to_segments(&elf_file);

close:
  uElf64_close(&elf_file);

  return 0;
}
