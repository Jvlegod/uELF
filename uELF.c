#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdint.h>
#include <dlfcn.h>
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
  elf_file->name = name;

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

  if (elf_file->loaded_segments) {
    for (size_t i = 0; i < elf_file->loaded_segment_count; i++) {
      if (elf_file->loaded_segments[i]) {
        munmap(elf_file->loaded_segments[i], elf_file->loaded_segment_sizes[i]);
      }
    }
    free(elf_file->loaded_segments);
    elf_file->loaded_segments = NULL;
  }

  if (elf_file->loaded_segment_sizes) {
    free(elf_file->loaded_segment_sizes);
    elf_file->loaded_segment_sizes = NULL;
  }
  elf_file->loaded_segment_count = 0;

  free(elf_file->section_headers);
  elf_file->section_headers = NULL;
  free(elf_file->program_headers);
  elf_file->program_headers = NULL;

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

  if (symtab_section && symtab_section->sh_size > 0) {
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

static int uELF64_print_relocations(uElf64_File *elf_file) {
  uElf64_Ehdr *ehdr = &elf_file->elf_header;
  uElf64_Shdr *shdrs = elf_file->section_headers;
  char *shstrtab = elf_file->shstrtab;
  
  int sym_type = -1;
  int found = 0;

  if (!shdrs) {
    uELF_WARN("No section headers found, cannot print relocations.");
    return -1;
  }

  for (int i = 0; i < ehdr->e_shnum; i++) {
    uElf64_Shdr *sh = &shdrs[i];
    uElf64_Sym *sym = NULL;

    // 只打印 SHT_RELA 或 SHT_REL 类型的节
    if (sh->sh_type != UELF_SHT_RELA && sh->sh_type != UELF_SHT_REL)
      continue;

    found = 1;
    const char *sec_name = shstrtab ? &shstrtab[sh->sh_name] : "(unknown)";
    size_t entry_count = sh->sh_entsize ? (sh->sh_size / sh->sh_entsize)
                                        : 0;
    if (entry_count == 0)
      continue;

    uELF_INFO("Relocation section '%s' (type=%s) at offset 0x%lx contains %lu sh_link: %lu entries:",
              sec_name,
              (sh->sh_type == UELF_SHT_RELA) ? "RELA" : "REL",
              (unsigned long)sh->sh_offset,
              (unsigned long)entry_count,
              (unsigned long)sh->sh_link);

    // 读取整个节内容
    void *buf = malloc(sh->sh_size);
    if (!buf) {
      uELF_ERROR("Failed to allocate memory for relocation section '%s'", sec_name);
      continue;
    }

    if (pread(elf_file->fd, buf, sh->sh_size, sh->sh_offset) != (ssize_t)sh->sh_size) {
      uELF_ERROR("Failed to read relocation section '%s'", sec_name);
      free(buf);
      continue;
    }

    // 遍历每个 relocation 条目
    for (size_t j = 0; j < entry_count; j++) {
      if (sh->sh_type == UELF_SHT_RELA) {
        uElf64_Rela *rela = &((uElf64_Rela *)buf)[j];
        uint32_t sym_index = UELF64_R_SYM(rela->r_info);
        uint32_t type = UELF64_R_TYPE(rela->r_info);
        // 处理符号名称
        if (strcmp(&elf_file->shstrtab[shdrs[sh->sh_link].sh_name], ".dynsym") == 0) {
          sym = (uElf64_Sym *)(elf_file->dynsym + sym_index * sizeof(uElf64_Sym));
          sym_type = 1;
        } else {
          sym = (uElf64_Sym *)(elf_file->symtab + sym_index * sizeof(uElf64_Sym));
          sym_type = 0;
        }
        uELF_INFO("  [%3lu] Offset: 0x%016lx  Info: 0x%016lx  Addend: %ld  Sym: %u  Name: %s  Type: %u",
                  j,
                  rela->r_offset,
                  rela->r_info,
                  rela->r_addend,
                  sym_index,
                  sym_type == 1 ? &elf_file->dynstr[sym->st_name] : &elf_file->strtab[sym->st_name],
                  type);
      } else {
        uElf64_Rel *rel = &((uElf64_Rel *)buf)[j];
        uint32_t sym_index = UELF64_R_SYM(rel->r_info);
        uint32_t type = UELF64_R_TYPE(rel->r_info);
        // 处理符号名称
        if (strcmp(&elf_file->shstrtab[shdrs[sh->sh_link].sh_name], ".dynsym") == 0) {
          sym = (uElf64_Sym *)(elf_file->dynsym + sym_index * sizeof(uElf64_Sym));
          sym_type = 1;
        } else {
          sym = (uElf64_Sym *)(elf_file->symtab + sym_index * sizeof(uElf64_Sym));
          sym_type = 0;
        }
        uELF_INFO("  [%3lu] Offset: 0x%016lx  Info: 0x%016lx  Sym: %u  Name: %s  Type: %u",
                  j,
                  rel->r_offset,
                  rel->r_info,
                  sym_index,
                  sym_type == 1 ? &elf_file->dynstr[sym->st_name] : &elf_file->strtab[sym->st_name],
                  type);
      }
    }

    free(buf);
  }

  if (!found)
    uELF_INFO("No relocation sections found.");

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
    elf_file->program_headers = NULL;
    return -1;
  }

  return 0;
}

// 如果某个 section 的文件范围 [sh_offset, sh_offset + sh_size)
// 完全在某个 segment 的范围 [p_offset, p_offset + p_filesz] 内，
// 那么这个 section 属于该 segment.
static int uELF64_print_map_sections_to_segments(uElf64_File *elf_file) {
    uElf64_Ehdr *ehdr = &elf_file->elf_header;
    uElf64_Shdr *shdrs = elf_file->section_headers;
    uElf64_Phdr *phdrs = elf_file->program_headers;
    const char *shstrtab = (const char *)elf_file->shstrtab;

    if (!phdrs) {
        uELF_WARN("No program headers available for mapping information");
        return 0;
    }

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

static int uelf_prot_from_flags(uint32_t flags) {
  int prot = 0;
  if (flags & UELF_PF_R) prot |= PROT_READ;
  if (flags & UELF_PF_W) prot |= PROT_WRITE;
  if (flags & UELF_PF_X) prot |= PROT_EXEC;
  return prot;
}

static int uELF64_load_segments(uElf64_File *elf_file) {
  uElf64_Ehdr *ehdr = &elf_file->elf_header;

  if (!elf_file->program_headers) {
    uELF_ERROR("Program headers not parsed, cannot load segments");
    return -1;
  }

  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) {
    page_size = 4096;
  }

  int loadable_count = 0;
  for (int i = 0; i < ehdr->e_phnum; i++) {
    if (elf_file->program_headers[i].p_type == UELF_PT_LOAD &&
        elf_file->program_headers[i].p_memsz > 0) {
      loadable_count++;
    }
  }

  if (loadable_count == 0) {
    uELF_WARN("No loadable segments found");
    return 0;
  }

  elf_file->loaded_segments = calloc(loadable_count, sizeof(void *));
  elf_file->loaded_segment_sizes = calloc(loadable_count, sizeof(size_t));
  if (!elf_file->loaded_segments || !elf_file->loaded_segment_sizes) {
    uELF_ERROR("Failed to allocate memory for segment tracking");
    free(elf_file->loaded_segments);
    elf_file->loaded_segments = NULL;
    free(elf_file->loaded_segment_sizes);
    elf_file->loaded_segment_sizes = NULL;
    return -1;
  }

  int is_pie = (ehdr->e_type == 3); // ET_DYN
  uintptr_t base = 0;
  uint64_t min_vaddr = UINT64_MAX;
  uint64_t max_vaddr = 0;

  for (int i = 0; i < ehdr->e_phnum; i++) {
    uElf64_Phdr *ph = &elf_file->program_headers[i];
    if (ph->p_type != UELF_PT_LOAD || ph->p_memsz == 0) {
      continue;
    }
    // 操作系统的内存映射（mmap, mprotect 等）必须以页为单位操作. 如果不对齐，会导致保护或映射错误.
    uint64_t aligned_vaddr = uelf_align_down(ph->p_vaddr, (uint64_t)page_size);
    uint64_t segment_end = uelf_align_up(ph->p_vaddr + ph->p_memsz, (uint64_t)page_size);
    if (aligned_vaddr < min_vaddr) {
      min_vaddr = aligned_vaddr;
    }
    if (segment_end > max_vaddr) {
      max_vaddr = segment_end;
    }
  }

  if (is_pie && loadable_count > 0) {
    size_t total_size = (size_t)(max_vaddr - min_vaddr);
    if (total_size == 0) {
      total_size = (size_t)page_size;
    }

    void *reservation = mmap(NULL, total_size,
                             PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reservation == MAP_FAILED) {
      uELF_ERROR("Failed to reserve address space for PIE: %s", strerror(errno));
      free(elf_file->loaded_segments);
      elf_file->loaded_segments = NULL;
      free(elf_file->loaded_segment_sizes);
      elf_file->loaded_segment_sizes = NULL;
      return -1;
    }

    base = (uintptr_t)reservation - min_vaddr;
    elf_file->loaded_segments[0] = reservation;
    elf_file->loaded_segment_sizes[0] = total_size;
    elf_file->loaded_segment_count = 1;
  }

  int segment_index = is_pie ? 1 : 0;

  for (int i = 0; i < ehdr->e_phnum; i++) {
    uElf64_Phdr *ph = &elf_file->program_headers[i];
    if (ph->p_type != UELF_PT_LOAD || ph->p_memsz == 0) {
      continue;
    }

    uint64_t aligned_vaddr = uelf_align_down(ph->p_vaddr, (uint64_t)page_size);
    uint64_t segment_end = uelf_align_up(ph->p_vaddr + ph->p_memsz, (uint64_t)page_size);
    size_t map_size = (size_t)(segment_end - aligned_vaddr);

    int prot = uelf_prot_from_flags(ph->p_flags);

    if (is_pie) {
      uint8_t *segment_data = (uint8_t *)(base + ph->p_vaddr);
      ssize_t read_bytes = pread(elf_file->fd, segment_data, ph->p_filesz, ph->p_offset);
      if (read_bytes != (ssize_t)ph->p_filesz) {
        uELF_ERROR("Failed to read segment %d contents", i);
        goto fail;
      }

      if (ph->p_memsz > ph->p_filesz) {
        size_t bss_size = (size_t)(ph->p_memsz - ph->p_filesz);
        memset(segment_data + ph->p_filesz, 0, bss_size);
      }

      if (mprotect((void *)(base + aligned_vaddr), map_size, prot) < 0) {
        uELF_WARN("mprotect failed for segment %d: %s", i, strerror(errno));
      }

      uELF_INFO("Loaded segment %d at 0x%lx (%zu bytes)",
                i, (unsigned long)(base + aligned_vaddr), map_size);
      continue;
    }

    int map_prot = prot | PROT_WRITE;
    uintptr_t target_addr = base + aligned_vaddr;
    void *mapping_base = mmap((void *)target_addr, map_size, map_prot,
                              MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (mapping_base == MAP_FAILED) {
      uELF_ERROR("mmap failed for segment %d: %s", i, strerror(errno));
      goto fail;
    }

    uint8_t *segment_data = (uint8_t *)(base + ph->p_vaddr);
    ssize_t read_bytes = pread(elf_file->fd, segment_data, ph->p_filesz, ph->p_offset);
    if (read_bytes != (ssize_t)ph->p_filesz) {
      uELF_ERROR("Failed to read segment %d contents", i);
      munmap(mapping_base, map_size);
      goto fail;
    }

    if (ph->p_memsz > ph->p_filesz) {
      size_t bss_size = (size_t)(ph->p_memsz - ph->p_filesz);
      memset(segment_data + ph->p_filesz, 0, bss_size);
    }

    if ((prot & PROT_WRITE) == 0) {
      if (mprotect(mapping_base, map_size, prot) < 0) {
        uELF_WARN("mprotect failed for segment %d: %s", i, strerror(errno));
      }
    }

    elf_file->loaded_segments[segment_index] = mapping_base;
    elf_file->loaded_segment_sizes[segment_index] = map_size;
    elf_file->loaded_segment_count++;
    segment_index++;

    uELF_INFO("Loaded segment %d at 0x%lx (%zu bytes)",
              i, (unsigned long)(base + aligned_vaddr), map_size);
  }

  elf_file->load_base = base;
  return 0;

fail:
  for (size_t j = 0; j < elf_file->loaded_segment_count; j++) {
    if (elf_file->loaded_segments[j]) {
      munmap(elf_file->loaded_segments[j], elf_file->loaded_segment_sizes[j]);
    }
  }
  free(elf_file->loaded_segments);
  elf_file->loaded_segments = NULL;
  free(elf_file->loaded_segment_sizes);
  elf_file->loaded_segment_sizes = NULL;
  elf_file->loaded_segment_count = 0;
  elf_file->load_base = 0;
  return -1;
}

static int uELF64_lookup_symbol(uElf64_File *elf_file, const char *symbol, uint64_t *value) {
  if (!symbol || !value) {
    return -1;
  }

  if (elf_file->symtab_section && elf_file->symtab) {
    uElf64_Shdr *strtab_section = elf_file->strtab_section;
    if (strtab_section && elf_file->strtab) {
      size_t count = elf_file->symtab_section->sh_size / elf_file->symtab_section->sh_entsize;
      for (size_t i = 0; i < count; i++) {
        uElf64_Sym *sym = (uElf64_Sym *)(elf_file->symtab + i * sizeof(uElf64_Sym));
        if (sym->st_name >= strtab_section->sh_size)
          continue;
        const char *name = &elf_file->strtab[sym->st_name];
        if (name && strcmp(name, symbol) == 0) {
          *value = sym->st_value;
          return 0;
        }
      }
    }
  }

  if (elf_file->dynsym_section && elf_file->dynsym) {
    uElf64_Shdr *dynstr_section = elf_file->dynstr_section;
    if (dynstr_section && elf_file->dynstr) {
      size_t count = elf_file->dynsym_section->sh_size / elf_file->dynsym_section->sh_entsize;
      for (size_t i = 0; i < count; i++) {
        uElf64_Sym *sym = (uElf64_Sym *)(elf_file->dynsym + i * sizeof(uElf64_Sym));
        if (sym->st_name >= dynstr_section->sh_size)
          continue;
        const char *name = &elf_file->dynstr[sym->st_name];
        if (name && strcmp(name, symbol) == 0) {
          *value = sym->st_value;
          return 0;
        }
      }
    }
  }

  return -1;
}

static int uELF64_resolve_symbol_address(uElf64_File *elf_file,
                                         const uElf64_Sym *sym,
                                         const char *name,
                                         uint64_t *value) {
  if (!sym || !value) {
    return -1;
  }

  if (sym->st_shndx != 0 && sym->st_shndx < 0xff00) {
    *value = elf_file->load_base + sym->st_value;
    return 0;
  }

  if (!name || name[0] == '\0') {
    if (UELF64_ST_BIND(sym->st_info) == UELF_STB_WEAK) {
      *value = 0;
      return 0;
    }
    return -1;
  }

  dlerror();
  void *addr = dlsym(RTLD_DEFAULT, name);
  const char *err = dlerror();
  if (err != NULL || addr == NULL) {
    if (UELF64_ST_BIND(sym->st_info) == UELF_STB_WEAK) {
      uELF_WARN("Leaving weak external symbol '%s' unresolved", name);
      *value = 0;
      return 0;
    }
    uELF_ERROR("Failed to resolve external symbol '%s': %s", name,
               err ? err : "unknown error");
    return -1;
  }

  *value = (uint64_t)(uintptr_t)addr;
  return 0;
}

static int uELF64_x86_64_relocate(uElf64_File *elf_file, uElf64_Rela *relocs, size_t count,
                                  uElf64_Shdr *symtab_section, char *symtab_data,
                                  char *strtab_data, size_t strtab_size, size_t sym_entsize) {
  for (size_t rel_idx = 0; rel_idx < count; rel_idx++) {
    uElf64_Rela *rela = &relocs[rel_idx];
    uint32_t type = UELF64_R_TYPE(rela->r_info);
    uint32_t sym_index = UELF64_R_SYM(rela->r_info);
    uintptr_t target = elf_file->load_base + rela->r_offset;

    uint64_t value = 0;
    const uElf64_Sym *sym = NULL;
    const char *name = NULL;

    if (sym_index != 0 && symtab_data) {
      size_t symtab_size = symtab_section->sh_size;
      size_t offset = (size_t)sym_index * sym_entsize;
      if (offset + sym_entsize <= symtab_size) {
        sym = (const uElf64_Sym *)(symtab_data + offset);
        if (sym && sym->st_name && strtab_data && (size_t)sym->st_name < strtab_size) {
          name = strtab_data + sym->st_name;
        }
      } else {
        uELF_ERROR("Relocation references invalid symbol index %u", sym_index);
        free(relocs);
        return -1;
      }
    }

    switch (type) {
      case UELF_R_X86_64_RELATIVE:
        *(uint64_t *)target = elf_file->load_base + rela->r_addend;
        break;
      case UELF_R_X86_64_GLOB_DAT:
      case UELF_R_X86_64_JUMP_SLOT:
        if (!sym) {
          uELF_ERROR("Relocation requires symbol but none provided (index %u)", sym_index);
          free(relocs);
          return -1;
        }
        // 用来解决特殊的符号处理问题.
        if (uELF64_resolve_symbol_address(elf_file, sym, name, &value) < 0) {
          free(relocs);
          return -1;
        }
        *(uint64_t *)target = value;
        break;
      case UELF_R_X86_64_64:
        if (!sym) {
          uELF_ERROR("Relocation requires symbol but none provided (index %u)", sym_index);
          free(relocs);
          return -1;
        }
        if (uELF64_resolve_symbol_address(elf_file, sym, name, &value) < 0) {
          free(relocs);
          return -1;
        }
        *(uint64_t *)target = value + rela->r_addend;
        break;
      case UELF_R_X86_64_NONE:
        break;
      default:
        uELF_WARN("Unsupported relocation type %u at offset 0x%lx", type,
                  (unsigned long)rela->r_offset);
        break;
    }
  }
}

static int uELF64_arch_relocate(uElf64_File *elf_file, uElf64_Rela *relocs, size_t count,
                                uElf64_Shdr *symtab_section, char *symtab_data,
                                char *strtab_data, size_t strtab_size, size_t sym_entsize) {
  switch (elf_file->elf_header.e_machine)
  {
  case 0x3E: // EM_X86_64
    return uELF64_x86_64_relocate(elf_file, relocs, count, symtab_section, symtab_data,
                                   strtab_data, strtab_size, sym_entsize);
  default:
    return -1;
  }
  return -1;
}

static int uELF64_apply_relocations(uElf64_File *elf_file) {
  if (!elf_file->section_headers) {
    return 0;
  }

  for (int i = 0; i < elf_file->elf_header.e_shnum; i++) {
    uElf64_Shdr *sh = &elf_file->section_headers[i];
    // "All relocations for the AMD64 architecture use the ELF64_Rela structure.
    // Entries of type Elf64_Rel are not used."
    if (sh->sh_type != UELF_SHT_RELA || sh->sh_size == 0) {
      continue;
    }

    size_t count = sh->sh_entsize ? (sh->sh_size / sh->sh_entsize)
                                  : (sh->sh_size / sizeof(uElf64_Rela));
    if (count == 0) {
      continue;
    }

    uElf64_Rela *relocs = malloc(sh->sh_size);
    if (!relocs) {
      uELF_ERROR("Failed to allocate memory for relocation section %d", i);
      return -1;
    }

    if (pread(elf_file->fd, relocs, sh->sh_size, sh->sh_offset) != (ssize_t)sh->sh_size) {
      uELF_ERROR("Failed to read relocation section %d", i);
      free(relocs);
      return -1;
    }

    if (sh->sh_link >= elf_file->elf_header.e_shnum) {
      uELF_ERROR("Relocation section %d references invalid symbol table", i);
      free(relocs);
      return -1;
    }

    uElf64_Shdr *symtab_section = &elf_file->section_headers[sh->sh_link];
    char *symtab_data = NULL;
    char *strtab_data = NULL;
    size_t sym_entsize = symtab_section->sh_entsize ? symtab_section->sh_entsize
                                                    : sizeof(uElf64_Sym);
    size_t strtab_size = 0;

    if (symtab_section == elf_file->symtab_section && elf_file->symtab) {
      symtab_data = elf_file->symtab;
      strtab_data = elf_file->strtab;
      if (elf_file->strtab_section) {
        strtab_size = elf_file->strtab_section->sh_size;
      }
    } else if (symtab_section == elf_file->dynsym_section && elf_file->dynsym) {
      symtab_data = elf_file->dynsym;
      strtab_data = elf_file->dynstr;
      if (elf_file->dynstr_section) {
        strtab_size = elf_file->dynstr_section->sh_size;
      }
    } else {
      uELF_WARN("Skipping relocation section %d: unsupported symbol table index %u",
                i, sh->sh_link);
      free(relocs);
      continue;
    }

    uELF64_arch_relocate(elf_file, relocs, count, symtab_section, symtab_data,
                       strtab_data, strtab_size, sym_entsize);

    free(relocs);
  }

  return 0;
}

static int uELF64_execute_symbol(uElf64_File *elf_file, const char *symbol) {
  uint64_t addr = 0;
  if (uELF64_lookup_symbol(elf_file, symbol, &addr) < 0) {
    uELF_ERROR("Symbol '%s' not found", symbol);
    return -1;
  }

  if (addr == 0) {
    uELF_ERROR("Symbol '%s' has no address", symbol);
    return -1;
  }

  addr += elf_file->load_base;

  uELF_INFO("Invoking symbol '%s' at 0x%lx", symbol, (unsigned long)addr);

  if (strcmp(symbol, "main") == 0) {
    typedef int (*main_fn_t)(int, char **, char **);
    main_fn_t fn = (main_fn_t)(uintptr_t)addr;
    char *argv0 = (char *)(elf_file->name ? elf_file->name : "uelf-loaded");
    char *argv_list[] = { argv0, NULL };
    int ret = fn(1, argv_list, NULL);
    uELF_INFO("Function 'main' returned %d", ret);
  } else {
    typedef void (*fn_t)(void);
    fn_t fn = (fn_t)(uintptr_t)addr;
    fn();
    uELF_INFO("Function '%s' finished execution", symbol);
  }

  return 0;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    printf("Usage: %s [--load|-l|--print|-p] <elf-file> [symbol]\n", argv[0]);
    return -1;
  }

  if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
    printf("Usage: %s [--load|-l|--print|-p] <elf-file> [symbol]\n", argv[0]);
    return 0;
  }

  int mode = 0;
  const char *entry_symbol = NULL;
  const char *path = NULL;
  const char *addend = NULL;

  if (strcmp(argv[1], "--load") == 0 || strcmp(argv[1], "-l") == 0) {
    mode = 1; // LOAD
    if (argc < 3) {
      uELF_ERROR("Missing ELF file path for load mode");
      return -1;
    }
    path = argv[2];
    if (argc >= 4) {
      entry_symbol = argv[3];
    }
    if (argc > 4) {
      uELF_WARN("Ignoring extra arguments after symbol name");
    }
  } else if (strcmp(argv[1], "--print") == 0 || strcmp(argv[1], "-p") == 0) {
    mode = 2; // PRINT
    if (argc < 3) {
      uELF_ERROR("Missing ELF file path for print mode");
      return -1;
    }
    
    if (argc == 4) {
      path = argv[3];
      addend = argv[2];
    } else if (argc == 3) {
      path = argv[2];
    } else {
      printf("Usage: %s [--load|-l|--print|-p] <elf-file> [symbol]\n", argv[0]);
      return -1;
    }
  } else {
    uELF_ERROR("Unknown option: %s", argv[1]);
    return -1;
  }

  uElf64_File elf_file;
  memset(&elf_file, 0, sizeof(elf_file));
  elf_file.fd = -1;

  if (uElf64_open(path, &elf_file) < 0) {
	  uELF_ERROR("Failed to open ELF file: %s", path);
	  return -1;
  }

  int ret = 0;

  if (uELF64_parse_sections(&elf_file) < 0) {
    ret = -1;
    goto close;
  }

  
  if (uELF64_parse_programs(&elf_file) < 0) {
    ret = -1;
    goto close;
  }

  if (mode == 2) {
    if (addend == NULL) {
      uELF64_print_header(&elf_file);
      uELF64_print_sections(&elf_file);
      uELF64_print_symbols(&elf_file);
      uELF64_print_programs(&elf_file);
      uELF64_print_relocations(&elf_file);
      uELF64_print_map_sections_to_segments(&elf_file);
      goto close;
    }

    if (strcmp(addend, "-r") == 0) {
      uELF64_print_relocations(&elf_file);      
    } else if (strcmp(addend, "-s") == 0) {
      uELF64_print_symbols(&elf_file);
    } else if (strcmp(addend, "-p") == 0) {
      uELF64_print_programs(&elf_file);
    } else if (strcmp(addend, "-m") == 0) {
      uELF64_print_map_sections_to_segments(&elf_file);
    } else if (strcmp(addend, "-S") == 0) {
      uELF64_print_sections(&elf_file);
    } else if (strcmp(addend, "-h") == 0) {
      uELF64_print_header(&elf_file);
    } else {
      uELF_ERROR("Unknown print option: %s", addend);
      ret = -1;
    }
    goto close;
  }

  if (mode == 1) {
    if (uELF64_load_segments(&elf_file) == 0) {
      uELF_INFO("ELF entry point: 0x%lx", elf_file.elf_header.e_entry);
      if (uELF64_apply_relocations(&elf_file) < 0) {
        ret = -1;
      } else if (entry_symbol) {
        if (uELF64_execute_symbol(&elf_file, entry_symbol) < 0) {
          ret = -1;
        }
      }
    } else {
      ret = -1;
    }
  }

close:
  uElf64_close(&elf_file);

  return ret;
}
