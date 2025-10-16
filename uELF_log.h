#pragma once
#include <stdio.h>
#include <time.h>
#include <stdarg.h>

#ifndef UELF_LOG_LEVEL
#define UELF_LOG_LEVEL 3
#endif

#define CLR_RED     "\033[31m"
#define CLR_YELLOW  "\033[33m"
#define CLR_GREEN   "\033[32m"
#define CLR_CYAN    "\033[36m"
#define CLR_RESET   "\033[0m"

static inline void uELF_log_base(
    const char *level,
    const char *color,
    const char *file,
    int line,
    const char *fmt, ...
) {
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    char buf[20];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(stderr, "%s %s%s%-5s%s (%s:%d) ",
            buf,
            color, level,
            "", CLR_RESET,
            file, line);

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}

#define uELF_ERROR(fmt, ...) \
    do { if (UELF_LOG_LEVEL >= 0) uELF_log_base("ERROR", CLR_RED, __FILE__, __LINE__, fmt, ##__VA_ARGS__); } while(0)

#define uELF_WARN(fmt, ...) \
    do { if (UELF_LOG_LEVEL >= 1) uELF_log_base("WARN", CLR_YELLOW, __FILE__, __LINE__, fmt, ##__VA_ARGS__); } while(0)

#define uELF_INFO(fmt, ...) \
    do { if (UELF_LOG_LEVEL >= 2) uELF_log_base("INFO", CLR_GREEN, __FILE__, __LINE__, fmt, ##__VA_ARGS__); } while(0)

#define uELF_DEBUG(fmt, ...) \
    do { if (UELF_LOG_LEVEL >= 3) uELF_log_base("DEBUG", CLR_CYAN, __FILE__, __LINE__, fmt, ##__VA_ARGS__); } while(0)

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