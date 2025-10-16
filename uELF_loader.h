#include "uELF.h"

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