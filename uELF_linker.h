#include "uELF.h"
#include "uELF_log.h"

typedef struct {
  uint8_t *data;
  size_t size;
  size_t capacity;
} uelf_buffer_t;

typedef struct {
  char *data;
  size_t size;
  size_t capacity;
} uelf_strtab_t;

typedef struct {
  const char *name;
  uint32_t type;
  uint64_t flags;
  uint64_t addr;
  uint64_t offset;
  uint64_t size;
  uint32_t link;
  uint32_t info;
  uint64_t addralign;
  uint64_t entsize;
  uint32_t name_off;
} uelf_out_section_t;

typedef struct {
  uint8_t kind;   // 0 none, 1 text, 2 data, 3 bss
  uint64_t offset;
} uelf_section_map_t;

typedef struct {
  uElf64_Sym sym;
  const char *name;
  uint8_t kind;
} uelf_pending_symbol_t;

typedef struct {
  uelf_pending_symbol_t base;
  int defined;
  int needs_stub;
  size_t plt_offset;
  size_t got_offset;
  size_t stub_local_index;
} uelf_global_symbol_t;

typedef struct {
  uint64_t offset;   // offset within section
  uint32_t type;
  uint32_t index;
  uint8_t is_global;
  int64_t addend;
  uint8_t target_kind; // 1 text, 2 data
} uelf_pending_reloc_t;

typedef struct {
  uint8_t *mem;
  size_t size;
  uElf64_Ehdr *ehdr;
  uElf64_Shdr *shdrs;
  char *shstr;
  uElf64_Sym *symtab;
  size_t symcount;
  char *symstr;
  size_t symstr_size;
  uelf_section_map_t *map;
  size_t *sym_index;
  uint8_t *sym_is_global;
} uelf_link_object_t;

static int uelf_buffer_reserve(uelf_buffer_t *buf, size_t need) {
  if (need <= buf->capacity)
    return 0;
  size_t new_cap = buf->capacity ? buf->capacity : 256;
  while (new_cap < need) {
    new_cap *= 2;
  }
  uint8_t *tmp = realloc(buf->data, new_cap);
  if (!tmp) {
    uELF_ERROR("Out of memory while reserving %zu bytes", need);
    return -1;
  }
  buf->data = tmp;
  buf->capacity = new_cap;
  return 0;
}

static ssize_t uelf_buffer_align(uelf_buffer_t *buf, size_t align) {
  if (align == 0)
    align = 1;
  size_t aligned = uelf_align_up(buf->size, align);
  if (aligned > buf->size) {
    if (uelf_buffer_reserve(buf, aligned) < 0)
      return -1;
    memset(buf->data + buf->size, 0, aligned - buf->size);
    buf->size = aligned;
  }
  return (ssize_t)aligned;
}

static ssize_t uelf_buffer_append(uelf_buffer_t *buf, const uint8_t *data,
                                  size_t len, size_t align) {
  ssize_t off = uelf_buffer_align(buf, align);
  if (off < 0)
    return -1;
  if (len == 0)
    return off;
  size_t need = (size_t)off + len;
  if (uelf_buffer_reserve(buf, need) < 0)
    return -1;
  memcpy(buf->data + off, data, len);
  buf->size = need;
  return off;
}

static void uelf_buffer_free(uelf_buffer_t *buf) {
  free(buf->data);
  buf->data = NULL;
  buf->size = buf->capacity = 0;
}

static int uelf_strtab_init(uelf_strtab_t *tab) {
  tab->data = malloc(16);
  if (!tab->data)
    return -1;
  tab->capacity = 16;
  tab->size = 1;
  tab->data[0] = '\0';
  return 0;
}

static size_t uelf_strtab_add(uelf_strtab_t *tab, const char *str) {
  if (!str || str[0] == '\0')
    return 0;
  size_t len = strlen(str);
  size_t need = tab->size + len + 1;
  if (need > tab->capacity) {
    size_t new_cap = tab->capacity ? tab->capacity : 16;
    while (new_cap < need)
      new_cap *= 2;
    char *tmp = realloc(tab->data, new_cap);
    if (!tmp)
      return (size_t)-1;
    tab->data = tmp;
    tab->capacity = new_cap;
  }
  size_t off = tab->size;
  memcpy(tab->data + tab->size, str, len + 1);
  tab->size = need;
  return off;
}

static void uelf_strtab_free(uelf_strtab_t *tab) {
  free(tab->data);
  tab->data = NULL;
  tab->size = tab->capacity = 0;
}

static int uelf_global_find(uelf_global_symbol_t *arr, size_t count,
                            const char *name) {
  for (size_t i = 0; i < count; i++) {
    const char *n = arr[i].base.name;
    if (n == name || (n && name && strcmp(n, name) == 0))
      return (int)i;
  }
  return -1;
}

static uint64_t uelf_section_base(uint8_t kind, uint64_t text_addr,
                                  uint64_t data_addr, uint64_t bss_addr) {
  switch (kind) {
  case 1:
    return text_addr;
  case 2:
    return data_addr;
  case 3:
    return bss_addr;
  default:
    return 0;
  }
}

static int uELF64_link_objects(const char *output_path,
                               const char *entry_symbol,
                               const char **inputs,
                               int input_count) {
  if (!output_path || !entry_symbol || !inputs || input_count <= 0) {
    uELF_ERROR("Invalid arguments for linker");
    return -1;
  }

  const uint64_t base_vaddr = 0x400000;
  const uint64_t page_align = 0x1000;

  uelf_buffer_t text_buf = {0};
  uelf_buffer_t data_buf = {0};
  size_t bss_size = 0;

  uelf_pending_symbol_t *locals = NULL;
  size_t local_count = 0, local_cap = 0;
  uelf_global_symbol_t *globals = NULL;
  size_t global_count = 0, global_cap = 0;

  uelf_pending_reloc_t *reloc_text = NULL;
  size_t reloc_text_count = 0, reloc_text_cap = 0;
  uelf_pending_reloc_t *reloc_data = NULL;
  size_t reloc_data_count = 0, reloc_data_cap = 0;

  uelf_link_object_t *objects = calloc((size_t)input_count, sizeof(uelf_link_object_t));
  if (!objects) {
    uELF_ERROR("Failed to allocate object array");
    return -1;
  }

  int status = -1;

  for (int obj_idx = 0; obj_idx < input_count; obj_idx++) {
    const char *path = inputs[obj_idx];
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
      uELF_ERROR("Failed to open object '%s': %s", path, strerror(errno));
      goto cleanup;
    }
    struct stat st;
    if (fstat(fd, &st) < 0) {
      uELF_ERROR("Failed to stat '%s'", path);
      close(fd);
      goto cleanup;
    }
    if (st.st_size <= 0) {
      uELF_ERROR("Object '%s' is empty", path);
      close(fd);
      goto cleanup;
    }
    uint8_t *mem = malloc((size_t)st.st_size);
    if (!mem) {
      uELF_ERROR("Failed to allocate %zu bytes for '%s'", (size_t)st.st_size, path);
      close(fd);
      goto cleanup;
    }
    ssize_t rd = read(fd, mem, (size_t)st.st_size);
    close(fd);
    if (rd != st.st_size) {
      uELF_ERROR("Failed to read '%s'", path);
      free(mem);
      goto cleanup;
    }

    uElf64_Ehdr *ehdr = (uElf64_Ehdr *)mem;
    if ((size_t)st.st_size < sizeof(*ehdr) ||
        memcmp(ehdr->e_ident, "\x7f" "ELF", 4) != 0 ||
        ehdr->e_ident[4] != 2 || ehdr->e_ident[5] != 1) {
      uELF_ERROR("Unsupported object format for '%s'", path);
      free(mem);
      goto cleanup;
    }
    if (ehdr->e_type != 1 || ehdr->e_machine != 0x3e) {
      uELF_ERROR("Object '%s' is not a x86-64 relocatable file", path);
      free(mem);
      goto cleanup;
    }
    if (ehdr->e_shoff == 0 || ehdr->e_shentsize != sizeof(uElf64_Shdr)) {
      uELF_ERROR("Object '%s' missing section headers", path);
      free(mem);
      goto cleanup;
    }

    uelf_link_object_t *obj = &objects[obj_idx];
    obj->mem = mem;
    obj->size = (size_t)st.st_size;
    obj->ehdr = ehdr;
    obj->shdrs = (uElf64_Shdr *)(mem + ehdr->e_shoff);
    if (ehdr->e_shoff + (uint64_t)ehdr->e_shnum * sizeof(uElf64_Shdr) > obj->size) {
      uELF_ERROR("Section headers truncated in '%s'", path);
      goto cleanup;
    }

    obj->map = calloc(ehdr->e_shnum, sizeof(uelf_section_map_t));
    if (!obj->map) {
      uELF_ERROR("Failed to allocate section map for '%s'", path);
      goto cleanup;
    }

    if (ehdr->e_shstrndx >= ehdr->e_shnum) {
      uELF_ERROR("Invalid shstr index in '%s'", path);
      goto cleanup;
    }
    uElf64_Shdr *shstr = &obj->shdrs[ehdr->e_shstrndx];
    if (shstr->sh_offset + shstr->sh_size > obj->size) {
      uELF_ERROR("Section string table truncated in '%s'", path);
      goto cleanup;
    }
    obj->shstr = (char *)(mem + shstr->sh_offset);

    for (int i = 0; i < ehdr->e_shnum; i++) {
      uElf64_Shdr *sh = &obj->shdrs[i];
      if (sh->sh_offset > obj->size || sh->sh_offset + sh->sh_size > obj->size) {
        uELF_ERROR("Section %d truncated in '%s'", i, path);
        goto cleanup;
      }
      if (!(sh->sh_flags & UELF_SHF_ALLOC))
        continue;
      size_t align = sh->sh_addralign ? sh->sh_addralign : 1;
      if (sh->sh_type == UELF_SHT_NOBITS) {
        if (sh->sh_size == 0)
          continue;
        size_t off = uelf_align_up(bss_size, align);
        obj->map[i].kind = 3;
        obj->map[i].offset = off;
        bss_size = off + sh->sh_size;
        continue;
      }
      if (sh->sh_type != UELF_SHT_PROGBITS || sh->sh_size == 0)
        continue;
      uint8_t kind = (sh->sh_flags & UELF_SHF_EXECINSTR) ? 1
                       : (sh->sh_flags & UELF_SHF_WRITE) ? 2
                       : 1;
      uelf_buffer_t *buf = (kind == 2) ? &data_buf : &text_buf;
      ssize_t off = uelf_buffer_append(buf, mem + sh->sh_offset,
                                       (size_t)sh->sh_size, align);
      if (off < 0)
        goto cleanup;
      obj->map[i].kind = kind;
      obj->map[i].offset = (uint64_t)off;
    }

    uElf64_Shdr *symtab_sec = NULL;
    for (int i = 0; i < ehdr->e_shnum; i++) {
      if (obj->shdrs[i].sh_type == UELF_SHT_SYMTAB) {
        symtab_sec = &obj->shdrs[i];
        break;
      }
    }
    if (!symtab_sec) {
      uELF_ERROR("Object '%s' has no symbol table", path);
      goto cleanup;
    }
    if (symtab_sec->sh_offset + symtab_sec->sh_size > obj->size) {
      uELF_ERROR("Symbol table truncated in '%s'", path);
      goto cleanup;
    }
    obj->symtab = (uElf64_Sym *)(mem + symtab_sec->sh_offset);
    obj->symcount = symtab_sec->sh_size / sizeof(uElf64_Sym);
    if (symtab_sec->sh_link >= ehdr->e_shnum) {
      uELF_ERROR("Invalid strtab link in '%s'", path);
      goto cleanup;
    }
    uElf64_Shdr *strtab_sec = &obj->shdrs[symtab_sec->sh_link];
    if (strtab_sec->sh_offset + strtab_sec->sh_size > obj->size) {
      uELF_ERROR("String table truncated in '%s'", path);
      goto cleanup;
    }
    obj->symstr = (char *)(mem + strtab_sec->sh_offset);
    obj->symstr_size = strtab_sec->sh_size;

    obj->sym_index = calloc(obj->symcount, sizeof(size_t));
    obj->sym_is_global = calloc(obj->symcount, 1);
    if (!obj->sym_index || !obj->sym_is_global) {
      uELF_ERROR("Failed to allocate symbol map for '%s'", path);
      goto cleanup;
    }

    for (size_t si = 1; si < obj->symcount; si++) {
      uElf64_Sym *sym = &obj->symtab[si];
      uint8_t bind = UELF64_ST_BIND(sym->st_info);
      const char *name = (sym->st_name < obj->symstr_size)
                             ? (obj->symstr + sym->st_name)
                             : "";
      uint8_t kind = 0;
      uint16_t shndx = sym->st_shndx;
      uint64_t value = 0;
      if (shndx != UELF_SHN_UNDEF && shndx < ehdr->e_shnum) {
        uelf_section_map_t *map = &obj->map[shndx];
        kind = map->kind;
        if (kind != 0)
          value = map->offset + sym->st_value;
      } else if (shndx == UELF_SHN_ABS) {
        kind = 0;
        value = sym->st_value;
      }

      uelf_pending_symbol_t pending;
      pending.name = name;
      pending.kind = kind;
      pending.sym = *sym;
      if (shndx == UELF_SHN_ABS) {
        pending.sym.st_shndx = UELF_SHN_ABS;
        pending.sym.st_value = value;
      } else if (kind == 1) {
        pending.sym.st_shndx = 1;
        pending.sym.st_value = value;
      } else if (kind == 2) {
        pending.sym.st_shndx = 2;
        pending.sym.st_value = value;
      } else if (kind == 3) {
        pending.sym.st_shndx = 3;
        pending.sym.st_value = value;
      } else {
        pending.sym.st_shndx = (shndx == UELF_SHN_ABS) ? UELF_SHN_ABS : UELF_SHN_UNDEF;
        pending.sym.st_value = 0;
      }

      if (bind == UELF_STB_LOCAL) {
        if (local_count == local_cap) {
          size_t new_cap = local_cap ? local_cap * 2 : 64;
          uelf_pending_symbol_t *tmp = realloc(locals, new_cap * sizeof(*locals));
          if (!tmp) {
            uELF_ERROR("Out of memory for local symbols");
            goto cleanup;
          }
          locals = tmp;
          local_cap = new_cap;
        }
        obj->sym_index[si] = local_count;
        obj->sym_is_global[si] = 0;
        locals[local_count++] = pending;
      } else {
        if (global_count == global_cap) {
          size_t new_cap = global_cap ? global_cap * 2 : 64;
          uelf_global_symbol_t *tmp = realloc(globals, new_cap * sizeof(*globals));
          if (!tmp) {
            uELF_ERROR("Out of memory for global symbols");
            goto cleanup;
          }
          globals = tmp;
          global_cap = new_cap;
        }
        int existing = uelf_global_find(globals, global_count, name);
        if (existing < 0) {
          globals[global_count].base = pending;
          globals[global_count].defined = (pending.sym.st_shndx != UELF_SHN_UNDEF);
          obj->sym_index[si] = global_count;
          obj->sym_is_global[si] = 1;
          global_count++;
        } else {
          obj->sym_index[si] = (size_t)existing;
          obj->sym_is_global[si] = 1;
          if (!globals[existing].defined && pending.sym.st_shndx != UELF_SHN_UNDEF) {
            globals[existing].base = pending;
            globals[existing].defined = 1;
          }
        }
      }
    }

    for (int si = 0; si < ehdr->e_shnum; si++) {
      uElf64_Shdr *sh = &obj->shdrs[si];
      if (sh->sh_type != UELF_SHT_RELA || sh->sh_size == 0)
        continue;
      if (sh->sh_info >= ehdr->e_shnum) {
        uELF_ERROR("Relocation references invalid section in '%s'", path);
        goto cleanup;
      }
      uelf_section_map_t *map = &obj->map[sh->sh_info];
      if (map->kind != 1 && map->kind != 2)
        continue;
      size_t count = sh->sh_size / sizeof(uElf64_Rela);
      if (sh->sh_offset + sh->sh_size > obj->size) {
        uELF_ERROR("Relocation section truncated in '%s'", path);
        goto cleanup;
      }
      uElf64_Rela *relas = (uElf64_Rela *)(mem + sh->sh_offset);
      for (size_t ri = 0; ri < count; ri++) {
        uElf64_Rela *rela = &relas[ri];
        uint32_t sym_index = UELF64_R_SYM(rela->r_info);
        if (sym_index >= obj->symcount) {
          uELF_ERROR("Relocation symbol index out of range in '%s'", path);
          goto cleanup;
        }
        uelf_pending_reloc_t reloc;
        reloc.offset = map->offset + rela->r_offset;
        reloc.type = UELF64_R_TYPE(rela->r_info);
        reloc.addend = rela->r_addend;
        reloc.index = obj->sym_index[sym_index];
        reloc.is_global = obj->sym_is_global[sym_index];
        reloc.target_kind = map->kind;
        if (map->kind == 1) {
          if (reloc_text_count == reloc_text_cap) {
            size_t new_cap = reloc_text_cap ? reloc_text_cap * 2 : 64;
            uelf_pending_reloc_t *tmp = realloc(reloc_text, new_cap * sizeof(*reloc_text));
            if (!tmp) {
              uELF_ERROR("Out of memory for text relocations");
              goto cleanup;
            }
            reloc_text = tmp;
            reloc_text_cap = new_cap;
          }
          reloc_text[reloc_text_count++] = reloc;
        } else {
          if (reloc_data_count == reloc_data_cap) {
            size_t new_cap = reloc_data_cap ? reloc_data_cap * 2 : 64;
            uelf_pending_reloc_t *tmp = realloc(reloc_data, new_cap * sizeof(*reloc_data));
            if (!tmp) {
              uELF_ERROR("Out of memory for data relocations");
              goto cleanup;
            }
            reloc_data = tmp;
            reloc_data_cap = new_cap;
          }
          reloc_data[reloc_data_count++] = reloc;
        }
      }
    }
  }

  // build simple PLT/GOT stubs for undefined globals
  for (size_t i = 0; i < global_count; i++) {
    if (globals[i].base.sym.st_shndx == UELF_SHN_UNDEF) {
      uint8_t zero[8] = {0};
      ssize_t got_off = uelf_buffer_append(&data_buf, zero, sizeof(zero), 8);
      if (got_off < 0)
        goto cleanup;
      uint8_t stub_code[9] = {0x48, 0x8B, 0x05, 0, 0, 0, 0, 0xFF, 0xE0};
      ssize_t plt_off = uelf_buffer_append(&text_buf, stub_code, sizeof(stub_code), 16);
      if (plt_off < 0)
        goto cleanup;

      uelf_pending_reloc_t got_reloc;
      got_reloc.offset = (uint64_t)got_off;
      got_reloc.type = UELF_R_X86_64_64;
      got_reloc.index = i;
      got_reloc.is_global = 1;
      got_reloc.addend = 0;
      got_reloc.target_kind = 2;
      if (reloc_data_count == reloc_data_cap) {
        size_t new_cap = reloc_data_cap ? reloc_data_cap * 2 : 64;
        uelf_pending_reloc_t *tmp = realloc(reloc_data, new_cap * sizeof(*reloc_data));
        if (!tmp) {
          uELF_ERROR("Out of memory for GOT relocations");
          goto cleanup;
        }
        reloc_data = tmp;
        reloc_data_cap = new_cap;
      }
      reloc_data[reloc_data_count++] = got_reloc;

      char stub_name_buf[256];
      const char *base_name = globals[i].base.name && globals[i].base.name[0]
                                ? globals[i].base.name
                                : "anon";
      snprintf(stub_name_buf, sizeof(stub_name_buf), ".plt.%s", base_name);
      char *stub_name = strdup(stub_name_buf);
      if (!stub_name) {
        uELF_ERROR("Failed to allocate stub name");
        goto cleanup;
      }

      if (local_count == local_cap) {
        size_t new_cap = local_cap ? local_cap * 2 : 64;
        uelf_pending_symbol_t *tmp = realloc(locals, new_cap * sizeof(*locals));
        if (!tmp) {
          free(stub_name);
          uELF_ERROR("Out of memory for stub symbols");
          goto cleanup;
        }
        locals = tmp;
        local_cap = new_cap;
      }

      uelf_pending_symbol_t stub_sym;
      memset(&stub_sym, 0, sizeof(stub_sym));
      stub_sym.name = stub_name;
      stub_sym.kind = 1;
      stub_sym.sym.st_info = (uint8_t)((UELF_STB_LOCAL << 4) | 2);
      stub_sym.sym.st_other = 0;
      stub_sym.sym.st_shndx = 1;
      stub_sym.sym.st_value = (uint64_t)plt_off;
      stub_sym.sym.st_size = 0;
      locals[local_count] = stub_sym;

      globals[i].needs_stub = 1;
      globals[i].plt_offset = (size_t)plt_off;
      globals[i].got_offset = (size_t)got_off;
      globals[i].stub_local_index = local_count;
      local_count++;
    }
  }

  for (size_t i = 0; i < reloc_text_count; i++) {
    if (reloc_text[i].is_global) {
      uelf_global_symbol_t *gs = &globals[reloc_text[i].index];
      if (gs->needs_stub &&
          (reloc_text[i].type == UELF_R_X86_64_PLT32 ||
           reloc_text[i].type == UELF_R_X86_64_PC32)) {
        reloc_text[i].is_global = 0;
        reloc_text[i].index = gs->stub_local_index;
      }
    }
  }

  uelf_strtab_t strtab;
  if (uelf_strtab_init(&strtab) < 0) {
    uELF_ERROR("Failed to init strtab");
    goto cleanup;
  }
  for (size_t i = 0; i < local_count; i++) {
    size_t off = uelf_strtab_add(&strtab, locals[i].name);
    if (off == (size_t)-1)
      goto cleanup_strtab;
    locals[i].sym.st_name = (uint32_t)off;
  }
  for (size_t i = 0; i < global_count; i++) {
    size_t off = uelf_strtab_add(&strtab, globals[i].base.name);
    if (off == (size_t)-1)
      goto cleanup_strtab;
    globals[i].base.sym.st_name = (uint32_t)off;
  }

  size_t symtab_count = 1 + local_count + global_count;
  uElf64_Sym *out_symtab = calloc(symtab_count, sizeof(uElf64_Sym));
  if (!out_symtab) {
    uELF_ERROR("Failed to allocate output symtab");
    goto cleanup_strtab;
  }

  size_t header_end = sizeof(uElf64_Ehdr) + sizeof(uElf64_Phdr);
  size_t text_offset = uelf_align_up(header_end, page_align);
  size_t data_offset = uelf_align_up(text_offset + text_buf.size, 16);
  size_t loadable_end = data_offset + data_buf.size;
  size_t bss_offset = uelf_align_up(loadable_end, 16);

  uint64_t text_addr = base_vaddr + text_offset;
  uint64_t data_addr = base_vaddr + data_offset;
  uint64_t bss_addr = base_vaddr + bss_offset;

  for (size_t i = 0; i < global_count; i++) {
    if (globals[i].needs_stub) {
      uint64_t stub_addr = text_addr + globals[i].plt_offset;
      uint64_t got_addr = data_addr + globals[i].got_offset;
      int32_t disp = (int32_t)(got_addr - (stub_addr + 7));
      memcpy(text_buf.data + globals[i].plt_offset + 3, &disp, sizeof(disp));
    }
  }

  for (size_t i = 0; i < local_count; i++) {
    out_symtab[1 + i] = locals[i].sym;
    if (locals[i].sym.st_shndx == UELF_SHN_ABS)
      continue;
    uint64_t base = uelf_section_base(locals[i].kind, text_addr, data_addr, bss_addr);
    out_symtab[1 + i].st_value = base + locals[i].sym.st_value;
  }
  for (size_t i = 0; i < global_count; i++) {
    out_symtab[1 + local_count + i] = globals[i].base.sym;
    if (globals[i].base.sym.st_shndx == UELF_SHN_ABS)
      continue;
    if (globals[i].base.sym.st_shndx == UELF_SHN_UNDEF)
      continue;
    uint64_t base = uelf_section_base(globals[i].base.kind, text_addr, data_addr, bss_addr);
    out_symtab[1 + local_count + i].st_value = base + globals[i].base.sym.st_value;
  }

  uint64_t entry_addr = 0;
  for (size_t i = 0; i < global_count; i++) {
    const char *name = globals[i].base.name;
    if (name && strcmp(name, entry_symbol) == 0 &&
        globals[i].base.sym.st_shndx != UELF_SHN_UNDEF) {
      entry_addr = out_symtab[1 + local_count + i].st_value;
      break;
    }
  }
  if (entry_addr == 0) {
    uELF_ERROR("Entry symbol '%s' not found", entry_symbol);
    free(out_symtab);
    goto cleanup_strtab;
  }

  size_t rela_text_size = reloc_text_count * sizeof(uElf64_Rela);
  size_t rela_data_size = reloc_data_count * sizeof(uElf64_Rela);

  uElf64_Rela *out_rela_text = NULL;
  uElf64_Rela *out_rela_data = NULL;
  if (rela_text_size) {
    out_rela_text = malloc(rela_text_size);
    if (!out_rela_text) {
      uELF_ERROR("Failed to allocate rela.text");
      free(out_symtab);
      goto cleanup_strtab;
    }
    for (size_t i = 0; i < reloc_text_count; i++) {
      uint32_t sym_index = reloc_text[i].is_global
                               ? (uint32_t)(1 + local_count + reloc_text[i].index)
                               : (uint32_t)(1 + reloc_text[i].index);
      uint64_t base = uelf_section_base(1, text_addr, data_addr, bss_addr);
      out_rela_text[i].r_offset = base + reloc_text[i].offset;
      out_rela_text[i].r_info = ((uint64_t)sym_index << 32) | reloc_text[i].type;
      out_rela_text[i].r_addend = reloc_text[i].addend;
    }
  }
  if (rela_data_size) {
    out_rela_data = malloc(rela_data_size);
    if (!out_rela_data) {
      uELF_ERROR("Failed to allocate rela.data");
      free(out_rela_text);
      free(out_symtab);
      goto cleanup_strtab;
    }
    for (size_t i = 0; i < reloc_data_count; i++) {
      uint32_t sym_index = reloc_data[i].is_global
                               ? (uint32_t)(1 + local_count + reloc_data[i].index)
                               : (uint32_t)(1 + reloc_data[i].index);
      uint64_t base = uelf_section_base(2, text_addr, data_addr, bss_addr);
      out_rela_data[i].r_offset = base + reloc_data[i].offset;
      out_rela_data[i].r_info = ((uint64_t)sym_index << 32) | reloc_data[i].type;
      out_rela_data[i].r_addend = reloc_data[i].addend;
    }
  }

  size_t cursor = loadable_end;
  size_t rela_text_offset = 0;
  size_t rela_data_offset = 0;
  if (rela_text_size) {
    cursor = uelf_align_up(cursor, 8);
    rela_text_offset = cursor;
    cursor += rela_text_size;
  }
  if (rela_data_size) {
    cursor = uelf_align_up(cursor, 8);
    rela_data_offset = cursor;
    cursor += rela_data_size;
  }
  cursor = uelf_align_up(cursor, 8);
  size_t symtab_offset = cursor;
  cursor += symtab_count * sizeof(uElf64_Sym);
  cursor = uelf_align_up(cursor, 1);
  size_t strtab_offset = cursor;
  cursor += strtab.size;

  uelf_strtab_t shstr;
  if (uelf_strtab_init(&shstr) < 0) {
    uELF_ERROR("Failed to init shstrtab");
    free(out_rela_data);
    free(out_rela_text);
    free(out_symtab);
    goto cleanup_strtab;
  }

  size_t sec_count = 0;
  uelf_out_section_t sections[10];
  sections[sec_count++] = (uelf_out_section_t){0};
  int idx_text = (int)sec_count;
  sections[sec_count++] = (uelf_out_section_t){
      .name = ".text",
      .type = UELF_SHT_PROGBITS,
      .flags = UELF_SHF_ALLOC | UELF_SHF_EXECINSTR,
      .addr = text_addr,
      .offset = text_offset,
      .size = text_buf.size,
      .addralign = 16,
  };
  int idx_data = (int)sec_count;
  sections[sec_count++] = (uelf_out_section_t){
      .name = ".data",
      .type = UELF_SHT_PROGBITS,
      .flags = UELF_SHF_ALLOC | UELF_SHF_WRITE,
      .addr = data_addr,
      .offset = data_offset,
      .size = data_buf.size,
      .addralign = 16,
  };
  sections[sec_count++] = (uelf_out_section_t){
      .name = ".bss",
      .type = UELF_SHT_NOBITS,
      .flags = UELF_SHF_ALLOC | UELF_SHF_WRITE,
      .addr = bss_addr,
      .offset = 0,
      .size = bss_size,
      .addralign = 16,
  };
  int idx_rela_text = -1;
  if (rela_text_size) {
    idx_rela_text = (int)sec_count;
    sections[sec_count++] = (uelf_out_section_t){
        .name = ".rela.text",
        .type = UELF_SHT_RELA,
        .addr = 0,
        .offset = rela_text_offset,
        .size = rela_text_size,
        .addralign = 8,
        .entsize = sizeof(uElf64_Rela),
    };
  }
  int idx_rela_data = -1;
  if (rela_data_size) {
    idx_rela_data = (int)sec_count;
    sections[sec_count++] = (uelf_out_section_t){
        .name = ".rela.data",
        .type = UELF_SHT_RELA,
        .addr = 0,
        .offset = rela_data_offset,
        .size = rela_data_size,
        .addralign = 8,
        .entsize = sizeof(uElf64_Rela),
    };
  }
  int idx_symtab = (int)sec_count;
  sections[sec_count++] = (uelf_out_section_t){
      .name = ".symtab",
      .type = UELF_SHT_SYMTAB,
      .addr = 0,
      .offset = symtab_offset,
      .size = symtab_count * sizeof(uElf64_Sym),
      .addralign = 8,
      .entsize = sizeof(uElf64_Sym),
  };
  int idx_strtab = (int)sec_count;
  sections[sec_count++] = (uelf_out_section_t){
      .name = ".strtab",
      .type = UELF_SHT_STRTAB,
      .addr = 0,
      .offset = strtab_offset,
      .size = strtab.size,
      .addralign = 1,
  };
  int idx_shstrtab = (int)sec_count;
  sections[sec_count++] = (uelf_out_section_t){
      .name = ".shstrtab",
      .type = UELF_SHT_STRTAB,
      .addr = 0,
      .offset = 0,
      .size = 0,
      .addralign = 1,
  };

  sections[idx_symtab].link = (uint32_t)idx_strtab;
  sections[idx_symtab].info = (uint32_t)(1 + local_count);
  if (idx_rela_text >= 0) {
    sections[idx_rela_text].link = (uint32_t)idx_symtab;
    sections[idx_rela_text].info = (uint32_t)idx_text;
  }
  if (idx_rela_data >= 0) {
    sections[idx_rela_data].link = (uint32_t)idx_symtab;
    sections[idx_rela_data].info = (uint32_t)idx_data;
  }

  for (size_t i = 0; i < sec_count; i++) {
    size_t off = uelf_strtab_add(&shstr, sections[i].name);
    if (off == (size_t)-1) {
      uELF_ERROR("Failed to build shstrtab");
      uelf_strtab_free(&shstr);
      free(out_rela_data);
      free(out_rela_text);
      free(out_symtab);
      goto cleanup_strtab;
    }
    sections[i].name_off = (uint32_t)off;
  }
  cursor = uelf_align_up(cursor, 1);
  size_t shstrtab_offset = cursor;
  cursor += shstr.size;
  sections[idx_shstrtab].offset = shstrtab_offset;
  sections[idx_shstrtab].size = shstr.size;

  size_t shoff = uelf_align_up(cursor, 8);
  size_t file_size = shoff + sec_count * sizeof(uElf64_Shdr);

  uint8_t *file = calloc(file_size, 1);
  if (!file) {
    uELF_ERROR("Failed to allocate output image");
    uelf_strtab_free(&shstr);
    free(out_rela_data);
    free(out_rela_text);
    free(out_symtab);
    goto cleanup_strtab;
  }

  memcpy(file + text_offset, text_buf.data, text_buf.size);
  memcpy(file + data_offset, data_buf.data, data_buf.size);
  if (rela_text_size)
    memcpy(file + rela_text_offset, out_rela_text, rela_text_size);
  if (rela_data_size)
    memcpy(file + rela_data_offset, out_rela_data, rela_data_size);
  memcpy(file + symtab_offset, out_symtab, symtab_count * sizeof(uElf64_Sym));
  memcpy(file + strtab_offset, strtab.data, strtab.size);
  memcpy(file + shstrtab_offset, shstr.data, shstr.size);

  uElf64_Ehdr *ehdr_out = (uElf64_Ehdr *)file;
  memset(ehdr_out, 0, sizeof(*ehdr_out));
  ehdr_out->e_ident[0] = 0x7f;
  ehdr_out->e_ident[1] = 'E';
  ehdr_out->e_ident[2] = 'L';
  ehdr_out->e_ident[3] = 'F';
  ehdr_out->e_ident[4] = 2;
  ehdr_out->e_ident[5] = 1;
  ehdr_out->e_ident[6] = 1;
  ehdr_out->e_type = 2;
  ehdr_out->e_machine = 0x3e;
  ehdr_out->e_version = 1;
  ehdr_out->e_entry = entry_addr;
  ehdr_out->e_phoff = sizeof(uElf64_Ehdr);
  ehdr_out->e_shoff = shoff;
  ehdr_out->e_ehsize = sizeof(uElf64_Ehdr);
  ehdr_out->e_phentsize = sizeof(uElf64_Phdr);
  ehdr_out->e_phnum = 1;
  ehdr_out->e_shentsize = sizeof(uElf64_Shdr);
  ehdr_out->e_shnum = (uint16_t)sec_count;
  ehdr_out->e_shstrndx = (uint16_t)idx_shstrtab;

  uElf64_Phdr *phdr_out = (uElf64_Phdr *)(file + ehdr_out->e_phoff);
  memset(phdr_out, 0, sizeof(*phdr_out));
  phdr_out->p_type = UELF_PT_LOAD;
  phdr_out->p_offset = 0;
  phdr_out->p_vaddr = base_vaddr;
  phdr_out->p_paddr = base_vaddr;
  phdr_out->p_filesz = loadable_end;
  phdr_out->p_memsz = uelf_align_up(loadable_end, 16) + bss_size;
  phdr_out->p_flags = UELF_PF_R | UELF_PF_W | UELF_PF_X;
  phdr_out->p_align = page_align;

  uElf64_Shdr *shdr_out = (uElf64_Shdr *)(file + shoff);
  memset(shdr_out, 0, sec_count * sizeof(uElf64_Shdr));
  for (size_t i = 0; i < sec_count; i++) {
    shdr_out[i].sh_name = sections[i].name_off;
    shdr_out[i].sh_type = sections[i].type;
    shdr_out[i].sh_flags = sections[i].flags;
    shdr_out[i].sh_addr = sections[i].addr;
    shdr_out[i].sh_offset = sections[i].offset;
    shdr_out[i].sh_size = sections[i].size;
    shdr_out[i].sh_link = sections[i].link;
    shdr_out[i].sh_info = sections[i].info;
    shdr_out[i].sh_addralign = sections[i].addralign ? sections[i].addralign : 1;
    shdr_out[i].sh_entsize = sections[i].entsize;
  }

  int out_fd = open(output_path, O_CREAT | O_TRUNC | O_WRONLY, 0755);
  if (out_fd < 0) {
    uELF_ERROR("Failed to open output '%s': %s", output_path, strerror(errno));
    free(file);
    uelf_strtab_free(&shstr);
    free(out_rela_data);
    free(out_rela_text);
    free(out_symtab);
    goto cleanup_strtab;
  }
  ssize_t written = write(out_fd, file, file_size);
  if (written != (ssize_t)file_size) {
    uELF_ERROR("Failed to write output '%s'", output_path);
    close(out_fd);
    free(file);
    uelf_strtab_free(&shstr);
    free(out_rela_data);
    free(out_rela_text);
    free(out_symtab);
    goto cleanup_strtab;
  }
  close(out_fd);
  free(file);
  uelf_strtab_free(&shstr);
  free(out_rela_data);
  free(out_rela_text);
  free(out_symtab);

  status = 0;

cleanup_strtab:
  uelf_strtab_free(&strtab);

cleanup:
  for (int i = 0; i < input_count; i++) {
    free(objects[i].map);
    free(objects[i].sym_index);
    free(objects[i].sym_is_global);
    free(objects[i].mem);
  }
  free(objects);
  uelf_buffer_free(&text_buf);
  uelf_buffer_free(&data_buf);
  free(locals);
  free(globals);
  free(reloc_text);
  free(reloc_data);

  if (status == 0)
    uELF_INFO("Linked %d object(s) into '%s'", input_count, output_path);

  return status;
}