#include "uELF.h"
#include "uELF_log.h"
#include "uELF_loader.h"
#include "uELF_linker.h"

// open file and read ELF header
int uElf64_open(const char *name, uElf64_File *elf_file) {
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

int uElf64_close(uElf64_File *elf_file) {
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

int uELF64_parse_sections(uElf64_File *elf_file) {
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

int uELF64_parse_programs(uElf64_File *elf_file) {
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

int main(int argc, char **argv) {
  if (argc < 2) {
    printf("Usage: %s [--load|-l|--print|-p|--link] ...\n", argv[0]);
    return -1;
  }

  if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
    printf("Usage: %s --print <elf-file> [(-r|-s|-h|-p|-S|-m)]\n", argv[0]);
    printf("       %s --load <elf-file> [symbol]\n", argv[0]);
    printf("       %s --link <output> <entry-symbol> <object> [object...]\n", argv[0]);
    return 0;
  }

  int mode = 0;
  const char *entry_symbol = NULL;
  const char *output_path = NULL;
  const char *path = NULL;
  const char *addend = NULL;
  const char **link_inputs = NULL;
  int link_count = 0;

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
      printf("Usage: %s --print <elf-file> [(-r|-s|-h|-p|-S|-m)]\n", argv[0]);
      return -1;
    }
  } else if (strcmp(argv[1], "--link") == 0) {
    mode = 3; // LINK
    if (argc < 5) {
      uELF_ERROR("Usage: %s --link <output> <entry-symbol> <object> [object...]", argv[0]);
      return -1;
    }
    output_path = argv[2];
    entry_symbol = argv[3];
    link_inputs = (const char **)&argv[4];
    link_count = argc - 4;
  } else {
    uELF_ERROR("Unknown option: %s", argv[1]);
    return -1;
  }

  if (mode == 3) {
    // TODO: parse linker
    return 0;
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
