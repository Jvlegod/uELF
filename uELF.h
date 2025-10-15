#pragma once
#include <stdio.h>
#include <stdint.h>


typedef enum {
	LINK_FILE,
	EXEC
} File_Type;

typedef struct {
  unsigned char e_ident[16]; // 魔数 + 文件类型
  uint16_t e_type;           // 文件类型 (ET_EXEC, ET_DYN, ET_REL)
  uint16_t e_machine;        // 架构类型 (EM_X86_64, EM_RISCV, etc.)
  uint32_t e_version;        // ELF 版本 (一般是 1)
  uint64_t e_entry;          // 程序入口地址
  uint64_t e_phoff;          // Program Header Table 偏移
  uint64_t e_shoff;          // Section Header Table 偏移
  uint32_t e_flags;          // 架构相关标志
  uint16_t e_ehsize;         // ELF Header 大小
  uint16_t e_phentsize;      // 每个 Program Header 的大小
  uint16_t e_phnum;          // Program Header 的数量
  uint16_t e_shentsize;      // 每个 Section Header 的大小
  uint16_t e_shnum;          // Section Header 的数量
  uint16_t e_shstrndx;       // 字符串表段索引（节名字符串表）
} uElf64_Ehdr;


typedef struct {
	const char *name;
  int fd;
	File_Type type;
	uElf64_Ehdr elf_header;
} uElf64_File;
