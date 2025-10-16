#pragma once
#include <stdio.h>
#include <stdint.h>


typedef enum {
	LINK_FILE,
	EXEC
} File_Type;

#define UELF_PF_X 0x1
#define UELF_PF_W 0x2
#define UELF_PF_R 0x4

typedef enum {
    UELF_SHT_NULL        = 0,          // 无效节
    UELF_SHT_PROGBITS    = 1,          // 程序数据
    UELF_SHT_SYMTAB      = 2,          // 符号表
    UELF_SHT_STRTAB      = 3,          // 字符串表
    UELF_SHT_RELA        = 4,          // 重定位表（带 addend）
    UELF_SHT_HASH        = 5,          // 符号哈希表
    UELF_SHT_DYNAMIC     = 6,          // 动态链接信息
    UELF_SHT_NOTE        = 7,          // 备注信息
    UELF_SHT_NOBITS      = 8,          // 不占文件空间（如 .bss）
    UELF_SHT_REL         = 9,          // 重定位表（不带 addend）
    UELF_SHT_SHLIB       = 10,         // 保留
    UELF_SHT_DYNSYM      = 11,         // 动态符号表
    UELF_SHT_INIT_ARRAY  = 14,         // 构造函数数组
    UELF_SHT_FINI_ARRAY  = 15,         // 析构函数数组
    UELF_SHT_PREINIT_ARRAY = 16,       // 预初始化数组
    UELF_SHT_GROUP       = 17,         // Section group
    UELF_SHT_SYMTAB_SHNDX = 18,        // 扩展符号节索引
    UELF_SHT_NUM         = 19,         // 节类型总数（标志）
    UELF_SHT_LOOS        = 0x60000000, // OS 特定
    UELF_SHT_HIOS        = 0x6fffffff,
    UELF_SHT_LOPROC      = 0x70000000, // 处理器特定
    UELF_SHT_HIPROC      = 0x7fffffff
} uELF_ShdrType;

typedef enum {
    UELF_PT_NULL        = 0,          // 无效段，占位用
    UELF_PT_LOAD        = 1,          // 可加载段 (.text, .data 等)
    UELF_PT_DYNAMIC     = 2,          // 动态链接信息段 (.dynamic)
    UELF_PT_INTERP      = 3,          // 解释器路径段 (.interp)
    UELF_PT_NOTE        = 4,          // 注释段 (.note)
    UELF_PT_SHLIB       = 5,          // 保留（很少使用）
    UELF_PT_PHDR        = 6,          // 程序头表本身
    UELF_PT_TLS         = 7,          // 线程局部存储段 (.tdata, .tbss)

    // 系统/平台特定范围
    UELF_PT_LOOS        = 0x60000000, // OS 特定范围下限
    UELF_PT_GNU_EH_FRAME= 0x6474e550, // GNU 异常处理段 (.eh_frame_hdr)
    UELF_PT_GNU_STACK   = 0x6474e551, // GNU 栈属性段（标记栈是否可执行）
    UELF_PT_GNU_RELRO   = 0x6474e552, // GNU 只读段（relro 保护区）
    UELF_PT_GNU_PROPERTY= 0x6474e553, // GNU 属性段
    UELF_PT_LOSUNW      = 0x6ffffffa, // Sun/UNIX 特定段
    UELF_PT_SUNWBSS     = 0x6ffffffa, // Sun 特定 BSS 段
    UELF_PT_SUNWSTACK   = 0x6ffffffb, // Sun 栈段

    UELF_PT_LOPROC      = 0x70000000, // 处理器特定范围下限
    UELF_PT_HIPROC      = 0x7fffffff  // 处理器特定范围上限
} uELF_ProgramType;

typedef struct {
  uint64_t r_offset;
  uint64_t r_info;
  int64_t r_addend;
} uElf64_Rela;

typedef struct {
  uint64_t r_offset;
  uint64_t r_info;
} uElf64_Rel;

#define UELF64_R_SYM(i) ((uint32_t)((i) >> 32))
#define UELF64_R_TYPE(i) ((uint32_t)(i))

#define UELF64_ST_BIND(i) ((uint8_t)((i) >> 4))
#define UELF64_ST_TYPE(i) ((uint8_t)((i) & 0xf))

#define UELF_STB_LOCAL  0
#define UELF_STB_GLOBAL 1
#define UELF_STB_WEAK   2

#define UELF_SHN_UNDEF 0

#define UELF_R_X86_64_NONE      0
#define UELF_R_X86_64_64        1
#define UELF_R_X86_64_GLOB_DAT  6
#define UELF_R_X86_64_JUMP_SLOT 7
#define UELF_R_X86_64_RELATIVE  8

typedef struct {
    uint32_t p_type;   // 段类型 (Segment type)
    uint32_t p_flags;  // 段标志 (Segment flags)
    uint64_t p_offset; // 文件中的偏移量
    uint64_t p_vaddr;  // 虚拟地址 (加载到内存中的地址)
    uint64_t p_paddr;  // 物理地址 (通常在系统中不用)
    uint64_t p_filesz; // 段在文件中的大小
    uint64_t p_memsz;  // 段在内存中的大小
    uint64_t p_align;  // 段的对齐约束
} uElf64_Phdr;

typedef struct {
    uint32_t st_name;  // 符号名在字符串表中的偏移
    uint8_t  st_info;  // 类型 + 绑定信息
    uint8_t  st_other; // 可见性
    uint16_t st_shndx; // 该符号所在节索引
    uint64_t st_value; // 符号值（地址/偏移）
    uint64_t st_size;  // 符号大小（例如函数长度）
} uElf64_Sym;

typedef struct {
  unsigned char e_ident[16]; // 魔数 + 文件类型
  uint16_t e_type;           // 文件类型 (ET_EXEC, ET_DYN, ET_REL, ET_CORE)
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
  uint16_t e_shstrndx;       // 字符串表段索引（节名字符串表），注: 指向特殊的段 .shstrtab
} uElf64_Ehdr;

typedef struct {
  uint32_t sh_name;       // 节名在字符串表中的偏移
  uint32_t sh_type;       // 节类型
  uint64_t sh_flags;      // 节标志
  uint64_t sh_addr;       // 虚拟地址（仅加载时使用）
  uint64_t sh_offset;     // 文件中偏移
  uint64_t sh_size;       // 节大小
  uint32_t sh_link;       // 关联节索引
  uint32_t sh_info;       // 额外信息
  uint64_t sh_addralign;  // 对齐
  uint64_t sh_entsize;    // 每个表项大小（符号表类）注：中文版中显示全体大小，很奇怪的翻译.
} uElf64_Shdr;

typedef struct {
	const char *name;
  int fd;
	File_Type type;
	uElf64_Ehdr elf_header;
  uElf64_Shdr *section_headers;
  uElf64_Phdr *program_headers;

  uElf64_Shdr *shstrtab_section; // 节名字符串表节
  char *shstrtab;                // 节名字符串表内容
  uElf64_Shdr *strtab_section;  // 字符串表节
  char *strtab;                 // 字符串表内容
  uElf64_Shdr *dynstr_section; // 动态字符串表节
  char *dynstr;                // 动态字符串表内容

  uElf64_Shdr *symtab_section; // 符号表节
  char *symtab;                // 符号表内容
  uElf64_Shdr *dynsym_section; // 动态符号表节
  char *dynsym;                // 动态符号表内容

  void **loaded_segments;      // 已加载段的基地址
  size_t *loaded_segment_sizes;// 已加载段的大小
  size_t loaded_segment_count; // 已加载段数量
  uintptr_t load_base;         // 加载基址（用于 PIE ）
} uElf64_File;

static const char *uelf_class_name(uint8_t c) {
    switch (c) {
        case 1: return "ELF32";
        case 2: return "ELF64";
        default: return "Invalid";
    }
}

static const char *uelf_data_encoding(uint8_t d) {
    switch (d) {
        case 1: return "Little Endian";
        case 2: return "Big Endian";
        default: return "Invalid";
    }
}

static const char *uelf_osabi_name(uint8_t a) {
    switch (a) {
        case 0: return "System V";
        case 3: return "Linux";
        default: return "Other";
    }
}

static const char *uelf_type_name(uint16_t t) {
    switch (t) {
        case 0: return "NONE (No file type)";
        case 1: return "REL (Relocatable file)";
        case 2: return "EXEC (Executable file)";
        case 3: return "DYN (Shared object file)";
        case 4: return "CORE (Core dump)";
        default: return "Unknown";
    }
}

static const char *uelf_machine_name(uint16_t m) {
    switch (m) {
        case 0x03: return "x86";
        case 0x3E: return "x86-64";
        case 0xB7: return "AArch64";
        case 0xF3: return "RISC-V";
        default: return "Other";
    }
}

static uint64_t uelf_align_down(uint64_t value, uint64_t alignment) {
  return value & ~(alignment - 1);
}

static uint64_t uelf_align_up(uint64_t value, uint64_t alignment) {
  return (value + alignment - 1) & ~(alignment - 1);
}