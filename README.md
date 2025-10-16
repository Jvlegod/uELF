## 1 概述

本次 `uELF` 是一次对 ELF 文件的尝试.

- 希望能够用足够精简的代码实现教学

- 希望通过该工具集能实现对 ELF 文件格式的各种解析.

目前暂时实现了一个加载器的功能.

## 2 基本用法

```bash
# ./uelf --print <elf-file>
./uelf -p [-r|-s|-h|-p|-S|-m] <elf-file>
```

这对于调试或了解 ELF 文件结构非常有用.

## 3 加载与执行符号

若要将 `PT_LOAD` 段映射到内存并执行某个符号，可使用 `--load`（或 `-l`）选项：

```bash
./uelf --load <elf-file> [symbol]
```

- 当指定 `symbol` 时，工具会在符号表中查找该名称，并在非 PIE（ET_EXEC）二进制上调用它.
- 如果未指定 `symbol`，程序会默认查找并执行 `main` 函数.
- 对于非 PIE（ET_EXEC）可执行文件，加载器会解析 `.rela.dyn`/`.rela.plt` 并通过宿主进程的 `dlsym` 填充 GOT 与全局数据重定位，因此可正常调用 `printf`/`puts` 等外部符号.
- 如果重定位引用了弱符号（如 `_ITM_deregisterTMCloneTable`），在宿主未提供实现的情况下会保持空指针同时输出告警.
- 对于 PIE/共享库（ET_DYN），当前实现只完成段映射，不会直接执行符号以避免缺少重定位导致的错误.

示例：

```bash
./uelf --load test/main hello
```

该命令会加载 `test/main`，找到名为 `hello` 的符号并执行它。

## 4 查看帮助

```bash
./uelf --help
```

会打印简要的命令行参数说明。

## 5 清理

```bash
make clean
```

会删除构建产物.