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
