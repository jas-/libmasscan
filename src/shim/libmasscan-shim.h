/* Force-included into upstream sources: routes exit(), printf() and stderr writes to hooks.c. */
#ifndef LIBMASSCAN_SHIM_H
#define LIBMASSCAN_SHIM_H

/* pixie-threads.c needs _GNU_SOURCE before the system headers below. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

void libmasscan_exit(int code) __attribute__((noreturn));
int libmasscan_fprintf(FILE *fp, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
int libmasscan_vfprintf(FILE *fp, const char *fmt, va_list ap);
int libmasscan_printf(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));

#undef exit
#define exit(code) libmasscan_exit(code)

#undef fprintf
#define fprintf(...) libmasscan_fprintf(__VA_ARGS__)

#undef printf
#define printf(...) libmasscan_printf(__VA_ARGS__)

#undef vfprintf
#define vfprintf(fp, fmt, ap) libmasscan_vfprintf((fp), (fmt), (ap))

#endif
