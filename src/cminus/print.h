#ifndef EGALITO_CMINUS_PRINT_H
#define EGALITO_CMINUS_PRINT_H

#include <stdarg.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NAME(x) egalito_ ## x
#define egalito_stdout STDOUT_FILENO
#define egalito_stderr STDERR_FILENO

// This function must take a variable format string. CWE-134 cannot be addressed here.
int NAME(printf) (const char *format, ...) /* Flawfinder: ignore */
#ifdef __GNUC__
    // This function must take a variable format string. CWE-134 cannot be addressed here.
    __attribute__(( format(printf, 1, 2) )) /* Flawfinder: ignore */
#endif
    ;
// This function must take a variable format string. CWE-134 cannot be addressed here.
int NAME(fprintf) (int stream, const char *format, ...); /* Flawfinder: ignore */
// This function must take a variable format string. CWE-134 cannot be addressed here.
int NAME(vfprintf) (int stream, const char *format, va_list args); /* Flawfinder: ignore */

// By definition, sprintf cannot require a size input. CWE-120 cannot be addressed here.
int NAME(sprintf) (char *s, const char *format, ...) /* Flawfinder: ignore */
#ifdef __GNUC__
    // This function must take a variable format string. CWE-134 cannot be addressed here.
    __attribute__(( format(printf, 2, 3) )) /* Flawfinder: ignore */
#endif
    ;
// This function must take a variable format string. CWE-134 cannot be addressed here.
int NAME(snprintf) (char *s, size_t size, const char *format, ...) /* Flawfinder: ignore */
#ifdef __GNUC__
    // This function must take a variable format string. CWE-134 cannot be addressed here.
    __attribute__(( format(printf, 3, 4) )) /* Flawfinder: ignore */
#endif
    ;
// This function must take a variable format string. CWE-134 cannot be addressed here.
int NAME(vsnprintf) (char *s, size_t size, const char *format, va_list args); /* Flawfinder: ignore */

int NAME(puts) (const char *s);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
