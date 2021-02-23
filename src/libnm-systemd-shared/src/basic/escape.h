/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <uchar.h>

#include "string-util.h"
#include "missing_type.h"

/* What characters are special in the shell? */
/* must be escaped outside and inside double-quotes */
#define SHELL_NEED_ESCAPE "\"\\`$"

/* Those that can be escaped or double-quoted.
 *
 * Strictly speaking, ! does not need to be escaped, except in interactive
 * mode, but let's be extra nice to the user and quote ! in case this
 * output is ever used in interactive mode. */
#define SHELL_NEED_QUOTES SHELL_NEED_ESCAPE GLOB_CHARS "'()<>|&;!"

/* Note that we assume control characters would need to be escaped too in
 * addition to the "special" characters listed here, if they appear in the
 * string. Current users disallow control characters. Also '"' shall not
 * be escaped.
 */
#define SHELL_NEED_ESCAPE_POSIX "\\\'"

typedef enum UnescapeFlags {
        UNESCAPE_RELAX      = 1 << 0,
        UNESCAPE_ACCEPT_NUL = 1 << 1,
} UnescapeFlags;

typedef enum EscapeStyle {
        ESCAPE_BACKSLASH         = 1,  /* Add shell quotes ("") so the shell will consider this a single
                                          argument, possibly multiline. Tabs and newlines are not escaped. */
        ESCAPE_BACKSLASH_ONELINE = 2,  /* Similar to ESCAPE_BACKSLASH, but always produces a single-line
                                          string instead. Shell escape sequences are produced for tabs and
                                          newlines. */
        ESCAPE_POSIX             = 3,  /* Similar to ESCAPE_BACKSLASH_ONELINE, but uses POSIX shell escape
                                        * syntax (a string enclosed in $'') instead of plain quotes. */
} EscapeStyle;

char* cescape(const char *s);
char* cescape_length(const char *s, size_t n);
int cescape_char(char c, char *buf);

int cunescape_length_with_prefix(const char *s, size_t length, const char *prefix, UnescapeFlags flags, char **ret);
static inline int cunescape_length(const char *s, size_t length, UnescapeFlags flags, char **ret) {
        return cunescape_length_with_prefix(s, length, NULL, flags, ret);
}
static inline int cunescape(const char *s, UnescapeFlags flags, char **ret) {
        return cunescape_length(s, strlen(s), flags, ret);
}
int cunescape_one(const char *p, size_t length, char32_t *ret, bool *eight_bit, bool accept_nul);

char* xescape_full(const char *s, const char *bad, size_t console_width, bool eight_bits);
static inline char* xescape(const char *s, const char *bad) {
        return xescape_full(s, bad, SIZE_MAX, false);
}
char* octescape(const char *s, size_t len);
char* escape_non_printable_full(const char *str, size_t console_width, bool eight_bit);

char* shell_escape(const char *s, const char *bad);
char* shell_maybe_quote(const char *s, EscapeStyle style);
