/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nm-sd-adapt-shared.h"

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "escape.h"
#include "extract-word.h"
#include "fileio.h"
#include "gunicode.h"
#include "locale-util.h"
#include "macro.h"
#include "memory-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "utf8.h"
#include "util.h"

int strcmp_ptr(const char *a, const char *b) {
        /* Like strcmp(), but tries to make sense of NULL pointers */

        if (a && b)
                return strcmp(a, b);
        return CMP(a, b); /* Direct comparison of pointers, one of which is NULL */
}

int strcasecmp_ptr(const char *a, const char *b) {
        /* Like strcasecmp(), but tries to make sense of NULL pointers */

        if (a && b)
                return strcasecmp(a, b);
        return CMP(a, b); /* Direct comparison of pointers, one of which is NULL */
}

char* endswith(const char *s, const char *postfix) {
        size_t sl, pl;

        assert(s);
        assert(postfix);

        sl = strlen(s);
        pl = strlen(postfix);

        if (pl == 0)
                return (char*) s + sl;

        if (sl < pl)
                return NULL;

        if (memcmp(s + sl - pl, postfix, pl) != 0)
                return NULL;

        return (char*) s + sl - pl;
}

char* endswith_no_case(const char *s, const char *postfix) {
        size_t sl, pl;

        assert(s);
        assert(postfix);

        sl = strlen(s);
        pl = strlen(postfix);

        if (pl == 0)
                return (char*) s + sl;

        if (sl < pl)
                return NULL;

        if (strcasecmp(s + sl - pl, postfix) != 0)
                return NULL;

        return (char*) s + sl - pl;
}

char* first_word(const char *s, const char *word) {
        size_t sl, wl;
        const char *p;

        assert(s);
        assert(word);

        /* Checks if the string starts with the specified word, either
         * followed by NUL or by whitespace. Returns a pointer to the
         * NUL or the first character after the whitespace. */

        sl = strlen(s);
        wl = strlen(word);

        if (sl < wl)
                return NULL;

        if (wl == 0)
                return (char*) s;

        if (memcmp(s, word, wl) != 0)
                return NULL;

        p = s + wl;
        if (*p == 0)
                return (char*) p;

        if (!strchr(WHITESPACE, *p))
                return NULL;

        p += strspn(p, WHITESPACE);
        return (char*) p;
}

char *strnappend(const char *s, const char *suffix, size_t b) {
        size_t a;
        char *r;

        if (!s && !suffix)
                return strdup("");

        if (!s)
                return strndup(suffix, b);

        if (!suffix)
                return strdup(s);

        assert(s);
        assert(suffix);

        a = strlen(s);
        if (b > ((size_t) -1) - a)
                return NULL;

        r = new(char, a+b+1);
        if (!r)
                return NULL;

        memcpy(r, s, a);
        memcpy(r+a, suffix, b);
        r[a+b] = 0;

        return r;
}

char *strjoin_real(const char *x, ...) {
        va_list ap;
        size_t l = 1;
        char *r, *p;

        va_start(ap, x);
        for (const char *t = x; t; t = va_arg(ap, const char *)) {
                size_t n;

                n = strlen(t);
                if (n > SIZE_MAX - l) {
                        va_end(ap);
                        return NULL;
                }
                l += n;
        }
        va_end(ap);

        p = r = new(char, l);
        if (!r)
                return NULL;

        va_start(ap, x);
        for (const char *t = x; t; t = va_arg(ap, const char *))
                p = stpcpy(p, t);
        va_end(ap);

        *p = 0;

        return r;
}

#if 0 /* NM_IGNORED */
char *strstrip(char *s) {
        if (!s)
                return NULL;

        /* Drops trailing whitespace. Modifies the string in place. Returns pointer to first non-space character */

        return delete_trailing_chars(skip_leading_chars(s, WHITESPACE), WHITESPACE);
}

char *delete_chars(char *s, const char *bad) {
        char *f, *t;

        /* Drops all specified bad characters, regardless where in the string */

        if (!s)
                return NULL;

        if (!bad)
                bad = WHITESPACE;

        for (f = s, t = s; *f; f++) {
                if (strchr(bad, *f))
                        continue;

                *(t++) = *f;
        }

        *t = 0;

        return s;
}

char *delete_trailing_chars(char *s, const char *bad) {
        char *p, *c = s;

        /* Drops all specified bad characters, at the end of the string */

        if (!s)
                return NULL;

        if (!bad)
                bad = WHITESPACE;

        for (p = s; *p; p++)
                if (!strchr(bad, *p))
                        c = p + 1;

        *c = 0;

        return s;
}
#endif /* NM_IGNORED */

char *truncate_nl(char *s) {
        assert(s);

        s[strcspn(s, NEWLINE)] = 0;
        return s;
}

char ascii_tolower(char x) {

        if (x >= 'A' && x <= 'Z')
                return x - 'A' + 'a';

        return x;
}

char ascii_toupper(char x) {

        if (x >= 'a' && x <= 'z')
                return x - 'a' + 'A';

        return x;
}

char *ascii_strlower(char *t) {
        char *p;

        assert(t);

        for (p = t; *p; p++)
                *p = ascii_tolower(*p);

        return t;
}

char *ascii_strupper(char *t) {
        char *p;

        assert(t);

        for (p = t; *p; p++)
                *p = ascii_toupper(*p);

        return t;
}

char *ascii_strlower_n(char *t, size_t n) {
        size_t i;

        if (n <= 0)
                return t;

        for (i = 0; i < n; i++)
                t[i] = ascii_tolower(t[i]);

        return t;
}

int ascii_strcasecmp_n(const char *a, const char *b, size_t n) {

        for (; n > 0; a++, b++, n--) {
                int x, y;

                x = (int) (uint8_t) ascii_tolower(*a);
                y = (int) (uint8_t) ascii_tolower(*b);

                if (x != y)
                        return x - y;
        }

        return 0;
}

int ascii_strcasecmp_nn(const char *a, size_t n, const char *b, size_t m) {
        int r;

        r = ascii_strcasecmp_n(a, b, MIN(n, m));
        if (r != 0)
                return r;

        return CMP(n, m);
}

bool chars_intersect(const char *a, const char *b) {
        const char *p;

        /* Returns true if any of the chars in a are in b. */
        for (p = a; *p; p++)
                if (strchr(b, *p))
                        return true;

        return false;
}

bool string_has_cc(const char *p, const char *ok) {
        const char *t;

        assert(p);

        /*
         * Check if a string contains control characters. If 'ok' is
         * non-NULL it may be a string containing additional CCs to be
         * considered OK.
         */

        for (t = p; *t; t++) {
                if (ok && strchr(ok, *t))
                        continue;

                if (*t > 0 && *t < ' ')
                        return true;

                if (*t == 127)
                        return true;
        }

        return false;
}

#if 0 /* NM_IGNORED */
static int write_ellipsis(char *buf, bool unicode) {
        if (unicode || is_locale_utf8()) {
                buf[0] = 0xe2; /* tri-dot ellipsis: … */
                buf[1] = 0x80;
                buf[2] = 0xa6;
        } else {
                buf[0] = '.';
                buf[1] = '.';
                buf[2] = '.';
        }

        return 3;
}

static char *ascii_ellipsize_mem(const char *s, size_t old_length, size_t new_length, unsigned percent) {
        size_t x, need_space, suffix_len;
        char *t;

        assert(s);
        assert(percent <= 100);
        assert(new_length != (size_t) -1);

        if (old_length <= new_length)
                return strndup(s, old_length);

        /* Special case short ellipsations */
        switch (new_length) {

        case 0:
                return strdup("");

        case 1:
                if (is_locale_utf8())
                        return strdup("…");
                else
                        return strdup(".");

        case 2:
                if (!is_locale_utf8())
                        return strdup("..");

                break;

        default:
                break;
        }

        /* Calculate how much space the ellipsis will take up. If we are in UTF-8 mode we only need space for one
         * character ("…"), otherwise for three characters ("..."). Note that in both cases we need 3 bytes of storage,
         * either for the UTF-8 encoded character or for three ASCII characters. */
        need_space = is_locale_utf8() ? 1 : 3;

        t = new(char, new_length+3);
        if (!t)
                return NULL;

        assert(new_length >= need_space);

        x = ((new_length - need_space) * percent + 50) / 100;
        assert(x <= new_length - need_space);

        memcpy(t, s, x);
        write_ellipsis(t + x, false);
        suffix_len = new_length - x - need_space;
        memcpy(t + x + 3, s + old_length - suffix_len, suffix_len);
        *(t + x + 3 + suffix_len) = '\0';

        return t;
}

char *ellipsize_mem(const char *s, size_t old_length, size_t new_length, unsigned percent) {
        size_t x, k, len, len2;
        const char *i, *j;
        char *e;
        int r;

        /* Note that 'old_length' refers to bytes in the string, while 'new_length' refers to character cells taken up
         * on screen. This distinction doesn't matter for ASCII strings, but it does matter for non-ASCII UTF-8
         * strings.
         *
         * Ellipsation is done in a locale-dependent way:
         * 1. If the string passed in is fully ASCII and the current locale is not UTF-8, three dots are used ("...")
         * 2. Otherwise, a unicode ellipsis is used ("…")
         *
         * In other words: you'll get a unicode ellipsis as soon as either the string contains non-ASCII characters or
         * the current locale is UTF-8.
         */

        assert(s);
        assert(percent <= 100);

        if (new_length == (size_t) -1)
                return strndup(s, old_length);

        if (new_length == 0)
                return strdup("");

        /* If no multibyte characters use ascii_ellipsize_mem for speed */
        if (ascii_is_valid_n(s, old_length))
                return ascii_ellipsize_mem(s, old_length, new_length, percent);

        x = ((new_length - 1) * percent) / 100;
        assert(x <= new_length - 1);

        k = 0;
        for (i = s; i < s + old_length; i = utf8_next_char(i)) {
                char32_t c;
                int w;

                r = utf8_encoded_to_unichar(i, &c);
                if (r < 0)
                        return NULL;

                w = unichar_iswide(c) ? 2 : 1;
                if (k + w <= x)
                        k += w;
                else
                        break;
        }

        for (j = s + old_length; j > i; ) {
                char32_t c;
                int w;
                const char *jj;

                jj = utf8_prev_char(j);
                r = utf8_encoded_to_unichar(jj, &c);
                if (r < 0)
                        return NULL;

                w = unichar_iswide(c) ? 2 : 1;
                if (k + w <= new_length) {
                        k += w;
                        j = jj;
                } else
                        break;
        }
        assert(i <= j);

        /* we don't actually need to ellipsize */
        if (i == j)
                return memdup_suffix0(s, old_length);

        /* make space for ellipsis, if possible */
        if (j < s + old_length)
                j = utf8_next_char(j);
        else if (i > s)
                i = utf8_prev_char(i);

        len = i - s;
        len2 = s + old_length - j;
        e = new(char, len + 3 + len2 + 1);
        if (!e)
                return NULL;

        /*
        printf("old_length=%zu new_length=%zu x=%zu len=%u len2=%u k=%u\n",
               old_length, new_length, x, len, len2, k);
        */

        memcpy(e, s, len);
        write_ellipsis(e + len, true);
        memcpy(e + len + 3, j, len2);
        *(e + len + 3 + len2) = '\0';

        return e;
}

char *cellescape(char *buf, size_t len, const char *s) {
        /* Escape and ellipsize s into buffer buf of size len. Only non-control ASCII
         * characters are copied as they are, everything else is escaped. The result
         * is different then if escaping and ellipsization was performed in two
         * separate steps, because each sequence is either stored in full or skipped.
         *
         * This function should be used for logging about strings which expected to
         * be plain ASCII in a safe way.
         *
         * An ellipsis will be used if s is too long. It was always placed at the
         * very end.
         */

        size_t i = 0, last_char_width[4] = {}, k = 0, j;

        assert(len > 0); /* at least a terminating NUL */

        for (;;) {
                char four[4];
                int w;

                if (*s == 0) /* terminating NUL detected? then we are done! */
                        goto done;

                w = cescape_char(*s, four);
                if (i + w + 1 > len) /* This character doesn't fit into the buffer anymore? In that case let's
                                      * ellipsize at the previous location */
                        break;

                /* OK, there was space, let's add this escaped character to the buffer */
                memcpy(buf + i, four, w);
                i += w;

                /* And remember its width in the ring buffer */
                last_char_width[k] = w;
                k = (k + 1) % 4;

                s++;
        }

        /* Ellipsation is necessary. This means we might need to truncate the string again to make space for 4
         * characters ideally, but the buffer is shorter than that in the first place take what we can get */
        for (j = 0; j < ELEMENTSOF(last_char_width); j++) {

                if (i + 4 <= len) /* nice, we reached our space goal */
                        break;

                k = k == 0 ? 3 : k - 1;
                if (last_char_width[k] == 0) /* bummer, we reached the beginning of the strings */
                        break;

                assert(i >= last_char_width[k]);
                i -= last_char_width[k];
        }

        if (i + 4 <= len) /* yay, enough space */
                i += write_ellipsis(buf + i, false);
        else if (i + 3 <= len) { /* only space for ".." */
                buf[i++] = '.';
                buf[i++] = '.';
        } else if (i + 2 <= len) /* only space for a single "." */
                buf[i++] = '.';
        else
                assert(i + 1 <= len);

 done:
        buf[i] = '\0';
        return buf;
}
#endif /* NM_IGNORED */

char* strshorten(char *s, size_t l) {
        assert(s);

        if (strnlen(s, l+1) > l)
                s[l] = 0;

        return s;
}

char *strreplace(const char *text, const char *old_string, const char *new_string) {
        size_t l, old_len, new_len, allocated = 0;
        char *t, *ret = NULL;
        const char *f;

        assert(old_string);
        assert(new_string);

        if (!text)
                return NULL;

        old_len = strlen(old_string);
        new_len = strlen(new_string);

        l = strlen(text);
        if (!GREEDY_REALLOC(ret, allocated, l+1))
                return NULL;

        f = text;
        t = ret;
        while (*f) {
                size_t d, nl;

                if (!startswith(f, old_string)) {
                        *(t++) = *(f++);
                        continue;
                }

                d = t - ret;
                nl = l - old_len + new_len;

                if (!GREEDY_REALLOC(ret, allocated, nl + 1))
                        return mfree(ret);

                l = nl;
                t = ret + d;

                t = stpcpy(t, new_string);
                f += old_len;
        }

        *t = 0;
        return ret;
}

#if 0 /* NM_IGNORED */
static void advance_offsets(
                ssize_t diff,
                size_t offsets[2], /* note: we can't use [static 2] here, since this may be NULL */
                size_t shift[static 2],
                size_t size) {

        if (!offsets)
                return;

        assert(shift);

        if ((size_t) diff < offsets[0])
                shift[0] += size;
        if ((size_t) diff < offsets[1])
                shift[1] += size;
}

char *strip_tab_ansi(char **ibuf, size_t *_isz, size_t highlight[2]) {
        const char *begin = NULL;
        enum {
                STATE_OTHER,
                STATE_ESCAPE,
                STATE_CSI,
                STATE_CSO,
        } state = STATE_OTHER;
        char *obuf = NULL;
        size_t osz = 0, isz, shift[2] = {}, n_carriage_returns = 0;
        FILE *f;

        assert(ibuf);
        assert(*ibuf);

        /* This does three things:
         *
         * 1. Replaces TABs by 8 spaces
         * 2. Strips ANSI color sequences (a subset of CSI), i.e. ESC '[' … 'm' sequences
         * 3. Strips ANSI operating system sequences (CSO), i.e. ESC ']' … BEL sequences
         * 4. Strip trailing \r characters (since they would "move the cursor", but have no
         *    other effect).
         *
         * Everything else will be left as it is. In particular other ANSI sequences are left as they are, as
         * are any other special characters. Truncated ANSI sequences are left-as is too. This call is
         * supposed to suppress the most basic formatting noise, but nothing else.
         *
         * Why care for CSO sequences? Well, to undo what terminal_urlify() and friends generate. */

        isz = _isz ? *_isz : strlen(*ibuf);

        /* Note we turn off internal locking on f for performance reasons. It's safe to do so since we
         * created f here and it doesn't leave our scope. */
        f = open_memstream_unlocked(&obuf, &osz);
        if (!f)
                return NULL;

        for (const char *i = *ibuf; i < *ibuf + isz + 1; i++) {

                switch (state) {

                case STATE_OTHER:
                        if (i >= *ibuf + isz) /* EOT */
                                break;

                        if (*i == '\r') {
                                n_carriage_returns++;
                                break;
                        } else if (*i == '\n')
                                /* Ignore carriage returns before new line */
                                n_carriage_returns = 0;
                        for (; n_carriage_returns > 0; n_carriage_returns--)
                                fputc('\r', f);

                        if (*i == '\x1B')
                                state = STATE_ESCAPE;
                        else if (*i == '\t') {
                                fputs("        ", f);
                                advance_offsets(i - *ibuf, highlight, shift, 7);
                        } else
                                fputc(*i, f);

                        break;

                case STATE_ESCAPE:
                        assert(n_carriage_returns == 0);

                        if (i >= *ibuf + isz) { /* EOT */
                                fputc('\x1B', f);
                                advance_offsets(i - *ibuf, highlight, shift, 1);
                                break;
                        } else if (*i == '[') { /* ANSI CSI */
                                state = STATE_CSI;
                                begin = i + 1;
                        } else if (*i == ']') { /* ANSI CSO */
                                state = STATE_CSO;
                                begin = i + 1;
                        } else {
                                fputc('\x1B', f);
                                fputc(*i, f);
                                advance_offsets(i - *ibuf, highlight, shift, 1);
                                state = STATE_OTHER;
                        }

                        break;

                case STATE_CSI:
                        assert(n_carriage_returns == 0);

                        if (i >= *ibuf + isz || /* EOT … */
                            !strchr("01234567890;m", *i)) { /* … or invalid chars in sequence */
                                fputc('\x1B', f);
                                fputc('[', f);
                                advance_offsets(i - *ibuf, highlight, shift, 2);
                                state = STATE_OTHER;
                                i = begin-1;
                        } else if (*i == 'm')
                                state = STATE_OTHER;

                        break;

                case STATE_CSO:
                        assert(n_carriage_returns == 0);

                        if (i >= *ibuf + isz || /* EOT … */
                            (*i != '\a' && (uint8_t) *i < 32U) || (uint8_t) *i > 126U) { /* … or invalid chars in sequence */
                                fputc('\x1B', f);
                                fputc(']', f);
                                advance_offsets(i - *ibuf, highlight, shift, 2);
                                state = STATE_OTHER;
                                i = begin-1;
                        } else if (*i == '\a')
                                state = STATE_OTHER;

                        break;
                }
        }

        if (fflush_and_check(f) < 0) {
                fclose(f);
                return mfree(obuf);
        }
        fclose(f);

        free_and_replace(*ibuf, obuf);

        if (_isz)
                *_isz = osz;

        if (highlight) {
                highlight[0] += shift[0];
                highlight[1] += shift[1];
        }

        return *ibuf;
}

char *strextend_with_separator_internal(char **x, const char *separator, ...) {
        size_t f, l, l_separator;
        bool need_separator;
        char *nr, *p;
        va_list ap;

        assert(x);

        l = f = strlen_ptr(*x);

        need_separator = !isempty(*x);
        l_separator = strlen_ptr(separator);

        va_start(ap, separator);
        for (;;) {
                const char *t;
                size_t n;

                t = va_arg(ap, const char *);
                if (!t)
                        break;

                n = strlen(t);

                if (need_separator)
                        n += l_separator;

                if (n >= SIZE_MAX - l) {
                        va_end(ap);
                        return NULL;
                }

                l += n;
                need_separator = true;
        }
        va_end(ap);

        need_separator = !isempty(*x);

        nr = realloc(*x, GREEDY_ALLOC_ROUND_UP(l+1));
        if (!nr)
                return NULL;

        *x = nr;
        p = nr + f;

        va_start(ap, separator);
        for (;;) {
                const char *t;

                t = va_arg(ap, const char *);
                if (!t)
                        break;

                if (need_separator && separator)
                        p = stpcpy(p, separator);

                p = stpcpy(p, t);

                need_separator = true;
        }
        va_end(ap);

        assert(p == nr + l);

        *p = 0;

        return p;
}
#endif /* NM_IGNORED */

char *strrep(const char *s, unsigned n) {
        size_t l;
        char *r, *p;
        unsigned i;

        assert(s);

        l = strlen(s);
        p = r = malloc(l * n + 1);
        if (!r)
                return NULL;

        for (i = 0; i < n; i++)
                p = stpcpy(p, s);

        *p = 0;
        return r;
}

int split_pair(const char *s, const char *sep, char **l, char **r) {
        char *x, *a, *b;

        assert(s);
        assert(sep);
        assert(l);
        assert(r);

        if (isempty(sep))
                return -EINVAL;

        x = strstr(s, sep);
        if (!x)
                return -EINVAL;

        a = strndup(s, x - s);
        if (!a)
                return -ENOMEM;

        b = strdup(x + strlen(sep));
        if (!b) {
                free(a);
                return -ENOMEM;
        }

        *l = a;
        *r = b;

        return 0;
}

int free_and_strdup(char **p, const char *s) {
        char *t;

        assert(p);

        /* Replaces a string pointer with a strdup()ed new string,
         * possibly freeing the old one. */

        if (streq_ptr(*p, s))
                return 0;

        if (s) {
                t = strdup(s);
                if (!t)
                        return -ENOMEM;
        } else
                t = NULL;

        free(*p);
        *p = t;

        return 1;
}

int free_and_strndup(char **p, const char *s, size_t l) {
        char *t;

        assert(p);
        assert(s || l == 0);

        /* Replaces a string pointer with a strndup()ed new string,
         * freeing the old one. */

        if (!*p && !s)
                return 0;

        if (*p && s && strneq(*p, s, l) && (l > strlen(*p) || (*p)[l] == '\0'))
                return 0;

        if (s) {
                t = strndup(s, l);
                if (!t)
                        return -ENOMEM;
        } else
                t = NULL;

        free_and_replace(*p, t);
        return 1;
}

bool string_is_safe(const char *p) {
        const char *t;

        if (!p)
                return false;

        /* Checks if the specified string contains no quotes or control characters */

        for (t = p; *t; t++) {
                if (*t > 0 && *t < ' ') /* no control characters */
                        return false;

                if (strchr(QUOTES "\\\x7f", *t))
                        return false;
        }

        return true;
}

#if 0 /* NM_IGNORED */
char* string_erase(char *x) {
        if (!x)
                return NULL;

        /* A delicious drop of snake-oil! To be called on memory where we stored passphrases or so, after we
         * used them. */
        explicit_bzero_safe(x, strlen(x));
        return x;
}

int string_truncate_lines(const char *s, size_t n_lines, char **ret) {
        const char *p = s, *e = s;
        bool truncation_applied = false;
        char *copy;
        size_t n = 0;

        assert(s);

        /* Truncate after the specified number of lines. Returns > 0 if a truncation was applied or == 0 if
         * there were fewer lines in the string anyway. Trailing newlines on input are ignored, and not
         * generated either. */

        for (;;) {
                size_t k;

                k = strcspn(p, "\n");

                if (p[k] == 0) {
                        if (k == 0) /* final empty line */
                                break;

                        if (n >= n_lines) /* above threshold */
                                break;

                        e = p + k; /* last line to include */
                        break;
                }

                assert(p[k] == '\n');

                if (n >= n_lines)
                        break;

                if (k > 0)
                        e = p + k;

                p += k + 1;
                n++;
        }

        /* e points after the last character we want to keep */
        if (isempty(e))
                copy = strdup(s);
        else {
                if (!in_charset(e, "\n")) /* We only consider things truncated if we remove something that
                                           * isn't a new-line or a series of them */
                        truncation_applied = true;

                copy = strndup(s, e - s);
        }
        if (!copy)
                return -ENOMEM;

        *ret = copy;
        return truncation_applied;
}

int string_extract_line(const char *s, size_t i, char **ret) {
        const char *p = s;
        size_t c = 0;

        /* Extract the i'nth line from the specified string. Returns > 0 if there are more lines after that,
         * and == 0 if we are looking at the last line or already beyond the last line. As special
         * optimization, if the first line is requested and the string only consists of one line we return
         * NULL, indicating the input string should be used as is, and avoid a memory allocation for a very
         * common case. */

        for (;;) {
                const char *q;

                q = strchr(p, '\n');
                if (i == c) {
                        /* The line we are looking for! */

                        if (q) {
                                char *m;

                                m = strndup(p, q - p);
                                if (!m)
                                        return -ENOMEM;

                                *ret = m;
                                return !isempty(q + 1); /* more coming? */
                        } else {
                                if (p == s)
                                        *ret = NULL; /* Just use the input string */
                                else {
                                        char *m;

                                        m = strdup(p);
                                        if (!m)
                                                return -ENOMEM;

                                        *ret = m;
                                }

                                return 0; /* The end */
                        }
                }

                if (!q) {
                        char *m;

                        /* No more lines, return empty line */

                        m = strdup("");
                        if (!m)
                                return -ENOMEM;

                        *ret = m;
                        return 0; /* The end */
                }

                p = q + 1;
                c++;
        }
}

int string_contains_word_strv(const char *string, const char *separators, char **words, const char **ret_word) {
        /* In the default mode with no separators specified, we split on whitespace and
         * don't coalesce separators. */
        const ExtractFlags flags = separators ? EXTRACT_DONT_COALESCE_SEPARATORS : 0;

        const char *found = NULL;

        for (const char *p = string;;) {
                _cleanup_free_ char *w = NULL;
                int r;

                r = extract_first_word(&p, &w, separators, flags);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                found = strv_find(words, w);
                if (found)
                        break;
        }

        if (ret_word)
                *ret_word = found;
        return !!found;
}
#endif /* NM_IGNORED */
