/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <fnmatch.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "alloc-util.h"
#include "extract-word.h"
#include "hashmap.h"
#include "macro.h"
#include "string-util.h"

char *strv_find(char * const *l, const char *name) _pure_;
char *strv_find_case(char * const *l, const char *name) _pure_;
char *strv_find_prefix(char * const *l, const char *name) _pure_;
char *strv_find_startswith(char * const *l, const char *name) _pure_;

#define strv_contains(l, s) (!!strv_find((l), (s)))
#define strv_contains_case(l, s) (!!strv_find_case((l), (s)))

char **strv_free(char **l);
DEFINE_TRIVIAL_CLEANUP_FUNC(char**, strv_free);
#define _cleanup_strv_free_ _cleanup_(strv_freep)

char **strv_free_erase(char **l);
DEFINE_TRIVIAL_CLEANUP_FUNC(char**, strv_free_erase);
#define _cleanup_strv_free_erase_ _cleanup_(strv_free_erasep)

char **strv_copy(char * const *l);
size_t strv_length(char * const *l) _pure_;

int strv_extend_strv(char ***a, char * const *b, bool filter_duplicates);
int strv_extend_strv_concat(char ***a, char * const *b, const char *suffix);
int strv_prepend(char ***l, const char *value);
int strv_extend(char ***l, const char *value);
int strv_extendf(char ***l, const char *format, ...) _printf_(2,0);
int strv_extend_front(char ***l, const char *value);
int strv_push(char ***l, char *value);
int strv_push_pair(char ***l, char *a, char *b);
int strv_insert(char ***l, size_t position, char *value);

static inline int strv_push_prepend(char ***l, char *value) {
        return strv_insert(l, 0, value);
}

int strv_consume(char ***l, char *value);
int strv_consume_pair(char ***l, char *a, char *b);
int strv_consume_prepend(char ***l, char *value);

char **strv_remove(char **l, const char *s);
char **strv_uniq(char **l);
bool strv_is_uniq(char * const *l);

int strv_compare(char * const *a, char * const *b);
static inline bool strv_equal(char * const *a, char * const *b) {
        return strv_compare(a, b) == 0;
}

char **strv_new_internal(const char *x, ...) _sentinel_;
char **strv_new_ap(const char *x, va_list ap);
#define strv_new(...) strv_new_internal(__VA_ARGS__, NULL)

#define STRV_IGNORE ((const char *) POINTER_MAX)

static inline const char* STRV_IFNOTNULL(const char *x) {
        return x ? x : STRV_IGNORE;
}

static inline bool strv_isempty(char * const *l) {
        return !l || !*l;
}

int strv_split_full(char ***t, const char *s, const char *separators, ExtractFlags flags);
static inline char **strv_split(const char *s, const char *separators) {
        char **ret;

        if (strv_split_full(&ret, s, separators, 0) < 0)
                return NULL;

        return ret;
}

int strv_split_newlines_full(char ***ret, const char *s, ExtractFlags flags);
static inline char **strv_split_newlines(const char *s) {
        char **ret;

        if (strv_split_newlines_full(&ret, s, 0) < 0)
                return NULL;

        return ret;
}

/* Given a string containing white-space separated tuples of words themselves separated by ':',
 * returns a vector of strings. If the second element in a tuple is missing, the corresponding
 * string in the vector is an empty string. */
int strv_split_colon_pairs(char ***t, const char *s);

char *strv_join_full(char * const *l, const char *separator, const char *prefix, bool escape_separtor);
static inline char *strv_join(char * const *l, const char *separator) {
        return strv_join_full(l, separator, NULL, false);
}

char **strv_parse_nulstr(const char *s, size_t l);
char **strv_split_nulstr(const char *s);
int strv_make_nulstr(char * const *l, char **p, size_t *n);

static inline int strv_from_nulstr(char ***a, const char *nulstr) {
        char **t;

        t = strv_split_nulstr(nulstr);
        if (!t)
                return -ENOMEM;
        *a = t;
        return 0;
}

bool strv_overlap(char * const *a, char * const *b) _pure_;

#define STRV_FOREACH(s, l)                      \
        for ((s) = (l); (s) && *(s); (s)++)

#define STRV_FOREACH_BACKWARDS(s, l)                                \
        for (s = ({                                                 \
                        typeof(l) _l = l;                           \
                        _l ? _l + strv_length(_l) - 1U : NULL;      \
                        });                                         \
             (l) && ((s) >= (l));                                   \
             (s)--)

#define STRV_FOREACH_PAIR(x, y, l)               \
        for ((x) = (l), (y) = (x) ? (x+1) : NULL; (x) && *(x) && *(y); (x) += 2, (y) = (x + 1))

char **strv_sort(char **l);
void strv_print(char * const *l);

#define strv_from_stdarg_alloca(first)                          \
        ({                                                      \
                char **_l;                                      \
                                                                \
                if (!first)                                     \
                        _l = (char**) &first;                   \
                else {                                          \
                        size_t _n;                              \
                        va_list _ap;                            \
                                                                \
                        _n = 1;                                 \
                        va_start(_ap, first);                   \
                        while (va_arg(_ap, char*))              \
                                _n++;                           \
                        va_end(_ap);                            \
                                                                \
                        _l = newa(char*, _n+1);                 \
                        _l[_n = 0] = (char*) first;             \
                        va_start(_ap, first);                   \
                        for (;;) {                              \
                                _l[++_n] = va_arg(_ap, char*);  \
                                if (!_l[_n])                    \
                                        break;                  \
                        }                                       \
                        va_end(_ap);                            \
                }                                               \
                _l;                                             \
        })

#define STR_IN_SET(x, ...) strv_contains(STRV_MAKE(__VA_ARGS__), x)
#define STRPTR_IN_SET(x, ...)                                    \
        ({                                                       \
                const char* _x = (x);                            \
                _x && strv_contains(STRV_MAKE(__VA_ARGS__), _x); \
        })

#define STRCASE_IN_SET(x, ...) strv_contains_case(STRV_MAKE(__VA_ARGS__), x)
#define STRCASEPTR_IN_SET(x, ...)                                    \
        ({                                                       \
                const char* _x = (x);                            \
                _x && strv_contains_case(STRV_MAKE(__VA_ARGS__), _x); \
        })

#define STARTSWITH_SET(p, ...)                                  \
        ({                                                      \
                const char *_p = (p);                           \
                char  *_found = NULL, **_i;                     \
                STRV_FOREACH(_i, STRV_MAKE(__VA_ARGS__)) {      \
                        _found = startswith(_p, *_i);           \
                        if (_found)                             \
                                break;                          \
                }                                               \
                _found;                                         \
        })

#define ENDSWITH_SET(p, ...)                                    \
        ({                                                      \
                const char *_p = (p);                           \
                char  *_found = NULL, **_i;                     \
                STRV_FOREACH(_i, STRV_MAKE(__VA_ARGS__)) {      \
                        _found = endswith(_p, *_i);             \
                        if (_found)                             \
                                break;                          \
                }                                               \
                _found;                                         \
        })

#define FOREACH_STRING(x, y, ...)                                       \
        for (char **_l = STRV_MAKE(({ x = y; }), ##__VA_ARGS__);        \
             x;                                                         \
             x = *(++_l))

char **strv_reverse(char **l);
char **strv_shell_escape(char **l, const char *bad);

bool strv_fnmatch_full(char* const* patterns, const char *s, int flags, size_t *matched_pos);
static inline bool strv_fnmatch(char* const* patterns, const char *s) {
        return strv_fnmatch_full(patterns, s, 0, NULL);
}

static inline bool strv_fnmatch_or_empty(char* const* patterns, const char *s, int flags) {
        assert(s);
        return strv_isempty(patterns) ||
               strv_fnmatch_full(patterns, s, flags, NULL);
}

char ***strv_free_free(char ***l);
DEFINE_TRIVIAL_CLEANUP_FUNC(char***, strv_free_free);

char **strv_skip(char **l, size_t n);

int strv_extend_n(char ***l, const char *value, size_t n);

int fputstrv(FILE *f, char * const *l, const char *separator, bool *space);

#define strv_free_and_replace(a, b)             \
        ({                                      \
                strv_free(a);                   \
                (a) = (b);                      \
                (b) = NULL;                     \
                0;                              \
        })

extern const struct hash_ops string_strv_hash_ops;
int _string_strv_hashmap_put(Hashmap **h, const char *key, const char *value  HASHMAP_DEBUG_PARAMS);
int _string_strv_ordered_hashmap_put(OrderedHashmap **h, const char *key, const char *value  HASHMAP_DEBUG_PARAMS);
#define string_strv_hashmap_put(h, k, v) _string_strv_hashmap_put(h, k, v  HASHMAP_DEBUG_SRC_ARGS)
#define string_strv_ordered_hashmap_put(h, k, v) _string_strv_ordered_hashmap_put(h, k, v  HASHMAP_DEBUG_SRC_ARGS)
