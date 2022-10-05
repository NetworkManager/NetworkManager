/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nm-sd-adapt-shared.h"

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "env-util.h"
#include "errno-util.h"
#include "escape.h"
#include "extract-word.h"
#include "macro.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"

#if 0 /* NM_IGNORED */
/* We follow bash for the character set. Different shells have different rules. */
#define VALID_BASH_ENV_NAME_CHARS               \
        DIGITS LETTERS                          \
        "_"

static bool env_name_is_valid_n(const char *e, size_t n) {
        if (!e)
                return false;

        if (n <= 0)
                return false;

        if (ascii_isdigit(e[0]))
                return false;

        /* POSIX says the overall size of the environment block cannot
         * be > ARG_MAX, an individual assignment hence cannot be
         * either. Discounting the equal sign and trailing NUL this
         * hence leaves ARG_MAX-2 as longest possible variable
         * name. */
        if (n > (size_t) sysconf(_SC_ARG_MAX) - 2)
                return false;

        for (const char *p = e; p < e + n; p++)
                if (!strchr(VALID_BASH_ENV_NAME_CHARS, *p))
                        return false;

        return true;
}

bool env_name_is_valid(const char *e) {
        return env_name_is_valid_n(e, strlen_ptr(e));
}

bool env_value_is_valid(const char *e) {
        if (!e)
                return false;

        if (!utf8_is_valid(e))
                return false;

        /* Note that variable *values* may contain control characters, in particular NL, TAB, BS, DEL, ESC…
         * When printing those variables with show-environment, we'll escape them. Make sure to print
         * environment variables carefully! */

        /* POSIX says the overall size of the environment block cannot be > ARG_MAX, an individual assignment
         * hence cannot be either. Discounting the shortest possible variable name of length 1, the equal
         * sign and trailing NUL this hence leaves ARG_MAX-3 as longest possible variable value. */
        if (strlen(e) > sc_arg_max() - 3)
                return false;

        return true;
}

bool env_assignment_is_valid(const char *e) {
        const char *eq;

        eq = strchr(e, '=');
        if (!eq)
                return false;

        if (!env_name_is_valid_n(e, eq - e))
                return false;

        if (!env_value_is_valid(eq + 1))
                return false;

        /* POSIX says the overall size of the environment block cannot be > ARG_MAX, hence the individual
         * variable assignments cannot be either, but let's leave room for one trailing NUL byte. */
        if (strlen(e) > sc_arg_max() - 1)
                return false;

        return true;
}

bool strv_env_is_valid(char **e) {
        STRV_FOREACH(p, e) {
                size_t k;

                if (!env_assignment_is_valid(*p))
                        return false;

                /* Check if there are duplicate assignments */
                k = strcspn(*p, "=");
                STRV_FOREACH(q, p + 1)
                        if (strneq(*p, *q, k) && (*q)[k] == '=')
                                return false;
        }

        return true;
}

bool strv_env_name_is_valid(char **l) {
        STRV_FOREACH(p, l) {
                if (!env_name_is_valid(*p))
                        return false;

                if (strv_contains(p + 1, *p))
                        return false;
        }

        return true;
}

bool strv_env_name_or_assignment_is_valid(char **l) {
        STRV_FOREACH(p, l) {
                if (!env_assignment_is_valid(*p) && !env_name_is_valid(*p))
                        return false;

                if (strv_contains(p + 1, *p))
                        return false;
        }

        return true;
}

static int env_append(char **r, char ***k, char **a) {
        assert(r);
        assert(k);
        assert(*k >= r);

        if (!a)
                return 0;

        /* Expects the following arguments: 'r' shall point to the beginning of an strv we are going to append to, 'k'
         * to a pointer pointing to the NULL entry at the end of the same array. 'a' shall point to another strv.
         *
         * This call adds every entry of 'a' to 'r', either overriding an existing matching entry, or appending to it.
         *
         * This call assumes 'r' has enough pre-allocated space to grow by all of 'a''s items. */

        for (; *a; a++) {
                char **j, *c;
                size_t n;

                n = strcspn(*a, "=");
                if ((*a)[n] == '=')
                        n++;

                for (j = r; j < *k; j++)
                        if (strneq(*j, *a, n))
                                break;

                c = strdup(*a);
                if (!c)
                        return -ENOMEM;

                if (j >= *k) { /* Append to the end? */
                        (*k)[0] = c;
                        (*k)[1] = NULL;
                        (*k)++;
                } else
                        free_and_replace(*j, c); /* Override existing item */
        }

        return 0;
}

char** _strv_env_merge(char **first, ...) {
        _cleanup_strv_free_ char **merged = NULL;
        char **k;
        va_list ap;

        /* Merges an arbitrary number of environment sets */

        size_t n = strv_length(first);

        va_start(ap, first);
        for (;;) {
                char **l;

                l = va_arg(ap, char**);
                if (l == POINTER_MAX)
                        break;

                n += strv_length(l);
        }
        va_end(ap);

        k = merged = new(char*, n + 1);
        if (!merged)
                return NULL;
        merged[0] = NULL;

        if (env_append(merged, &k, first) < 0)
                return NULL;

        va_start(ap, first);
        for (;;) {
                char **l;

                l = va_arg(ap, char**);
                if (l == POINTER_MAX)
                        break;

                if (env_append(merged, &k, l) < 0) {
                        va_end(ap);
                        return NULL;
                }
        }
        va_end(ap);

        return TAKE_PTR(merged);
}

static bool env_match(const char *t, const char *pattern) {
        assert(t);
        assert(pattern);

        /* pattern a matches string a
         *         a matches a=
         *         a matches a=b
         *         a= matches a=
         *         a=b matches a=b
         *         a= does not match a
         *         a=b does not match a=
         *         a=b does not match a
         *         a=b does not match a=c */

        if (streq(t, pattern))
                return true;

        if (!strchr(pattern, '=')) {
                size_t l = strlen(pattern);

                return strneq(t, pattern, l) && t[l] == '=';
        }

        return false;
}

static bool env_entry_has_name(const char *entry, const char *name) {
        const char *t;

        assert(entry);
        assert(name);

        t = startswith(entry, name);
        if (!t)
                return false;

        return *t == '=';
}

char **strv_env_delete(char **x, size_t n_lists, ...) {
        size_t n, i = 0;
        char **r;
        va_list ap;

        /* Deletes every entry from x that is mentioned in the other
         * string lists */

        n = strv_length(x);

        r = new(char*, n+1);
        if (!r)
                return NULL;

        STRV_FOREACH(k, x) {
                va_start(ap, n_lists);
                for (size_t v = 0; v < n_lists; v++) {
                        char **l;

                        l = va_arg(ap, char**);
                        STRV_FOREACH(j, l)
                                if (env_match(*k, *j))
                                        goto skip;
                }
                va_end(ap);

                r[i] = strdup(*k);
                if (!r[i]) {
                        strv_free(r);
                        return NULL;
                }

                i++;
                continue;

        skip:
                va_end(ap);
        }

        r[i] = NULL;

        assert(i <= n);

        return r;
}

char **strv_env_unset(char **l, const char *p) {
        char **f, **t;

        if (!l)
                return NULL;

        assert(p);

        /* Drops every occurrence of the env var setting p in the
         * string list. Edits in-place. */

        for (f = t = l; *f; f++) {

                if (env_match(*f, p)) {
                        free(*f);
                        continue;
                }

                *(t++) = *f;
        }

        *t = NULL;
        return l;
}

char **strv_env_unset_many(char **l, ...) {
        char **f, **t;

        if (!l)
                return NULL;

        /* Like strv_env_unset() but applies many at once. Edits in-place. */

        for (f = t = l; *f; f++) {
                bool found = false;
                const char *p;
                va_list ap;

                va_start(ap, l);

                while ((p = va_arg(ap, const char*))) {
                        if (env_match(*f, p)) {
                                found = true;
                                break;
                        }
                }

                va_end(ap);

                if (found) {
                        free(*f);
                        continue;
                }

                *(t++) = *f;
        }

        *t = NULL;
        return l;
}

int strv_env_replace_consume(char ***l, char *p) {
        const char *t, *name;
        int r;

        assert(p);

        /* Replace first occurrence of the env var or add a new one in the string list. Drop other
         * occurrences. Edits in-place. Does not copy p and CONSUMES p EVEN ON FAILURE.
         *
         * p must be a valid key=value assignment. */

        t = strchr(p, '=');
        if (!t) {
                free(p);
                return -EINVAL;
        }

        name = strndupa_safe(p, t - p);

        STRV_FOREACH(f, *l)
                if (env_entry_has_name(*f, name)) {
                        free_and_replace(*f, p);
                        strv_env_unset(f + 1, *f);
                        return 0;
                }

        /* We didn't find a match, we need to append p or create a new strv */
        r = strv_consume(l, p);
        if (r < 0)
                return r;

        return 1;
}

int strv_env_replace_strdup(char ***l, const char *assignment) {
        /* Like strv_env_replace_consume(), but copies the argument. */

        char *p = strdup(assignment);
        if (!p)
                return -ENOMEM;

        return strv_env_replace_consume(l, p);
}

int strv_env_replace_strdup_passthrough(char ***l, const char *assignment) {
        /* Like strv_env_replace_strdup(), but pulls the variable from the environment of
         * the calling program, if a variable name without value is specified.
         */
        char *p;

        if (strchr(assignment, '=')) {
                if (!env_assignment_is_valid(assignment))
                        return -EINVAL;

                p = strdup(assignment);
        } else {
                if (!env_name_is_valid(assignment))
                        return -EINVAL;

                /* If we can't find the variable in our environment, we will use
                 * the empty string. This way "passthrough" is equivalent to passing
                 * --setenv=FOO=$FOO in the shell. */
                p = strjoin(assignment, "=", secure_getenv(assignment));
        }
        if (!p)
                return -ENOMEM;

        return strv_env_replace_consume(l, p);
}

int strv_env_assign(char ***l, const char *key, const char *value) {
        if (!env_name_is_valid(key))
                return -EINVAL;

        /* NULL removes assignment, "" creates an empty assignment. */

        if (!value) {
                strv_env_unset(*l, key);
                return 0;
        }

        char *p = strjoin(key, "=", value);
        if (!p)
                return -ENOMEM;

        return strv_env_replace_consume(l, p);
}

char *strv_env_get_n(char **l, const char *name, size_t k, unsigned flags) {
        assert(name);

        if (k <= 0)
                return NULL;

        STRV_FOREACH_BACKWARDS(i, l)
                if (strneq(*i, name, k) &&
                    (*i)[k] == '=')
                        return *i + k + 1;

        if (flags & REPLACE_ENV_USE_ENVIRONMENT) {
                const char *t;

                t = strndupa_safe(name, k);
                return getenv(t);
        };

        return NULL;
}

char *strv_env_get(char **l, const char *name) {
        assert(name);

        return strv_env_get_n(l, name, strlen(name), 0);
}

char *strv_env_pairs_get(char **l, const char *name) {
        char *result = NULL;

        assert(name);

        STRV_FOREACH_PAIR(key, value, l)
                if (streq(*key, name))
                        result = *value;

        return result;
}

char **strv_env_clean_with_callback(char **e, void (*invalid_callback)(const char *p, void *userdata), void *userdata) {
        int k = 0;

        STRV_FOREACH(p, e) {
                size_t n;
                bool duplicate = false;

                if (!env_assignment_is_valid(*p)) {
                        if (invalid_callback)
                                invalid_callback(*p, userdata);
                        free(*p);
                        continue;
                }

                n = strcspn(*p, "=");
                STRV_FOREACH(q, p + 1)
                        if (strneq(*p, *q, n) && (*q)[n] == '=') {
                                duplicate = true;
                                break;
                        }

                if (duplicate) {
                        free(*p);
                        continue;
                }

                e[k++] = *p;
        }

        if (e)
                e[k] = NULL;

        return e;
}

char *replace_env_n(const char *format, size_t n, char **env, unsigned flags) {
        enum {
                WORD,
                CURLY,
                VARIABLE,
                VARIABLE_RAW,
                TEST,
                DEFAULT_VALUE,
                ALTERNATE_VALUE,
        } state = WORD;

        const char *e, *word = format, *test_value = NULL; /* test_value is initialized to appease gcc */
        char *k;
        _cleanup_free_ char *r = NULL;
        size_t i, len = 0; /* len is initialized to appease gcc */
        int nest = 0;

        assert(format);

        for (e = format, i = 0; *e && i < n; e ++, i ++)
                switch (state) {

                case WORD:
                        if (*e == '$')
                                state = CURLY;
                        break;

                case CURLY:
                        if (*e == '{') {
                                k = strnappend(r, word, e-word-1);
                                if (!k)
                                        return NULL;

                                free_and_replace(r, k);

                                word = e-1;
                                state = VARIABLE;
                                nest++;
                        } else if (*e == '$') {
                                k = strnappend(r, word, e-word);
                                if (!k)
                                        return NULL;

                                free_and_replace(r, k);

                                word = e+1;
                                state = WORD;

                        } else if (flags & REPLACE_ENV_ALLOW_BRACELESS && strchr(VALID_BASH_ENV_NAME_CHARS, *e)) {
                                k = strnappend(r, word, e-word-1);
                                if (!k)
                                        return NULL;

                                free_and_replace(r, k);

                                word = e-1;
                                state = VARIABLE_RAW;

                        } else
                                state = WORD;
                        break;

                case VARIABLE:
                        if (*e == '}') {
                                const char *t;

                                t = strv_env_get_n(env, word+2, e-word-2, flags);

                                if (!strextend(&r, t))
                                        return NULL;

                                word = e+1;
                                state = WORD;
                                nest--;
                        } else if (*e == ':') {
                                if (flags & REPLACE_ENV_ALLOW_EXTENDED) {
                                        len = e - word - 2;
                                        state = TEST;
                                } else
                                        /* Treat this as unsupported syntax, i.e. do no replacement */
                                        state = WORD;
                        }
                        break;

                case TEST:
                        if (*e == '-')
                                state = DEFAULT_VALUE;
                        else if (*e == '+')
                                state = ALTERNATE_VALUE;
                        else {
                                state = WORD;
                                break;
                        }

                        test_value = e+1;
                        break;

                case DEFAULT_VALUE: /* fall through */
                case ALTERNATE_VALUE:
                        assert(flags & REPLACE_ENV_ALLOW_EXTENDED);

                        if (*e == '{') {
                                nest++;
                                break;
                        }

                        if (*e != '}')
                                break;

                        nest--;
                        if (nest == 0) {
                                const char *t;
                                _cleanup_free_ char *v = NULL;

                                t = strv_env_get_n(env, word+2, len, flags);

                                if (t && state == ALTERNATE_VALUE)
                                        t = v = replace_env_n(test_value, e-test_value, env, flags);
                                else if (!t && state == DEFAULT_VALUE)
                                        t = v = replace_env_n(test_value, e-test_value, env, flags);

                                if (!strextend(&r, t))
                                        return NULL;

                                word = e+1;
                                state = WORD;
                        }
                        break;

                case VARIABLE_RAW:
                        assert(flags & REPLACE_ENV_ALLOW_BRACELESS);

                        if (!strchr(VALID_BASH_ENV_NAME_CHARS, *e)) {
                                const char *t;

                                t = strv_env_get_n(env, word+1, e-word-1, flags);

                                if (!strextend(&r, t))
                                        return NULL;

                                word = e--;
                                i--;
                                state = WORD;
                        }
                        break;
                }

        if (state == VARIABLE_RAW) {
                const char *t;

                assert(flags & REPLACE_ENV_ALLOW_BRACELESS);

                t = strv_env_get_n(env, word+1, e-word-1, flags);
                return strjoin(r, t);
        } else
                return strnappend(r, word, e-word);
}

char **replace_env_argv(char **argv, char **env) {
        char **ret;
        size_t k = 0, l = 0;

        l = strv_length(argv);

        ret = new(char*, l+1);
        if (!ret)
                return NULL;

        STRV_FOREACH(i, argv) {

                /* If $FOO appears as single word, replace it by the split up variable */
                if ((*i)[0] == '$' && !IN_SET((*i)[1], '{', '$')) {
                        char *e;
                        char **w, **m = NULL;
                        size_t q;

                        e = strv_env_get(env, *i+1);
                        if (e) {
                                int r;

                                r = strv_split_full(&m, e, WHITESPACE, EXTRACT_RELAX|EXTRACT_UNQUOTE);
                                if (r < 0) {
                                        ret[k] = NULL;
                                        strv_free(ret);
                                        return NULL;
                                }
                        } else
                                m = NULL;

                        q = strv_length(m);
                        l = l + q - 1;

                        w = reallocarray(ret, l + 1, sizeof(char *));
                        if (!w) {
                                ret[k] = NULL;
                                strv_free(ret);
                                strv_free(m);
                                return NULL;
                        }

                        ret = w;
                        if (m) {
                                memcpy(ret + k, m, q * sizeof(char*));
                                free(m);
                        }

                        k += q;
                        continue;
                }

                /* If ${FOO} appears as part of a word, replace it by the variable as-is */
                ret[k] = replace_env(*i, env, 0);
                if (!ret[k]) {
                        strv_free(ret);
                        return NULL;
                }
                k++;
        }

        ret[k] = NULL;
        return ret;
}
#endif /* NM_IGNORED */

int getenv_bool(const char *p) {
        const char *e;

        e = getenv(p);
        if (!e)
                return -ENXIO;

        return parse_boolean(e);
}

int getenv_bool_secure(const char *p) {
        const char *e;

        e = secure_getenv(p);
        if (!e)
                return -ENXIO;

        return parse_boolean(e);
}

#if 0 /* NM_IGNORED */
int getenv_uint64_secure(const char *p, uint64_t *ret) {
        const char *e;

        assert(p);

        e = secure_getenv(p);
        if (!e)
                return -ENXIO;

        return safe_atou64(e, ret);
}

int set_unset_env(const char *name, const char *value, bool overwrite) {
        assert(name);

        if (value)
                return RET_NERRNO(setenv(name, value, overwrite));

        return RET_NERRNO(unsetenv(name));
}

int putenv_dup(const char *assignment, bool override) {
        const char *e, *n;

        e = strchr(assignment, '=');
        if (!e)
                return -EINVAL;

        n = strndupa_safe(assignment, e - assignment);

        /* This is like putenv(), but uses setenv() so that our memory doesn't become part of environ[]. */
        return RET_NERRNO(setenv(n, e + 1, override));
}

int setenv_systemd_exec_pid(bool update_only) {
        char str[DECIMAL_STR_MAX(pid_t)];
        const char *e;

        /* Update $SYSTEMD_EXEC_PID=pid except when '*' is set for the variable. */

        e = secure_getenv("SYSTEMD_EXEC_PID");
        if (!e && update_only)
                return 0;

        if (streq_ptr(e, "*"))
                return 0;

        xsprintf(str, PID_FMT, getpid_cached());

        if (setenv("SYSTEMD_EXEC_PID", str, 1) < 0)
                return -errno;

        return 1;
}

int getenv_path_list(const char *name, char ***ret_paths) {
        _cleanup_strv_free_ char **l = NULL;
        const char *e;
        int r;

        assert(name);
        assert(ret_paths);

        e = secure_getenv(name);
        if (!e)
                return -ENXIO;

        r = strv_split_full(&l, e, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse $%s: %m", name);

        STRV_FOREACH(p, l) {
                if (!path_is_absolute(*p))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Path '%s' is not absolute, refusing.", *p);

                if (!path_is_normalized(*p))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Path '%s' is not normalized, refusing.", *p);

                if (path_equal(*p, "/"))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Path '%s' is the root fs, refusing.", *p);
        }

        if (strv_isempty(l))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "No paths specified, refusing.");

        *ret_paths = TAKE_PTR(l);
        return 1;
}

int getenv_steal_erase(const char *name, char **ret) {
        _cleanup_(erase_and_freep) char *a = NULL;
        char *e;

        assert(name);

        /* Reads an environment variable, makes a copy of it, erases its memory in the environment block and removes
         * it from there. Usecase: reading passwords from the env block (which is a bad idea, but useful for
         * testing, and given that people are likely going to misuse this, be thorough) */

        e = getenv(name);
        if (!e) {
                if (ret)
                        *ret = NULL;
                return 0;
        }

        if (ret) {
                a = strdup(e);
                if (!a)
                        return -ENOMEM;
        }

        string_erase(e);

        if (unsetenv(name) < 0)
                return -errno;

        if (ret)
                *ret = TAKE_PTR(a);

        return 1;
}
#endif /* NM_IGNORED */
