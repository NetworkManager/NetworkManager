/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2016 Red Hat, Inc.
 */

#define NM_WANT_NM_ARRAY_FIND_BSEARCH_INLINE

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-shared-utils.h"

#include <pwd.h>
#include <arpa/inet.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <pthread.h>

#include "c-list/src/c-list.h"
#include "nm-errno.h"
#include "nm-str-buf.h"

G_STATIC_ASSERT(sizeof(NMEtherAddr) == 6);
G_STATIC_ASSERT(_nm_alignof(NMEtherAddr) == 1);

G_STATIC_ASSERT(sizeof(NMUtilsNamedEntry) == sizeof(const char *));
G_STATIC_ASSERT(G_STRUCT_OFFSET(NMUtilsNamedValue, value_ptr) == sizeof(const char *));

/*****************************************************************************/

const char _nm_hexchar_table_lower[16] = "0123456789abcdef";
const char _nm_hexchar_table_upper[16] = "0123456789ABCDEF";

const void *const _NM_PTRARRAY_EMPTY[1] = {NULL};

/*****************************************************************************/

G_STATIC_ASSERT(ETH_ALEN == sizeof(struct ether_addr));
G_STATIC_ASSERT(ETH_ALEN == 6);
G_STATIC_ASSERT(ETH_ALEN == sizeof(NMEtherAddr));

G_STATIC_ASSERT(_nm_alignof(struct ether_addr) <= _nm_alignof(NMEtherAddr));

NMEtherAddr *
nm_ether_addr_from_string(NMEtherAddr *addr, const char *str)
{
    nm_assert(addr);

    if (!str || !_nm_utils_hwaddr_aton_exact(str, addr, ETH_ALEN)) {
        *addr = NM_ETHER_ADDR_INIT(0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
        return NULL;
    }

    return addr;
}

/*****************************************************************************/

/**
 * nm_utils_inet6_is_token:
 * @in6addr: the AF_INET6 address structure
 *
 * Checks if only the bottom 64bits of the address are set.
 *
 * Return value: %TRUE or %FALSE
 */
gboolean
_nm_utils_inet6_is_token(const struct in6_addr *in6addr)
{
    if (in6addr->s6_addr[0] || in6addr->s6_addr[1] || in6addr->s6_addr[2] || in6addr->s6_addr[3]
        || in6addr->s6_addr[4] || in6addr->s6_addr[5] || in6addr->s6_addr[6] || in6addr->s6_addr[7])
        return FALSE;

    if (in6addr->s6_addr[8] || in6addr->s6_addr[9] || in6addr->s6_addr[10] || in6addr->s6_addr[11]
        || in6addr->s6_addr[12] || in6addr->s6_addr[13] || in6addr->s6_addr[14]
        || in6addr->s6_addr[15])
        return TRUE;

    return FALSE;
}

/**
 * nm_utils_ipv6_interface_identifier_get_from_token:
 * @iid: output %NMUtilsIPv6IfaceId interface identifier set from the token
 * @token: token encoded as string
 *
 * Converts the %in6_addr encoded token (as used in ip6 settings) to
 * the interface identifier.
 *
 * Returns: %TRUE if the @token is a valid token, %FALSE otherwise
 */
gboolean
nm_utils_ipv6_interface_identifier_get_from_token(NMUtilsIPv6IfaceId *iid, const char *token)
{
    struct in6_addr i6_token;

    g_return_val_if_fail(token, FALSE);

    if (!inet_pton(AF_INET6, token, &i6_token))
        return FALSE;

    if (!_nm_utils_inet6_is_token(&i6_token))
        return FALSE;

    nm_utils_ipv6_interface_identifier_get_from_addr(iid, &i6_token);
    return TRUE;
}

/**
 * nm_utils_inet6_interface_identifier_to_token:
 * @iid: %NMUtilsIPv6IfaceId interface identifier
 * @buf: the destination buffer of at least %NM_INET_ADDRSTRLEN
 *   bytes.
 *
 * Converts the interface identifier to a string token.
 *
 * Returns: the input buffer filled with the id as string.
 */
const char *
nm_utils_inet6_interface_identifier_to_token(const NMUtilsIPv6IfaceId *iid,
                                             char                      buf[static INET6_ADDRSTRLEN])
{
    struct in6_addr i6_token = {.s6_addr = {
                                    0,
                                }};

    nm_assert(buf);
    nm_utils_ipv6_addr_set_interface_identifier(&i6_token, iid);
    return nm_inet6_ntop(&i6_token, buf);
}

/*****************************************************************************/

pid_t
nm_utils_gettid(void)
{
    return (pid_t) syscall(SYS_gettid);
}

/* Used for asserting that this function is called on the main-thread.
 * The main-thread is determined by remembering the thread-id
 * of when the function was called the first time.
 *
 * When forking, the thread-id is again reset upon first call.
 *
 * Note that this is only used for asserting, to check that we don't
 * call the function on the wrong thread. As it's difficult to correctly
 * cache the tid/pid, we might get this wrong during fork. That is not
 * a problem, because we err on the side of pretending all is good. */
gboolean
_nm_assert_on_main_thread(void)
{
    static GMutex lock;
    static int    seen_tid;
    pid_t         tid;
    int           t;
    gboolean      success = FALSE;

    tid = nm_utils_gettid();
    nm_assert(tid != 0);
    nm_assert(({
        const int tt = tid;

        tt == tid;
    }));

    t = g_atomic_int_get(&seen_tid);
    if (G_LIKELY(t == tid)) {
        /* we don't care about false positives (when the process forked, and the thread-id
         * is accidentally re-used) . It's for assertions only. */
        return TRUE;
    }

    g_mutex_lock(&lock);

    t = g_atomic_int_get(&seen_tid);
    if (G_UNLIKELY(t == tid))
        success = TRUE;
    else {
        static pid_t seen_pid;
        pid_t        pid;

        pid = getpid();
        nm_assert(pid != 0);

        if (t == 0 || seen_pid != pid) {
            /* either this is the first time we call the function, or the process
             * forked. In both cases, update the thread-id. */
            g_atomic_int_set(&seen_tid, tid);
            seen_pid = pid;
            success  = TRUE;
        }
    }

    g_mutex_unlock(&lock);

    return success;
}

/*****************************************************************************/

void
nm_strbuf_append_c(char **buf, gsize *len, char c)
{
    switch (*len) {
    case 0:
        return;
    case 1:
        (*buf)[0] = '\0';
        *len      = 0;
        (*buf)++;
        return;
    default:
        (*buf)[0] = c;
        (*buf)[1] = '\0';
        (*len)--;
        (*buf)++;
        return;
    }
}

void
nm_strbuf_append_bin(char **buf, gsize *len, gconstpointer str, gsize str_len)
{
    switch (*len) {
    case 0:
        return;
    case 1:
        if (str_len == 0) {
            (*buf)[0] = '\0';
            return;
        }
        (*buf)[0] = '\0';
        *len      = 0;
        (*buf)++;
        return;
    default:
        if (str_len == 0) {
            (*buf)[0] = '\0';
            return;
        }
        if (str_len >= *len) {
            memcpy(*buf, str, *len - 1);
            (*buf)[*len - 1] = '\0';
            *buf             = &(*buf)[*len];
            *len             = 0;
        } else {
            memcpy(*buf, str, str_len);
            *buf      = &(*buf)[str_len];
            (*buf)[0] = '\0';
            *len -= str_len;
        }
        return;
    }
}

void
nm_strbuf_append_str(char **buf, gsize *len, const char *str)
{
    gsize src_len;

    switch (*len) {
    case 0:
        return;
    case 1:
        if (!str || !*str) {
            (*buf)[0] = '\0';
            return;
        }
        (*buf)[0] = '\0';
        *len      = 0;
        (*buf)++;
        return;
    default:
        if (!str || !*str) {
            (*buf)[0] = '\0';
            return;
        }
        src_len = g_strlcpy(*buf, str, *len);
        if (src_len >= *len) {
            *buf = &(*buf)[*len];
            *len = 0;
        } else {
            *buf = &(*buf)[src_len];
            *len -= src_len;
        }
        return;
    }
}

void
nm_strbuf_append(char **buf, gsize *len, const char *format, ...)
{
    char   *p = *buf;
    va_list args;
    int     retval;

    if (*len == 0)
        return;

    va_start(args, format);
    retval = g_vsnprintf(p, *len, format, args);
    va_end(args);

    if ((gsize) retval >= *len) {
        *buf = &p[*len];
        *len = 0;
    } else {
        *buf = &p[retval];
        *len -= retval;
    }
}

/**
 * nm_strbuf_seek_end:
 * @buf: the input/output buffer
 * @len: the input/output length of the buffer.
 *
 * Commonly, one uses nm_strbuf_append*(), to incrementally
 * append strings to the buffer. However, sometimes we need to use
 * existing API to write to the buffer.
 * After doing so, we want to adjust the buffer counter.
 * Essentially,
 *
 *   g_snprintf (buf, len, ...);
 *   nm_strbuf_seek_end (&buf, &len);
 *
 * is almost the same as
 *
 *   nm_strbuf_append (&buf, &len, ...);
 *
 * The only difference is the behavior when the string got truncated:
 * nm_strbuf_append() will recognize that and set the remaining
 * length to zero.
 *
 * In general, the behavior is:
 *
 *  - if *len is zero, do nothing
 *  - if the buffer contains a NUL byte within the first *len characters,
 *    the buffer is pointed to the NUL byte and len is adjusted. In this
 *    case, the remaining *len is always >= 1.
 *    In particular, that is also the case if the NUL byte is at the very last
 *    position ((*buf)[*len -1]). That happens, when the previous operation
 *    either fit the string exactly into the buffer or the string was truncated
 *    by g_snprintf(). The difference cannot be determined.
 *  - if the buffer contains no NUL bytes within the first *len characters,
 *    write NUL at the last position, set *len to zero, and point *buf past
 *    the NUL byte. This would happen with
 *
 *       strncpy (buf, long_str, len);
 *       nm_strbuf_seek_end (&buf, &len).
 *
 *    where strncpy() does truncate the string and not NUL terminate it.
 *    nm_strbuf_seek_end() would then NUL terminate it.
 */
void
nm_strbuf_seek_end(char **buf, gsize *len)
{
    gsize l;
    char *end;

    nm_assert(len);
    nm_assert(buf && *buf);

    if (*len <= 1) {
        if (*len == 1 && (*buf)[0])
            goto truncate;
        return;
    }

    end = memchr(*buf, 0, *len);
    if (end) {
        l = end - *buf;
        nm_assert(l < *len);

        *buf = end;
        *len -= l;
        return;
    }

truncate:
    /* hm, no NUL character within len bytes.
     * Just NUL terminate the array and consume them
     * all. */
    *buf += *len;
    (*buf)[-1] = '\0';
    *len       = 0;
    return;
}

/*****************************************************************************/

GBytes *
nm_g_bytes_get_empty(void)
{
    static GBytes *bytes = NULL;
    GBytes        *b;

again:
    b = g_atomic_pointer_get(&bytes);
    if (G_UNLIKELY(!b)) {
        b = g_bytes_new_static("", 0);
        if (!g_atomic_pointer_compare_and_exchange(&bytes, NULL, b)) {
            g_bytes_unref(b);
            goto again;
        }
    }
    return b;
}

GBytes *
nm_g_bytes_new_from_str(const char *str)
{
    gsize l;

    if (!str)
        return NULL;

    /* the returned array is guaranteed to have a trailing '\0'
     * character *after* the length. */

    l = strlen(str);
    return g_bytes_new_take(nm_memdup(str, l + 1u), l);
}

GBytes *
nm_g_bytes_new_from_variant_ay(GVariant *var)
{
    if (!var)
        return NULL;
    if (!g_variant_is_of_type(var, G_VARIANT_TYPE_BYTESTRING))
        g_return_val_if_reached(NULL);
    return g_variant_get_data_as_bytes(var);
}

/**
 * nm_g_bytes_equal_mem:
 * @bytes: (allow-none): a #GBytes array to compare. Note that
 *   %NULL is treated like an #GBytes array of length zero.
 * @mem_data: the data pointer with @mem_len bytes
 * @mem_len: the length of the data pointer
 *
 * Returns: %TRUE if @bytes contains the same data as @mem_data. As a
 *   special case, a %NULL @bytes is treated like an empty array.
 */
gboolean
nm_g_bytes_equal_mem(GBytes *bytes, gconstpointer mem_data, gsize mem_len)
{
    gconstpointer p;
    gsize         l;

    if (!bytes) {
        /* as a special case, let %NULL GBytes compare identical
         * to an empty array. */
        return (mem_len == 0);
    }

    p = g_bytes_get_data(bytes, &l);
    return l == mem_len
           && (mem_len == 0 /* allow @mem_data to be %NULL */
               || memcmp(p, mem_data, mem_len) == 0);
}

GVariant *
nm_g_bytes_to_variant_ay(const GBytes *bytes)
{
    const guint8 *p = NULL;
    gsize         l = 0;

    if (!bytes) {
        /* for convenience, accept NULL to return an empty variant */
    } else
        p = g_bytes_get_data((GBytes *) bytes, &l);

    return nm_g_variant_new_ay(p, l);
}

/*****************************************************************************/

#define _variant_singleton_get(create_variant)                                       \
    ({                                                                               \
        static GVariant *_singleton = NULL;                                          \
        GVariant        *_v;                                                         \
                                                                                     \
        while (TRUE) {                                                               \
            _v = g_atomic_pointer_get(&_singleton);                                  \
            if (G_UNLIKELY(!_v)) {                                                   \
                _v = (create_variant);                                               \
                nm_assert(_v);                                                       \
                nm_assert(g_variant_is_floating(_v));                                \
                g_variant_ref_sink(_v);                                              \
                if (!g_atomic_pointer_compare_and_exchange(&_singleton, NULL, _v)) { \
                    g_variant_unref(_v);                                             \
                    continue;                                                        \
                }                                                                    \
            }                                                                        \
            break;                                                                   \
        }                                                                            \
        _v;                                                                          \
    })

GVariant *
nm_g_variant_singleton_u_0(void)
{
    return _variant_singleton_get(g_variant_new_uint32(0));
}

GVariant *
nm_g_variant_singleton_i_0(void)
{
    return _variant_singleton_get(g_variant_new_int32(0));
}

GVariant *
nm_g_variant_singleton_b(gboolean value)
{
    return value ? _variant_singleton_get(g_variant_new_boolean(TRUE))
                 : _variant_singleton_get(g_variant_new_boolean(FALSE));
}

GVariant *
nm_g_variant_singleton_s_empty(void)
{
    return _variant_singleton_get(g_variant_new_string(""));
}

static GVariant *
_variant_singleton_get_array_init(GVariant **p_singleton, const char *variant_type)
{
    GVariant *v;

    v = g_variant_new_array(G_VARIANT_TYPE(variant_type), NULL, 0);
    g_variant_ref_sink(v);

    if (G_LIKELY(g_atomic_pointer_compare_and_exchange(p_singleton, NULL, v)))
        return v;

    g_variant_unref(v);

    return g_atomic_pointer_get(p_singleton);
}

#define _variant_singleton_get_array(variant_type)                                   \
    ({                                                                               \
        static GVariant *_singleton = NULL;                                          \
        GVariant        *_v;                                                         \
                                                                                     \
        _v = g_atomic_pointer_get(&_singleton);                                      \
        if (G_UNLIKELY(!_v)) {                                                       \
            _v = _variant_singleton_get_array_init(&_singleton, "" variant_type ""); \
            nm_assert(_v);                                                           \
        }                                                                            \
        nm_assert(g_variant_is_of_type(_v, G_VARIANT_TYPE("a" variant_type "")));    \
        _v;                                                                          \
    })

GVariant *
nm_g_variant_singleton_au(void)
{
    return _variant_singleton_get_array("u");
}

GVariant *
nm_g_variant_singleton_aay(void)
{
    return _variant_singleton_get_array("ay");
}

GVariant *
nm_g_variant_singleton_as(void)
{
    return _variant_singleton_get_array("s");
}

GVariant *
nm_g_variant_singleton_aLsvI(void)
{
    return _variant_singleton_get_array("{sv}");
}

GVariant *
nm_g_variant_singleton_aLsaLsvII(void)
{
    return _variant_singleton_get_array("{sa{sv}}");
}

GVariant *
nm_g_variant_singleton_aaLsvI(void)
{
    return _variant_singleton_get_array("a{sv}");
}

GVariant *
nm_g_variant_singleton_ao(void)
{
    return _variant_singleton_get_array("o");
}

GVariant *
nm_g_variant_maybe_singleton_i(gint32 value)
{
    /* Warning: this function always returns a non-floating reference
     * that must be consumed (and later unrefed) by the caller.
     *
     * The instance is either a singleton instance or a newly created
     * instance.
     *
     * The idea of this is that common values (zero) can use the immutable
     * singleton/flyweight instance and avoid allocating a new instance in
     * the (presumable) common case.
     */
    switch (value) {
    case 0:
        return g_variant_ref(nm_g_variant_singleton_i_0());
    default:
        return g_variant_take_ref(g_variant_new_int32(value));
    }
}

/*****************************************************************************/

GHashTable *
nm_strdict_clone(GHashTable *src)
{
    GHashTable    *dst;
    GHashTableIter iter;
    const char    *key;
    const char    *val;

    if (!src)
        return NULL;

    dst = g_hash_table_new_full(nm_str_hash, g_str_equal, g_free, g_free);
    g_hash_table_iter_init(&iter, src);
    while (g_hash_table_iter_next(&iter, (gpointer *) &key, (gpointer *) &val))
        g_hash_table_insert(dst, g_strdup(key), g_strdup(val));
    return dst;
}

/* Convert a hash table with "char *" keys and values to an "a{ss}" GVariant.
 * The keys will be sorted asciibetically.
 * Returns a floating reference.
 */
GVariant *
nm_strdict_to_variant_ass(GHashTable *strdict)
{
    gs_free NMUtilsNamedValue *values_free = NULL;
    NMUtilsNamedValue          values_prepared[20];
    const NMUtilsNamedValue   *values;
    GVariantBuilder            builder;
    guint                      i;
    guint                      n;

    values = nm_utils_named_values_from_strdict(strdict, &n, values_prepared, &values_free);

    g_variant_builder_init(&builder, G_VARIANT_TYPE("a{ss}"));
    for (i = 0; i < n; i++) {
        g_variant_builder_add(&builder, "{ss}", values[i].name, values[i].value_str);
    }
    return g_variant_builder_end(&builder);
}

/*****************************************************************************/

GVariant *
nm_strdict_to_variant_asv(GHashTable *strdict)
{
    gs_free NMUtilsNamedValue *values_free = NULL;
    NMUtilsNamedValue          values_prepared[20];
    const NMUtilsNamedValue   *values;
    GVariantBuilder            builder;
    guint                      i;
    guint                      n;

    values = nm_utils_named_values_from_strdict(strdict, &n, values_prepared, &values_free);

    g_variant_builder_init(&builder, G_VARIANT_TYPE("a{sv}"));
    for (i = 0; i < n; i++) {
        g_variant_builder_add(&builder,
                              "{sv}",
                              values[i].name,
                              g_variant_new_string(values[i].value_str));
    }
    return g_variant_builder_end(&builder);
}

/*****************************************************************************/

/**
 * nm_strquote:
 * @buf: the output buffer of where to write the quoted @str argument.
 * @buf_len: the size of @buf.
 * @str: (allow-none): the string to quote.
 *
 * Writes @str to @buf with quoting. The resulting buffer
 * is always NUL terminated, unless @buf_len is zero.
 * If @str is %NULL, it writes "(null)".
 *
 * If @str needs to be truncated, the closing quote is '^' instead
 * of '"'.
 *
 * This is similar to nm_strquote_a(), which however uses alloca()
 * to allocate a new buffer. Also, here @buf_len is the size of @buf,
 * while nm_strquote_a() has the number of characters to print. The latter
 * doesn't include the quoting.
 *
 * Returns: the input buffer with the quoted string.
 */
const char *
nm_strquote(char *buf, gsize buf_len, const char *str)
{
    const char *const buf0 = buf;

    if (!str) {
        nm_strbuf_append_str(&buf, &buf_len, "(null)");
        goto out;
    }

    if (G_UNLIKELY(buf_len <= 2)) {
        switch (buf_len) {
        case 2:
            *(buf++) = '^';
            /* fall-through */
        case 1:
            *(buf++) = '\0';
            break;
        }
        goto out;
    }

    *(buf++) = '"';
    buf_len--;

    nm_strbuf_append_str(&buf, &buf_len, str);

    /* if the string was too long we indicate truncation with a
     * '^' instead of a closing quote. */
    if (G_UNLIKELY(buf_len <= 1)) {
        switch (buf_len) {
        case 1:
            buf[-1] = '^';
            break;
        case 0:
            buf[-2] = '^';
            break;
        default:
            nm_assert_not_reached();
            break;
        }
    } else {
        nm_assert(buf_len >= 2);
        *(buf++) = '"';
        *(buf++) = '\0';
    }

out:
    return buf0;
}

/*****************************************************************************/

_nm_thread_local char _nm_utils_to_string_buffer[] = {0};

void
nm_utils_to_string_buffer_init(char **buf, gsize *len)
{
    if (!*buf) {
        *buf = _nm_utils_to_string_buffer;
        *len = NM_UTILS_TO_STRING_BUFFER_SIZE;

        /* We no longer want to support callers to omit the buffer
         * and fallback to the global buffer. Callers should be fixed
         * to always provide a valid buffer. */
        g_return_if_reached();
    }
}

gboolean
nm_utils_to_string_buffer_init_null(gconstpointer obj, char **buf, gsize *len)
{
    nm_utils_to_string_buffer_init(buf, len);
    if (!obj) {
        g_strlcpy(*buf, "(null)", *len);
        return FALSE;
    }
    return TRUE;
}

/*****************************************************************************/

const char *
nm_utils_flags2str(const NMUtilsFlags2StrDesc *descs,
                   gsize                       n_descs,
                   unsigned                    flags,
                   char                       *buf,
                   gsize                       len)
{
    gsize i;
    char *p;

#if NM_MORE_ASSERTS > 10
    nm_assert(descs);
    nm_assert(n_descs > 0);
    for (i = 0; i < n_descs; i++) {
        gsize j;

        nm_assert(descs[i].name && descs[i].name[0]);
        for (j = 0; j < i; j++)
            nm_assert(descs[j].flag != descs[i].flag);
    }
#endif

    nm_utils_to_string_buffer_init(&buf, &len);

    if (!len)
        return buf;

    buf[0] = '\0';
    p      = buf;
    if (!flags) {
        for (i = 0; i < n_descs; i++) {
            if (!descs[i].flag) {
                nm_strbuf_append_str(&p, &len, descs[i].name);
                break;
            }
        }
        return buf;
    }

    for (i = 0; flags && i < n_descs; i++) {
        if (descs[i].flag && NM_FLAGS_ALL(flags, descs[i].flag)) {
            flags &= ~descs[i].flag;

            if (buf[0] != '\0')
                nm_strbuf_append_c(&p, &len, ',');
            nm_strbuf_append_str(&p, &len, descs[i].name);
        }
    }
    if (flags) {
        if (buf[0] != '\0')
            nm_strbuf_append_c(&p, &len, ',');
        nm_strbuf_append(&p, &len, "0x%x", flags);
    }
    return buf;
};

/*****************************************************************************/

gboolean
nm_utils_parse_next_line(const char **inout_ptr,
                         gsize       *inout_len,
                         const char **out_line,
                         gsize       *out_line_len)
{
    gboolean    eol_is_carriage_return;
    const char *line_start;
    gsize       line_len;

    nm_assert(inout_ptr);
    nm_assert(inout_len);
    nm_assert(*inout_len == 0 || *inout_ptr);
    nm_assert(out_line);
    nm_assert(out_line_len);

    if (G_UNLIKELY(*inout_len == 0))
        return FALSE;

    line_start = *inout_ptr;

    eol_is_carriage_return = FALSE;
    for (line_len = 0;; line_len++) {
        if (line_len >= *inout_len) {
            /* if we consumed the entire line, we place the pointer at
             * one character after the end. */
            *inout_ptr = &line_start[line_len];
            *inout_len = 0;
            goto done;
        }
        switch (line_start[line_len]) {
        case '\r':
            eol_is_carriage_return = TRUE;
            /* fall-through*/
        case '\0':
        case '\n':
            *inout_ptr = &line_start[line_len + 1];
            *inout_len = *inout_len - line_len - 1u;
            if (eol_is_carriage_return && *inout_len > 0 && (*inout_ptr)[0] == '\n') {
                /* also consume "\r\n" as one. */
                (*inout_len)--;
                (*inout_ptr)++;
            }
            goto done;
        }
    }

done:
    *out_line     = line_start;
    *out_line_len = line_len;
    return TRUE;
}

/*****************************************************************************/

/**
 * nm_g_ascii_strtoll()
 * @nptr: the string to parse
 * @endptr: the pointer on the first invalid chars
 * @base: the base.
 *
 * This wraps g_ascii_strtoll() and should in almost all cases behave identical
 * to it.
 *
 * However, it seems there are situations where g_ascii_strtoll() might set
 * errno to some unexpected value EAGAIN. Possibly this is related to creating
 * the C locale during
 *
 *   #ifdef USE_XLOCALE
 *   return strtoll_l (nptr, endptr, base, get_C_locale ());
 *
 * This wrapper tries to workaround that condition.
 */
gint64
nm_g_ascii_strtoll(const char *nptr, char **endptr, guint base)
{
    int       try_count = 2;
    gint64    v;
    const int errsv_orig = errno;
    int       errsv;

    nm_assert(nptr);
    nm_assert(base == 0u || (base >= 2u && base <= 36u));

again:
    errno = 0;
    v     = g_ascii_strtoll(nptr, endptr, base);
    errsv = errno;

    if (errsv == 0) {
        if (errsv_orig != 0)
            errno = errsv_orig;
        return v;
    }

    if (errsv == ERANGE && NM_IN_SET(v, G_MININT64, G_MAXINT64))
        return v;

    if (errsv == EINVAL && v == 0 && nptr && nptr[0] == '\0')
        return v;

    if (try_count-- > 0)
        goto again;

#if NM_MORE_ASSERTS
    g_critical("g_ascii_strtoll() for \"%s\" failed with errno=%d (%s) and v=%" G_GINT64_FORMAT,
               nptr,
               errsv,
               nm_strerror_native(errsv),
               v);
#endif

    return v;
}

/* See nm_g_ascii_strtoll() */
guint64
nm_g_ascii_strtoull(const char *nptr, char **endptr, guint base)
{
    int       try_count = 2;
    guint64   v;
    const int errsv_orig = errno;
    int       errsv;

    nm_assert(nptr);
    nm_assert(base == 0u || (base >= 2u && base <= 36u));

again:
    errno = 0;
    v     = g_ascii_strtoull(nptr, endptr, base);
    errsv = errno;

    if (errsv == 0) {
        if (errsv_orig != 0)
            errno = errsv_orig;
        return v;
    }

    if (errsv == ERANGE && NM_IN_SET(v, G_MAXUINT64))
        return v;

    if (errsv == EINVAL && v == 0 && nptr && nptr[0] == '\0')
        return v;

    if (try_count-- > 0)
        goto again;

#if NM_MORE_ASSERTS
    g_critical("g_ascii_strtoull() for \"%s\" failed with errno=%d (%s) and v=%" G_GUINT64_FORMAT,
               nptr,
               errsv,
               nm_strerror_native(errsv),
               v);
#endif

    return v;
}

/* see nm_g_ascii_strtoll(). */
double
nm_g_ascii_strtod(const char *nptr, char **endptr)
{
    int    try_count = 2;
    double v;
    int    errsv;

    nm_assert(nptr);

again:
    v     = g_ascii_strtod(nptr, endptr);
    errsv = errno;

    if (errsv == 0)
        return v;

    if (errsv == ERANGE)
        return v;

    if (try_count-- > 0)
        goto again;

#if NM_MORE_ASSERTS
    g_critical("g_ascii_strtod() for \"%s\" failed with errno=%d (%s) and v=%f",
               nptr,
               errsv,
               nm_strerror_native(errsv),
               v);
#endif

    /* Not really much else to do. Return the parsed value and leave errno set
     * to the unexpected value. */
    return v;
}

/* _nm_utils_ascii_str_to_int64:
 *
 * A wrapper for g_ascii_strtoll, that checks whether the whole string
 * can be successfully converted to a number and is within a given
 * range. On any error, @fallback will be returned and %errno will be set
 * to a non-zero value. On success, %errno will be set to zero, check %errno
 * for errors. Any trailing or leading (ascii) white space is ignored and the
 * functions is locale independent.
 *
 * The function is guaranteed to return a value between @min and @max
 * (inclusive) or @fallback. Also, the parsing is rather strict, it does
 * not allow for any unrecognized characters, except leading and trailing
 * white space.
 **/
gint64
_nm_utils_ascii_str_to_int64(const char *str, guint base, gint64 min, gint64 max, gint64 fallback)
{
    gint64      v;
    const char *s = NULL;

    str = nm_str_skip_leading_spaces(str);
    if (!str || !str[0]) {
        errno = EINVAL;
        return fallback;
    }

    errno = 0;
    v     = nm_g_ascii_strtoll(str, (char **) &s, base);

    if (errno != 0)
        return fallback;

    if (s[0] != '\0') {
        s = nm_str_skip_leading_spaces(s);
        if (s[0] != '\0') {
            errno = EINVAL;
            return fallback;
        }
    }
    if (v > max || v < min) {
        errno = ERANGE;
        return fallback;
    }

    return v;
}

guint64
_nm_utils_ascii_str_to_uint64(const char *str,
                              guint       base,
                              guint64     min,
                              guint64     max,
                              guint64     fallback)
{
    guint64     v;
    const char *s = NULL;

    if (str) {
        while (g_ascii_isspace(str[0]))
            str++;
    }
    if (!str || !str[0]) {
        errno = EINVAL;
        return fallback;
    }

    errno = 0;
    v     = nm_g_ascii_strtoull(str, (char **) &s, base);

    if (errno != 0)
        return fallback;
    if (s[0] != '\0') {
        while (g_ascii_isspace(s[0]))
            s++;
        if (s[0] != '\0') {
            errno = EINVAL;
            return fallback;
        }
    }
    if (v > max || v < min) {
        errno = ERANGE;
        return fallback;
    }

    if (v != 0 && str[0] == '-') {
        /* As documented, g_ascii_strtoull() accepts negative values, and returns their
         * absolute value. We don't. */
        errno = ERANGE;
        return fallback;
    }

    return v;
}

/*****************************************************************************/

gint64
_nm_utils_ascii_str_to_int64_bin(const char *str,
                                 gssize      len,
                                 guint       base,
                                 gint64      min,
                                 gint64      max,
                                 gint64      fallback)
{
    gs_free char *str_clone = NULL;

    /* This is like _nm_utils_ascii_str_to_int64(), but the user may provide
     * an optional string length, in which case str is not assumed to be NUL
     * terminated. In that case, any NUL characters inside the first len characters
     * lead to a failure, except one last NUL character is allowed. */

    if (len >= 0) {
        gsize l = len;

        nm_assert(l == 0 || str);

        if (l > 0 && str[l - 1u] == '\0') {
            /* we accept one '\0' at the end of the string. */
            l--;
        }

        if (l > 0 && memchr(str, '\0', l)) {
            /* but we don't accept other NUL characters in the middle. */
            errno = EINVAL;
            return fallback;
        }

        str = nm_strndup_a(300, str, len, &str_clone);
    }

    return _nm_utils_ascii_str_to_int64(str, base, min, max, fallback);
}

/*****************************************************************************/

int
nm_strcmp_with_data(gconstpointer a, gconstpointer b, gpointer user_data)
{
    const char *s1 = a;
    const char *s2 = b;

    return strcmp(s1, s2);
}

/* like nm_strcmp_p(), suitable for g_ptr_array_sort_with_data().
 * g_ptr_array_sort() just casts nm_strcmp_p() to a function of different
 * signature. I guess, in glib there are knowledgeable people that ensure
 * that this additional argument doesn't cause problems due to different ABI
 * for every architecture that glib supports.
 * For NetworkManager, we'd rather avoid such stunts.
 **/
int
nm_strcmp_p_with_data(gconstpointer a, gconstpointer b, gpointer user_data)
{
    const char *s1 = *((const char **) a);
    const char *s2 = *((const char **) b);

    return strcmp(s1, s2);
}

int
nm_strcmp0_p_with_data(gconstpointer a, gconstpointer b, gpointer user_data)
{
    const char *s1 = *((const char **) a);
    const char *s2 = *((const char **) b);

    return nm_strcmp0(s1, s2);
}

int
nm_strcmp_ascii_case_with_data(gconstpointer a, gconstpointer b, gpointer user_data)
{
    const char *s1 = a;
    const char *s2 = b;

    return g_ascii_strcasecmp(s1, s2);
}

int
nm_cmp_uint32_p_with_data(gconstpointer p_a, gconstpointer p_b, gpointer user_data)
{
    const guint32 a = *((const guint32 *) p_a);
    const guint32 b = *((const guint32 *) p_b);

    if (a < b)
        return -1;
    if (a > b)
        return 1;
    return 0;
}

int
nm_cmp_int2ptr_p_with_data(gconstpointer p_a, gconstpointer p_b, gpointer user_data)
{
    /* p_a and p_b are two pointers to a pointer, where the pointer is
     * interpreted as a integer using GPOINTER_TO_INT().
     *
     * That is the case of a hash-table that uses GINT_TO_POINTER() to
     * convert integers as pointers, and the resulting keys-as-array
     * array. */
    const int a = GPOINTER_TO_INT(*((gconstpointer *) p_a));
    const int b = GPOINTER_TO_INT(*((gconstpointer *) p_b));

    if (a < b)
        return -1;
    if (a > b)
        return 1;
    return 0;
}

/*****************************************************************************/

const char *
nm_utils_dbus_path_get_last_component(const char *dbus_path)
{
    if (dbus_path) {
        dbus_path = strrchr(dbus_path, '/');
        if (dbus_path)
            return dbus_path + 1;
    }
    return NULL;
}

static gint64
_dbus_path_component_as_num(const char *p)
{
    gint64 n;

    /* no odd stuff. No leading zeros, only a non-negative, decimal integer.
     *
     * Otherwise, there would be multiple ways to encode the same number "10"
     * and "010". That is just confusing. A number has no leading zeros,
     * if it has, it's not a number (as far as we are concerned here). */
    if (p[0] == '0') {
        if (p[1] != '\0')
            return -1;
        else
            return 0;
    }
    if (!(p[0] >= '1' && p[0] <= '9'))
        return -1;
    if (!NM_STRCHAR_ALL(&p[1], ch, (ch >= '0' && ch <= '9')))
        return -1;
    n = _nm_utils_ascii_str_to_int64(p, 10, 0, G_MAXINT64, -1);
    nm_assert(n == -1 || nm_streq0(p, nm_sprintf_bufa(100, "%" G_GINT64_FORMAT, n)));
    return n;
}

int
nm_utils_dbus_path_cmp(const char *dbus_path_a, const char *dbus_path_b)
{
    const char *l_a, *l_b;
    gsize       plen;
    gint64      n_a, n_b;

    /* compare function for two D-Bus paths. It behaves like
     * strcmp(), except, if both paths have the same prefix,
     * and both end in a (positive) number, then the paths
     * will be sorted by number. */

    NM_CMP_SELF(dbus_path_a, dbus_path_b);

    /* if one or both paths have no slash (and no last component)
     * compare the full paths directly. */
    if (!(l_a = nm_utils_dbus_path_get_last_component(dbus_path_a))
        || !(l_b = nm_utils_dbus_path_get_last_component(dbus_path_b)))
        goto comp_full;

    /* check if both paths have the same prefix (up to the last-component). */
    plen = l_a - dbus_path_a;
    if (plen != (l_b - dbus_path_b))
        goto comp_full;
    NM_CMP_RETURN(strncmp(dbus_path_a, dbus_path_b, plen));

    n_a = _dbus_path_component_as_num(l_a);
    n_b = _dbus_path_component_as_num(l_b);
    if (n_a == -1 && n_b == -1)
        goto comp_l;

    /* both components must be convertible to a number. If they are not,
     * (and only one of them is), then we must always strictly sort numeric parts
     * after non-numeric components. If we wouldn't, we wouldn't have
     * a total order.
     *
     * An example of a not total ordering would be:
     *   "8"   < "010"  (numeric)
     *   "0x"  < "8"    (lexical)
     *   "0x"  > "010"  (lexical)
     * We avoid this, by forcing that a non-numeric entry "0x" always sorts
     * before numeric entries.
     *
     * Additionally, _dbus_path_component_as_num() would also reject "010" as
     * not a valid number.
     */
    if (n_a == -1)
        return -1;
    if (n_b == -1)
        return 1;

    NM_CMP_DIRECT(n_a, n_b);
    nm_assert(nm_streq(dbus_path_a, dbus_path_b));
    return 0;

comp_full:
    NM_CMP_DIRECT_STRCMP0(dbus_path_a, dbus_path_b);
    return 0;
comp_l:
    NM_CMP_DIRECT_STRCMP0(l_a, l_b);
    nm_assert(nm_streq(dbus_path_a, dbus_path_b));
    return 0;
}

/*****************************************************************************/

typedef struct {
    union {
        guint8  table[256];
        guint64 _dummy_for_alignment;
    };
} CharLookupTable;

static void
_char_lookup_table_set_one(CharLookupTable *lookup, char ch)
{
    lookup->table[(guint8) ch] = 1;
}

static void
_char_lookup_table_set_all(CharLookupTable *lookup, const char *candidates)
{
    while (candidates[0] != '\0')
        _char_lookup_table_set_one(lookup, (candidates++)[0]);
}

static void
_char_lookup_table_init(CharLookupTable *lookup, const char *candidates)
{
    *lookup = (CharLookupTable){
        .table = {0},
    };
    if (candidates)
        _char_lookup_table_set_all(lookup, candidates);
}

static gboolean
_char_lookup_has(const CharLookupTable *lookup, char ch)
{
    /* with some optimization levels, the compiler thinks this code
     * might access uninitialized @lookup. It is not -- when you look at the
     * callers of this function. */
    NM_PRAGMA_WARNING_DISABLE("-Wmaybe-uninitialized")
    nm_assert(lookup->table[(guint8) '\0'] == 0);
    return lookup->table[(guint8) ch] != 0;
    NM_PRAGMA_WARNING_REENABLE
}

static gboolean
_char_lookup_has_all(const CharLookupTable *lookup, const char *candidates)
{
    if (candidates) {
        while (candidates[0] != '\0') {
            if (!_char_lookup_has(lookup, (candidates++)[0]))
                return FALSE;
        }
    }
    return TRUE;
}

/**
 * nm_strsplit_set_full:
 * @str: the string to split.
 * @delimiters: the set of delimiters.
 * @flags: additional flags for controlling the operation.
 *
 * This is a replacement for g_strsplit_set() which avoids copying
 * each word once (the entire strv array), but instead copies it once
 * and all words point into that internal copy.
 *
 * Note that for @str %NULL and "", this always returns %NULL too. That differs
 * from g_strsplit_set(), which would return an empty strv array for "".
 * This never returns an empty array.
 *
 * Returns: %NULL if @str is %NULL or "".
 *   If @str only contains delimiters and %NM_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY
 *   is not set, it also returns %NULL.
 *   Otherwise, a %NULL terminated strv array containing the split words.
 *   (delimiter characters are removed).
 *   The strings to which the result strv array points to are allocated
 *   after the returned result itself. Don't free the strings themself,
 *   but free everything with g_free().
 *   It is however safe and allowed to modify the individual strings in-place,
 *   like "g_strstrip((char *) iter[0])".
 */
const char **
nm_strsplit_set_full(const char *str, const char *delimiters, NMUtilsStrsplitSetFlags flags)
{
    const char    **ptr;
    gsize           num_tokens;
    gsize           i_token;
    gsize           str_len_p1;
    const char     *c_str;
    char           *s;
    CharLookupTable ch_lookup;
    const gboolean  f_escaped = NM_FLAGS_HAS(flags, NM_STRSPLIT_SET_FLAGS_ESCAPED);
    const gboolean  f_allow_escaping =
        f_escaped || NM_FLAGS_HAS(flags, NM_STRSPLIT_SET_FLAGS_ALLOW_ESCAPING);
    const gboolean f_preserve_empty = NM_FLAGS_HAS(flags, NM_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY);
    const gboolean f_strstrip       = NM_FLAGS_HAS(flags, NM_STRSPLIT_SET_FLAGS_STRSTRIP);

    if (!str)
        return NULL;

    if (!delimiters) {
        nm_assert_not_reached();
        delimiters = " \t\n";
    }
    _char_lookup_table_init(&ch_lookup, delimiters);

    nm_assert(!f_allow_escaping || !_char_lookup_has(&ch_lookup, '\\'));

    if (!f_preserve_empty) {
        while (_char_lookup_has(&ch_lookup, str[0]))
            str++;
    }

    if (!str[0]) {
        /* We return %NULL here, also with NM_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY.
         * That makes nm_strsplit_set_full() with NM_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY
         * different from g_strsplit_set(), which would in this case return an empty array.
         * If you need to handle %NULL, and "" specially, then check the input string first. */
        return NULL;
    }

#define _char_is_escaped(str_start, str_cur)              \
    ({                                                    \
        const char *const _str_start = (str_start);       \
        const char *const _str_cur   = (str_cur);         \
        const char       *_str_i     = (_str_cur);        \
                                                          \
        while (_str_i > _str_start && _str_i[-1] == '\\') \
            _str_i--;                                     \
        (((_str_cur - _str_i) % 2) != 0);                 \
    })

    num_tokens = 1;
    c_str      = str;
    while (TRUE) {
        while (G_LIKELY(!_char_lookup_has(&ch_lookup, c_str[0]))) {
            if (c_str[0] == '\0')
                goto done1;
            c_str++;
        }

        /* we assume escapings are not frequent. After we found
         * this delimiter, check whether it was escaped by counting
         * the backslashed before. */
        if (f_allow_escaping && _char_is_escaped(str, c_str)) {
            /* the delimiter is escaped. This was not an accepted delimiter. */
            c_str++;
            continue;
        }

        c_str++;

        /* if we drop empty tokens, then we now skip over all consecutive delimiters. */
        if (!f_preserve_empty) {
            while (_char_lookup_has(&ch_lookup, c_str[0]))
                c_str++;
            if (c_str[0] == '\0')
                break;
        }

        num_tokens++;
    }

done1:

    nm_assert(c_str[0] == '\0');

    str_len_p1 = (c_str - str) + 1;

    nm_assert(str[str_len_p1 - 1] == '\0');

    ptr = g_malloc((sizeof(const char *) * (num_tokens + 1)) + str_len_p1);
    s   = (char *) &ptr[num_tokens + 1];
    memcpy(s, str, str_len_p1);

    i_token = 0;

    while (TRUE) {
        nm_assert(i_token < num_tokens);
        ptr[i_token++] = s;

        if (s[0] == '\0') {
            nm_assert(f_preserve_empty);
            goto done2;
        }
        nm_assert(f_preserve_empty || !_char_lookup_has(&ch_lookup, s[0]));

        while (!_char_lookup_has(&ch_lookup, s[0])) {
            if (G_UNLIKELY(s[0] == '\\' && f_allow_escaping)) {
                s++;
                if (s[0] == '\0')
                    goto done2;
                s++;
            } else if (s[0] == '\0')
                goto done2;
            else
                s++;
        }

        nm_assert(_char_lookup_has(&ch_lookup, s[0]));
        s[0] = '\0';
        s++;

        if (!f_preserve_empty) {
            while (_char_lookup_has(&ch_lookup, s[0]))
                s++;
            if (s[0] == '\0')
                goto done2;
        }
    }

done2:
    nm_assert(i_token == num_tokens);
    ptr[i_token] = NULL;

    if (f_strstrip) {
        gsize i;

        i_token = 0;
        for (i = 0; ptr[i]; i++) {
            s = (char *) nm_str_skip_leading_spaces(ptr[i]);
            if (s[0] != '\0') {
                char *s_last;

                s_last = &s[strlen(s) - 1];
                while (s_last > s && g_ascii_isspace(s_last[0])
                       && (!f_allow_escaping || !_char_is_escaped(s, s_last)))
                    (s_last--)[0] = '\0';
            }

            if (!f_preserve_empty && s[0] == '\0')
                continue;

            ptr[i_token++] = s;
        }

        if (i_token == 0) {
            g_free(ptr);
            return NULL;
        }
        ptr[i_token] = NULL;
    }

    if (f_escaped) {
        gsize i, j;

        /* We no longer need ch_lookup for its original purpose. Modify it, so it
         * can detect the delimiters, '\\', and (optionally) whitespaces. */
        _char_lookup_table_set_one(&ch_lookup, '\\');
        if (f_strstrip)
            _char_lookup_table_set_all(&ch_lookup, NM_ASCII_SPACES);

        for (i_token = 0; ptr[i_token]; i_token++) {
            s = (char *) ptr[i_token];
            j = 0;
            for (i = 0; s[i] != '\0';) {
                if (s[i] == '\\' && _char_lookup_has(&ch_lookup, s[i + 1]))
                    i++;
                s[j++] = s[i++];
            }
            s[j] = '\0';
        }
    }

    nm_assert(ptr && ptr[0]);
    return ptr;
}

/*****************************************************************************/

const char *
nm_utils_escaped_tokens_escape_full(const char                     *str,
                                    const char                     *delimiters,
                                    const char                     *delimiters_as_needed,
                                    NMUtilsEscapedTokensEscapeFlags flags,
                                    char                          **out_to_free)
{
    CharLookupTable ch_lookup;
    CharLookupTable ch_lookup_as_needed;
    gboolean        has_ch_lookup_as_needed = FALSE;
    char           *ret;
    gsize           str_len;
    gsize           alloc_len;
    gsize           n_escapes;
    gsize           i, j;
    gboolean        escape_leading_space;
    gboolean        escape_trailing_space;
    gboolean        escape_backslash_as_needed;

    nm_assert(
        !delimiters_as_needed
        || (delimiters_as_needed[0]
            && NM_FLAGS_HAS(flags,
                            NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_BACKSLASH_AS_NEEDED)));

    if (!str || str[0] == '\0') {
        *out_to_free = NULL;
        return str;
    }

    str_len = strlen(str);

    _char_lookup_table_init(&ch_lookup, delimiters);
    if (!delimiters || NM_FLAGS_HAS(flags, NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_SPACES)) {
        flags &= ~(NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_LEADING_SPACE
                   | NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_TRAILING_SPACE);
        _char_lookup_table_set_all(&ch_lookup, NM_ASCII_SPACES);
    }

    if (NM_FLAGS_HAS(flags, NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_BACKSLASH_ALWAYS)) {
        _char_lookup_table_set_one(&ch_lookup, '\\');
        escape_backslash_as_needed = FALSE;
    } else if (_char_lookup_has(&ch_lookup, '\\'))
        escape_backslash_as_needed = FALSE;
    else {
        escape_backslash_as_needed =
            NM_FLAGS_HAS(flags, NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_BACKSLASH_AS_NEEDED);
        if (escape_backslash_as_needed) {
            if (NM_FLAGS_ANY(flags,
                             NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_LEADING_SPACE
                                 | NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_TRAILING_SPACE)
                && !_char_lookup_has_all(&ch_lookup, NM_ASCII_SPACES)) {
                /* ESCAPE_LEADING_SPACE and ESCAPE_TRAILING_SPACE implies that we escape backslash
                 * before whitespaces. */
                if (!has_ch_lookup_as_needed) {
                    has_ch_lookup_as_needed = TRUE;
                    _char_lookup_table_init(&ch_lookup_as_needed, NULL);
                }
                _char_lookup_table_set_all(&ch_lookup_as_needed, NM_ASCII_SPACES);
            }
            if (delimiters_as_needed && !_char_lookup_has_all(&ch_lookup, delimiters_as_needed)) {
                if (!has_ch_lookup_as_needed) {
                    has_ch_lookup_as_needed = TRUE;
                    _char_lookup_table_init(&ch_lookup_as_needed, NULL);
                }
                _char_lookup_table_set_all(&ch_lookup_as_needed, delimiters_as_needed);
            }
        }
    }

    escape_leading_space =
        NM_FLAGS_HAS(flags, NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_LEADING_SPACE)
        && g_ascii_isspace(str[0]) && !_char_lookup_has(&ch_lookup, str[0]);
    if (str_len == 1)
        escape_trailing_space = FALSE;
    else {
        escape_trailing_space =
            NM_FLAGS_HAS(flags, NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_TRAILING_SPACE)
            && g_ascii_isspace(str[str_len - 1]) && !_char_lookup_has(&ch_lookup, str[str_len - 1]);
    }

    n_escapes = 0;
    for (i = 0; str[i] != '\0'; i++) {
        if (_char_lookup_has(&ch_lookup, str[i]))
            n_escapes++;
        else if (str[i] == '\\' && escape_backslash_as_needed
                 && (_char_lookup_has(&ch_lookup, str[i + 1]) || NM_IN_SET(str[i + 1], '\0', '\\')
                     || (has_ch_lookup_as_needed
                         && _char_lookup_has(&ch_lookup_as_needed, str[i + 1]))))
            n_escapes++;
    }
    if (escape_leading_space)
        n_escapes++;
    if (escape_trailing_space)
        n_escapes++;

    if (n_escapes == 0u) {
        *out_to_free = NULL;
        return str;
    }

    alloc_len = str_len + n_escapes + 1u;
    ret       = g_new(char, alloc_len);

    j = 0;
    i = 0;

    if (escape_leading_space) {
        ret[j++] = '\\';
        ret[j++] = str[i++];
    }
    for (; str[i] != '\0'; i++) {
        if (_char_lookup_has(&ch_lookup, str[i]))
            ret[j++] = '\\';
        else if (str[i] == '\\' && escape_backslash_as_needed
                 && (_char_lookup_has(&ch_lookup, str[i + 1]) || NM_IN_SET(str[i + 1], '\0', '\\')
                     || (has_ch_lookup_as_needed
                         && _char_lookup_has(&ch_lookup_as_needed, str[i + 1]))))
            ret[j++] = '\\';
        ret[j++] = str[i];
    }
    if (escape_trailing_space) {
        nm_assert(!_char_lookup_has(&ch_lookup, ret[j - 1]) && g_ascii_isspace(ret[j - 1]));
        ret[j]     = ret[j - 1];
        ret[j - 1] = '\\';
        j++;
    }

    nm_assert(j == alloc_len - 1);
    ret[j] = '\0';
    nm_assert(strlen(ret) == j);

    *out_to_free = ret;
    return ret;
}

/**
 * nm_utils_escaped_tokens_options_split:
 * @str: the src string. This string will be modified in-place.
 *   The output values will point into @str.
 * @out_key: (allow-none): the returned output key. This will always be set to @str
 *   itself. @str will be modified to contain only the unescaped, truncated
 *   key name.
 * @out_val: returns the parsed (and unescaped) value or %NULL, if @str contains
 *   no '=' delimiter.
 *
 * Honors backslash escaping to parse @str as "key=value" pairs. Optionally, if no '='
 * is present, @out_val will be returned as %NULL. Backslash can be used to escape
 * '=', ',', '\\', and ascii whitespace. Other backslash sequences are taken verbatim.
 *
 * For keys, '=' obviously must be escaped. For values, that is optional because an
 * unescaped '=' is just taken verbatim. For example, in a key, the sequence "\\="
 * must be escaped as "\\\\\\=". For the value, that works too, but "\\\\=" is also
 * accepted.
 *
 * Unescaped Space around the key and value are also removed. Space in general must
 * not be escaped, unless they are at the beginning or the end of key/value.
 */
void
nm_utils_escaped_tokens_options_split(char *str, const char **out_key, const char **out_val)
{
    const char *val = NULL;
    gsize       i;
    gsize       j;
    gsize       last_space_idx;
    gboolean    last_space_has;

    nm_assert(str);

    i = 0;
    while (g_ascii_isspace(str[i]))
        i++;

    j              = 0;
    last_space_idx = 0;
    last_space_has = FALSE;
    while (str[i] != '\0') {
        if (g_ascii_isspace(str[i])) {
            if (!last_space_has) {
                last_space_has = TRUE;
                last_space_idx = j;
            }
        } else {
            if (str[i] == '\\') {
                if (NM_IN_SET(str[i + 1u], '\\', ',', '=') || g_ascii_isspace(str[i + 1u]))
                    i++;
            } else if (str[i] == '=') {
                /* Encounter an unescaped '=' character. When we still parse the key, this
                 * is the separator we were waiting for. If we are parsing the value,
                 * we take the character verbatim. */
                if (!val) {
                    if (last_space_has) {
                        str[last_space_idx] = '\0';
                        j                   = last_space_idx + 1;
                        last_space_has      = FALSE;
                    } else
                        str[j++] = '\0';
                    val = &str[j];
                    i++;
                    while (g_ascii_isspace(str[i]))
                        i++;
                    continue;
                }
            }
            last_space_has = FALSE;
        }
        str[j++] = str[i++];
    }

    if (last_space_has)
        str[last_space_idx] = '\0';
    else
        str[j] = '\0';

    *out_key = str;
    *out_val = val;
}

/*****************************************************************************/

/**
 * nm_utils_strsplit_quoted:
 * @str: the string to split (e.g. from /proc/cmdline).
 *
 * This basically does that systemd's extract_first_word() does
 * with the flags "EXTRACT_UNQUOTE | EXTRACT_RELAX". This is what
 * systemd uses to parse /proc/cmdline, and we do too.
 *
 * Splits the string. We have nm_strsplit_set() which
 * supports a variety of flags. However, extending that already
 * complex code to also support quotation and escaping is hard.
 * Instead, add a naive implementation.
 *
 * Returns: (transfer full): the split string.
 */
char **
nm_utils_strsplit_quoted(const char *str)
{
    char          **arr       = NULL;
    gsize           arr_len   = 0;
    gsize           arr_alloc = 0;
    gs_free char   *str_out   = NULL;
    CharLookupTable ch_lookup;

    nm_assert(str);

    _char_lookup_table_init(&ch_lookup, NM_ASCII_WHITESPACES);

    for (;;) {
        char  quote;
        gsize j;

        while (_char_lookup_has(&ch_lookup, str[0]))
            str++;

        if (str[0] == '\0')
            break;

        if (!str_out)
            str_out = g_new(char, strlen(str) + 1);

        quote = '\0';
        j     = 0;
        for (;;) {
            if (str[0] == '\\') {
                str++;
                if (str[0] == '\0')
                    break;
                str_out[j++] = str[0];
                str++;
                continue;
            }
            if (quote) {
                if (str[0] == '\0')
                    break;
                if (str[0] == quote) {
                    quote = '\0';
                    str++;
                    continue;
                }
                str_out[j++] = str[0];
                str++;
                continue;
            }
            if (str[0] == '\0')
                break;
            if (NM_IN_SET(str[0], '\'', '"')) {
                quote = str[0];
                str++;
                continue;
            }
            if (_char_lookup_has(&ch_lookup, str[0])) {
                str++;
                break;
            }
            str_out[j++] = str[0];
            str++;
        }

        if (arr_len >= arr_alloc) {
            if (arr_alloc == 0)
                arr_alloc = 4;
            else
                arr_alloc *= 2;
            arr = g_realloc(arr, sizeof(char *) * arr_alloc);
        }

        arr[arr_len++] = g_strndup(str_out, j);
    }

    if (!arr)
        return g_new0(char *, 1);

    /* We want to return an optimally sized strv array, with no excess
     * memory allocated. Hence, clone once more. */

    if (arr_len + 1u != arr_alloc) {
        gs_free char **arr_old = arr;

        arr = g_new(char *, arr_len + 1u);
        memcpy(arr, arr_old, sizeof(char *) * arr_len);
    }

    arr[arr_len] = NULL;
    return arr;
}

/*****************************************************************************/

/**
 * _nm_strv_find_first:
 * @list: the strv list to search
 * @len: the length of the list, or a negative value if @list is %NULL terminated.
 * @needle: the value to search for. The search is done using strcmp().
 *
 * Searches @list for @needle and returns the index of the first match (based
 * on strcmp()).
 *
 * For convenience, @list has type 'char**' instead of 'const char **'.
 *
 * Returns: index of first occurrence or -1 if @needle is not found in @list.
 */
gssize
_nm_strv_find_first(const char *const *list, gssize len, const char *needle)
{
    gssize i;

    if (len > 0) {
        g_return_val_if_fail(list, -1);

        if (!needle) {
            /* if we search a list with known length, %NULL is a valid @needle. */
            for (i = 0; i < len; i++) {
                if (!list[i])
                    return i;
            }
        } else {
            for (i = 0; i < len; i++) {
                if (list[i] && !strcmp(needle, list[i]))
                    return i;
            }
        }
    } else if (len < 0) {
        g_return_val_if_fail(needle, -1);

        if (list) {
            for (i = 0; list[i]; i++) {
                if (strcmp(needle, list[i]) == 0)
                    return i;
            }
        }
    }
    return -1;
}

gboolean
nm_strv_has_duplicate(const char *const *strv, gssize len, gboolean is_sorted)
{
    gsize l;
    gsize i;
    gsize j;

    l = len < 0 ? NM_PTRARRAY_LEN(strv) : (gsize) len;

    if (is_sorted) {
#if NM_MORE_ASSERTS > 10
        for (i = 1; i < l; i++)
            nm_assert(nm_strcmp0(strv[i - 1], strv[i]) <= 0);
#endif
        for (i = 1; i < l; i++) {
            if (nm_streq0(strv[i - 1], strv[i]))
                return TRUE;
        }
    } else {
        for (i = 1; i < l; i++) {
            for (j = 0; j < i; j++) {
                if (nm_streq0(strv[j], strv[i]))
                    return TRUE;
            }
        }
    }

    return FALSE;
}

gboolean
nm_strv_is_same_unordered(const char *const *strv1,
                          gssize             len1,
                          const char *const *strv2,
                          gssize             len2)
{
    gs_free const char **ss1_free = NULL;
    gs_free const char **ss2_free = NULL;
    gsize                l2;
    gsize                l;
    gsize                i;

    if (len1 < 0)
        l = NM_PTRARRAY_LEN(strv1);
    else
        l = (gsize) len1;

    if (len2 < 0)
        l2 = NM_PTRARRAY_LEN(strv2);
    else
        l2 = (gsize) len2;

    if (l != l2)
        return FALSE;

    if (l == 0) {
        /* An empty array. We treat (NULL, -1), (NULL, 0) and ([...], 0)
         * all the same. */
        return TRUE;
    }

    if (l > 1) {
        strv1 = nm_memdup_maybe_a(300, strv1, sizeof(char *) * l, &ss1_free);
        strv2 = nm_memdup_maybe_a(300, strv2, sizeof(char *) * l2, &ss2_free);
        _nm_strv_sort((const char **) strv1, l);
        _nm_strv_sort((const char **) strv2, l);
    }

    for (i = 0; i < l; i++) {
        if (!nm_streq0(strv1[i], strv2[i]))
            return FALSE;
    }

    return TRUE;
}

const char **
nm_strv_cleanup_const(const char **strv, gboolean skip_empty, gboolean skip_repeated)
{
    gsize i;
    gsize j;

    if (!strv || !*strv)
        return strv;

    if (!skip_empty && !skip_repeated)
        return strv;

    j = 0;
    for (i = 0; strv[i]; i++) {
        if ((skip_empty && !*strv[i])
            || (skip_repeated && nm_strv_find_first(strv, j, strv[i]) >= 0))
            continue;
        strv[j++] = strv[i];
    }
    strv[j] = NULL;
    return strv;
}

char **
nm_strv_cleanup(char **strv, gboolean strip_whitespace, gboolean skip_empty, gboolean skip_repeated)
{
    gsize i;
    gsize j;

    if (!strv || !*strv)
        return strv;

    if (strip_whitespace) {
        /* we only modify the strings pointed to by @strv if @strip_whitespace is
         * requested. Otherwise, the strings themselves are untouched. */
        for (i = 0; strv[i]; i++)
            g_strstrip(strv[i]);
    }
    if (!skip_empty && !skip_repeated)
        return strv;
    j = 0;
    for (i = 0; strv[i]; i++) {
        if ((skip_empty && !*strv[i])
            || (skip_repeated && nm_strv_find_first(strv, j, strv[i]) >= 0))
            g_free(strv[i]);
        else
            strv[j++] = strv[i];
    }
    strv[j] = NULL;
    return strv;
}

/*****************************************************************************/

GPtrArray *
nm_g_ptr_array_new_clone(GPtrArray     *array,
                         GCopyFunc      func,
                         gpointer       user_data,
                         GDestroyNotify element_free_func)
{
    GPtrArray *new_array;
    guint      i;

    g_return_val_if_fail(array, NULL);
    nm_assert((!!func) == (!!element_free_func));

    new_array = g_ptr_array_new_full(array->len, element_free_func);
    for (i = 0; i < array->len; i++) {
        g_ptr_array_add(new_array, func ? func(array->pdata[i], user_data) : array->pdata[i]);
    }
    return new_array;
}

/*****************************************************************************/

int
_nm_utils_ascii_str_to_bool(const char *str, int default_value)
{
    gs_free char *str_free = NULL;

    if (!str)
        return default_value;

    str = nm_strstrip_avoid_copy_a(300, str, &str_free);
    if (str[0] == '\0')
        return default_value;

    if (!g_ascii_strcasecmp(str, "true") || !g_ascii_strcasecmp(str, "yes")
        || !g_ascii_strcasecmp(str, "on") || !g_ascii_strcasecmp(str, "1"))
        return TRUE;

    if (!g_ascii_strcasecmp(str, "false") || !g_ascii_strcasecmp(str, "no")
        || !g_ascii_strcasecmp(str, "off") || !g_ascii_strcasecmp(str, "0"))
        return FALSE;

    return default_value;
}

/*****************************************************************************/

NM_CACHED_QUARK_FCN("nm-manager-error-quark", nm_manager_error_quark);

NM_CACHED_QUARK_FCN("nm-utils-error-quark", nm_utils_error_quark);

void
nm_utils_error_set_cancelled(GError **error, gboolean is_disposing, const char *instance_name)
{
    if (is_disposing) {
        g_set_error(error,
                    NM_UTILS_ERROR,
                    NM_UTILS_ERROR_CANCELLED_DISPOSING,
                    "Disposing %s instance",
                    instance_name && *instance_name ? instance_name : "source");
    } else {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_CANCELLED, "Request cancelled");
    }
}

gboolean
nm_utils_error_is_cancelled_or_disposing(GError *error)
{
    if (error) {
        if (error->domain == G_IO_ERROR)
            return NM_IN_SET(error->code, G_IO_ERROR_CANCELLED);
        if (error->domain == NM_UTILS_ERROR)
            return NM_IN_SET(error->code, NM_UTILS_ERROR_CANCELLED_DISPOSING);
    }
    return FALSE;
}

gboolean
nm_utils_error_is_notfound(GError *error)
{
    if (error) {
        if (error->domain == G_IO_ERROR)
            return NM_IN_SET(error->code, G_IO_ERROR_NOT_FOUND);
        if (error->domain == G_FILE_ERROR)
            return NM_IN_SET(error->code, G_FILE_ERROR_NOENT);
    }
    return FALSE;
}

/*****************************************************************************/

/**
 * nm_g_object_set_property:
 * @object: the target object
 * @property_name: the property name
 * @value: the #GValue to set
 * @error: (allow-none): optional error argument
 *
 * A reimplementation of g_object_set_property(), but instead
 * returning an error instead of logging a warning. All g_object_set*()
 * versions in glib require you to not pass invalid types or they will
 * log a g_warning() -- without reporting an error. We don't want that,
 * so we need to hack error checking around it.
 *
 * Returns: whether the value was successfully set.
 */
gboolean
nm_g_object_set_property(GObject      *object,
                         const char   *property_name,
                         const GValue *value,
                         GError      **error)
{
    GParamSpec                 *pspec;
    nm_auto_unset_gvalue GValue tmp_value = G_VALUE_INIT;
    GObjectClass               *klass;

    g_return_val_if_fail(G_IS_OBJECT(object), FALSE);
    g_return_val_if_fail(property_name != NULL, FALSE);
    g_return_val_if_fail(G_IS_VALUE(value), FALSE);
    g_return_val_if_fail(!error || !*error, FALSE);

    /* g_object_class_find_property() does g_param_spec_get_redirect_target(),
     * where we differ from a plain g_object_set_property(). */
    pspec = g_object_class_find_property(G_OBJECT_GET_CLASS(object), property_name);

    if (!pspec) {
        g_set_error(error,
                    NM_UTILS_ERROR,
                    NM_UTILS_ERROR_UNKNOWN,
                    _("object class '%s' has no property named '%s'"),
                    G_OBJECT_TYPE_NAME(object),
                    property_name);
        return FALSE;
    }
    if (!(pspec->flags & G_PARAM_WRITABLE)) {
        g_set_error(error,
                    NM_UTILS_ERROR,
                    NM_UTILS_ERROR_UNKNOWN,
                    _("property '%s' of object class '%s' is not writable"),
                    pspec->name,
                    G_OBJECT_TYPE_NAME(object));
        return FALSE;
    }
    if ((pspec->flags & G_PARAM_CONSTRUCT_ONLY)) {
        g_set_error(error,
                    NM_UTILS_ERROR,
                    NM_UTILS_ERROR_UNKNOWN,
                    _("construct property \"%s\" for object '%s' can't be set after construction"),
                    pspec->name,
                    G_OBJECT_TYPE_NAME(object));
        return FALSE;
    }

    klass = g_type_class_peek(pspec->owner_type);
    if (klass == NULL) {
        g_set_error(error,
                    NM_UTILS_ERROR,
                    NM_UTILS_ERROR_UNKNOWN,
                    _("'%s::%s' is not a valid property name; '%s' is not a GObject subtype"),
                    g_type_name(pspec->owner_type),
                    pspec->name,
                    g_type_name(pspec->owner_type));
        return FALSE;
    }

    /* provide a copy to work from, convert (if necessary) and validate */
    g_value_init(&tmp_value, pspec->value_type);
    if (!g_value_transform(value, &tmp_value)) {
        g_set_error(error,
                    NM_UTILS_ERROR,
                    NM_UTILS_ERROR_UNKNOWN,
                    _("unable to set property '%s' of type '%s' from value of type '%s'"),
                    pspec->name,
                    g_type_name(pspec->value_type),
                    G_VALUE_TYPE_NAME(value));
        return FALSE;
    }
    if (g_param_value_validate(pspec, &tmp_value) && !(pspec->flags & G_PARAM_LAX_VALIDATION)) {
        gs_free char *contents = g_strdup_value_contents(value);

        g_set_error(error,
                    NM_UTILS_ERROR,
                    NM_UTILS_ERROR_UNKNOWN,
                    _("value \"%s\" of type '%s' is invalid or out of range for property '%s' of "
                      "type '%s'"),
                    contents,
                    G_VALUE_TYPE_NAME(value),
                    pspec->name,
                    g_type_name(pspec->value_type));
        return FALSE;
    }

    g_object_set_property(object, property_name, &tmp_value);
    return TRUE;
}

#define _set_property(object, property_name, gtype, gtype_set, value, error)          \
    G_STMT_START                                                                      \
    {                                                                                 \
        nm_auto_unset_gvalue GValue gvalue = {0};                                     \
                                                                                      \
        g_value_init(&gvalue, gtype);                                                 \
        gtype_set(&gvalue, (value));                                                  \
        return nm_g_object_set_property((object), (property_name), &gvalue, (error)); \
    }                                                                                 \
    G_STMT_END

gboolean
nm_g_object_set_property_string(GObject    *object,
                                const char *property_name,
                                const char *value,
                                GError    **error)
{
    _set_property(object, property_name, G_TYPE_STRING, g_value_set_string, value, error);
}

gboolean
nm_g_object_set_property_string_static(GObject    *object,
                                       const char *property_name,
                                       const char *value,
                                       GError    **error)
{
    _set_property(object, property_name, G_TYPE_STRING, g_value_set_static_string, value, error);
}

gboolean
nm_g_object_set_property_string_take(GObject    *object,
                                     const char *property_name,
                                     char       *value,
                                     GError    **error)
{
    _set_property(object, property_name, G_TYPE_STRING, g_value_take_string, value, error);
}

gboolean
nm_g_object_set_property_boolean(GObject    *object,
                                 const char *property_name,
                                 gboolean    value,
                                 GError    **error)
{
    _set_property(object, property_name, G_TYPE_BOOLEAN, g_value_set_boolean, !!value, error);
}

gboolean
nm_g_object_set_property_char(GObject    *object,
                              const char *property_name,
                              gint8       value,
                              GError    **error)
{
    /* glib says about G_TYPE_CHAR:
     *
     * The type designated by G_TYPE_CHAR is unconditionally an 8-bit signed integer.
     *
     * This is always a (signed!) char. */
    _set_property(object, property_name, G_TYPE_CHAR, g_value_set_schar, value, error);
}

gboolean
nm_g_object_set_property_uchar(GObject    *object,
                               const char *property_name,
                               guint8      value,
                               GError    **error)
{
    _set_property(object, property_name, G_TYPE_UCHAR, g_value_set_uchar, value, error);
}

gboolean
nm_g_object_set_property_int(GObject *object, const char *property_name, int value, GError **error)
{
    _set_property(object, property_name, G_TYPE_INT, g_value_set_int, value, error);
}

gboolean
nm_g_object_set_property_int64(GObject    *object,
                               const char *property_name,
                               gint64      value,
                               GError    **error)
{
    _set_property(object, property_name, G_TYPE_INT64, g_value_set_int64, value, error);
}

gboolean
nm_g_object_set_property_uint(GObject    *object,
                              const char *property_name,
                              guint       value,
                              GError    **error)
{
    _set_property(object, property_name, G_TYPE_UINT, g_value_set_uint, value, error);
}

gboolean
nm_g_object_set_property_uint64(GObject    *object,
                                const char *property_name,
                                guint64     value,
                                GError    **error)
{
    _set_property(object, property_name, G_TYPE_UINT64, g_value_set_uint64, value, error);
}

gboolean
nm_g_object_set_property_flags(GObject    *object,
                               const char *property_name,
                               GType       gtype,
                               guint       value,
                               GError    **error)
{
    nm_assert(({
        nm_auto_unref_gtypeclass GTypeClass *gtypeclass = g_type_class_ref(gtype);
        G_IS_FLAGS_CLASS(gtypeclass);
    }));
    _set_property(object, property_name, gtype, g_value_set_flags, value, error);
}

gboolean
nm_g_object_set_property_enum(GObject    *object,
                              const char *property_name,
                              GType       gtype,
                              int         value,
                              GError    **error)
{
    nm_assert(({
        nm_auto_unref_gtypeclass GTypeClass *gtypeclass = g_type_class_ref(gtype);
        G_IS_ENUM_CLASS(gtypeclass);
    }));
    _set_property(object, property_name, gtype, g_value_set_enum, value, error);
}

GParamSpec *
nm_g_object_class_find_property_from_gtype(GType gtype, const char *property_name)
{
    nm_auto_unref_gtypeclass GObjectClass *gclass = NULL;

    gclass = g_type_class_ref(gtype);
    return g_object_class_find_property(gclass, property_name);
}

/*****************************************************************************/

/**
 * nm_g_type_find_implementing_class_for_property:
 * @gtype: the GObject type which has a property @pname
 * @pname: the name of the property to look up
 *
 * This is only a helper function for printf debugging. It's not
 * used in actual code. Hence, the function just asserts that
 * @pname and @gtype arguments are suitable. It cannot fail.
 *
 * Returns: the most ancestor type of @gtype, that
 *   implements the property @pname. It means, it
 *   searches the type hierarchy to find the type
 *   that added @pname.
 */
GType
nm_g_type_find_implementing_class_for_property(GType gtype, const char *pname)
{
    nm_auto_unref_gtypeclass GObjectClass *klass = NULL;
    GParamSpec                            *pspec;

    g_return_val_if_fail(pname, G_TYPE_INVALID);

    klass = g_type_class_ref(gtype);
    g_return_val_if_fail(G_IS_OBJECT_CLASS(klass), G_TYPE_INVALID);

    pspec = g_object_class_find_property(klass, pname);
    g_return_val_if_fail(pspec, G_TYPE_INVALID);

    gtype = G_TYPE_FROM_CLASS(klass);

    while (TRUE) {
        nm_auto_unref_gtypeclass GObjectClass *k = NULL;

        k = g_type_class_ref(g_type_parent(gtype));

        g_return_val_if_fail(G_IS_OBJECT_CLASS(k), G_TYPE_INVALID);

        if (g_object_class_find_property(k, pname) != pspec)
            return gtype;

        gtype = G_TYPE_FROM_CLASS(k);
    }
}

/*****************************************************************************/

static void
_str_buf_append_c_escape_octal(NMStrBuf *strbuf, char ch)
{
    nm_str_buf_append_c(strbuf,
                        '\\',
                        '0' + ((char) ((((guchar) ch) >> 6) & 07)),
                        '0' + ((char) ((((guchar) ch) >> 3) & 07)),
                        '0' + ((char) ((((guchar) ch)) & 07)));
}

/**
 * nm_utils_buf_utf8safe_unescape:
 * @str: (allow-none): the string to unescape. The string itself is a NUL terminated
 *   ASCII string, that can have C-style backslash escape sequences (which
 *   are to be unescaped). Non-ASCII characters (e.g. UTF-8) are taken verbatim, so
 *   it doesn't care that this string is UTF-8. However, usually this is a UTF-8 encoded
 *   string.
 * @flags: flags for unescaping. The following flags are supported.
 *   %NM_UTILS_STR_UTF8_SAFE_UNESCAPE_STRIP_SPACES performs a g_strstrip() on the input string,
 *   but preserving escaped spaces. For example, "a\\t " gives "a\t" (that is, the escaped space does
 *   not get stripped). Likewise, the invalid escape sequence "a\\  " results in "a " (stripping
 *   the unescaped space, but preserving the escaped one).
 * @out_len: (out): the length of the parsed string.
 * @to_free: (out): if @str requires unescaping, the function will clone the string. In
 *   that case, the allocated buffer will be returned here.
 *
 * See C-style escapes at https://en.wikipedia.org/wiki/Escape_sequences_in_C#Table_of_escape_sequences.
 * Note that hex escapes ("\\xhh") and unicode escapes ("\\uhhhh", "\\Uhhhhhhhh") are not supported.
 *
 * Also, this function is very similar to g_strcompress() but without issuing g_warning()
 * assertions and proper handling of "\\000" escape sequences.
 *
 * Invalid escape sequences (or non-UTF-8 input) are gracefully accepted. For example "\\ "
 * is an invalid escape sequence, in this case the backslash is removed and " " gets returned.
 *
 * The function never leaks secrets in memory.
 *
 * Returns: the unescaped buffer of length @out_len. If @str is %NULL, this returns %NULL
 *   and sets @out_len to 0. Otherwise, a non-%NULL binary buffer is returned with
 *   @out_len bytes. Note that the binary buffer is guaranteed to be NUL terminated
 *   (@result[@out_len] is NUL).
 *   Note that the result is binary, and may have embedded NUL characters and non-UTF-8.
 *   If the function can avoid cloning the input string, it will return a pointer inside
 *   the input @str. For example, if there is no backslash, no cloning is necessary. In that
 *   case, @to_free will be %NULL. Otherwise, @to_free is set to a newly allocated buffer
 *   containing the unescaped string and returned.
 */
gconstpointer
nm_utils_buf_utf8safe_unescape(const char             *str,
                               NMUtilsStrUtf8SafeFlags flags,
                               gsize                  *out_len,
                               gpointer               *to_free)
{
    gboolean    strip_spaces = NM_FLAGS_HAS(flags, NM_UTILS_STR_UTF8_SAFE_UNESCAPE_STRIP_SPACES);
    NMStrBuf    strbuf;
    const char *s;
    gsize       len;

    g_return_val_if_fail(to_free, NULL);
    g_return_val_if_fail(out_len, NULL);

    if (!str) {
        *out_len = 0;
        *to_free = NULL;
        return NULL;
    }

    if (strip_spaces)
        str = nm_str_skip_leading_spaces(str);

    len = strlen(str);

    s = memchr(str, '\\', len);
    if (!s) {
        if (strip_spaces && len > 0 && g_ascii_isspace(str[len - 1])) {
            len--;
            while (len > 0 && g_ascii_isspace(str[len - 1]))
                len--;
            *out_len = len;
            return (*to_free = g_strndup(str, len));
        }
        *out_len = len;
        *to_free = NULL;
        return str;
    }

    strbuf = NM_STR_BUF_INIT(len + 1u, FALSE);

    nm_str_buf_append_len(&strbuf, str, s - str);
    str = s;

    for (;;) {
        char  ch;
        guint v;

        nm_assert(str[0] == '\\');

        ch = (++str)[0];

        if (ch == '\0') {
            /* error. Trailing '\\' */
            break;
        }

        if (ch >= '0' && ch <= '9') {
            v  = ch - '0';
            ch = (++str)[0];
            if (ch >= '0' && ch <= '7') {
                v  = v * 8 + (ch - '0');
                ch = (++str)[0];
                if (ch >= '0' && ch <= '7') {
                    /* technically, escape sequences larger than \3FF are out of range
                     * and invalid. We don't check for that, and do the same as
                     * g_strcompress(): silently clip the value with & 0xFF. */
                    v = v * 8 + (ch - '0');
                    ++str;
                }
            }
            ch = v;
        } else {
            switch (ch) {
            case 'b':
                ch = '\b';
                break;
            case 'f':
                ch = '\f';
                break;
            case 'n':
                ch = '\n';
                break;
            case 'r':
                ch = '\r';
                break;
            case 't':
                ch = '\t';
                break;
            case 'v':
                ch = '\v';
                break;
            default:
                /* Here we handle "\\\\", but all other unexpected escape sequences are really a bug.
                 * Take them literally, after removing the escape character */
                break;
            }
            str++;
        }

        nm_str_buf_append_c(&strbuf, ch);

        s = strchr(str, '\\');
        if (!s) {
            gsize l = strlen(str);

            if (strip_spaces) {
                while (l > 0 && g_ascii_isspace(str[l - 1]))
                    l--;
            }
            nm_str_buf_append_len(&strbuf, str, l);
            break;
        }

        nm_str_buf_append_len(&strbuf, str, s - str);
        str = s;
    }

    /* assert that no reallocation was necessary. For one, unescaping should
     * never result in a longer string than the input. Also, when unescaping
     * secrets, we want to ensure that we don't leak secrets in memory. */
    nm_assert(strbuf.allocated == len + 1u);

    return (*to_free = nm_str_buf_finalize(&strbuf, out_len));
}

/**
 * nm_utils_buf_utf8safe_escape:
 * @buf: byte array, possibly in utf-8 encoding, may have NUL characters.
 * @buflen: the length of @buf in bytes, or -1 if @buf is a NUL terminated
 *   string. Note that if @buflen is zero, then the function returns NULL.
 *   If @buflen is negative, then the function returns NULL if @buf is NULL
 *   and @buf if @buf is "".
 * @flags: #NMUtilsStrUtf8SafeFlags flags
 * @to_free: (out): return the pointer location of the string
 *   if a copying was necessary.
 *
 * Based on the assumption, that @buf contains UTF-8 encoded bytes,
 * this will return valid UTF-8 sequence, and invalid sequences
 * will be escaped with backslash (C escaping, like g_strescape()).
 * This is sanitize non UTF-8 characters. The result is valid
 * UTF-8.
 *
 * The operation can be reverted with nm_utils_buf_utf8safe_unescape().
 * Note that if, and only if @buf contains no NUL bytes, the operation
 * can also be reverted with g_strcompress().
 *
 * Depending on @flags, valid UTF-8 characters are not escaped at all
 * (except the escape character '\\'). This is the difference to g_strescape(),
 * which escapes all non-ASCII characters. This allows to pass on
 * valid UTF-8 characters as-is and can be directly shown to the user
 * as UTF-8 -- with exception of the backslash escape character,
 * invalid UTF-8 sequences, and other (depending on @flags).
 *
 * Returns: the escaped input buffer, as valid UTF-8. If no escaping
 *   is necessary and @buflen is negative, it returns the input @buf
 *   that can be interpreted as NUL terminated UTF-8 string.
 *   Otherwise, an allocated string @to_free is returned which must be freed
 *   by the caller with g_free().
 *   The escaping can be reverted by nm_utils_buf_utf8safe_unescape()
 *   (or, if in the absence of NUL characters, with g_strcompress()).
 *   There are cases where this function returns %NULL:
 *   - if @buflen is 0.
 *   - if @buflen is negative and @buf is NULL.
 **/
const char *
nm_utils_buf_utf8safe_escape(gconstpointer           buf,
                             gssize                  buflen,
                             NMUtilsStrUtf8SafeFlags flags,
                             char                  **to_free)
{
    const char *const str = buf;
    const char       *p   = NULL;
    const char       *s;
    gboolean          nul_terminated = FALSE;
    NMStrBuf          strbuf;

    g_return_val_if_fail(to_free, NULL);

    *to_free = NULL;

    if (buflen == 0)
        return NULL;

    if (buflen < 0) {
        if (!str)
            return NULL;
        buflen = strlen(str);
        if (buflen == 0)
            return str;
        nul_terminated = TRUE;
    }

    if (g_utf8_validate(str, buflen, &p) && nul_terminated) {
        /* note that g_utf8_validate() does not allow NUL character inside @str. Good.
         * We can treat @str like a NUL terminated string. */
        if (!NM_STRCHAR_ANY(str,
                            ch,
                            (ch == '\\'
                             || (NM_FLAGS_HAS(flags, NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL)
                                 && nm_ascii_is_ctrl_or_del(ch))
                             || (NM_FLAGS_HAS(flags, NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_NON_ASCII)
                                 && nm_ascii_is_non_ascii(ch)))))
            return str;
    }

    strbuf = NM_STR_BUF_INIT(buflen + 5, NM_FLAGS_HAS(flags, NM_UTILS_STR_UTF8_SAFE_FLAG_SECRET));

    s = str;
    do {
        buflen -= p - s;
        nm_assert(buflen >= 0);

        for (; s < p; s++) {
            char ch = s[0];

            nm_assert(ch);
            if (ch == '\\')
                nm_str_buf_append_c(&strbuf, '\\', '\\');
            else if ((NM_FLAGS_HAS(flags, NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL)
                      && nm_ascii_is_ctrl_or_del(ch))
                     || (NM_FLAGS_HAS(flags, NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_NON_ASCII)
                         && nm_ascii_is_non_ascii(ch)))
                _str_buf_append_c_escape_octal(&strbuf, ch);
            else
                nm_str_buf_append_c(&strbuf, ch);
        }

        if (buflen <= 0)
            break;

        _str_buf_append_c_escape_octal(&strbuf, p[0]);

        buflen--;
        if (buflen == 0)
            break;

        s = &p[1];
        (void) g_utf8_validate(s, buflen, &p);
    } while (TRUE);

    return (*to_free = nm_str_buf_finalize(&strbuf, NULL));
}

const char *
nm_utils_buf_utf8safe_escape_bytes(GBytes *bytes, NMUtilsStrUtf8SafeFlags flags, char **to_free)
{
    gconstpointer p;
    gsize         l;

    if (bytes)
        p = g_bytes_get_data(bytes, &l);
    else {
        p = NULL;
        l = 0;
    }

    return nm_utils_buf_utf8safe_escape(p, l, flags, to_free);
}

char *
nm_utils_buf_utf8safe_escape_cp(gconstpointer buf, gssize buflen, NMUtilsStrUtf8SafeFlags flags)
{
    const char *s_const;
    char       *s;

    s_const = nm_utils_buf_utf8safe_escape(buf, buflen, flags, &s);
    nm_assert(!s || s == s_const);
    return s ?: g_strdup(s_const);
}

/*****************************************************************************/

const char *
nm_utils_str_utf8safe_unescape(const char *str, NMUtilsStrUtf8SafeFlags flags, char **to_free)
{
    const char *res;
    gsize       len;

    g_return_val_if_fail(to_free, NULL);

    res = nm_utils_buf_utf8safe_unescape(str, flags, &len, (gpointer *) to_free);

    nm_assert((!res && len == 0) || (strlen(res) <= len));

    return res;
}

/**
 * nm_utils_str_utf8safe_escape:
 * @str: NUL terminated input string, possibly in utf-8 encoding
 * @flags: #NMUtilsStrUtf8SafeFlags flags
 * @to_free: (out): return the pointer location of the string
 *   if a copying was necessary.
 *
 * Returns the possible non-UTF-8 NUL terminated string @str
 * and uses backslash escaping (C escaping, like g_strescape())
 * to sanitize non UTF-8 characters. The result is valid
 * UTF-8.
 *
 * The operation can be reverted with g_strcompress() or
 * nm_utils_str_utf8safe_unescape().
 *
 * Depending on @flags, valid UTF-8 characters are not escaped at all
 * (except the escape character '\\'). This is the difference to g_strescape(),
 * which escapes all non-ASCII characters. This allows to pass on
 * valid UTF-8 characters as-is and can be directly shown to the user
 * as UTF-8 -- with exception of the backslash escape character,
 * invalid UTF-8 sequences, and other (depending on @flags).
 *
 * Returns: the escaped input string, as valid UTF-8. If no escaping
 *   is necessary, it returns the input @str. Otherwise, an allocated
 *   string @to_free is returned which must be freed by the caller
 *   with g_free. The escaping can be reverted by g_strcompress().
 **/
const char *
nm_utils_str_utf8safe_escape(const char *str, NMUtilsStrUtf8SafeFlags flags, char **to_free)
{
    return nm_utils_buf_utf8safe_escape(str, -1, flags, to_free);
}

/**
 * nm_utils_str_utf8safe_escape_cp:
 * @str: NUL terminated input string, possibly in utf-8 encoding
 * @flags: #NMUtilsStrUtf8SafeFlags flags
 *
 * Like nm_utils_str_utf8safe_escape(), except the returned value
 * is always a copy of the input and must be freed by the caller.
 *
 * Returns: the escaped input string in UTF-8 encoding. The returned
 *   value should be freed with g_free().
 *   The escaping can be reverted by g_strcompress().
 **/
char *
nm_utils_str_utf8safe_escape_cp(const char *str, NMUtilsStrUtf8SafeFlags flags)
{
    char *s;

    nm_utils_str_utf8safe_escape(str, flags, &s);
    return s ?: g_strdup(str);
}

char *
nm_utils_str_utf8safe_unescape_cp(const char *str, NMUtilsStrUtf8SafeFlags flags)
{
    char *s;

    str = nm_utils_str_utf8safe_unescape(str, flags, &s);
    return s ?: g_strdup(str);
}

char *
nm_utils_str_utf8safe_escape_take(char *str, NMUtilsStrUtf8SafeFlags flags)
{
    char *str_to_free;

    nm_utils_str_utf8safe_escape(str, flags, &str_to_free);
    if (str_to_free) {
        g_free(str);
        return str_to_free;
    }
    return str;
}

/*****************************************************************************/

/* taken from systemd's fd_wait_for_event(). Note that the timeout
 * is here in nano-seconds, not micro-seconds. */
int
nm_utils_fd_wait_for_event(int fd, int event, gint64 timeout_nsec)
{
    struct pollfd pollfd = {
        .fd     = fd,
        .events = event,
    };
    struct timespec ts, *pts;
    int             r;

    nm_assert(fd >= 0);

    if (timeout_nsec < 0)
        pts = NULL;
    else {
        ts.tv_sec  = (time_t) (timeout_nsec / NM_UTILS_NSEC_PER_SEC);
        ts.tv_nsec = (long int) (timeout_nsec % NM_UTILS_NSEC_PER_SEC);
        pts        = &ts;
    }

    r = ppoll(&pollfd, 1, pts, NULL);
    if (r < 0)
        return -NM_ERRNO_NATIVE(errno);
    if (r == 0)
        return 0;

    nm_assert(r == 1);
    nm_assert(pollfd.revents > 0);

    if (pollfd.revents & POLLNVAL)
        return nm_assert_unreachable_val(-EBADF);

    return pollfd.revents;
}

/* taken from systemd's loop_read() */
ssize_t
nm_utils_fd_read_loop(int fd, void *buf, size_t nbytes, bool do_poll)
{
    uint8_t *p = buf;
    ssize_t  n = 0;

    g_return_val_if_fail(fd >= 0, -EINVAL);
    g_return_val_if_fail(buf, -EINVAL);

    /* If called with nbytes == 0, let's call read() at least
     * once, to validate the operation */

    if (nbytes > (size_t) SSIZE_MAX)
        return -EINVAL;

    do {
        ssize_t k;

        k = read(fd, p, nbytes);
        if (k < 0) {
            int errsv = errno;

            if (errsv == EINTR)
                continue;

            if (errsv == EAGAIN && do_poll) {
                /* We knowingly ignore any return value here,
                 * and expect that any error/EOF is reported
                 * via read() */

                (void) nm_utils_fd_wait_for_event(fd, POLLIN, -1);
                continue;
            }

            return n > 0 ? n : -NM_ERRNO_NATIVE(errsv);
        }

        if (k == 0)
            return n;

        g_assert((size_t) k <= nbytes);

        p += k;
        nbytes -= k;
        n += k;
    } while (nbytes > 0);

    return n;
}

/* taken from systemd's loop_read_exact() */
int
nm_utils_fd_read_loop_exact(int fd, void *buf, size_t nbytes, bool do_poll)
{
    ssize_t n;

    n = nm_utils_fd_read_loop(fd, buf, nbytes, do_poll);
    if (n < 0)
        return (int) n;
    if ((size_t) n != nbytes)
        return -EIO;

    return 0;
}

/*****************************************************************************/

void
nm_utils_named_value_clear_with_g_free(NMUtilsNamedValue *val)
{
    if (val) {
        nm_clear_g_free(&val->name_mutable);
        nm_clear_g_free(&val->value_ptr);
    }
}

G_STATIC_ASSERT(G_STRUCT_OFFSET(NMUtilsNamedValue, name) == 0);

gssize
nm_utils_named_value_list_find(const NMUtilsNamedValue *arr,
                               gsize                    len,
                               const char              *name,
                               gboolean                 sorted)
{
    gsize i;

    nm_assert(name);

#if NM_MORE_ASSERTS > 5
    {
        for (i = 0; i < len; i++) {
            const NMUtilsNamedValue *v = &arr[i];

            nm_assert(v->name);
            if (sorted && i > 0)
                nm_assert(strcmp(arr[i - 1].name, v->name) < 0);
        }
    }

    nm_assert(!sorted || nm_utils_named_value_list_is_sorted(arr, len, FALSE, NULL, NULL));
#endif

    if (sorted) {
        return nm_array_find_bsearch(arr,
                                     len,
                                     sizeof(NMUtilsNamedValue),
                                     &name,
                                     nm_strcmp_p_with_data,
                                     NULL);
    }
    for (i = 0; i < len; i++) {
        if (nm_streq(arr[i].name, name))
            return i;
    }
    return ~((gssize) len);
}

gboolean
nm_utils_named_value_list_is_sorted(const NMUtilsNamedValue *arr,
                                    gsize                    len,
                                    gboolean                 accept_duplicates,
                                    GCompareDataFunc         compare_func,
                                    gpointer                 user_data)
{
    gsize i;
    int   c_limit;

    if (len == 0)
        return TRUE;

    g_return_val_if_fail(arr, FALSE);

    if (!compare_func)
        compare_func = nm_strcmp_p_with_data;

    c_limit = accept_duplicates ? 0 : -1;

    for (i = 1; i < len; i++) {
        int c;

        c = compare_func(&arr[i - 1], &arr[i], user_data);
        if (c > c_limit)
            return FALSE;
    }
    return TRUE;
}

void
nm_utils_named_value_list_sort(NMUtilsNamedValue *arr,
                               gsize              len,
                               GCompareDataFunc   compare_func,
                               gpointer           user_data)
{
    if (len == 0)
        return;

    g_return_if_fail(arr);

    if (len == 1)
        return;

    g_qsort_with_data(arr,
                      len,
                      sizeof(NMUtilsNamedValue),
                      compare_func ?: nm_strcmp_p_with_data,
                      user_data);
}

/*****************************************************************************/

gpointer *
nm_utils_hash_keys_to_array(GHashTable      *hash,
                            GCompareDataFunc compare_func,
                            gpointer         user_data,
                            guint           *out_len)
{
    guint     len;
    gpointer *keys;

    /* by convention, we never return an empty array. In that
     * case, always %NULL. */
    if (!hash || g_hash_table_size(hash) == 0) {
        NM_SET_OUT(out_len, 0);
        return NULL;
    }

    keys = g_hash_table_get_keys_as_array(hash, &len);
    if (len > 1 && compare_func) {
        g_qsort_with_data(keys, len, sizeof(gpointer), compare_func, user_data);
    }
    NM_SET_OUT(out_len, len);
    return keys;
}

gpointer *
nm_utils_hash_values_to_array(GHashTable      *hash,
                              GCompareDataFunc compare_func,
                              gpointer         user_data,
                              guint           *out_len)
{
    GHashTableIter iter;
    gpointer       value;
    gpointer      *arr;
    guint          i, len;

    if (!hash || (len = g_hash_table_size(hash)) == 0u) {
        NM_SET_OUT(out_len, 0);
        return NULL;
    }

    arr = g_new(gpointer, ((gsize) len) + 1);
    i   = 0;
    g_hash_table_iter_init(&iter, hash);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &value))
        arr[i++] = value;

    nm_assert(i == len);
    arr[len] = NULL;

    if (len > 1 && compare_func) {
        g_qsort_with_data(arr, len, sizeof(gpointer), compare_func, user_data);
    }

    NM_SET_OUT(out_len, len);
    return arr;
}

NMUtilsNamedValue *
nm_utils_hash_to_array_full(GHashTable         *hash,
                            guint              *out_len,
                            GCompareDataFunc    compare_func,
                            gpointer            user_data,
                            NMUtilsNamedValue  *provided_buffer,
                            guint               provided_buffer_len,
                            NMUtilsNamedValue **out_allocated_buffer)
{
    GHashTableIter     iter;
    NMUtilsNamedValue *values;
    guint              len;
    guint              i;

    nm_assert(provided_buffer_len == 0 || provided_buffer);
    nm_assert(!out_allocated_buffer || !*out_allocated_buffer);

    if (!hash || ((len = g_hash_table_size(hash)) == 0)) {
        NM_SET_OUT(out_len, 0);
        return NULL;
    }

    if (provided_buffer_len >= len + 1) {
        /* the buffer provided by the caller is large enough. Use it. */
        values = provided_buffer;
    } else {
        /* allocate a new buffer. */
        values = g_new(NMUtilsNamedValue, len + 1);
        NM_SET_OUT(out_allocated_buffer, values);
    }

    i = 0;
    g_hash_table_iter_init(&iter, hash);
    while (g_hash_table_iter_next(&iter, &values[i].name_ptr, &values[i].value_ptr))
        i++;
    nm_assert(i == len);
    values[i].name_ptr  = NULL;
    values[i].value_ptr = NULL;

    if (compare_func && len > 1)
        g_qsort_with_data(values, len, sizeof(NMUtilsNamedValue), compare_func, user_data);

    NM_SET_OUT(out_len, len);
    return values;
}

/*****************************************************************************/

/**
 * nm_utils_hashtable_equal:
 * @a: one #GHashTable
 * @b: other #GHashTable
 * @treat_null_as_empty: if %TRUE, when either @a or @b is %NULL, it is
 *   treated like an empty hash. It means, a %NULL hash will compare equal
 *   to an empty hash.
 * @equal_func: the equality function, for comparing the values.
 *   If %NULL, the values are not compared. In that case, the function
 *   only checks, if both dictionaries have the same keys -- according
 *   to @b's key equality function.
 *   Note that the values of @a will be passed as first argument
 *   to @equal_func.
 *
 * Compares two hash tables, whether they have equal content.
 * This only makes sense, if @a and @b have the same key types and
 * the same key compare-function.
 *
 * Returns: %TRUE, if both dictionaries have the same content.
 */
gboolean
nm_utils_hashtable_equal(const GHashTable *a,
                         const GHashTable *b,
                         gboolean          treat_null_as_empty,
                         GEqualFunc        equal_func)
{
    guint          n;
    GHashTableIter iter;
    gconstpointer  key, v_a, v_b;

    if (a == b)
        return TRUE;
    if (!treat_null_as_empty) {
        if (!a || !b)
            return FALSE;
    }

    n = a ? g_hash_table_size((GHashTable *) a) : 0;
    if (n != (b ? g_hash_table_size((GHashTable *) b) : 0))
        return FALSE;

    if (n > 0) {
        g_hash_table_iter_init(&iter, (GHashTable *) a);
        while (g_hash_table_iter_next(&iter, (gpointer *) &key, (gpointer *) &v_a)) {
            if (!g_hash_table_lookup_extended((GHashTable *) b, key, NULL, (gpointer *) &v_b))
                return FALSE;
            if (equal_func && !equal_func(v_a, v_b))
                return FALSE;
        }
    }

    return TRUE;
}

static gboolean
_utils_hashtable_equal(GHashTable      *hash_a,
                       GHashTable      *hash_b,
                       GCompareDataFunc cmp_values,
                       gpointer         user_data)
{
    GHashTableIter h;
    gpointer       a_key;
    gpointer       a_val;
    gpointer       b_val;

    nm_assert(hash_a);
    nm_assert(hash_b);
    nm_assert(hash_a != hash_b);
    nm_assert(g_hash_table_size(hash_a) == g_hash_table_size(hash_b));

    /* We rely on both hashes to have the same hash/equal function. Otherwise, we would have to iterate
     * both hashes and check whether all keys/values are present in the respective other hash (which
     * would be O(n^2), since we couldn't use the plain lookup function. That is not a useful thing
     * for this function. */

    g_hash_table_iter_init(&h, hash_a);
    while (g_hash_table_iter_next(&h, &a_key, &a_val)) {
        if (!g_hash_table_lookup_extended(hash_b, a_key, NULL, &b_val))
            return FALSE;

        if (!cmp_values) {
            /* we accept %NULL compare function to indicate that we don't care about the key. */
            continue;
        }

        if (cmp_values(a_val, b_val, user_data) != 0)
            return FALSE;
    }

    return TRUE;
}

/**
 * nm_utils_hashtable_cmp_equal:
 * @a: (allow-none): the hash table or %NULL
 * @b: (allow-none): the other hash table or %NULL
 * @cmp_values: (allow-none): if %NULL, only the keys
 *   will be compared. Otherwise, this function is used to
 *   check whether all keys are equal.
 * @user_data: the argument for @cmp_values.
 *
 * It is required that both @a and @b have the same hash and equals
 * function.
 *
 * Returns: %TRUE, if both keys have the same keys and (if
 *   @cmp_values is given) all values are the same.
 */
gboolean
nm_utils_hashtable_cmp_equal(const GHashTable *a,
                             const GHashTable *b,
                             GCompareDataFunc  cmp_values,
                             gpointer          user_data)
{
    GHashTable *hash_a = (GHashTable *) a;
    GHashTable *hash_b = (GHashTable *) b;
    gboolean    same;
    guint       size;

    if (hash_a == hash_b)
        return TRUE;

    if (!hash_a || !hash_b)
        return FALSE;

    size = g_hash_table_size(hash_a);
    if (size != g_hash_table_size(hash_b))
        return FALSE;

    if (size == 0)
        return TRUE;

    same = _utils_hashtable_equal(hash_a, hash_b, cmp_values, user_data);

#if NM_MORE_ASSERTS > 5
    nm_assert(same == _utils_hashtable_equal(hash_b, hash_a, cmp_values, user_data));
#endif

    return same;
}

typedef struct {
    gpointer key;
    gpointer val;
} HashTableCmpData;

typedef struct {
    GCompareDataFunc cmp_keys;
    gpointer         user_data;
} HashTableUserData;

static int
_hashtable_cmp_func(gconstpointer a, gconstpointer b, gpointer user_data)
{
    const HashTableUserData *d   = user_data;
    const HashTableCmpData  *d_a = *((const HashTableCmpData *const *) a);
    const HashTableCmpData  *d_b = *((const HashTableCmpData *const *) b);

    NM_CMP_RETURN(d->cmp_keys(d_a, d_b, d->user_data));
    return 0;
}

/**
 * nm_utils_hashtable_cmp:
 * @a: (allow-none): the hash to compare. May be %NULL.
 * @b: (allow-none): the other hash to compare. May be %NULL.
 * @do_fast_precheck: if %TRUE, assume that the hashes are equal
 *   and that it is worth calling nm_utils_hashtable_cmp_equal() first.
 *   That requires, that both hashes have the same equals function
 *   which is compatible with the @cmp_keys function.
 * @cmp_keys: the compare function for keys. Usually, the hash/equal function
 *   of both hashes corresponds to this function. If you set @do_fast_precheck
 *   to false, then this is not a requirement.
 * @cmp_values: (allow-none): if %NULL, only the keys are compared.
 *   Otherwise, the values must are also compared with this function.
 *
 * Both hashes must have keys/values of the same domain, so that
 * they can be effectively compared with @cmp_keys and @cmp_values.
 *
 * %NULL hashes compare equal to %NULL, but not to empty hashes.
 *
 * Returns: 0 if both hashes are equal, or -1 or 1 if one of the hashes
 *   sorts before/after.
 */
int
nm_utils_hashtable_cmp(const GHashTable *a,
                       const GHashTable *b,
                       gboolean          do_fast_precheck,
                       GCompareDataFunc  cmp_keys,
                       GCompareDataFunc  cmp_values,
                       gpointer          user_data)
{
    GHashTable               *hash_a         = (GHashTable *) a;
    GHashTable               *hash_b         = (GHashTable *) b;
    gs_free HashTableCmpData *cmp_array_free = NULL;
    HashTableCmpData         *cmp_array_a;
    HashTableCmpData         *cmp_array_b;
    GHashTableIter            h;
    gpointer                  i_key;
    gpointer                  i_val;
    gsize                     size2;
    guint                     size;
    guint                     i;

    nm_assert(cmp_keys);

    NM_CMP_SELF(hash_a, hash_b);

    size = g_hash_table_size(hash_a);

    NM_CMP_DIRECT(size, g_hash_table_size(hash_b));

    if (size == 0)
        return 0;

    if (do_fast_precheck) {
        gboolean same;

        /* we expect that the hashes are equal and the caller ensures us that they
         * use the same hash/equal functions. Do a fast path check first...
         *
         * It's unclear whether this is worth it. The full comparison is O(n*ln(n)),
         * while the fast check (using the hash lookup) is O(n). But then, the pre-check
         * makes additional requirements on the hash's hash/equal functions -- the
         * full comparison does not make such requirements. */
        same = _utils_hashtable_equal(hash_a, hash_b, cmp_values, user_data);
#if NM_MORE_ASSERTS > 5
        nm_assert(same == _utils_hashtable_equal(hash_b, hash_a, cmp_values, user_data));
#endif
        if (same)
            return 0;
    }

    size2 = ((gsize) size) * 2u;
    if (size2 > 600u / sizeof(HashTableCmpData)) {
        cmp_array_free = g_new(HashTableCmpData, size2);
        cmp_array_a    = cmp_array_free;
    } else
        cmp_array_a = g_newa(HashTableCmpData, size2);
    cmp_array_b = &cmp_array_a[size];

    i = 0;
    g_hash_table_iter_init(&h, hash_a);
    while (g_hash_table_iter_next(&h, &i_key, &i_val)) {
        nm_assert(i < size);
        cmp_array_a[i++] = (HashTableCmpData){
            .key = i_key,
            .val = i_val,
        };
    }
    nm_assert(i == size);

    i = 0;
    g_hash_table_iter_init(&h, hash_b);
    while (g_hash_table_iter_next(&h, &i_key, &i_val)) {
        nm_assert(i < size);
        cmp_array_b[i++] = (HashTableCmpData){
            .key = i_key,
            .val = i_val,
        };
    }
    nm_assert(i == size);

    g_qsort_with_data(cmp_array_a,
                      size,
                      sizeof(HashTableCmpData),
                      _hashtable_cmp_func,
                      &((HashTableUserData){
                          .cmp_keys  = cmp_keys,
                          .user_data = user_data,
                      }));

    g_qsort_with_data(cmp_array_b,
                      size,
                      sizeof(HashTableCmpData),
                      _hashtable_cmp_func,
                      &((HashTableUserData){
                          .cmp_keys  = cmp_keys,
                          .user_data = user_data,
                      }));

    for (i = 0; i < size; i++) {
        NM_CMP_RETURN(cmp_keys(cmp_array_a[i].key, cmp_array_b[i].key, user_data));
    }

    if (cmp_values) {
        for (i = 0; i < size; i++) {
            NM_CMP_RETURN(cmp_values(cmp_array_a[i].val, cmp_array_b[i].val, user_data));
        }
    }

    /* the fast-precheck should have already told that the arrays are equal. */
    nm_assert(!do_fast_precheck);

    return 0;
}

char **
nm_strv_make_deep_copied(const char **strv)
{
    gsize i;

    /* it takes a strv list, and copies each
     * strings. Note that this updates @strv *in-place*
     * and returns it. */

    if (!strv)
        return NULL;
    for (i = 0; strv[i]; i++)
        strv[i] = g_strdup(strv[i]);

    return (char **) strv;
}

char **
nm_strv_make_deep_copied_n(const char **strv, gsize len)
{
    gsize i;

    /* it takes a strv array with len elements, and copies each
     * strings. Note that this updates @strv *in-place*
     * and returns it. */

    if (!strv)
        return NULL;
    for (i = 0; i < len; i++)
        strv[i] = g_strdup(strv[i]);

    return (char **) strv;
}

/**
 * @strv: the strv array to copy. It may be %NULL if @len
 *   is negative or zero (in which case %NULL will be returned).
 * @len: the length of strings in @str. If negative, strv is assumed
 *   to be a NULL terminated array.
 * @deep_copied: if %TRUE, clones the individual strings. In that case,
 *   the returned array must be freed with g_strfreev(). Otherwise, the
 *   strings themself are not copied. You must take care of who owns the
 *   strings yourself.
 *
 * Like g_strdupv(), with two differences:
 *
 * - accepts a @len parameter for non-null terminated strv array.
 *
 * - this never returns an empty strv array, but always %NULL if
 *   there are no strings.
 *
 * Note that if @len is non-negative, then it still must not
 * contain any %NULL pointers within the first @len elements.
 * Otherwise, you would leak elements if you try to free the
 * array with g_strfreev(). Allowing that would be error prone.
 *
 * Returns: (transfer full): a clone of the strv array. Always
 *   %NULL terminated. Depending on @deep_copied, the strings are
 *   cloned or not.
 */
char **
_nm_strv_dup(const char *const *strv, gssize len, gboolean deep_copied)
{
    gsize  i, l;
    char **v;

    if (len < 0)
        l = NM_PTRARRAY_LEN(strv);
    else
        l = len;
    if (l == 0) {
        /* this function never returns an empty strv array. If you
         * need that, handle it yourself. */
        return NULL;
    }

    v = g_new(char *, l + 1);
    for (i = 0; i < l; i++) {
        if (G_UNLIKELY(!strv[i])) {
            /* NULL strings are not allowed. Clear the remainder of the array
             * and return it (with assertion failure). */
            l++;
            for (; i < l; i++)
                v[i] = NULL;
            g_return_val_if_reached(v);
        }

        if (deep_copied)
            v[i] = g_strdup(strv[i]);
        else
            v[i] = (char *) strv[i];
    }
    v[l] = NULL;
    return v;
}

const char **
_nm_strv_dup_packed(const char *const *strv, gssize len)

{
    gs_free gsize *str_len_free = NULL;
    gsize         *str_len;
    const char   **result;
    gsize          mem_len;
    gsize          pre_len;
    gsize          len2;
    char          *sbuf;
    gsize          i;

    nm_assert(len >= -1);

    if (G_LIKELY(len < 0)) {
        if (!strv || !strv[0]) {
            /* This function never returns an empty strv array. If you need that, handle it
             * yourself. */
            return NULL;
        }
        len2 = NM_PTRARRAY_LEN(strv);
    } else {
        if (len == 0)
            return NULL;
        len2 = len;
    }

    if (len2 > 300u / sizeof(gsize)) {
        str_len_free = g_new(gsize, len2);
        str_len      = str_len_free;
    } else
        str_len = g_newa(gsize, len2);

    mem_len = 0;
    for (i = 0; i < len2; i++) {
        gsize l;

        if (G_LIKELY(strv[i]))
            l = strlen(strv[i]) + 1u;
        else
            l = 0;
        str_len[i] = l;
        mem_len += l;
    }

    pre_len = sizeof(const char *) * (len2 + 1u);

    result = g_malloc(pre_len + mem_len);
    sbuf   = &(((char *) result)[pre_len]);
    for (i = 0; i < len2; i++) {
        gsize l;

        if (G_UNLIKELY(!strv[i])) {
            /* Technically there is no problem with accepting NULL strings. But that
             * does not really result in a strv array, and likely this only happens due
             * to a bug. We want to catch such bugs by asserting.
             *
             * We clear the remainder of the buffer and fail with an assertion. */
            len2++;
            for (; i < len2; i++)
                result[i] = NULL;
            g_return_val_if_reached(result);
        }

        result[i] = sbuf;

        l = str_len[i];
        memcpy(sbuf, strv[i], l);
        sbuf += l;
    }
    result[i] = NULL;
    nm_assert(i == len2);
    nm_assert(sbuf == (&((const char *) result)[pre_len]) + mem_len);

    return result;
}

/*****************************************************************************/

gssize
nm_utils_ptrarray_find_first(gconstpointer *list, gssize len, gconstpointer needle)
{
    gssize i;

    if (len == 0)
        return -1;

    if (len > 0) {
        g_return_val_if_fail(list, -1);
        for (i = 0; i < len; i++) {
            if (list[i] == needle)
                return i;
        }
    } else {
        g_return_val_if_fail(needle, -1);
        for (i = 0; list && list[i]; i++) {
            if (list[i] == needle)
                return i;
        }
    }
    return -1;
}

/*****************************************************************************/

gboolean
nm_utils_ptrarray_is_sorted(gconstpointer   *list,
                            gsize            len,
                            gboolean         require_strict,
                            GCompareDataFunc cmpfcn,
                            gpointer         user_data)
{
    gsize i;

    for (i = 1; i < len; i++) {
        int c;

        c = cmpfcn(list[i - 1], list[i], user_data);
        if (G_LIKELY(c < 0))
            continue;

        if (c > 0 || require_strict)
            return FALSE;
    }
    return TRUE;
}

gssize
nm_ptrarray_find_bsearch(gconstpointer   *list,
                         gsize            len,
                         gconstpointer    needle,
                         GCompareDataFunc cmpfcn,
                         gpointer         user_data)
{
    gssize imax;
    gssize imid;
    gssize imin;
    int    cmp;

    nm_assert(list || len == 0);
    nm_assert(cmpfcn);

    imin = 0;
    if (len > 0) {
        imax = len - 1;

        while (imin <= imax) {
            imid = imin + (imax - imin) / 2;

            cmp = cmpfcn(list[imid], needle, user_data);
            if (cmp == 0)
                return imid;

            if (cmp < 0)
                imin = imid + 1;
            else
                imax = imid - 1;
        }
    }

    /* return the inverse of @imin. This is a negative number, but
     * also is ~imin the position where the value should be inserted. */
    imin = ~imin;
    return imin;
}

gssize
nm_ptrarray_find_bsearch_range(gconstpointer   *list,
                               gsize            len,
                               gconstpointer    needle,
                               GCompareDataFunc cmpfcn,
                               gpointer         user_data,
                               gssize          *out_idx_first,
                               gssize          *out_idx_last)
{
    gssize imax;
    gssize imid;
    gssize imin;
    gssize i2max;
    gssize i2mid;
    gssize i2min;
    int    cmp;

    nm_assert(list || len == 0);
    nm_assert(cmpfcn);

    imin = 0;
    if (len > 0) {
        imax = len - 1;

        while (imin <= imax) {
            imid = imin + (imax - imin) / 2;

            cmp = cmpfcn(list[imid], needle, user_data);
            if (cmp == 0) {
                /* we found a matching entry at index imid.
                 *
                 * Does the caller request the first/last index as well (in case that
                 * there are multiple entries which compare equal). */

                if (out_idx_first) {
                    i2min = imin;
                    i2max = imid + 1;
                    while (i2min <= i2max) {
                        i2mid = i2min + (i2max - i2min) / 2;

                        cmp = cmpfcn(list[i2mid], needle, user_data);
                        if (cmp == 0)
                            i2max = i2mid - 1;
                        else {
                            nm_assert(cmp < 0);
                            i2min = i2mid + 1;
                        }
                    }
                    *out_idx_first = i2min;
                }
                if (out_idx_last) {
                    i2min = imid + 1;
                    i2max = imax;
                    while (i2min <= i2max) {
                        i2mid = i2min + (i2max - i2min) / 2;

                        cmp = cmpfcn(list[i2mid], needle, user_data);
                        if (cmp == 0)
                            i2min = i2mid + 1;
                        else {
                            nm_assert(cmp > 0);
                            i2max = i2mid - 1;
                        }
                    }
                    *out_idx_last = i2min - 1;
                }
                return imid;
            }

            if (cmp < 0)
                imin = imid + 1;
            else
                imax = imid - 1;
        }
    }

    /* return the inverse of @imin. This is a negative number, but
     * also is ~imin the position where the value should be inserted. */
    imin = ~imin;
    NM_SET_OUT(out_idx_first, imin);
    NM_SET_OUT(out_idx_last, imin);
    return imin;
}

/*****************************************************************************/

/**
 * nm_array_find_bsearch:
 * @list: the list to search. It must be sorted according to @cmpfcn ordering.
 * @len: the number of elements in @list
 * @elem_size: the size in bytes of each element in the list
 * @needle: the value that is searched
 * @cmpfcn: the compare function. The elements @list are passed as first
 *   argument to @cmpfcn, while @needle is passed as second. Usually, the
 *   needle is the same data type as inside the list, however, that is
 *   not necessary, as long as @cmpfcn takes care to cast the two arguments
 *   accordingly.
 * @user_data: optional argument passed to @cmpfcn
 *
 * Performs binary search for @needle in @list. On success, returns the
 * (non-negative) index where the compare function found the searched element.
 * On success, it returns a negative value. Note that the return negative value
 * is the bitwise inverse of the position where the element should be inserted.
 *
 * If the list contains multiple matching elements, an arbitrary index is
 * returned.
 *
 * Returns: the index to the element in the list, or the (negative, bitwise inverted)
 *   position where it should be.
 */
gssize
nm_array_find_bsearch(gconstpointer    list,
                      gsize            len,
                      gsize            elem_size,
                      gconstpointer    needle,
                      GCompareDataFunc cmpfcn,
                      gpointer         user_data)
{
    return nm_array_find_bsearch_inline(list, len, elem_size, needle, cmpfcn, user_data);
}

/*****************************************************************************/

/**
 * nm_utils_get_start_time_for_pid:
 * @pid: the process identifier
 * @out_state: return the state character, like R, S, Z. See `man 5 proc`.
 * @out_ppid: parent process id
 *
 * Originally copied from polkit source (src/polkit/polkitunixprocess.c)
 * and adjusted.
 *
 * Returns: the timestamp when the process started (by parsing /proc/$PID/stat).
 * If an error occurs (e.g. the process does not exist), 0 is returned.
 *
 * The returned start time counts since boot, in the unit HZ (with HZ usually being (1/100) seconds)
 **/
guint64
nm_utils_get_start_time_for_pid(pid_t pid, char *out_state, pid_t *out_ppid)
{
    guint64              start_time;
    char                 filename[256];
    gs_free char        *contents = NULL;
    size_t               length;
    gs_free const char **tokens = NULL;
    char                *p;
    char                 state = ' ';
    gint64               ppid  = 0;

    start_time = 0;
    contents   = NULL;

    g_return_val_if_fail(pid > 0, 0);

    G_STATIC_ASSERT_EXPR(sizeof(GPid) >= sizeof(pid_t));

    nm_sprintf_buf(filename, "/proc/%" G_PID_FORMAT "/stat", (GPid) pid);

    if (!g_file_get_contents(filename, &contents, &length, NULL))
        goto fail;

    /* start time is the token at index 19 after the '(process name)' entry - since only this
     * field can contain the ')' character, search backwards for this to avoid malicious
     * processes trying to fool us
     */
    p = strrchr(contents, ')');
    if (!p)
        goto fail;
    p += 2; /* skip ') ' */
    if (p - contents >= (int) length)
        goto fail;

    state = p[0];

    tokens = nm_strsplit_set(p, " ");

    if (NM_PTRARRAY_LEN(tokens) < 20)
        goto fail;

    if (out_ppid) {
        ppid = _nm_utils_ascii_str_to_int64(tokens[1], 10, 1, G_MAXINT, 0);
        if (ppid == 0)
            goto fail;
    }

    start_time = _nm_utils_ascii_str_to_int64(tokens[19], 10, 1, G_MAXINT64, 0);
    if (start_time == 0)
        goto fail;

    NM_SET_OUT(out_state, state);
    NM_SET_OUT(out_ppid, ppid);
    return start_time;

fail:
    NM_SET_OUT(out_state, ' ');
    NM_SET_OUT(out_ppid, 0);
    return 0;
}

/*****************************************************************************/

/**
 * _nm_strv_sort:
 * @strv: pointer containing strings that will be sorted
 *   in-place, %NULL is allowed, unless @len indicates
 *   that there are more elements.
 * @len: the number of elements in strv. If negative,
 *   strv must be a NULL terminated array and the length
 *   will be calculated first. If @len is a positive
 *   number, @strv is allowed to contain %NULL strings
 *   too.
 *
 * Ascending sort of the array @strv inplace, using plain strcmp() string
 * comparison.
 */
void
_nm_strv_sort(const char **strv, gssize len)
{
    GCompareDataFunc cmp;
    gsize            l;

    if (len < 0) {
        l   = NM_PTRARRAY_LEN(strv);
        cmp = nm_strcmp_p_with_data;
    } else {
        l   = len;
        cmp = nm_strcmp0_p_with_data;
    }

    if (l <= 1)
        return;

    nm_assert(l <= (gsize) G_MAXINT);

    g_qsort_with_data(strv, l, sizeof(const char *), cmp, NULL);
}

/**
 * _nm_strv_cmp_n:
 * @strv1: a string array
 * @len1: the length of @strv1, or -1 for NULL terminated array.
 * @strv2: a string array
 * @len2: the length of @strv2, or -1 for NULL terminated array.
 *
 * Note that
 *   - len == -1 && strv == NULL
 * is treated like a %NULL argument and compares differently from
 * other arrays.
 *
 * Note that an empty array can be represented as
 *   - len == -1 &&  strv && !strv[0]
 *   - len ==  0 && !strv
 *   - len ==  0 &&  strv
 * These 3 forms all compare equal.
 * It also means, if length is 0, then it is permissible for strv to be %NULL.
 *
 * The strv arrays may contain %NULL strings (if len is positive).
 *
 * Returns: 0 if the arrays are equal (using strcmp).
 **/
int
_nm_strv_cmp_n(const char *const *strv1, gssize len1, const char *const *strv2, gssize len2)
{
    gsize n, n2;

    if (len1 < 0) {
        if (!strv1)
            return (len2 < 0 && !strv2) ? 0 : -1;
        n = NM_PTRARRAY_LEN(strv1);
    } else
        n = len1;

    if (len2 < 0) {
        if (!strv2)
            return 1;
        n2 = NM_PTRARRAY_LEN(strv2);
    } else
        n2 = len2;

    NM_CMP_DIRECT(n, n2);
    for (; n > 0; n--, strv1++, strv2++)
        NM_CMP_DIRECT_STRCMP0(*strv1, *strv2);
    return 0;
}

/*****************************************************************************/

/**
 * nm_utils_g_slist_find_str:
 * @list: the #GSList with NUL terminated strings to search
 * @needle: the needle string to look for.
 *
 * Search the list for @needle and return the first found match
 * (or %NULL if not found). Uses strcmp() for finding the first matching
 * element.
 *
 * Returns: the #GSList element with @needle as string value or
 *   %NULL if not found.
 */
GSList *
nm_utils_g_slist_find_str(const GSList *list, const char *needle)
{
    nm_assert(needle);

    for (; list; list = list->next) {
        nm_assert(list->data);
        if (nm_streq(list->data, needle))
            return (GSList *) list;
    }
    return NULL;
}

/**
 * nm_utils_g_slist_strlist_cmp:
 * @a: the left #GSList of strings
 * @b: the right #GSList of strings to compare.
 *
 * Compares two string lists. The data elements are compared with
 * strcmp(), allowing %NULL elements.
 *
 * Returns: 0, 1, or -1, depending on how the lists compare.
 */
int
nm_utils_g_slist_strlist_cmp(const GSList *a, const GSList *b)
{
    while (TRUE) {
        if (!a)
            return !b ? 0 : -1;
        if (!b)
            return 1;
        NM_CMP_DIRECT_STRCMP0(a->data, b->data);
        a = a->next;
        b = b->next;
    }
}

char *
nm_utils_g_slist_strlist_join(const GSList *a, const char *separator)
{
    GString *str = NULL;

    if (!a)
        return NULL;

    for (; a; a = a->next) {
        if (!str)
            str = g_string_new(NULL);
        else
            g_string_append(str, separator);
        g_string_append(str, a->data);
    }
    return g_string_free(str, FALSE);
}

/*****************************************************************************/

NMUtilsUserData *
_nm_utils_user_data_pack(int nargs, gconstpointer *args)
{
    int       i;
    gpointer *data;

    nm_assert(nargs > 0);
    nm_assert(args);

    data = g_slice_alloc(((gsize) nargs) * sizeof(gconstpointer));
    for (i = 0; i < nargs; i++)
        data[i] = (gpointer) args[i];
    return (NMUtilsUserData *) data;
}

void
_nm_utils_user_data_unpack(NMUtilsUserData *user_data, int nargs, ...)
{
    gpointer *data = (gpointer *) user_data;
    va_list   ap;
    int       i;

    nm_assert(data);
    nm_assert(nargs > 0);

    va_start(ap, nargs);
    for (i = 0; i < nargs; i++) {
        gpointer *dst;

        dst = va_arg(ap, gpointer *);
        nm_assert(dst);

        *dst = data[i];
    }
    va_end(ap);

    g_slice_free1(((gsize) nargs) * sizeof(gconstpointer), data);
}

/*****************************************************************************/

typedef struct {
    gpointer                    callback_user_data;
    GCancellable               *cancellable;
    GSource                    *source;
    NMUtilsInvokeOnIdleCallback callback;
    gulong                      cancelled_id;
} InvokeOnIdleData;

static void
_nm_utils_invoke_on_idle_complete(InvokeOnIdleData *data)
{
    nm_clear_g_signal_handler(data->cancellable, &data->cancelled_id);

    data->callback(data->callback_user_data, data->cancellable);

    nm_g_object_unref(data->cancellable);
    g_source_destroy(data->source);
    nm_g_slice_free(data);
}

static gboolean
_nm_utils_invoke_on_idle_cb_idle(gpointer user_data)
{
    _nm_utils_invoke_on_idle_complete(user_data);
    return G_SOURCE_REMOVE;
}

static void
_nm_utils_invoke_on_idle_cb_cancelled(GCancellable *cancellable, InvokeOnIdleData *data)
{
    if (data->cancelled_id == 0) {
        /* this can only happen during _nm_utils_invoke_on_idle_start(). Don't do anything,
         * we still schedule an idle action. */
        return;
    }

    /* On cancellation, we invoke the callback synchronously.
     *
     * Note that this is not thread-safe, meaning: you can only cancel the cancellable
     * while not iterating the GMainContext (that has the idle/timeout source attached).
     * Making this thread safe would be complicated, and it's simply not used by our
     * callers. */
    _nm_utils_invoke_on_idle_complete(data);
}

static void
_nm_utils_invoke_on_idle_start(gboolean                    use_timeout,
                               guint                       timeout_msec,
                               GCancellable               *cancellable,
                               NMUtilsInvokeOnIdleCallback callback,
                               gpointer                    callback_user_data)
{
    InvokeOnIdleData *data;
    GSource          *source;

    g_return_if_fail(callback);

    data  = g_slice_new(InvokeOnIdleData);
    *data = (InvokeOnIdleData){
        .callback           = callback,
        .callback_user_data = callback_user_data,
        .cancellable        = nm_g_object_ref(cancellable),
        .cancelled_id       = 0,
    };

    if (cancellable) {
        gulong cancelled_id;

        cancelled_id = g_cancellable_connect(cancellable,
                                             G_CALLBACK(_nm_utils_invoke_on_idle_cb_cancelled),
                                             data,
                                             NULL);
        if (cancelled_id == 0) {
            /* the cancellable is already cancelled. We still schedule an idle action. */
            use_timeout = FALSE;
        } else
            data->cancelled_id = cancelled_id;
    }

    if (use_timeout) {
        /* We use G_PRIORITY_DEFAULT_IDLE both for the with/without timeout
         * case. The reason is not strong, but it seems right that the caller
         * requests a lower priority than G_PRIORITY_DEFAULT. That is unlike
         * what g_timeout_add() would do. */
        source = nm_g_timeout_source_new(timeout_msec,
                                         G_PRIORITY_DEFAULT_IDLE,
                                         _nm_utils_invoke_on_idle_cb_idle,
                                         data,
                                         NULL);
    } else {
        source = nm_g_idle_source_new(G_PRIORITY_DEFAULT_IDLE,
                                      _nm_utils_invoke_on_idle_cb_idle,
                                      data,
                                      NULL);
    }

    /* use the current thread default context. */
    g_source_attach(source, g_main_context_get_thread_default());

    data->source = source;
}

void
nm_utils_invoke_on_idle(GCancellable               *cancellable,
                        NMUtilsInvokeOnIdleCallback callback,
                        gpointer                    callback_user_data)
{
    _nm_utils_invoke_on_idle_start(FALSE, 0, cancellable, callback, callback_user_data);
}

void
nm_utils_invoke_on_timeout(guint                       timeout_msec,
                           GCancellable               *cancellable,
                           NMUtilsInvokeOnIdleCallback callback,
                           gpointer                    callback_user_data)
{
    _nm_utils_invoke_on_idle_start(TRUE, timeout_msec, cancellable, callback, callback_user_data);
}

/*****************************************************************************/

int
nm_utils_getpagesize(void)
{
    static volatile int val = 0;
    long                l;
    int                 v;

    v = g_atomic_int_get(&val);

    if (G_UNLIKELY(v == 0)) {
        l = sysconf(_SC_PAGESIZE);

        g_return_val_if_fail(l > 0 && l < G_MAXINT, 4 * 1024);

        v = (int) l;
        if (!g_atomic_int_compare_and_exchange(&val, 0, v)) {
            v = g_atomic_int_get(&val);
            g_return_val_if_fail(v > 0, 4 * 1024);
        }
    }

    nm_assert(v > 0);
#if NM_MORE_ASSERTS > 5
    nm_assert(v == getpagesize());
    nm_assert(v == sysconf(_SC_PAGESIZE));
#endif

    return v;
}

gboolean
nm_utils_memeqzero(gconstpointer data, gsize length)
{
    const unsigned char *p = data;
    int                  len;

    /* Taken from https://github.com/rustyrussell/ccan/blob/9d2d2c49f053018724bcc6e37029da10b7c3d60d/ccan/mem/mem.c#L92,
     * CC-0 licensed. */

    /* Check first 16 bytes manually */
    for (len = 0; len < 16; len++) {
        if (!length)
            return TRUE;
        if (*p)
            return FALSE;
        p++;
        length--;
    }

    /* Now we know that's zero, memcmp with self. */
    return memcmp(data, p, length) == 0;
}

/**
 * nm_utils_bin2hexstr_fuller:
 * @addr: pointer of @length bytes. If @length is zero, this may
 *   also be %NULL.
 * @length: number of bytes in @addr. May also be zero, in which
 *   case this will return an empty string.
 * @delimiter: either '\0', otherwise the output string will have the
 *   given delimiter character between each two hex numbers.
 * @upper_case: if TRUE, use upper case ASCII characters for hex.
 * @with_leading_zero: if TRUE, then the hex values from 0 to 0xf
 *   are written as "00" to "0f", respectively. Otherwise, the leading
 *   zero is dropped. With @with_leading_zero set to FALSE, the resulting
 *   string may be shorter than expected. @delimiter must be set
 *   if @with_leading_zero is FALSE.
 * @out: if %NULL, the function will allocate a new buffer of
 *   either (@length*2+1) or MAX(1, (@length*3)) bytes, depending on whether
 *   a @delimiter is specified. In that case, the allocated buffer will
 *   be returned and must be freed by the caller.
 *   If not %NULL, the buffer must already be preallocated and contain
 *   at least (@length*2+1) or MAX(1, (@length*3)) bytes, depending on the delimiter.
 *   If @length is zero, then of course at least one byte will be allocated
 *   or @out (if given) must contain at least room for the trailing NUL byte.
 *
 * Returns: the binary value converted to a hex string. If @out is given,
 *   this always returns @out. If @out is %NULL, a newly allocated string
 *   is returned. This never returns %NULL, for buffers of length zero
 *   an empty string is returned.
 */
char *
nm_utils_bin2hexstr_fuller(gconstpointer addr,
                           gsize         length,
                           char          delimiter,
                           gboolean      upper_case,
                           gboolean      with_leading_zero,
                           char         *out)
{
    const guint8 *in     = addr;
    const char   *LOOKUP = upper_case ? "0123456789ABCDEF" : "0123456789abcdef";
    char         *out0;

    nm_assert(with_leading_zero || delimiter != '\0');

    /* @out must contain at least (MAX(1, @length*3)) bytes if @delimiter is set,
     * otherwise, @length*2+1. */

    if (!out)
        out = g_new(char, length == 0 ? 1u : (delimiter == '\0' ? length * 2u + 1u : length * 3u));

    out0 = out;

    if (length > 0) {
        nm_assert(in);
        for (;;) {
            const guint8 v = *in++;
            guint8       v_hi;

            v_hi = (v >> 4);
            if (v_hi != 0 || with_leading_zero) {
                nm_assert(v_hi < 16);
                *out++ = LOOKUP[v_hi];
            }
            *out++ = LOOKUP[v & 0x0F];
            length--;
            if (length == 0)
                break;
            if (delimiter != '\0')
                *out++ = delimiter;
        }
    }

    *out = '\0';
    return out0;
}

char *
_nm_utils_bin2hexstr(gconstpointer src, gsize len, int final_len)
{
    char *result;
    gsize buflen = (len * 2) + 1;

    nm_assert(src);
    nm_assert(len > 0 && (buflen - 1) / 2 == len);
    nm_assert(final_len < 0 || (gsize) final_len < buflen);

    result = g_malloc(buflen);

    nm_utils_bin2hexstr_full(src, len, '\0', FALSE, result);

    /* Cut converted key off at the correct length for this cipher type */
    if (final_len >= 0 && (gsize) final_len < buflen)
        result[final_len] = '\0';

    return result;
}

guint8 *
nm_utils_hexstr2bin_full(const char *hexstr,
                         gboolean    allow_0x_prefix,
                         gboolean    delimiter_required,
                         gboolean    hexdigit_pairs_required,
                         const char *delimiter_candidates,
                         gsize       required_len,
                         guint8     *buffer,
                         gsize       buffer_len,
                         gsize      *out_len)
{
    const char *in            = hexstr;
    guint8     *out           = buffer;
    gboolean    delimiter_has = TRUE;
    guint8      delimiter     = '\0';
    gsize       len;

    nm_assert(hexstr);
    nm_assert(buffer);
    nm_assert(required_len > 0 || out_len);

    if (allow_0x_prefix && in[0] == '0' && in[1] == 'x')
        in += 2;

    while (TRUE) {
        const guint8 d1 = in[0];
        guint8       d2;
        int          i1, i2;

        i1 = nm_utils_hexchar_to_int(d1);
        if (i1 < 0)
            goto fail;

        /* If there's no leading zero (ie "aa:b:cc") then fake it */
        d2 = in[1];
        if (d2 && (i2 = nm_utils_hexchar_to_int(d2)) >= 0) {
            *out++ = (i1 << 4) + i2;
            d2     = in[2];
            if (!d2)
                break;
            in += 2;
        } else {
            /* Fake leading zero */
            *out++ = i1;
            if (!d2) {
                if (!delimiter_has || hexdigit_pairs_required) {
                    /* when using no delimiter, there must be pairs of hex chars */
                    goto fail;
                }
                break;
            } else if (hexdigit_pairs_required)
                goto fail;
            in += 1;
        }

        if (--buffer_len == 0)
            goto fail;

        if (delimiter_has) {
            if (d2 != delimiter) {
                if (delimiter)
                    goto fail;
                if (delimiter_candidates) {
                    while (delimiter_candidates[0]) {
                        if (delimiter_candidates++[0] == d2)
                            delimiter = d2;
                    }
                }
                if (!delimiter) {
                    if (delimiter_required)
                        goto fail;
                    delimiter_has = FALSE;
                    continue;
                }
            }
            in++;
        }
    }

    len = out - buffer;
    if (required_len == 0 || len == required_len) {
        NM_SET_OUT(out_len, len);
        return buffer;
    }

fail:
    NM_SET_OUT(out_len, 0);
    return NULL;
}

guint8 *
nm_utils_hexstr2bin_alloc(const char *hexstr,
                          gboolean    allow_0x_prefix,
                          gboolean    delimiter_required,
                          const char *delimiter_candidates,
                          gsize       required_len,
                          gsize      *out_len)
{
    guint8 *buffer;
    gsize   buffer_len, len;

    if (G_UNLIKELY(!hexstr)) {
        NM_SET_OUT(out_len, 0);
        g_return_val_if_fail(hexstr, NULL);
    }

    nm_assert(required_len > 0 || out_len);

    if (allow_0x_prefix && hexstr[0] == '0' && hexstr[1] == 'x')
        hexstr += 2;

    if (!hexstr[0])
        goto fail;

    if (required_len > 0)
        buffer_len = required_len;
    else
        buffer_len = strlen(hexstr) / 2 + 3;

    buffer = g_malloc(buffer_len);

    if (nm_utils_hexstr2bin_full(hexstr,
                                 FALSE,
                                 delimiter_required,
                                 FALSE,
                                 delimiter_candidates,
                                 required_len,
                                 buffer,
                                 buffer_len,
                                 &len)) {
        NM_SET_OUT(out_len, len);
        return buffer;
    }

    g_free(buffer);

fail:
    NM_SET_OUT(out_len, 0);
    return NULL;
}

/*****************************************************************************/

GVariant *
nm_utils_gvariant_vardict_filter(GVariant *src,
                                 gboolean (*filter_fcn)(const char *key,
                                                        GVariant   *val,
                                                        char      **out_key,
                                                        GVariant  **out_val,
                                                        gpointer    user_data),
                                 gpointer user_data)
{
    GVariantIter    iter;
    GVariantBuilder builder;
    const char     *key;
    GVariant       *val;

    g_return_val_if_fail(src && g_variant_is_of_type(src, G_VARIANT_TYPE_VARDICT), NULL);
    g_return_val_if_fail(filter_fcn, NULL);

    g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);

    g_variant_iter_init(&iter, src);
    while (g_variant_iter_next(&iter, "{&sv}", &key, &val)) {
        _nm_unused gs_unref_variant GVariant *val_free = val;
        gs_free char                         *key2     = NULL;
        gs_unref_variant GVariant            *val2     = NULL;

        if (filter_fcn(key, val, &key2, &val2, user_data)) {
            g_variant_builder_add(&builder, "{sv}", key2 ?: key, val2 ?: val);
        }
    }

    return g_variant_builder_end(&builder);
}

static gboolean
_gvariant_vardict_filter_drop_one(const char *key,
                                  GVariant   *val,
                                  char      **out_key,
                                  GVariant  **out_val,
                                  gpointer    user_data)
{
    return !nm_streq(key, user_data);
}

GVariant *
nm_utils_gvariant_vardict_filter_drop_one(GVariant *src, const char *key)
{
    return nm_utils_gvariant_vardict_filter(src, _gvariant_vardict_filter_drop_one, (gpointer) key);
}

/*****************************************************************************/

static gboolean
debug_key_matches(const char *key, const char *token, guint length)
{
    /* may not call GLib functions: see note in g_parse_debug_string() */
    for (; length; length--, key++, token++) {
        char k = (*key == '_') ? '-' : g_ascii_tolower(*key);
        char t = (*token == '_') ? '-' : g_ascii_tolower(*token);

        if (k != t)
            return FALSE;
    }

    return *key == '\0';
}

/**
 * nm_utils_parse_debug_string:
 * @string: the string to parse
 * @keys: the debug keys
 * @nkeys: number of entries in @keys
 *
 * Similar to g_parse_debug_string(), but does not special
 * case "help" or "all".
 *
 * Returns: the flags
 */
guint
nm_utils_parse_debug_string(const char *string, const GDebugKey *keys, guint nkeys)
{
    guint       i;
    guint       result = 0;
    const char *q;

    if (string == NULL)
        return 0;

    while (*string) {
        q = strpbrk(string, ":;, \t");
        if (!q)
            q = string + strlen(string);

        for (i = 0; i < nkeys; i++) {
            if (debug_key_matches(keys[i].key, string, q - string))
                result |= keys[i].value;
        }

        string = q;
        if (*string)
            string++;
    }

    return result;
}

/*****************************************************************************/

GSource *_nm_g_source_sentinel[] = {
    NULL,
};

GSource *
_nm_g_source_sentinel_get_init(GSource **p_source)
{
    static const GSourceFuncs source_funcs = {
        NULL,
    };
    GSource *source;

    source = g_source_new((GSourceFuncs *) &source_funcs, sizeof(GSource));
    g_source_set_priority(source, G_PRIORITY_DEFAULT_IDLE);
    g_source_set_name(source, "nm_g_source_sentinel");

    if (!g_atomic_pointer_compare_and_exchange(p_source, NULL, source)) {
        g_source_unref(source);
        source = g_atomic_pointer_get(p_source);
        nm_assert(source);
    }

    return source;
}

/*****************************************************************************/

GSource *
nm_g_idle_source_new(int            priority,
                     GSourceFunc    func,
                     gpointer       user_data,
                     GDestroyNotify destroy_notify)
{
    GSource *source;

    source = g_idle_source_new();
    if (priority != G_PRIORITY_DEFAULT)
        g_source_set_priority(source, priority);
    g_source_set_callback(source, func, user_data, destroy_notify);
    return source;
}

GSource *
nm_g_timeout_source_new(guint          timeout_msec,
                        int            priority,
                        GSourceFunc    func,
                        gpointer       user_data,
                        GDestroyNotify destroy_notify)
{
    GSource *source;

    source = g_timeout_source_new(timeout_msec);
    if (priority != G_PRIORITY_DEFAULT)
        g_source_set_priority(source, priority);
    g_source_set_callback(source, func, user_data, destroy_notify);
    return source;
}

GSource *
nm_g_timeout_source_new_seconds(guint          timeout_sec,
                                int            priority,
                                GSourceFunc    func,
                                gpointer       user_data,
                                GDestroyNotify destroy_notify)
{
    GSource *source;

    source = g_timeout_source_new_seconds(timeout_sec);
    if (priority != G_PRIORITY_DEFAULT)
        g_source_set_priority(source, priority);
    g_source_set_callback(source, func, user_data, destroy_notify);
    return source;
}

GSource *
nm_g_unix_signal_source_new(int            signum,
                            int            priority,
                            GSourceFunc    handler,
                            gpointer       user_data,
                            GDestroyNotify notify)
{
    GSource *source;

    source = g_unix_signal_source_new(signum);

    if (priority != G_PRIORITY_DEFAULT)
        g_source_set_priority(source, priority);
    g_source_set_callback(source, handler, user_data, notify);
    return source;
}

GSource *
nm_g_unix_fd_source_new(int               fd,
                        GIOCondition      io_condition,
                        int               priority,
                        GUnixFDSourceFunc source_func,
                        gpointer          user_data,
                        GDestroyNotify    destroy_notify)
{
    GSource *source;

    source = g_unix_fd_source_new(fd, io_condition);

    if (priority != G_PRIORITY_DEFAULT)
        g_source_set_priority(source, priority);
    g_source_set_callback(source, G_SOURCE_FUNC(source_func), user_data, destroy_notify);
    return source;
}

GSource *
nm_g_child_watch_source_new(GPid            pid,
                            int             priority,
                            GChildWatchFunc handler,
                            gpointer        user_data,
                            GDestroyNotify  notify)
{
    GSource *source;

    source = g_child_watch_source_new(pid);

    if (priority != G_PRIORITY_DEFAULT)
        g_source_set_priority(source, priority);
    g_source_set_callback(source, G_SOURCE_FUNC(handler), user_data, notify);
    return source;
}

/*****************************************************************************/

#define _CTX_LOG(fmt, ...)                                                                       \
    G_STMT_START                                                                                 \
    {                                                                                            \
        if (FALSE) {                                                                             \
            gint64 _ts = g_get_monotonic_time() / 100;                                           \
                                                                                                 \
            g_printerr(">>>> [%" G_GINT64_FORMAT ".%05" G_GINT64_FORMAT "] [src:%p]: " fmt "\n", \
                       _ts / 10000,                                                              \
                       _ts % 10000,                                                              \
                       (ctx_src),                                                                \
                       ##__VA_ARGS__);                                                           \
        }                                                                                        \
    }                                                                                            \
    G_STMT_END

typedef struct {
    int   fd;
    guint events;
    guint registered_events;
    union {
        int  one;
        int *many;
    } idx;
    gpointer tag;
    bool     stale : 1;
    bool     has_many_idx : 1;
} PollData;

typedef struct {
    GSource       source;
    GMainContext *context;
    GHashTable   *fds;
    GPollFD      *fds_arr;
    guint         fds_len;
    int           max_priority;
    bool          acquired : 1;
} CtxIntegSource;

static void
_poll_data_free(gpointer user_data)
{
    PollData *poll_data = user_data;

    if (poll_data->has_many_idx)
        g_free(poll_data->idx.many);
    nm_g_slice_free(poll_data);
}

static void
_ctx_integ_source_reacquire(CtxIntegSource *ctx_src)
{
    if (G_LIKELY(ctx_src->acquired && g_main_context_is_owner(ctx_src->context)))
        return;

    /* the parent context now iterates on a different thread.
     * We need to release and reacquire the inner context. */

    if (ctx_src->acquired)
        g_main_context_release(ctx_src->context);

    if (G_UNLIKELY(!g_main_context_acquire(ctx_src->context))) {
        /* Nobody is supposed to reacquire the context while we use it. This is a bug
         * of the user. */
        ctx_src->acquired = FALSE;
        g_return_if_reached();
    }
    ctx_src->acquired = TRUE;
}

static gboolean
_ctx_integ_source_prepare(GSource *source, int *out_timeout)
{
    CtxIntegSource  *ctx_src = ((CtxIntegSource *) source);
    int              max_priority;
    int              timeout = -1;
    gboolean         any_ready;
    GHashTableIter   h_iter;
    PollData        *poll_data;
    gboolean         fds_changed;
    GPollFD          new_fds_stack[300u / sizeof(GPollFD)];
    gs_free GPollFD *new_fds_heap = NULL;
    GPollFD         *new_fds;
    guint            new_fds_len;
    guint            new_fds_alloc;
    guint            i;

    _CTX_LOG("prepare...");

    _ctx_integ_source_reacquire(ctx_src);

    any_ready = g_main_context_prepare(ctx_src->context, &max_priority);

    new_fds_alloc = NM_MAX(G_N_ELEMENTS(new_fds_stack), ctx_src->fds_len);

    if (new_fds_alloc > G_N_ELEMENTS(new_fds_stack)) {
        new_fds_heap = g_new(GPollFD, new_fds_alloc);
        new_fds      = new_fds_heap;
    } else
        new_fds = new_fds_stack;

    for (;;) {
        int l;

        nm_assert(new_fds_alloc <= (guint) G_MAXINT);

        l = g_main_context_query(ctx_src->context,
                                 max_priority,
                                 &timeout,
                                 new_fds,
                                 (int) new_fds_alloc);
        nm_assert(l >= 0);

        new_fds_len = (guint) l;

        if (G_LIKELY(new_fds_len <= new_fds_alloc))
            break;

        new_fds_alloc = new_fds_len;
        g_free(new_fds_heap);
        new_fds_heap = g_new(GPollFD, new_fds_alloc);
        new_fds      = new_fds_heap;
    }

    fds_changed = FALSE;
    if (new_fds_len != ctx_src->fds_len)
        fds_changed = TRUE;
    else {
        for (i = 0; i < new_fds_len; i++) {
            if (new_fds[i].fd != ctx_src->fds_arr[i].fd
                || new_fds[i].events != ctx_src->fds_arr[i].events) {
                fds_changed = TRUE;
                break;
            }
        }
    }

    if (G_UNLIKELY(fds_changed)) {
        g_free(ctx_src->fds_arr);
        ctx_src->fds_len = new_fds_len;
        if (G_LIKELY(new_fds == new_fds_stack) || new_fds_alloc != new_fds_len)
            ctx_src->fds_arr = nm_memdup(new_fds, sizeof(*new_fds) * new_fds_len);
        else
            ctx_src->fds_arr = g_steal_pointer(&new_fds_heap);

        g_hash_table_iter_init(&h_iter, ctx_src->fds);
        while (g_hash_table_iter_next(&h_iter, (gpointer *) &poll_data, NULL))
            poll_data->stale = TRUE;

        for (i = 0; i < ctx_src->fds_len; i++) {
            const GPollFD *fd = &ctx_src->fds_arr[i];

            poll_data = g_hash_table_lookup(ctx_src->fds, &fd->fd);

            if (G_UNLIKELY(!poll_data)) {
                poll_data  = g_slice_new(PollData);
                *poll_data = (PollData){
                    .fd                = fd->fd,
                    .idx.one           = i,
                    .has_many_idx      = FALSE,
                    .events            = fd->events,
                    .registered_events = 0,
                    .tag               = NULL,
                    .stale             = FALSE,
                };
                g_hash_table_add(ctx_src->fds, poll_data);
                nm_assert(poll_data == g_hash_table_lookup(ctx_src->fds, &fd->fd));
                continue;
            }

            if (G_LIKELY(poll_data->stale)) {
                if (poll_data->has_many_idx) {
                    g_free(poll_data->idx.many);
                    poll_data->has_many_idx = FALSE;
                }
                poll_data->events  = fd->events;
                poll_data->idx.one = i;
                poll_data->stale   = FALSE;
                continue;
            }

            /* How odd. We have duplicate FDs. In fact, currently g_main_context_query() always
             * coalesces the FDs and this cannot happen. However, that is not documented behavior,
             * so we should not rely on that. So we need to keep a list of indexes... */
            poll_data->events |= fd->events;
            if (!poll_data->has_many_idx) {
                int idx0;

                idx0                    = poll_data->idx.one;
                poll_data->has_many_idx = TRUE;
                poll_data->idx.many     = g_new(int, 4);
                poll_data->idx.many[0]  = 2; /* number allocated */
                poll_data->idx.many[1]  = 2; /* number used */
                poll_data->idx.many[2]  = idx0;
                poll_data->idx.many[3]  = i;
            } else {
                if (poll_data->idx.many[0] == poll_data->idx.many[1]) {
                    poll_data->idx.many[0] *= 2;
                    poll_data->idx.many =
                        g_realloc(poll_data->idx.many, sizeof(int) * (2 + poll_data->idx.many[0]));
                }
                poll_data->idx.many[2 + poll_data->idx.many[1]] = i;
                poll_data->idx.many[1]++;
            }
        }

        g_hash_table_iter_init(&h_iter, ctx_src->fds);
        while (g_hash_table_iter_next(&h_iter, (gpointer *) &poll_data, NULL)) {
            if (poll_data->stale) {
                nm_assert(poll_data->tag);
                nm_assert(poll_data->events == poll_data->registered_events);
                _CTX_LOG("prepare: remove poll fd=%d, events=0x%x",
                         poll_data->fd,
                         poll_data->events);
                g_source_remove_unix_fd(&ctx_src->source, poll_data->tag);
                g_hash_table_iter_remove(&h_iter);
                continue;
            }
            if (!poll_data->tag) {
                _CTX_LOG("prepare: add poll fd=%d, events=0x%x", poll_data->fd, poll_data->events);
                poll_data->registered_events = poll_data->events;
                poll_data->tag               = g_source_add_unix_fd(&ctx_src->source,
                                                      poll_data->fd,
                                                      poll_data->registered_events);
                continue;
            }
            if (poll_data->registered_events != poll_data->events) {
                _CTX_LOG("prepare: update poll fd=%d, events=0x%x",
                         poll_data->fd,
                         poll_data->events);
                poll_data->registered_events = poll_data->events;
                g_source_modify_unix_fd(&ctx_src->source,
                                        poll_data->tag,
                                        poll_data->registered_events);
            }
        }
    }

    NM_SET_OUT(out_timeout, timeout);
    ctx_src->max_priority = max_priority;

    _CTX_LOG("prepare: done, any-ready=%d, timeout=%d, max-priority=%d",
             any_ready,
             timeout,
             max_priority);

    /* we always need to poll, because we have some file descriptors. */
    return FALSE;
}

static gboolean
_ctx_integ_source_check(GSource *source)
{
    CtxIntegSource *ctx_src = ((CtxIntegSource *) source);
    GHashTableIter  h_iter;
    gboolean        some_ready;
    PollData       *poll_data;

    nm_assert(ctx_src->context);

    _CTX_LOG("check");

    _ctx_integ_source_reacquire(ctx_src);

    g_hash_table_iter_init(&h_iter, ctx_src->fds);
    while (g_hash_table_iter_next(&h_iter, (gpointer *) &poll_data, NULL)) {
        guint revents;

        revents = g_source_query_unix_fd(&ctx_src->source, poll_data->tag);
        if (G_UNLIKELY(poll_data->has_many_idx)) {
            int  num   = poll_data->idx.many[1];
            int *p_idx = &poll_data->idx.many[2];

            for (; num > 0; num--, p_idx++)
                ctx_src->fds_arr[*p_idx].revents = revents;
        } else
            ctx_src->fds_arr[poll_data->idx.one].revents = revents;
    }

    nm_assert(ctx_src->fds_len <= (guint) G_MAXINT);

    some_ready = g_main_context_check(ctx_src->context,
                                      ctx_src->max_priority,
                                      ctx_src->fds_arr,
                                      (int) ctx_src->fds_len);

    _CTX_LOG("check (some-ready=%d)...", some_ready);

    return some_ready;
}

static gboolean
_ctx_integ_source_dispatch(GSource *source, GSourceFunc callback, gpointer user_data)
{
    CtxIntegSource *ctx_src = ((CtxIntegSource *) source);

    nm_assert(ctx_src->context);

    _ctx_integ_source_reacquire(ctx_src);

    _CTX_LOG("dispatch");

    g_main_context_dispatch(ctx_src->context);

    return G_SOURCE_CONTINUE;
}

static void
_ctx_integ_source_finalize(GSource *source)
{
    CtxIntegSource *ctx_src = ((CtxIntegSource *) source);
    GHashTableIter  h_iter;
    PollData       *poll_data;

    g_return_if_fail(ctx_src->context);

    _CTX_LOG("finalize...");

    g_hash_table_iter_init(&h_iter, ctx_src->fds);
    while (g_hash_table_iter_next(&h_iter, (gpointer *) &poll_data, NULL)) {
        nm_assert(poll_data->tag);
        _CTX_LOG("prepare: remove poll fd=%d, events=0x%x", poll_data->fd, poll_data->events);
        g_source_remove_unix_fd(&ctx_src->source, poll_data->tag);
        g_hash_table_iter_remove(&h_iter);
    }

    nm_clear_pointer(&ctx_src->fds, g_hash_table_unref);
    nm_clear_g_free(&ctx_src->fds_arr);
    ctx_src->fds_len = 0;

    if (ctx_src->acquired) {
        ctx_src->acquired = FALSE;
        g_main_context_release(ctx_src->context);
    }

    nm_clear_pointer(&ctx_src->context, g_main_context_unref);
}

static GSourceFuncs ctx_integ_source_funcs = {
    .prepare  = _ctx_integ_source_prepare,
    .check    = _ctx_integ_source_check,
    .dispatch = _ctx_integ_source_dispatch,
    .finalize = _ctx_integ_source_finalize,
};

/**
 * nm_utils_g_main_context_create_integrate_source:
 * @inner_context: the inner context that will be integrated to an
 *   outer #GMainContext.
 *
 * By integrating the inner context with an outer context, when iterating the outer
 * context sources on the inner context will be dispatched. Note that while the
 * created source exists, the @inner_context will be acquired. The user gets restricted
 * what to do with the inner context. In particular while the inner context is integrated,
 * the user should not acquire the inner context again or explicitly iterate it. What
 * the user of course still can (and wants to) do is attaching new sources to the inner
 * context.
 *
 * Note that GSource has a priority. While each context dispatches events based on
 * their source's priorities, the outer context dispatches to the inner context
 * only with one priority (the priority of the created source). That is, the sources
 * from the two contexts are kept separate and are not sorted by their priorities.
 *
 * Returns: a newly created GSource that should be attached to the
 *   outer context.
 */
GSource *
nm_utils_g_main_context_create_integrate_source(GMainContext *inner_context)
{
    CtxIntegSource *ctx_src;

    g_return_val_if_fail(inner_context, NULL);

    if (!g_main_context_acquire(inner_context)) {
        /* We require to acquire the context while it's integrated. We need to keep it acquired
         * for the entire duration.
         *
         * This is also necessary because g_source_attach() only wakes up the context, if
         * the context is currently acquired. */
        g_return_val_if_reached(NULL);
    }

    ctx_src = (CtxIntegSource *) g_source_new(&ctx_integ_source_funcs, sizeof(CtxIntegSource));

    g_source_set_name(&ctx_src->source, "ContextIntegrateSource");

    ctx_src->context  = g_main_context_ref(inner_context);
    ctx_src->fds      = g_hash_table_new_full(nm_pint_hash, nm_pint_equal, _poll_data_free, NULL);
    ctx_src->fds_len  = 0;
    ctx_src->fds_arr  = NULL;
    ctx_src->acquired = TRUE;
    ctx_src->max_priority = G_MAXINT;

    _CTX_LOG("create new integ-source for %p", inner_context);

    return &ctx_src->source;
}

/*****************************************************************************/

void
nm_utils_ifname_cpy(char *dst, const char *name)
{
    int i;

    g_return_if_fail(dst);
    g_return_if_fail(name && name[0]);

    nm_assert(nm_utils_ifname_valid_kernel(name, NULL));

    /* ensures NUL padding of the entire IFNAMSIZ buffer. */

    for (i = 0; i < (int) IFNAMSIZ && name[i] != '\0'; i++)
        dst[i] = name[i];

    nm_assert(name[i] == '\0');

    for (; i < (int) IFNAMSIZ; i++)
        dst[i] = '\0';
}

/*****************************************************************************/

gboolean
nm_utils_ifname_valid_kernel(const char *name, GError **error)
{
    int i;

    /* This function follows kernel's interface validation
     * function dev_valid_name() in net/core/dev.c.
     */

    if (!name) {
        g_set_error_literal(error,
                            NM_UTILS_ERROR,
                            NM_UTILS_ERROR_UNKNOWN,
                            _("interface name is missing"));
        return FALSE;
    }

    if (name[0] == '\0') {
        g_set_error_literal(error,
                            NM_UTILS_ERROR,
                            NM_UTILS_ERROR_UNKNOWN,
                            _("interface name is too short"));
        return FALSE;
    }

    if (name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'))) {
        g_set_error_literal(error,
                            NM_UTILS_ERROR,
                            NM_UTILS_ERROR_UNKNOWN,
                            _("interface name is reserved"));
        return FALSE;
    }

    for (i = 0; i < IFNAMSIZ; i++) {
        char ch = name[i];

        if (ch == '\0')
            return TRUE;
        if (NM_IN_SET(ch, '/', ':') || g_ascii_isspace(ch)) {
            g_set_error_literal(error,
                                NM_UTILS_ERROR,
                                NM_UTILS_ERROR_UNKNOWN,
                                _("interface name contains an invalid character"));
            return FALSE;
        }
    }

    g_set_error_literal(error,
                        NM_UTILS_ERROR,
                        NM_UTILS_ERROR_UNKNOWN,
                        _("interface name is longer than 15 characters"));
    return FALSE;
}

/*****************************************************************************/

static gboolean
_nm_utils_ifname_valid_kernel(const char *name, GError **error)
{
    if (!nm_utils_ifname_valid_kernel(name, error))
        return FALSE;

    if (strchr(name, '%')) {
        /* Kernel's dev_valid_name() accepts (almost) any binary up to 15 chars.
         * However, '%' is treated special as a format specifier. Try
         *
         *   ip link add 'dummy%dx' type dummy
         *
         * Don't allow that for "connection.interface-name", which either
         * matches an existing netdev name (thus, it cannot have a '%') or
         * is used to configure a name (in which case we don't want kernel
         * to replace the format specifier). */
        g_set_error_literal(error,
                            NM_UTILS_ERROR,
                            NM_UTILS_ERROR_UNKNOWN,
                            _("'%%' is not allowed in interface names"));
        return FALSE;
    }

    if (NM_IN_STRSET(name, "all", "default", "bonding_masters")) {
        /* Certain names are not allowed. The "all" and "default" names are reserved
         * due to their directories in "/proc/sys/net/ipv4/conf/" and "/proc/sys/net/ipv6/conf/".
         *
         * Also, there is "/sys/class/net/bonding_masters" file.
         */
        nm_utils_error_set(error,
                           NM_UTILS_ERROR_UNKNOWN,
                           _("'%s' is not allowed as interface name"),
                           name);
        return FALSE;
    }

    return TRUE;
}

static gboolean
_nm_utils_ifname_valid_ovs(const char *name, GError **error)
{
    const char *ch;

    /* OVS actually accepts a wider range of chars (all printable UTF-8 chars),
     * NetworkManager restricts this to ASCII char as it's a safer option for
     * now since OVS is not well documented on this matter.
     **/
    for (ch = name; *ch; ++ch) {
        if (*ch == '\\' || *ch == '/' || !g_ascii_isgraph(*ch)) {
            g_set_error_literal(error,
                                NM_UTILS_ERROR,
                                NM_UTILS_ERROR_UNKNOWN,
                                _("interface name must be alphanumerical with "
                                  "no forward or backward slashes"));
            return FALSE;
        }
    };
    return TRUE;
}

gboolean
nm_utils_ifname_valid(const char *name, NMUtilsIfaceType type, GError **error)
{
    g_return_val_if_fail(!error || !(*error), FALSE);

    if (!name || !(name[0])) {
        g_set_error_literal(error,
                            NM_UTILS_ERROR,
                            NM_UTILS_ERROR_UNKNOWN,
                            _("interface name must not be empty"));
        return FALSE;
    }

    if (!g_utf8_validate(name, -1, NULL)) {
        g_set_error_literal(error,
                            NM_UTILS_ERROR,
                            NM_UTILS_ERROR_UNKNOWN,
                            _("interface name must be UTF-8 encoded"));
        return FALSE;
    }

    switch (type) {
    case NMU_IFACE_KERNEL:
        return _nm_utils_ifname_valid_kernel(name, error);
    case NMU_IFACE_OVS:
        return _nm_utils_ifname_valid_ovs(name, error);
    case NMU_IFACE_OVS_AND_KERNEL:
        return _nm_utils_ifname_valid_kernel(name, error)
               && _nm_utils_ifname_valid_ovs(name, error);
    case NMU_IFACE_ANY:
    {
        gs_free_error GError *local = NULL;

        if (_nm_utils_ifname_valid_kernel(name, error ? &local : NULL))
            return TRUE;
        if (_nm_utils_ifname_valid_ovs(name, NULL))
            return TRUE;
        if (error)
            g_propagate_error(error, g_steal_pointer(&local));
        return FALSE;
    }
    }

    g_return_val_if_reached(FALSE);
}

/*****************************************************************************/

void
_nm_str_buf_ensure_size(NMStrBuf *strbuf, gsize new_size, gboolean reserve_exact)
{
    _nm_str_buf_assert(strbuf);

    /* Currently, this only supports strictly growing the buffer. */
    nm_assert(new_size > strbuf->_priv_allocated);

    if (!reserve_exact) {
        new_size = nm_utils_get_next_realloc_size(!strbuf->_priv_do_bzero_mem, new_size);
    }

    if (strbuf->_priv_malloced) {
        strbuf->_priv_str = nm_secret_mem_realloc(strbuf->_priv_str,
                                                  strbuf->_priv_do_bzero_mem,
                                                  strbuf->_priv_allocated,
                                                  new_size);
    } else {
        char *old = strbuf->_priv_str;

        strbuf->_priv_str = g_malloc(new_size);
        if (strbuf->_priv_len > 0) {
            memcpy(strbuf->_priv_str, old, strbuf->_priv_len);
            if (strbuf->_priv_do_bzero_mem)
                nm_explicit_bzero(old, strbuf->_priv_len);
        }
        strbuf->_priv_malloced = TRUE;
    }
    strbuf->_priv_allocated = new_size;
}

void
nm_str_buf_append_printfv(NMStrBuf *strbuf, const char *format, va_list args)
{
    va_list args_copy;
    gsize   available;
    int     l;

    _nm_str_buf_assert(strbuf);

    available = strbuf->_priv_allocated - strbuf->_priv_len;

    nm_assert(available < G_MAXULONG);

    va_copy(args_copy, args);
    l = g_vsnprintf(strbuf->_priv_allocated > 0 ? &strbuf->_priv_str[strbuf->_priv_len] : NULL,
                    available,
                    format,
                    args_copy);
    va_end(args_copy);

    nm_assert(l >= 0);
    nm_assert(l < G_MAXINT);

    if ((gsize) l >= available) {
        gsize l2;

        if (l == 0)
            return;

        l2 = ((gsize) l) + 1u;

        nm_str_buf_maybe_expand(strbuf, l2, FALSE);

        va_copy(args_copy, args);
        l = g_vsnprintf(&strbuf->_priv_str[strbuf->_priv_len], l2, format, args_copy);
        va_end(args_copy);

        nm_assert(l >= 0);
        nm_assert((gsize) l == l2 - 1u);
    }

    strbuf->_priv_len += (gsize) l;
}

/*****************************************************************************/

/**
 * nm_indirect_g_free:
 * @arg: a pointer to a pointer that is to be freed.
 *
 * This does the same as nm_clear_g_free(arg) (g_clear_pointer (arg, g_free)).
 * This is for example useful when you have a GArray with pointers and a
 * clear function to free them. g_array_set_clear_func()'s destroy notify
 * function gets a pointer to the array location, so we have to follow
 * the first pointer.
 */
void
nm_indirect_g_free(gpointer arg)
{
    gpointer *p = arg;

    nm_clear_g_free(p);
}

/*****************************************************************************/

static char *
attribute_escape(const char *src, char c1, char c2)
{
    char *ret, *dest;

    dest = ret = g_malloc(strlen(src) * 2 + 1);

    while (*src) {
        if (*src == c1 || *src == c2 || *src == '\\')
            *dest++ = '\\';
        *dest++ = *src++;
    }
    *dest++ = '\0';

    return ret;
}

void
_nm_utils_format_variant_attributes_full(GString                             *str,
                                         const NMUtilsNamedValue             *values,
                                         guint                                num_values,
                                         const NMVariantAttributeSpec *const *spec,
                                         char                                 attr_separator,
                                         char                                 key_value_separator)
{
    const NMVariantAttributeSpec *const *s;
    const char                          *name, *value;
    GVariant                            *variant;
    char                                *escaped;
    char                                 buf[64];
    char                                 sep = 0;
    guint                                i;

    for (i = 0; i < num_values; i++) {
        name    = values[i].name;
        variant = values[i].value_ptr;
        value   = NULL;
        s       = NULL;

        if (spec) {
            for (s = spec; *s; s++) {
                if (nm_streq0((*s)->name, name))
                    break;
            }

            if (!*s)
                continue;
        }

        if (g_variant_is_of_type(variant, G_VARIANT_TYPE_UINT32))
            value = nm_sprintf_buf(buf, "%u", g_variant_get_uint32(variant));
        else if (g_variant_is_of_type(variant, G_VARIANT_TYPE_INT32))
            value = nm_sprintf_buf(buf, "%d", (int) g_variant_get_int32(variant));
        else if (g_variant_is_of_type(variant, G_VARIANT_TYPE_UINT64))
            value = nm_sprintf_buf(buf, "%" G_GUINT64_FORMAT, g_variant_get_uint64(variant));
        else if (g_variant_is_of_type(variant, G_VARIANT_TYPE_BYTE))
            value = nm_sprintf_buf(buf, "%hhu", g_variant_get_byte(variant));
        else if (g_variant_is_of_type(variant, G_VARIANT_TYPE_BOOLEAN))
            value = g_variant_get_boolean(variant) ? "true" : "false";
        else if (g_variant_is_of_type(variant, G_VARIANT_TYPE_STRING))
            value = g_variant_get_string(variant, NULL);
        else if (g_variant_is_of_type(variant, G_VARIANT_TYPE_BYTESTRING)) {
            /* FIXME: there is no guarantee that the byte array
             * is valid UTF-8.*/
            value = g_variant_get_bytestring(variant);
        } else
            continue;

        if (sep)
            g_string_append_c(str, sep);

        escaped = attribute_escape(name, attr_separator, key_value_separator);
        g_string_append(str, escaped);
        g_free(escaped);

        if (!s || !*s || !(*s)->no_value) {
            g_string_append_c(str, key_value_separator);

            escaped = attribute_escape(value, attr_separator, key_value_separator);
            g_string_append(str, escaped);
            g_free(escaped);
        }

        sep = attr_separator;
    }
}

char *
_nm_utils_format_variant_attributes(GHashTable                          *attributes,
                                    const NMVariantAttributeSpec *const *spec,
                                    char                                 attr_separator,
                                    char                                 key_value_separator)
{
    gs_free NMUtilsNamedValue *values_free = NULL;
    NMUtilsNamedValue          values_prepared[20];
    const NMUtilsNamedValue   *values;
    GString                   *str = NULL;
    guint                      len;

    g_return_val_if_fail(attr_separator, NULL);
    g_return_val_if_fail(key_value_separator, NULL);

    if (!attributes)
        return NULL;

    values = nm_utils_named_values_from_strdict(attributes, &len, values_prepared, &values_free);
    if (len == 0)
        return NULL;

    str = g_string_new("");
    _nm_utils_format_variant_attributes_full(str,
                                             values,
                                             len,
                                             spec,
                                             attr_separator,
                                             key_value_separator);
    return g_string_free(str, FALSE);
}

/*****************************************************************************/

gboolean
nm_utils_is_localhost(const char *name)
{
    static const char *const NAMES[] = {
        "localhost",
        "localhost4",
        "localhost6",
        "localhost.localdomain",
        "localhost4.localdomain4",
        "localhost6.localdomain6",
    };
    gsize name_len;
    int   i;

    if (!name)
        return FALSE;

    /* This tries to identify local host and domain names
     * described in RFC6761 plus the redhatism of localdomain.
     *
     * Similar to systemd's is_localhost(). */

    name_len = strlen(name);

    if (name_len == 0)
        return FALSE;

    if (name[name_len - 1] == '.') {
        /* one trailing dot is fine. Hide it. */
        name_len--;
    }

    for (i = 0; i < (int) G_N_ELEMENTS(NAMES); i++) {
        const char *n = NAMES[i];
        gsize       l = strlen(n);
        gsize       s;

        if (name_len < l)
            continue;

        s = name_len - l;

        if (g_ascii_strncasecmp(&name[s], n, l) != 0)
            continue;

        /* we accept the name if it is equal to one of the well-known names,
         * or if it is some prefix, a '.' and the well-known name. */
        if (s == 0)
            return TRUE;
        if (name[s - 1] == '.')
            return TRUE;
    }

    return FALSE;
}

gboolean
nm_utils_is_specific_hostname(const char *name)
{
    if (nm_str_is_empty(name))
        return FALSE;

    if (nm_streq(name, "(none)")) {
        /* This is not a special hostname. Probably an artefact by somebody wrongly
         * printing NULL. */
        return FALSE;
    }

    if (nm_utils_is_localhost(name))
        return FALSE;

    /* FIXME: properly validate the hostname, like systemd's hostname_is_valid() */

    return TRUE;
}

/*****************************************************************************/

/* taken from systemd's uid_to_name(). */
char *
nm_utils_uid_to_name(uid_t uid)
{
    gs_free char *buf_heap = NULL;
    char          buf_stack[4096];
    gsize         bufsize;
    char         *buf;

    bufsize = sizeof(buf_stack);
    buf     = buf_stack;

    for (;;) {
        struct passwd  pwbuf;
        struct passwd *pw = NULL;
        int            r;

        r = getpwuid_r(uid, &pwbuf, buf, bufsize, &pw);
        if (r == 0 && pw)
            return nm_strdup_not_empty(pw->pw_name);

        if (r != ERANGE)
            return NULL;

        if (bufsize > G_MAXSIZE / 2u)
            return NULL;

        bufsize *= 2u;
        g_free(buf_heap);
        buf_heap = g_malloc(bufsize);
        buf      = buf_heap;
    }
}

/* taken from systemd's nss_user_record_by_name() */
gboolean
nm_utils_name_to_uid(const char *name, uid_t *out_uid)
{
    gs_free char *buf_heap = NULL;
    char          buf_stack[4096];
    gsize         bufsize;
    char         *buf;

    if (!name)
        return nm_assert_unreachable_val(FALSE);

    bufsize = sizeof(buf_stack);
    buf     = buf_stack;

    for (;;) {
        struct passwd *result;
        struct passwd  pwd;
        int            r;

        r = getpwnam_r(name, &pwd, buf, bufsize, &result);
        if (r == 0) {
            if (!result)
                return FALSE;
            NM_SET_OUT(out_uid, pwd.pw_uid);
            return TRUE;
        }

        if (r != ERANGE)
            return FALSE;

        if (bufsize > G_MAXSIZE / 2u)
            return FALSE;

        bufsize *= 2u;
        g_free(buf_heap);
        buf_heap = g_malloc(bufsize);
        buf      = buf_heap;
    }
}

/*****************************************************************************/

static double
_exp10(guint16 ex)
{
    double v;

    if (ex == 0)
        return 1.0;

    v = _exp10(ex / 2);
    v = v * v;
    if (ex % 2)
        v *= 10;
    return v;
}

/*
 * nm_utils_exp10:
 * @ex: the exponent
 *
 * Returns: 10^ex, or pow(10, ex), or exp10(ex).
 */
double
nm_utils_exp10(gint16 ex)
{
    if (ex >= 0)
        return _exp10(ex);
    return 1.0 / _exp10(-((gint32) ex));
}

/*****************************************************************************/

gboolean
_nm_utils_is_empty_ssid_arr(const guint8 *ssid, gsize len)
{
    /* Single white space is for Linksys APs */
    if (len == 1 && ssid[0] == ' ')
        return TRUE;

    /* Otherwise, if the entire ssid is 0, we assume it is hidden */
    while (len--) {
        if (ssid[len] != '\0')
            return FALSE;
    }
    return TRUE;
}

gboolean
_nm_utils_is_empty_ssid_gbytes(GBytes *ssid)
{
    const guint8 *p;
    gsize         l;

    g_return_val_if_fail(ssid, FALSE);

    p = g_bytes_get_data(ssid, &l);
    return _nm_utils_is_empty_ssid_arr(p, l);
}

char *
_nm_utils_ssid_to_string_arr(const guint8 *ssid, gsize len)
{
    gs_free char *s_copy = NULL;
    const char   *s_cnst;

    if (len == 0)
        return g_strdup("(empty)");

    s_cnst =
        nm_utils_buf_utf8safe_escape(ssid, len, NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL, &s_copy);
    nm_assert(s_cnst);

    if (_nm_utils_is_empty_ssid_arr(ssid, len))
        return g_strdup_printf("\"%s\" (hidden)", s_cnst);

    return g_strdup_printf("\"%s\"", s_cnst);
}

char *
_nm_utils_ssid_to_string_gbytes(GBytes *ssid)
{
    gconstpointer p;
    gsize         l;

    if (!ssid)
        return g_strdup("(none)");

    p = g_bytes_get_data(ssid, &l);
    return _nm_utils_ssid_to_string_arr(p, l);
}

/*****************************************************************************/

#define IPV6_PROPERTY_DIR "/proc/sys/net/ipv6/conf/"
#define IPV4_PROPERTY_DIR "/proc/sys/net/ipv4/conf/"

G_STATIC_ASSERT(sizeof(IPV4_PROPERTY_DIR) == sizeof(IPV6_PROPERTY_DIR));
G_STATIC_ASSERT(NM_STRLEN(IPV6_PROPERTY_DIR) + IFNAMSIZ + 60
                == NM_UTILS_SYSCTL_IP_CONF_PATH_BUFSIZE);

/**
 * nm_utils_sysctl_ip_conf_path:
 * @addr_family: either AF_INET or AF_INET6.
 * @buf: the output buffer where to write the path. It
 *   must be at least NM_UTILS_SYSCTL_IP_CONF_PATH_BUFSIZE bytes
 *   long.
 * @ifname: an interface name
 * @property: a property name
 *
 * Returns: the path to IPv6 property @property on @ifname. Note that
 * this returns the input argument @buf.
 */
const char *
nm_utils_sysctl_ip_conf_path(int addr_family, char *buf, const char *ifname, const char *property)
{
    int len;

    nm_assert(buf);
    nm_assert_addr_family(addr_family);

    g_assert(nm_utils_ifname_valid_kernel(ifname, NULL));
    property = NM_ASSERT_VALID_PATH_COMPONENT(property);

    len = g_snprintf(buf,
                     NM_UTILS_SYSCTL_IP_CONF_PATH_BUFSIZE,
                     "%s%s/%s",
                     addr_family == AF_INET6 ? IPV6_PROPERTY_DIR : IPV4_PROPERTY_DIR,
                     ifname,
                     property);
    g_assert(len < NM_UTILS_SYSCTL_IP_CONF_PATH_BUFSIZE - 1);
    return buf;
}

gboolean
nm_utils_sysctl_ip_conf_is_path(int         addr_family,
                                const char *path,
                                const char *ifname,
                                const char *property)
{
    g_return_val_if_fail(path, FALSE);
    NM_ASSERT_VALID_PATH_COMPONENT(property);
    g_assert(!ifname || nm_utils_ifname_valid_kernel(ifname, NULL));

    if (addr_family == AF_INET) {
        if (!g_str_has_prefix(path, IPV4_PROPERTY_DIR))
            return FALSE;
        path += NM_STRLEN(IPV4_PROPERTY_DIR);
    } else if (addr_family == AF_INET6) {
        if (!g_str_has_prefix(path, IPV6_PROPERTY_DIR))
            return FALSE;
        path += NM_STRLEN(IPV6_PROPERTY_DIR);
    } else
        g_return_val_if_reached(FALSE);

    if (ifname) {
        if (!g_str_has_prefix(path, ifname))
            return FALSE;
        path += strlen(ifname);
        if (path[0] != '/')
            return FALSE;
        path++;
    } else {
        const char *slash;
        char        buf[IFNAMSIZ];
        gsize       l;

        slash = strchr(path, '/');
        if (!slash)
            return FALSE;
        l = slash - path;
        if (l >= IFNAMSIZ)
            return FALSE;
        memcpy(buf, path, l);
        buf[l] = '\0';
        if (!nm_utils_ifname_valid_kernel(buf, NULL))
            return FALSE;
        path = slash + 1;
    }

    if (!nm_streq(path, property))
        return FALSE;

    return TRUE;
}

gboolean
nm_utils_is_valid_path_component(const char *name)
{
    const char *n;

    if (name == NULL || name[0] == '\0')
        return FALSE;

    if (name[0] == '.') {
        if (name[1] == '\0')
            return FALSE;
        if (name[1] == '.' && name[2] == '\0')
            return FALSE;
    }
    n = name;
    do {
        if (*n == '/')
            return FALSE;
    } while (*(++n) != '\0');

    return TRUE;
}

const char *
NM_ASSERT_VALID_PATH_COMPONENT(const char *name)
{
    if (G_LIKELY(nm_utils_is_valid_path_component(name)))
        return name;

    g_error("FATAL: Failed asserting path component: %s%s%s",
            NM_PRINT_FMT_QUOTED(name, "\"", name, "\"", "(null)"));
    g_assert_not_reached();
}

/*****************************************************************************/

void
nm_crypto_md5_hash(const guint8 *salt,
                   gsize         salt_len,
                   const guint8 *password,
                   gsize         password_len,
                   guint8       *buffer,
                   gsize         buflen)
{
    nm_auto_free_checksum GChecksum                  *ctx = NULL;
    nm_auto_clear_static_secret_ptr const NMSecretPtr digest =
        NM_SECRET_PTR_STATIC(NM_UTILS_CHECKSUM_LENGTH_MD5);
    gsize bufidx = 0;
    int   i;

    g_return_if_fail(password_len == 0 || password);
    g_return_if_fail(buffer);
    g_return_if_fail(buflen > 0);
    g_return_if_fail(salt_len == 0 || salt);

    ctx = g_checksum_new(G_CHECKSUM_MD5);

    for (;;) {
        if (password_len > 0)
            g_checksum_update(ctx, (const guchar *) password, password_len);
        if (salt_len > 0)
            g_checksum_update(ctx, (const guchar *) salt, salt_len);

        nm_utils_checksum_get_digest_len(ctx, digest.bin, NM_UTILS_CHECKSUM_LENGTH_MD5);

        for (i = 0; i < NM_UTILS_CHECKSUM_LENGTH_MD5; i++) {
            if (bufidx >= buflen)
                return;
            buffer[bufidx++] = digest.bin[i];
        }

        g_checksum_reset(ctx);
        g_checksum_update(ctx, digest.ptr, NM_UTILS_CHECKSUM_LENGTH_MD5);
    }
}

/*****************************************************************************/

const char *
nm_utils_get_process_exit_status_desc_buf(int status, char *buf, gsize buf_len)
{
    const char *buf0 = buf;

    nm_assert(buf_len == 0 || buf);

    /* This should give a partial sentence, it it can be combined with
     * prinft("command XYZ %s.\n", desc) */

    if (WIFEXITED(status))
        nm_strbuf_append(&buf, &buf_len, "exited with status %d", WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        nm_strbuf_append(&buf, &buf_len, "killed by signal %d", WTERMSIG(status));
    else if (WIFSTOPPED(status))
        nm_strbuf_append(&buf, &buf_len, "stopped by signal %d", WSTOPSIG(status));
    else if (WIFCONTINUED(status))
        nm_strbuf_append(&buf, &buf_len, "resumed by SIGCONT");
    else
        nm_strbuf_append(&buf, &buf_len, "exited with unknown status 0x%x", status);

    return buf0;
}

char *
nm_utils_get_process_exit_status_desc(int status)
{
    char buf[NM_UTILS_GET_PROCESS_EXIT_STATUS_BUF_LEN];

    nm_utils_get_process_exit_status_desc_buf(status, buf, sizeof(buf));

    return g_strdup(buf);
}

/*****************************************************************************/

gboolean
nm_utils_validate_hostname(const char *hostname)
{
    const char *p;
    gboolean    dot = TRUE;

    if (!hostname || !hostname[0])
        return FALSE;

    for (p = hostname; *p; p++) {
        if (*p == '.') {
            if (dot)
                return FALSE;
            dot = TRUE;
        } else {
            if (!g_ascii_isalnum(*p) && (*p != '-') && (*p != '_'))
                return FALSE;
            dot = FALSE;
        }
    }

    if (dot)
        return FALSE;

    return (p - hostname <= NM_HOST_NAME_MAX);
}

/*****************************************************************************/

typedef struct {
    CList          lst;
    gpointer       tls_data;
    GDestroyNotify destroy_notify;
} TlsRegData;

static pthread_key_t _tls_reg_key;

static void
_tls_reg_destroy(gpointer data)
{
    CList      *lst_head = data;
    TlsRegData *entry;

    if (!lst_head)
        return;

    /* For no strong reason are we destroying the elements in reverse
     * order than they were added. It seems a bit more sensible (but shouldn't
     * matter nor should you rely on that). */
    while ((entry = c_list_last_entry(lst_head, TlsRegData, lst))) {
        c_list_unlink_stale(&entry->lst);
        entry->destroy_notify(entry->tls_data);
        nm_g_slice_free(entry);
    }

    nm_g_slice_free(lst_head);
}

static void
_tls_reg_make_key(void)
{
    if (pthread_key_create(&_tls_reg_key, _tls_reg_destroy) != 0)
        g_return_if_reached();
}

/**
 * nm_utils_thread_local_register_destroy:
 * @tls_data: the thread local storage data that should be destroyed when the thread
 *   exits. This pointer will be "owned" by the current thread. There is no way
 *   to un-register the destruction.
 * @destroy_notify: the free function that will be called when the thread exits.
 *
 * If _nm_tread_local storage is heap allocated it requires freeing the pointer
 * when the thread exits. Use this function to register the pointer to be
 * released.
 *
 * This function does not change errno.
 */
void
nm_utils_thread_local_register_destroy(gpointer tls_data, GDestroyNotify destroy_notify)
{
    NM_AUTO_PROTECT_ERRNO(errsv);
    static pthread_once_t key_once = PTHREAD_ONCE_INIT;
    CList                *lst_head;
    TlsRegData           *entry;

    nm_assert(destroy_notify);

    if (pthread_once(&key_once, _tls_reg_make_key) != 0)
        g_return_if_reached();

    if ((lst_head = pthread_getspecific(_tls_reg_key)) == NULL) {
        lst_head = g_slice_new(CList);
        c_list_init(lst_head);
        if (pthread_setspecific(_tls_reg_key, lst_head) != 0)
            g_return_if_reached();
    }

    entry                 = g_slice_new(TlsRegData);
    entry->tls_data       = tls_data;
    entry->destroy_notify = destroy_notify;
    c_list_link_tail(lst_head, &entry->lst);
}

/*****************************************************************************/

static gboolean
_iterate_for_msec_timeout(gpointer user_data)
{
    GSource **p_source = user_data;

    nm_clear_g_source_inst(p_source);
    return G_SOURCE_CONTINUE;
}

void
nm_g_main_context_iterate_for_msec(GMainContext *context, guint timeout_msec)
{
    GSource *source;

    /* In production is this function not very useful. It is however useful to
     * have in the toolbox for printf debugging. */

    source = g_timeout_source_new(timeout_msec);
    g_source_set_callback(source, _iterate_for_msec_timeout, &source, NULL);

    if (!context)
        context = g_main_context_default();

    g_source_attach(source, context);
    while (source)
        g_main_context_iteration(context, TRUE);
}

/*****************************************************************************/

gboolean
nm_g_main_context_can_acquire(GMainContext *context)
{
    /* Fast path. Usually we don't pass contexts between threads
     * and operate while iterating the context. Hence, usually we
     * already acquired the context. Check that first. */
    if (g_main_context_is_owner(context))
        return TRUE;

    /* Either the context is not owned, or owned by somebody else. Only
     * one way to find out. */
    if (!g_main_context_acquire(context))
        return FALSE;

    g_main_context_release(context);
    return TRUE;
}

/*****************************************************************************/

int
nm_unbase64char(char c)
{
    /* copied from systemd's unbase64char():
     * https://github.com/systemd/systemd/blob/688efe7703328c5a0251fafac55757b8864a9f9a/src/basic/hexdecoct.c#L539 */

    switch (c) {
    case 'A' ... 'Z':
        return c - 'A';
    case 'a' ... 'z':
        return (c - 'a') + ('Z' - 'A' + 1);
    case '0' ... '9':
        return (c - '0') + (('Z' - 'A' + 1) + ('z' - 'a' + 1));
    case '+':
        return ('Z' - 'A' + 1) + ('z' - 'a' + 1) + ('9' - '0' + 1);
    case '/':
        return ('Z' - 'A' + 1) + ('z' - 'a' + 1) + ('9' - '0' + 1) + 1;
    case '=':
        /* The padding is a different kind of base64 character. Return
         * a special error code for it. */
        return -ERANGE;
    default:
        return -EINVAL;
    }
}

static int
unbase64_next(const char **p, size_t *l)
{
    int ret;

    nm_assert(p);
    nm_assert(l);

    /* copied from systemd's unbase64_next():
     * https://github.com/systemd/systemd/blob/688efe7703328c5a0251fafac55757b8864a9f9a/src/basic/hexdecoct.c#L709 */

    /* Find the next non-whitespace character, and decode it. If we find padding, we return it as INT_MAX. We
     * greedily skip all preceding and all following whitespace. */

    for (;;) {
        if (*l == 0)
            return -EPIPE;

        if (!nm_ascii_is_whitespace(**p))
            break;

        /* Skip leading whitespace */
        (*p)++;
        (*l)--;
    }

    ret = nm_unbase64char(**p);
    if (ret < 0) {
        nm_assert(NM_IN_SET(ret, -EINVAL, -ERANGE));
        if (ret != -ERANGE)
            return ret;
    }

    for (;;) {
        (*p)++;
        (*l)--;

        if (*l == 0)
            break;
        if (!nm_ascii_is_whitespace(**p))
            break;

        /* Skip following whitespace */
    }

    nm_assert(ret == -ERANGE || ret >= 0);
    return ret;
}

/**
 * nm_unbase64mem_full:
 * @p: a valid base64 string. Whitespace is ignored, but invalid encodings
 *   will cause the function to fail.
 * @l: the length of @p. @p is not treated as NUL terminated string but
 *   merely as a buffer of ascii characters.
 * @secure: whether the temporary memory will be cleared to avoid leaving
 *   secrets in memory (see also nm_explicit_bzero()).
 * @mem: (transfer full): the decoded buffer on success.
 * @len: the length of @mem on success.
 *
 * glib provides g_base64_decode(), but that does not report any errors
 * from invalid encodings. Our own implementation (based on systemd code)
 * rejects invalid inputs.
 *
 * Returns: a non-negative code on success. Invalid encoding let the
 *   function fail.
 */
int
nm_unbase64mem_full(const char *p, gsize l, gboolean secure, guint8 **ret, gsize *ret_size)
{
    gs_free uint8_t *buf = NULL;
    const char      *x;
    guint8          *z;
    gsize            len;
    int              r;

    /* copied from systemd's unbase64mem_full():
     * https://github.com/systemd/systemd/blob/688efe7703328c5a0251fafac55757b8864a9f9a/src/basic/hexdecoct.c#L751 */

    nm_assert(p || l == 0);

    if (l == G_MAXSIZE)
        l = strlen(p);

    /* A group of four input bytes needs three output bytes, in case of padding we need to add two or three extra
     * bytes. Note that this calculation is an upper boundary, as we ignore whitespace while decoding */
    len = (l / 4) * 3 + (l % 4 != 0 ? (l % 4) - 1 : 0);

    buf = g_malloc(len + 1);

    for (x = p, z = buf;;) {
        int a; /* a == 00XXXXXX */
        int b; /* b == 00YYYYYY */
        int c; /* c == 00ZZZZZZ */
        int d; /* d == 00WWWWWW */

        a = unbase64_next(&x, &l);
        if (a < 0) {
            if (a == -EPIPE) /* End of string */
                break;
            if (a == -ERANGE) { /* Padding is not allowed at the beginning of a 4ch block */
                r = -EINVAL;
                goto on_failure;
            }
            r = a;
            goto on_failure;
        }

        b = unbase64_next(&x, &l);
        if (b < 0) {
            if (b == -ERANGE) {
                /* Padding is not allowed at the second character of a 4ch block either */
                r = -EINVAL;
                goto on_failure;
            }
            r = b;
            goto on_failure;
        }

        c = unbase64_next(&x, &l);
        if (c < 0) {
            if (c != -ERANGE) {
                r = c;
                goto on_failure;
            }
        }

        d = unbase64_next(&x, &l);
        if (d < 0) {
            if (d != -ERANGE) {
                r = d;
                goto on_failure;
            }
        }

        if (c == -ERANGE) { /* Padding at the third character */

            if (d != -ERANGE) { /* If the third character is padding, the fourth must be too */
                r = -EINVAL;
                goto on_failure;
            }

            /* b == 00YY0000 */
            if (b & 15) {
                r = -EINVAL;
                goto on_failure;
            }

            if (l > 0) { /* Trailing rubbish? */
                r = -ENAMETOOLONG;
                goto on_failure;
            }

            *(z++) = (uint8_t) a << 2 | (uint8_t) (b >> 4); /* XXXXXXYY */
            break;
        }

        if (d == -ERANGE) {
            /* c == 00ZZZZ00 */
            if (c & 3) {
                r = -EINVAL;
                goto on_failure;
            }

            if (l > 0) { /* Trailing rubbish? */
                r = -ENAMETOOLONG;
                goto on_failure;
            }

            *(z++) = (uint8_t) a << 2 | (uint8_t) b >> 4; /* XXXXXXYY */
            *(z++) = (uint8_t) b << 4 | (uint8_t) c >> 2; /* YYYYZZZZ */
            break;
        }

        *(z++) = (uint8_t) a << 2 | (uint8_t) b >> 4; /* XXXXXXYY */
        *(z++) = (uint8_t) b << 4 | (uint8_t) c >> 2; /* YYYYZZZZ */
        *(z++) = (uint8_t) c << 6 | (uint8_t) d;      /* ZZWWWWWW */
    }

    *z = '\0';

    NM_SET_OUT(ret_size, (gsize) (z - buf));
    NM_SET_OUT(ret, g_steal_pointer(&buf));
    return 0;

on_failure:
    if (secure)
        nm_explicit_bzero(buf, len);
    return r;
}

/*****************************************************************************/

static const char *
skip_slash_or_dot(const char *p)
{
    for (; !nm_str_is_empty(p);) {
        if (p[0] == '/') {
            p += 1;
            continue;
        }
        if (p[0] == '.' && p[1] == '/') {
            p += 2;
            continue;
        }
        break;
    }
    return p;
}

int
nm_path_find_first_component(const char **p, gboolean accept_dot_dot, const char **ret)
{
    const char *q, *first, *end_first, *next;
    size_t      len;

    /* Copied from systemd's path_compare()
     * https://github.com/systemd/systemd/blob/bc85f8b51d962597360e982811e674c126850f56/src/basic/path-util.c#L809 */

    nm_assert(p);

    /* When a path is input, then returns the pointer to the first component and its length, and
     * move the input pointer to the next component or nul. This skips both over any '/'
     * immediately *before* and *after* the first component before returning.
     *
     * Examples
     *   Input:  p: "//.//aaa///bbbbb/cc"
     *   Output: p: "bbbbb///cc"
     *           ret: "aaa///bbbbb/cc"
     *           return value: 3 (== strlen("aaa"))
     *
     *   Input:  p: "aaa//"
     *   Output: p: (pointer to NUL)
     *           ret: "aaa//"
     *           return value: 3 (== strlen("aaa"))
     *
     *   Input:  p: "/", ".", ""
     *   Output: p: (pointer to NUL)
     *           ret: NULL
     *           return value: 0
     *
     *   Input:  p: NULL
     *   Output: p: NULL
     *           ret: NULL
     *           return value: 0
     *
     *   Input:  p: "(too long component)"
     *   Output: return value: -EINVAL
     *
     *   (when accept_dot_dot is false)
     *   Input:  p: "//..//aaa///bbbbb/cc"
     *   Output: return value: -EINVAL
     */

    q = *p;

    first = skip_slash_or_dot(q);
    if (nm_str_is_empty(first)) {
        *p = first;
        if (ret)
            *ret = NULL;
        return 0;
    }
    if (nm_streq(first, ".")) {
        *p = first + 1;
        if (ret)
            *ret = NULL;
        return 0;
    }

    end_first = strchrnul(first, '/');
    len       = end_first - first;

    if (len > NAME_MAX)
        return -EINVAL;
    if (!accept_dot_dot && len == 2 && first[0] == '.' && first[1] == '.')
        return -EINVAL;

    next = skip_slash_or_dot(end_first);

    *p = next + (nm_streq(next, ".") ? 1 : 0);
    if (ret)
        *ret = first;
    return len;
}

int
nm_path_compare(const char *a, const char *b)
{
    /* Copied from systemd's path_compare()
     * https://github.com/systemd/systemd/blob/bc85f8b51d962597360e982811e674c126850f56/src/basic/path-util.c#L415 */

    /* Order NULL before non-NULL */
    NM_CMP_SELF(a, b);

    /* A relative path and an absolute path must not compare as equal.
     * Which one is sorted before the other does not really matter.
     * Here a relative path is ordered before an absolute path. */
    NM_CMP_DIRECT(nm_path_is_absolute(a), nm_path_is_absolute(b));

    for (;;) {
        const char *aa, *bb;
        int         j, k;

        j = nm_path_find_first_component(&a, TRUE, &aa);
        k = nm_path_find_first_component(&b, TRUE, &bb);

        if (j < 0 || k < 0) {
            /* When one of paths is invalid, order invalid path after valid one. */
            NM_CMP_DIRECT(j < 0, k < 0);

            /* fallback to use strcmp() if both paths are invalid. */
            NM_CMP_DIRECT_STRCMP(a, b);
            return 0;
        }

        /* Order prefixes first: "/foo" before "/foo/bar" */
        if (j == 0) {
            if (k == 0)
                return 0;
            return -1;
        }
        if (k == 0)
            return 1;

        /* Alphabetical sort: "/foo/aaa" before "/foo/b" */
        NM_CMP_DIRECT_MEMCMP(aa, bb, NM_MIN(j, k));

        /* Sort "/foo/a" before "/foo/aaa" */
        NM_CMP_DIRECT(j, k);
    }
}

char *
nm_path_startswith_full(const char *path, const char *prefix, gboolean accept_dot_dot)
{
    /* Copied from systemd's path_startswith_full()
     * https://github.com/systemd/systemd/blob/bc85f8b51d962597360e982811e674c126850f56/src/basic/path-util.c#L375 */

    nm_assert(path);
    nm_assert(prefix);

    /* Returns a pointer to the start of the first component after the parts matched by
     * the prefix, iff
     * - both paths are absolute or both paths are relative,
     * and
     * - each component in prefix in turn matches a component in path at the same position.
     * An empty string will be returned when the prefix and path are equivalent.
     *
     * Returns NULL otherwise.
     */

    if ((path[0] == '/') != (prefix[0] == '/'))
        return NULL;

    for (;;) {
        const char *p, *q;
        int         r, k;

        r = nm_path_find_first_component(&path, accept_dot_dot, &p);
        if (r < 0)
            return NULL;

        k = nm_path_find_first_component(&prefix, accept_dot_dot, &q);
        if (k < 0)
            return NULL;

        if (k == 0)
            return (char *) (p ?: path);

        if (r != k)
            return NULL;

        if (strncmp(p, q, r) != 0)
            return NULL;
    }
}

char *
nm_path_simplify(char *path)
{
    bool  add_slash = false;
    char *f         = path;
    int   r;

    /* Copied from systemd's path_simplify()
     * https://github.com/systemd/systemd/blob/bc85f8b51d962597360e982811e674c126850f56/src/basic/path-util.c#L325 */

    nm_assert(path);

    /* Removes redundant inner and trailing slashes. Also removes unnecessary dots.
     * Modifies the passed string in-place.
     *
     * ///foo//./bar/.   becomes /foo/bar
     * .//./foo//./bar/. becomes foo/bar
     */

    if (path[0] == '\0')
        return path;

    if (nm_path_is_absolute(path))
        f++;

    for (const char *p = f;;) {
        const char *e;

        r = nm_path_find_first_component(&p, TRUE, &e);
        if (r == 0)
            break;

        if (add_slash)
            *f++ = '/';

        if (r < 0) {
            /* if path is invalid, then refuse to simplify remaining part. */
            memmove(f, p, strlen(p) + 1);
            return path;
        }

        memmove(f, e, r);
        f += r;

        add_slash = TRUE;
    }

    /* Special rule, if we stripped everything, we need a "." for the current directory. */
    if (f == path)
        *f++ = '.';

    *f = '\0';
    return path;
}

/*****************************************************************************/

static gboolean
valid_ldh_char(char c)
{
    /* "LDH" → "Letters, digits, hyphens", as per RFC 5890, Section 2.3.1 */

    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-';
}

/**
 * nm_hostname_is_valid:
 * @s: the hostname to check.
 * @trailing_dot: Accept trailing dot on multi-label names.
 *
 * Return: %TRUE if valid.
 */
gboolean
nm_hostname_is_valid(const char *s, gboolean trailing_dot)
{
    unsigned    n_dots = 0;
    const char *p;
    gboolean    dot;
    gboolean    hyphen;

    /* Copied from systemd's hostname_is_valid()
     * https://github.com/systemd/systemd/blob/bc85f8b51d962597360e982811e674c126850f56/src/basic/hostname-util.c#L85 */

    /* Check if s looks like a valid hostname or FQDN. This does not do full DNS validation, but only
     * checks if the name is composed of allowed characters and the length is not above the maximum
     * allowed by Linux (c.f. dns_name_is_valid()). A trailing dot is allowed if
     * VALID_HOSTNAME_TRAILING_DOT flag is set and at least two components are present in the name. Note
     * that due to the restricted charset and length this call is substantially more conservative than
     * dns_name_is_valid(). Doesn't accept empty hostnames, hostnames with leading dots, and hostnames
     * with multiple dots in a sequence. Doesn't allow hyphens at the beginning or end of label. */

    if (nm_str_is_empty(s))
        return FALSE;

    for (p = s, dot = hyphen = TRUE; *p; p++)
        if (*p == '.') {
            if (dot || hyphen)
                return FALSE;

            dot    = TRUE;
            hyphen = FALSE;
            n_dots++;

        } else if (*p == '-') {
            if (dot)
                return FALSE;

            dot    = FALSE;
            hyphen = TRUE;

        } else {
            if (!valid_ldh_char(*p))
                return FALSE;

            dot    = FALSE;
            hyphen = FALSE;
        }

    if (dot && (n_dots < 2 || !trailing_dot))
        return FALSE;
    if (hyphen)
        return FALSE;

    /* Note that HOST_NAME_MAX is 64 on Linux, but DNS allows domain names up to
     * 255 characters */
    if (p - s > NM_HOST_NAME_MAX)
        return FALSE;

    return TRUE;
}
