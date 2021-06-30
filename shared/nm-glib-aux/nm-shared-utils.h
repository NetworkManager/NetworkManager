/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2016 Red Hat, Inc.
 */

#ifndef __NM_SHARED_UTILS_H__
#define __NM_SHARED_UTILS_H__

#include <netinet/in.h>

/*****************************************************************************/

/* An optional boolean (like NMTernary, with identical numerical
 * enum values). Note that this enum type is _nm_packed! */
typedef enum _nm_packed {
    NM_OPTION_BOOL_DEFAULT = -1,
    NM_OPTION_BOOL_FALSE   = 0,
    NM_OPTION_BOOL_TRUE    = 1,
} NMOptionBool;

/*****************************************************************************/

static inline gboolean
nm_is_ascii(char ch)
{
    return ((uint8_t) ch) < 128;
}

/*****************************************************************************/

pid_t nm_utils_gettid(void);

gboolean _nm_assert_on_main_thread(void);

#if NM_MORE_ASSERTS > 5
    #define NM_ASSERT_ON_MAIN_THREAD()              \
        G_STMT_START                                \
        {                                           \
            nm_assert(_nm_assert_on_main_thread()); \
        }                                           \
        G_STMT_END
#else
    #define NM_ASSERT_ON_MAIN_THREAD() \
        G_STMT_START                   \
        {                              \
            ;                          \
        }                              \
        G_STMT_END
#endif

/*****************************************************************************/

static inline gboolean
_NM_INT_NOT_NEGATIVE(gssize val)
{
    /* whether an enum (without negative values) is a signed int, depends on compiler options
     * and compiler implementation.
     *
     * When using such an enum for accessing an array, one naturally wants to check
     * that the enum is not negative. However, the compiler doesn't like a plain
     * comparison "enum_val >= 0", because (if the enum is unsigned), it will warn
     * that the expression is always true *duh*. Not even a cast to a signed
     * type helps to avoid the compiler warning in any case.
     *
     * The sole purpose of this function is to avoid a compiler warning, when checking
     * that an enum is not negative. */
    return val >= 0;
}

/* check whether the integer value is smaller than G_MAXINT32. This macro exists
 * for the sole purpose, that a plain "((int) value <= G_MAXINT32)" comparison
 * may cause the compiler or coverity that this check is always TRUE. But the
 * check depends on compile time and the size of C type "int".  Of course, most
 * of the time in is gint32 and an int value is always <= G_MAXINT32.  The check
 * exists to catch cases where that is not true.
 *
 * Together with the G_STATIC_ASSERT(), we make sure that this is always satisfied. */
G_STATIC_ASSERT(sizeof(int) == sizeof(gint32));
#if _NM_CC_SUPPORT_GENERIC
    #define _NM_INT_LE_MAXINT32(value)                 \
        ({                                             \
            _nm_unused typeof(value) _value = (value); \
                                                       \
            _Generic((value), int : TRUE);             \
        })
#else
    #define _NM_INT_LE_MAXINT32(value)                 \
        ({                                             \
            _nm_unused typeof(value) _value = (value); \
            _nm_unused const int *_p_value  = &_value; \
                                                       \
            TRUE;                                      \
        })
#endif

/*****************************************************************************/

typedef struct {
    guint8 ether_addr_octet[6 /*ETH_ALEN*/];
} NMEtherAddr;

#define NM_ETHER_ADDR_FORMAT_STR "%02X:%02X:%02X:%02X:%02X:%02X"

#define NM_ETHER_ADDR_FORMAT_VAL(x)                                               \
    (x)->ether_addr_octet[0], (x)->ether_addr_octet[1], (x)->ether_addr_octet[2], \
        (x)->ether_addr_octet[3], (x)->ether_addr_octet[4], (x)->ether_addr_octet[5]

#define _NM_ETHER_ADDR_INIT(a0, a1, a2, a3, a4, a5) \
    {                                               \
        .ether_addr_octet = {                       \
            (a0),                                   \
            (a1),                                   \
            (a2),                                   \
            (a3),                                   \
            (a4),                                   \
            (a5),                                   \
        },                                          \
    }

#define NM_ETHER_ADDR_INIT(...) ((NMEtherAddr) _NM_ETHER_ADDR_INIT(__VA_ARGS__))

static inline int
nm_ether_addr_cmp(const NMEtherAddr *a, const NMEtherAddr *b)
{
    NM_CMP_SELF(a, b);
    NM_CMP_DIRECT_MEMCMP(a, b, sizeof(NMEtherAddr));
    return 0;
}

static inline gboolean
nm_ether_addr_equal(const NMEtherAddr *a, const NMEtherAddr *b)
{
    return nm_ether_addr_cmp(a, b) == 0;
}

/*****************************************************************************/

typedef struct {
    union {
        guint8          addr_ptr[1];
        in_addr_t       addr4;
        struct in_addr  addr4_struct;
        struct in6_addr addr6;

        /* NMIPAddr is really a union for IP addresses.
         * However, as ethernet addresses fit in here nicely, use
         * it also for an ethernet MAC address. */
        guint8      ether_addr_octet[6 /*ETH_ALEN*/];
        NMEtherAddr ether_addr;

        guint8 array[sizeof(struct in6_addr)];
    };
} NMIPAddr;

#define NM_IP_ADDR_INIT \
    {                   \
        .array = { 0 }  \
    }

extern const NMIPAddr nm_ip_addr_zero;

#define nm_ether_addr_zero (nm_ip_addr_zero.ether_addr)

static inline int
nm_ip_addr_cmp(int addr_family, gconstpointer a, gconstpointer b)
{
    nm_assert_addr_family(addr_family);
    nm_assert(a);
    nm_assert(b);

    return memcmp(a, b, nm_utils_addr_family_to_size(addr_family));
}

static inline gboolean
nm_ip_addr_equal(int addr_family, gconstpointer a, gconstpointer b)
{
    return nm_ip_addr_cmp(addr_family, a, b) == 0;
}

static inline gboolean
nm_ip_addr_is_null(int addr_family, gconstpointer addr)
{
    nm_assert(addr);
    if (addr_family == AF_INET6)
        return IN6_IS_ADDR_UNSPECIFIED((const struct in6_addr *) addr);
    nm_assert(addr_family == AF_INET);
    return ((const struct in_addr *) addr)->s_addr == 0;
}

static inline void
nm_ip_addr_set(int addr_family, gpointer dst, gconstpointer src)
{
    nm_assert_addr_family(addr_family);
    nm_assert(dst);
    nm_assert(src);

    memcpy(dst, src, (addr_family != AF_INET6) ? sizeof(in_addr_t) : sizeof(struct in6_addr));
}

gboolean nm_ip_addr_set_from_untrusted(int           addr_family,
                                       gpointer      dst,
                                       gconstpointer src,
                                       gsize         src_len,
                                       int *         out_addr_family);

static inline gboolean
nm_ip4_addr_is_localhost(in_addr_t addr4)
{
    return (addr4 & htonl(0xFF000000u)) == htonl(0x7F000000u);
}

/*****************************************************************************/

struct ether_addr;

static inline int
nm_utils_ether_addr_cmp(const struct ether_addr *a1, const struct ether_addr *a2)
{
    nm_assert(a1);
    nm_assert(a2);
    return memcmp(a1, a2, 6 /*ETH_ALEN*/);
}

static inline gboolean
nm_utils_ether_addr_equal(const struct ether_addr *a1, const struct ether_addr *a2)
{
    return nm_utils_ether_addr_cmp(a1, a2) == 0;
}

/*****************************************************************************/

#define NM_UTILS_INET_ADDRSTRLEN INET6_ADDRSTRLEN

static inline const char *
nm_utils_inet_ntop(int addr_family, gconstpointer addr, char *dst)
{
    const char *s;

    const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);

    nm_assert_addr_family(addr_family);
    nm_assert(addr);
    nm_assert(dst);

    s = inet_ntop(addr_family,
                  addr,
                  dst,
                  addr_family == AF_INET6 ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN);
    nm_assert(s);
    return s;
}

static inline const char *
_nm_utils_inet4_ntop(in_addr_t addr, char dst[static INET_ADDRSTRLEN])
{
    return nm_utils_inet_ntop(AF_INET, &addr, dst);
}

static inline const char *
_nm_utils_inet6_ntop(const struct in6_addr *addr, char dst[static INET6_ADDRSTRLEN])
{
    return nm_utils_inet_ntop(AF_INET6, addr, dst);
}

static inline char *
nm_utils_inet_ntop_dup(int addr_family, gconstpointer addr)
{
    char buf[NM_UTILS_INET_ADDRSTRLEN];

    return g_strdup(nm_utils_inet_ntop(addr_family, addr, buf));
}

static inline char *
nm_utils_inet4_ntop_dup(in_addr_t addr)
{
    return nm_utils_inet_ntop_dup(AF_INET, &addr);
}

static inline char *
nm_utils_inet6_ntop_dup(const struct in6_addr *addr)
{
    return nm_utils_inet_ntop_dup(AF_INET6, addr);
}

/*****************************************************************************/

gboolean nm_utils_ipaddr_is_valid(int addr_family, const char *str_addr);

gboolean nm_utils_ipaddr_is_normalized(int addr_family, const char *str_addr);

/*****************************************************************************/

gboolean nm_utils_memeqzero(gconstpointer data, gsize length);

/*****************************************************************************/

extern const void *const _NM_PTRARRAY_EMPTY[1];

#define NM_PTRARRAY_EMPTY(type) ((type const *) _NM_PTRARRAY_EMPTY)

static inline void
_nm_utils_strbuf_init(char *buf, gsize len, char **p_buf_ptr, gsize *p_buf_len)
{
    NM_SET_OUT(p_buf_len, len);
    NM_SET_OUT(p_buf_ptr, buf);
    buf[0] = '\0';
}

#define nm_utils_strbuf_init(buf, p_buf_ptr, p_buf_len)                                    \
    G_STMT_START                                                                           \
    {                                                                                      \
        G_STATIC_ASSERT(G_N_ELEMENTS(buf) == sizeof(buf) && sizeof(buf) > sizeof(char *)); \
        _nm_utils_strbuf_init((buf), sizeof(buf), (p_buf_ptr), (p_buf_len));               \
    }                                                                                      \
    G_STMT_END
void nm_utils_strbuf_append(char **buf, gsize *len, const char *format, ...) _nm_printf(3, 4);
void nm_utils_strbuf_append_c(char **buf, gsize *len, char c);
void nm_utils_strbuf_append_str(char **buf, gsize *len, const char *str);
void nm_utils_strbuf_append_bin(char **buf, gsize *len, gconstpointer str, gsize str_len);
void nm_utils_strbuf_seek_end(char **buf, gsize *len);

const char *nm_strquote(char *buf, gsize buf_len, const char *str);

static inline gboolean
nm_utils_is_separator(const char c)
{
    return NM_IN_SET(c, ' ', '\t');
}

/*****************************************************************************/

GBytes *nm_gbytes_get_empty(void);

GBytes *nm_g_bytes_new_from_str(const char *str);

static inline gboolean
nm_gbytes_equal0(GBytes *a, GBytes *b)
{
    return a == b || (a && b && g_bytes_equal(a, b));
}

gboolean nm_utils_gbytes_equal_mem(GBytes *bytes, gconstpointer mem_data, gsize mem_len);

GVariant *nm_utils_gbytes_to_variant_ay(GBytes *bytes);

GHashTable *nm_utils_strdict_clone(GHashTable *src);

GVariant *nm_utils_strdict_to_variant_ass(GHashTable *strdict);
GVariant *nm_utils_strdict_to_variant_asv(GHashTable *strdict);

/*****************************************************************************/

GVariant *nm_utils_gvariant_vardict_filter(GVariant *src,
                                           gboolean (*filter_fcn)(const char *key,
                                                                  GVariant *  val,
                                                                  char **     out_key,
                                                                  GVariant ** out_val,
                                                                  gpointer    user_data),
                                           gpointer user_data);

GVariant *nm_utils_gvariant_vardict_filter_drop_one(GVariant *src, const char *key);

/*****************************************************************************/

static inline int
nm_utils_hexchar_to_int(char ch)
{
    G_STATIC_ASSERT_EXPR('0' < 'A');
    G_STATIC_ASSERT_EXPR('A' < 'a');

    if (ch >= '0') {
        if (ch <= '9')
            return ch - '0';
        if (ch >= 'A') {
            if (ch <= 'F')
                return ((int) ch) + (10 - (int) 'A');
            if (ch >= 'a' && ch <= 'f')
                return ((int) ch) + (10 - (int) 'a');
        }
    }
    return -1;
}

/*****************************************************************************/

const char *nm_utils_dbus_path_get_last_component(const char *dbus_path);

int nm_utils_dbus_path_cmp(const char *dbus_path_a, const char *dbus_path_b);

/*****************************************************************************/

typedef enum {
    NM_UTILS_STRSPLIT_SET_FLAGS_NONE = 0,

    /* by default, strsplit will coalesce consecutive delimiters and remove
     * them from the result. If this flag is present, empty values are preserved
     * and returned.
     *
     * When combined with %NM_UTILS_STRSPLIT_SET_FLAGS_STRSTRIP, if a value gets
     * empty after strstrip(), it also gets removed. */
    NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY = (1u << 0),

    /* %NM_UTILS_STRSPLIT_SET_FLAGS_ALLOW_ESCAPING means that delimiters prefixed
     * by a backslash are not treated as a separator. Such delimiters and their escape
     * character are copied to the current word without unescaping them. In general,
     * nm_utils_strsplit_set_full() does not remove any backslash escape characters
     * and does no unescaping. It only considers them for skipping to split at
     * an escaped delimiter.
     *
     * If this is combined with (or implied by %NM_UTILS_STRSPLIT_SET_FLAGS_ESCAPED), then
     * the backslash escapes are removed from the result.
     */
    NM_UTILS_STRSPLIT_SET_FLAGS_ALLOW_ESCAPING = (1u << 1),

    /* If flag is set, does the same as g_strstrip() on the returned tokens.
     * This will remove leading and trailing ascii whitespaces (g_ascii_isspace()
     * and NM_ASCII_SPACES).
     *
     * - when combined with !%NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY,
     *   empty tokens will be removed (and %NULL will be returned if that
     *   results in an empty string array).
     * - when combined with %NM_UTILS_STRSPLIT_SET_FLAGS_ALLOW_ESCAPING,
     *   trailing whitespace escaped by backslash are not stripped. */
    NM_UTILS_STRSPLIT_SET_FLAGS_STRSTRIP = (1u << 2),

    /* This implies %NM_UTILS_STRSPLIT_SET_FLAGS_ALLOW_ESCAPING.
     *
     * This will do a final run over all tokens and remove all backslash
     * escape characters that
     *   - precede a delimiter.
     *   - precede a backslash.
     *   - preceed a whitespace (with %NM_UTILS_STRSPLIT_SET_FLAGS_STRSTRIP).
     *
     *  Note that with %NM_UTILS_STRSPLIT_SET_FLAGS_STRSTRIP, it is only
     *  necessary to escape the very last whitespace (if the delimiters
     *  are not whitespace themself). So, technically, it would be sufficient
     *  to only unescape a backslash before the last whitespace and the user
     *  still could express everything. However, such a rule would be complicated
     *  to understand, so when using backslash escaping with nm_utils_strsplit_set_full(),
     *  then all characters (including backslash) are treated verbatim, except:
     *
     *    - "\\$DELIMITER" (escaped delimiter)
     *    - "\\\\" (escaped backslash)
     *    - "\\$SPACE" (escaped space) (with %NM_UTILS_STRSPLIT_SET_FLAGS_STRSTRIP).
     *
     * Note that all other escapes like "\\n" or "\\001" are left alone.
     * That makes the escaping/unescaping rules simple. Also, for the most part
     * a text is just taken as-is, with little additional rules. Only backslashes
     * need extra care, and then only if they proceed one of the relevant characters.
     */
    NM_UTILS_STRSPLIT_SET_FLAGS_ESCAPED = (1u << 3),

} NMUtilsStrsplitSetFlags;

const char **
nm_utils_strsplit_set_full(const char *str, const char *delimiter, NMUtilsStrsplitSetFlags flags);

static inline const char **
nm_utils_strsplit_set_with_empty(const char *str, const char *delimiters)
{
    /* this returns the same result as g_strsplit_set(str, delimiters, -1), except
     * it does not deep-clone the strv array.
     * Also, for @str == "", this returns %NULL while g_strsplit_set() would return
     * an empty strv array. */
    return nm_utils_strsplit_set_full(str, delimiters, NM_UTILS_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY);
}

static inline const char **
nm_utils_strsplit_set(const char *str, const char *delimiters)
{
    return nm_utils_strsplit_set_full(str, delimiters, NM_UTILS_STRSPLIT_SET_FLAGS_NONE);
}

gssize nm_utils_strv_find_first(char **list, gssize len, const char *needle);

char **_nm_utils_strv_cleanup(char **  strv,
                              gboolean strip_whitespace,
                              gboolean skip_empty,
                              gboolean skip_repeated);

/*****************************************************************************/

static inline gpointer
nm_copy_func_g_strdup(gconstpointer arg, gpointer user_data)
{
    return g_strdup(arg);
}

/*****************************************************************************/

static inline const char **
nm_utils_escaped_tokens_split(const char *str, const char *delimiters)
{
    return nm_utils_strsplit_set_full(str,
                                      delimiters,
                                      NM_UTILS_STRSPLIT_SET_FLAGS_ESCAPED
                                          | NM_UTILS_STRSPLIT_SET_FLAGS_STRSTRIP);
}

typedef enum {
    NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_NONE                  = 0,
    NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_SPACES         = (1ull << 0),
    NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_LEADING_SPACE  = (1ull << 1),
    NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_TRAILING_SPACE = (1ull << 2),

    /* Backslash characters will be escaped as "\\\\" if they precede another
     * character that makes it necessary. Such characters are:
     *
     *  1) before another '\\' backslash.
     *  2) before any delimiter in @delimiters.
     *  3) before any delimiter in @delimiters_as_needed.
     *  4) before a white space, if ESCAPE_LEADING_SPACE or ESCAPE_TRAILING_SPACE is set.
     *  5) before the end of the word
     *
     * Rule 4) is an extension. It's not immediately clear why with ESCAPE_LEADING_SPACE
     * and ESCAPE_TRAILING_SPACE we want *all* backslashes before a white space escaped.
     * The reason is, that we obviously want to use ESCAPE_LEADING_SPACE and ESCAPE_TRAILING_SPACE
     * in cases, where we later parse the backslash escaped strings back, but allowing to strip
     * unescaped white spaces. That means, we want that " a " gets escaped as "\\ a\\ ".
     * On the other hand, we also want that " a\\ b " gets escaped as "\\ a\\\\ b\\ ",
     * and not "\\ a\\ b\\ ". Because otherwise, the parser would need to treat "\\ "
     * differently depending on whether the sequence is at the beginning, end or middle
     * of the word.
     *
     * Rule 5) is also not immediately obvious. When used with ESCAPE_TRAILING_SPACE,
     * we clearly want to allow that an escaped word can have arbitrary
     * whitespace suffixes. That's why this mode exists. So we must escape "a\\" as
     * "a\\\\", so that appending " " does not change the meaning.
     * Also without ESCAPE_TRAILING_SPACE, we want in general that we can concatenate
     * two escaped words without changing their meaning. If the words would be "a\\"
     * and "," (with ',' being a delimiter), then the result must be "a\\\\" and "\\,"
     * so that the concatenated word ("a\\\\\\,") is still the same. If we would escape
     * them instead as "a\\" + "\\,", then the concatenated word would be "a\\\\," and
     * different.
     * */
    NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_BACKSLASH_AS_NEEDED = (1ull << 3),

    NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_BACKSLASH_ALWAYS = (1ull << 4),
} NMUtilsEscapedTokensEscapeFlags;

const char *nm_utils_escaped_tokens_escape_full(const char *str,
                                                const char *delimiters,
                                                const char *delimiters_as_needed,
                                                NMUtilsEscapedTokensEscapeFlags flags,
                                                char **                         out_to_free);

static inline const char *
nm_utils_escaped_tokens_escape(const char *str, const char *delimiters, char **out_to_free)
{
    return nm_utils_escaped_tokens_escape_full(
        str,
        delimiters,
        NULL,
        NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_BACKSLASH_ALWAYS
            | NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_TRAILING_SPACE,
        out_to_free);
}

/**
 * nm_utils_escaped_tokens_escape_unnecessary:
 * @str: the string to check for "escape"
 * @delimiters: the delimiters
 *
 * This asserts that calling nm_utils_escaped_tokens_escape()
 * on @str has no effect and returns @str directly. This is only
 * for asserting that @str is safe to not require any escaping.
 *
 * Returns: @str
 */
static inline const char *
nm_utils_escaped_tokens_escape_unnecessary(const char *str, const char *delimiters)
{
#if NM_MORE_ASSERTS > 0

    nm_assert(str);
    nm_assert(delimiters);

    {
        gs_free char *str_to_free = NULL;
        const char *  str0;

        str0 = nm_utils_escaped_tokens_escape(str, delimiters, &str_to_free);
        nm_assert(str0 == str);
        nm_assert(!str_to_free);
    }
#endif

    return str;
}

static inline void
nm_utils_escaped_tokens_escape_gstr_assert(const char *str,
                                           const char *delimiters,
                                           GString *   gstring)
{
    g_string_append(gstring, nm_utils_escaped_tokens_escape_unnecessary(str, delimiters));
}

static inline GString *
nm_utils_escaped_tokens_escape_gstr(const char *str, const char *delimiters, GString *gstring)
{
    gs_free char *str_to_free = NULL;

    nm_assert(str);
    nm_assert(gstring);

    g_string_append(gstring, nm_utils_escaped_tokens_escape(str, delimiters, &str_to_free));
    return gstring;
}

/*****************************************************************************/

char **nm_utils_strsplit_quoted(const char *str);

/*****************************************************************************/

static inline const char **
nm_utils_escaped_tokens_options_split_list(const char *str)
{
    return nm_utils_strsplit_set_full(str,
                                      ",",
                                      NM_UTILS_STRSPLIT_SET_FLAGS_STRSTRIP
                                          | NM_UTILS_STRSPLIT_SET_FLAGS_ALLOW_ESCAPING);
}

void nm_utils_escaped_tokens_options_split(char *str, const char **out_key, const char **out_val);

static inline const char *
nm_utils_escaped_tokens_options_escape_key(const char *key, char **out_to_free)
{
    return nm_utils_escaped_tokens_escape_full(
        key,
        ",=",
        NULL,
        NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_BACKSLASH_AS_NEEDED
            | NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_LEADING_SPACE
            | NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_TRAILING_SPACE,
        out_to_free);
}

static inline const char *
nm_utils_escaped_tokens_options_escape_val(const char *val, char **out_to_free)
{
    return nm_utils_escaped_tokens_escape_full(
        val,
        ",",
        "=",
        NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_BACKSLASH_AS_NEEDED
            | NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_LEADING_SPACE
            | NM_UTILS_ESCAPED_TOKENS_ESCAPE_FLAGS_ESCAPE_TRAILING_SPACE,
        out_to_free);
}

/*****************************************************************************/

#define NM_UTILS_CHECKSUM_LENGTH_MD5    16
#define NM_UTILS_CHECKSUM_LENGTH_SHA1   20
#define NM_UTILS_CHECKSUM_LENGTH_SHA256 32

#define nm_utils_checksum_get_digest(sum, arr)                                   \
    G_STMT_START                                                                 \
    {                                                                            \
        GChecksum *const _sum = (sum);                                           \
        gsize            _len;                                                   \
                                                                                 \
        G_STATIC_ASSERT_EXPR(sizeof(arr) == NM_UTILS_CHECKSUM_LENGTH_MD5         \
                             || sizeof(arr) == NM_UTILS_CHECKSUM_LENGTH_SHA1     \
                             || sizeof(arr) == NM_UTILS_CHECKSUM_LENGTH_SHA256); \
        G_STATIC_ASSERT_EXPR(sizeof(arr) == G_N_ELEMENTS(arr));                  \
                                                                                 \
        nm_assert(_sum);                                                         \
                                                                                 \
        _len = G_N_ELEMENTS(arr);                                                \
                                                                                 \
        g_checksum_get_digest(_sum, (arr), &_len);                               \
        nm_assert(_len == G_N_ELEMENTS(arr));                                    \
    }                                                                            \
    G_STMT_END

#define nm_utils_checksum_get_digest_len(sum, buf, len)        \
    G_STMT_START                                               \
    {                                                          \
        GChecksum *const _sum  = (sum);                        \
        const gsize      _len0 = (len);                        \
        gsize            _len;                                 \
                                                               \
        nm_assert(NM_IN_SET(_len0,                             \
                            NM_UTILS_CHECKSUM_LENGTH_MD5,      \
                            NM_UTILS_CHECKSUM_LENGTH_SHA1,     \
                            NM_UTILS_CHECKSUM_LENGTH_SHA256)); \
        nm_assert(_sum);                                       \
                                                               \
        _len = _len0;                                          \
        g_checksum_get_digest(_sum, (buf), &_len);             \
        nm_assert(_len == _len0);                              \
    }                                                          \
    G_STMT_END

/*****************************************************************************/

guint32 _nm_utils_ip4_prefix_to_netmask(guint32 prefix);
guint32 _nm_utils_ip4_get_default_prefix0(in_addr_t ip);
guint32 _nm_utils_ip4_get_default_prefix(in_addr_t ip);

gconstpointer
nm_utils_ipx_address_clear_host_address(int family, gpointer dst, gconstpointer src, guint8 plen);
in_addr_t              nm_utils_ip4_address_clear_host_address(in_addr_t addr, guint8 plen);
const struct in6_addr *nm_utils_ip6_address_clear_host_address(struct in6_addr *      dst,
                                                               const struct in6_addr *src,
                                                               guint8                 plen);
int                    nm_utils_ip6_address_same_prefix_cmp(const struct in6_addr *addr_a,
                                                            const struct in6_addr *addr_b,
                                                            guint8                 plen);

gboolean nm_utils_ip_is_site_local(int addr_family, const void *address);

/*****************************************************************************/

gboolean nm_utils_parse_inaddr_bin_full(int         addr_family,
                                        gboolean    accept_legacy,
                                        const char *text,
                                        int *       out_addr_family,
                                        gpointer    out_addr);
static inline gboolean
nm_utils_parse_inaddr_bin(int         addr_family,
                          const char *text,
                          int *       out_addr_family,
                          gpointer    out_addr)
{
    return nm_utils_parse_inaddr_bin_full(addr_family, FALSE, text, out_addr_family, out_addr);
}

gboolean nm_utils_parse_inaddr(int addr_family, const char *text, char **out_addr);

gboolean nm_utils_parse_inaddr_prefix_bin(int         addr_family,
                                          const char *text,
                                          int *       out_addr_family,
                                          gpointer    out_addr,
                                          int *       out_prefix);

gboolean
nm_utils_parse_inaddr_prefix(int addr_family, const char *text, char **out_addr, int *out_prefix);

gboolean nm_utils_parse_next_line(const char **inout_ptr,
                                  gsize *      inout_len,
                                  const char **out_line,
                                  gsize *      out_line_len);

gint64 nm_g_ascii_strtoll(const char *nptr, char **endptr, guint base);

guint64 nm_g_ascii_strtoull(const char *nptr, char **endptr, guint base);

double nm_g_ascii_strtod(const char *nptr, char **endptr);

gint64
_nm_utils_ascii_str_to_int64(const char *str, guint base, gint64 min, gint64 max, gint64 fallback);
guint64 _nm_utils_ascii_str_to_uint64(const char *str,
                                      guint       base,
                                      guint64     min,
                                      guint64     max,
                                      guint64     fallback);

int _nm_utils_ascii_str_to_bool(const char *str, int default_value);

/*****************************************************************************/

extern char _nm_utils_to_string_buffer[2096];

void     nm_utils_to_string_buffer_init(char **buf, gsize *len);
gboolean nm_utils_to_string_buffer_init_null(gconstpointer obj, char **buf, gsize *len);

/*****************************************************************************/

typedef struct {
    unsigned    flag;
    const char *name;
} NMUtilsFlags2StrDesc;

#define NM_UTILS_FLAGS2STR(f, n) \
    {                            \
        .flag = f, .name = "" n, \
    }

#define NM_UTILS_FLAGS2STR_DEFINE(fcn_name, flags_type, ...)                    \
    const char *fcn_name(flags_type flags, char *buf, gsize len)                \
    {                                                                           \
        static const NMUtilsFlags2StrDesc descs[] = {__VA_ARGS__};              \
        G_STATIC_ASSERT(sizeof(flags_type) <= sizeof(unsigned));                \
                                                                                \
        return nm_utils_flags2str(descs, G_N_ELEMENTS(descs), flags, buf, len); \
    }                                                                           \
    _NM_DUMMY_STRUCT_FOR_TRAILING_SEMICOLON

const char *nm_utils_flags2str(const NMUtilsFlags2StrDesc *descs,
                               gsize                       n_descs,
                               unsigned                    flags,
                               char *                      buf,
                               gsize                       len);

/*****************************************************************************/

#define NM_UTILS_ENUM2STR(v, n) \
    (void) 0;                   \
case v:                         \
    s = "" n "";                \
    break;                      \
    (void) 0
#define NM_UTILS_ENUM2STR_IGNORE(v) \
    (void) 0;                       \
case v:                             \
    break;                          \
    (void) 0

#define NM_UTILS_ENUM2STR_DEFINE_FULL(fcn_name, lookup_type, int_fmt, ...) \
    const char *fcn_name(lookup_type val, char *buf, gsize len)            \
    {                                                                      \
        nm_utils_to_string_buffer_init(&buf, &len);                        \
        if (len) {                                                         \
            const char *s = NULL;                                          \
            switch (val) {                                                 \
                (void) 0, __VA_ARGS__(void) 0;                             \
            };                                                             \
            if (s)                                                         \
                g_strlcpy(buf, s, len);                                    \
            else                                                           \
                g_snprintf(buf, len, "(%" int_fmt ")", val);               \
        }                                                                  \
        return buf;                                                        \
    }                                                                      \
    _NM_DUMMY_STRUCT_FOR_TRAILING_SEMICOLON

#define NM_UTILS_ENUM2STR_DEFINE(fcn_name, lookup_type, ...) \
    NM_UTILS_ENUM2STR_DEFINE_FULL(fcn_name, lookup_type, "d", __VA_ARGS__)

/*****************************************************************************/

#define _nm_g_slice_free_fcn_define(mem_size)                              \
    static inline void _nm_g_slice_free_fcn_##mem_size(gpointer mem_block) \
    {                                                                      \
        g_slice_free1(mem_size, mem_block);                                \
    }

_nm_g_slice_free_fcn_define(1) _nm_g_slice_free_fcn_define(2) _nm_g_slice_free_fcn_define(4)
    _nm_g_slice_free_fcn_define(8) _nm_g_slice_free_fcn_define(10) _nm_g_slice_free_fcn_define(12)
        _nm_g_slice_free_fcn_define(16) _nm_g_slice_free_fcn_define(32)

#define nm_g_slice_free_fcn1(mem_size)                                                        \
    ({                                                                                        \
        void (*_fcn)(gpointer);                                                               \
                                                                                              \
        /* If mem_size is a compile time constant, the compiler
         * will be able to optimize this. Hence, you don't want
         * to call this with a non-constant size argument. */                               \
        G_STATIC_ASSERT_EXPR(((mem_size) == 1) || ((mem_size) == 2) || ((mem_size) == 4)      \
                             || ((mem_size) == 8) || ((mem_size) == 10) || ((mem_size) == 12) \
                             || ((mem_size) == 16) || ((mem_size) == 32));                    \
        switch ((mem_size)) {                                                                 \
        case 1:                                                                               \
            _fcn = _nm_g_slice_free_fcn_1;                                                    \
            break;                                                                            \
        case 2:                                                                               \
            _fcn = _nm_g_slice_free_fcn_2;                                                    \
            break;                                                                            \
        case 4:                                                                               \
            _fcn = _nm_g_slice_free_fcn_4;                                                    \
            break;                                                                            \
        case 8:                                                                               \
            _fcn = _nm_g_slice_free_fcn_8;                                                    \
            break;                                                                            \
        case 10:                                                                              \
            _fcn = _nm_g_slice_free_fcn_10;                                                   \
            break;                                                                            \
        case 12:                                                                              \
            _fcn = _nm_g_slice_free_fcn_12;                                                   \
            break;                                                                            \
        case 16:                                                                              \
            _fcn = _nm_g_slice_free_fcn_16;                                                   \
            break;                                                                            \
        case 32:                                                                              \
            _fcn = _nm_g_slice_free_fcn_32;                                                   \
            break;                                                                            \
        default:                                                                              \
            g_assert_not_reached();                                                           \
            _fcn = NULL;                                                                      \
            break;                                                                            \
        }                                                                                     \
        _fcn;                                                                                 \
    })

/**
 * nm_g_slice_free_fcn:
 * @type: type argument for sizeof() operator that you would
 *   pass to g_slice_new().
 *
 * Returns: a function pointer with GDestroyNotify signature
 *   for g_slice_free(type,*).
 *
 * Only certain types are implemented. You'll get a compile time
 * error for the wrong types. */
#define nm_g_slice_free_fcn(type) (nm_g_slice_free_fcn1(sizeof(type)))

#define nm_g_slice_free_fcn_gint64 (nm_g_slice_free_fcn(gint64))

/*****************************************************************************/

/* Like g_error_matches() however:
 * - as macro it is always inlined.
 * - the @domain is usually a error quark getter function that cannot
 *   be inlined. This macro calls the getter only if there is an error (lazy).
 * - accept a list of allowed codes, instead of only one.
 */
#define nm_g_error_matches(error, err_domain, ...)                                        \
    ({                                                                                    \
        const GError *const _error = (error);                                             \
                                                                                          \
        _error && _error->domain == (err_domain) && NM_IN_SET(_error->code, __VA_ARGS__); \
    })

            static inline void nm_g_set_error_take(GError **error, GError *error_take)
{
    if (!error_take)
        g_return_if_reached();
    if (!error) {
        g_error_free(error_take);
        return;
    }
    if (*error) {
        g_error_free(error_take);
        g_return_if_reached();
    }
    *error = error_take;
}

#define nm_g_set_error_take_lazy(error, error_take_lazy)    \
    G_STMT_START                                            \
    {                                                       \
        GError **_error = (error);                          \
                                                            \
        if (_error)                                         \
            nm_g_set_error_take(_error, (error_take_lazy)); \
    }                                                       \
    G_STMT_END

/**
 * NMUtilsError:
 * @NM_UTILS_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_UTILS_ERROR_CANCELLED_DISPOSING: when disposing an object that has
 *   pending asynchronous operations, the operation is cancelled with this
 *   error reason. Depending on the usage, this might indicate a bug because
 *   usually the target object should stay alive as long as there are pending
 *   operations.
 * @NM_UTILS_ERROR_NOT_READY: the failure is related to being currently
 *   not ready to perform the operation.
 *
 * @NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE: used for a very particular
 *   purpose during nm_device_check_connection_compatible() to indicate that
 *   the profile does not match the device already because their type differs.
 *   That is, there is a fundamental reason of trying to check a profile that
 *   cannot possibly match on this device.
 * @NM_UTILS_ERROR_CONNECTION_AVAILABLE_UNMANAGED_DEVICE: used for a very particular
 *   purpose during nm_device_check_connection_available(), to indicate that the
 *   device is not available because it is unmanaged.
 * @NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY: the profile is currently not
 *   available/compatible with the device, but this may be only temporary.
 *
 * @NM_UTILS_ERROR_SETTING_MISSING: the setting is missing
 *
 * @NM_UTILS_ERROR_INVALID_ARGUMENT: invalid argument.
 */
typedef enum {
    NM_UTILS_ERROR_UNKNOWN = 0,         /*< nick=Unknown >*/
    NM_UTILS_ERROR_CANCELLED_DISPOSING, /*< nick=CancelledDisposing >*/
    NM_UTILS_ERROR_INVALID_ARGUMENT,    /*< nick=InvalidArgument >*/
    NM_UTILS_ERROR_NOT_READY,           /*< nick=NotReady >*/

    /* the following codes have a special meaning and are exactly used for
     * nm_device_check_connection_compatible() and nm_device_check_connection_available().
     *
     * Actually, their meaning is not very important (so, don't think too
     * hard about the name of these error codes). What is important, is their
     * relative order (i.e. the integer value of the codes). When manager
     * searches for a suitable device, it will check all devices whether
     * a profile can be activated. If they all fail, it will pick the error
     * message from the device that returned the *highest* error code,
     * in the hope that this message makes the most sense for the caller.
     * */
    NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE,
    NM_UTILS_ERROR_CONNECTION_AVAILABLE_UNMANAGED_DEVICE,
    NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,

    NM_UTILS_ERROR_SETTING_MISSING,

} NMUtilsError;

#define NM_UTILS_ERROR (nm_utils_error_quark())
GQuark nm_utils_error_quark(void);

GQuark nm_manager_error_quark(void);
#define _NM_MANAGER_ERROR (nm_manager_error_quark())

#define _NM_MANAGER_ERROR_UNKNOWN_LOG_LEVEL  10
#define _NM_MANAGER_ERROR_UNKNOWN_LOG_DOMAIN 11

void nm_utils_error_set_cancelled(GError **error, gboolean is_disposing, const char *instance_name);

static inline GError *
nm_utils_error_new_cancelled(gboolean is_disposing, const char *instance_name)
{
    GError *error = NULL;

    nm_utils_error_set_cancelled(&error, is_disposing, instance_name);
    return error;
}

gboolean nm_utils_error_is_cancelled_or_disposing(GError *error);

static inline gboolean
nm_utils_error_is_cancelled(GError *error)
{
    return error && error->code == G_IO_ERROR_CANCELLED && error->domain == G_IO_ERROR;
}

gboolean nm_utils_error_is_notfound(GError *error);

static inline void
nm_utils_error_set_literal(GError **error, int error_code, const char *literal)
{
    g_set_error_literal(error, NM_UTILS_ERROR, error_code, literal);
}

#define nm_utils_error_set(error, error_code, ...)                           \
    G_STMT_START                                                             \
    {                                                                        \
        if (NM_NARG(__VA_ARGS__) == 1) {                                     \
            g_set_error_literal((error),                                     \
                                NM_UTILS_ERROR,                              \
                                (error_code),                                \
                                _NM_UTILS_MACRO_FIRST(__VA_ARGS__));         \
        } else {                                                             \
            g_set_error((error), NM_UTILS_ERROR, (error_code), __VA_ARGS__); \
        }                                                                    \
    }                                                                        \
    G_STMT_END

#define nm_utils_error_set_errno(error, errsv, fmt, ...)                                          \
    G_STMT_START                                                                                  \
    {                                                                                             \
        char _bstrerr[NM_STRERROR_BUFSIZE];                                                       \
                                                                                                  \
        g_set_error((error),                                                                      \
                    NM_UTILS_ERROR,                                                               \
                    NM_UTILS_ERROR_UNKNOWN,                                                       \
                    fmt,                                                                          \
                    ##__VA_ARGS__,                                                                \
                    nm_strerror_native_r(                                                         \
                        ({                                                                        \
                            const int _errsv = (errsv);                                           \
                                                                                                  \
                            (_errsv >= 0 ? _errsv                                                 \
                                         : (G_UNLIKELY(_errsv == G_MININT) ? G_MAXINT : -errsv)); \
                        }),                                                                       \
                        _bstrerr,                                                                 \
                        sizeof(_bstrerr)));                                                       \
    }                                                                                             \
    G_STMT_END

#define nm_utils_error_new(error_code, ...)                                                      \
    ((NM_NARG(__VA_ARGS__) == 1)                                                                 \
         ? g_error_new_literal(NM_UTILS_ERROR, (error_code), _NM_UTILS_MACRO_FIRST(__VA_ARGS__)) \
         : g_error_new(NM_UTILS_ERROR, (error_code), __VA_ARGS__))

/*****************************************************************************/

gboolean nm_g_object_set_property(GObject *     object,
                                  const char *  property_name,
                                  const GValue *value,
                                  GError **     error);

gboolean nm_g_object_set_property_string(GObject *   object,
                                         const char *property_name,
                                         const char *value,
                                         GError **   error);

gboolean nm_g_object_set_property_string_static(GObject *   object,
                                                const char *property_name,
                                                const char *value,
                                                GError **   error);

gboolean nm_g_object_set_property_string_take(GObject *   object,
                                              const char *property_name,
                                              char *      value,
                                              GError **   error);

gboolean nm_g_object_set_property_boolean(GObject *   object,
                                          const char *property_name,
                                          gboolean    value,
                                          GError **   error);

gboolean nm_g_object_set_property_char(GObject *   object,
                                       const char *property_name,
                                       gint8       value,
                                       GError **   error);

gboolean nm_g_object_set_property_uchar(GObject *   object,
                                        const char *property_name,
                                        guint8      value,
                                        GError **   error);

gboolean
nm_g_object_set_property_int(GObject *object, const char *property_name, int value, GError **error);

gboolean nm_g_object_set_property_int64(GObject *   object,
                                        const char *property_name,
                                        gint64      value,
                                        GError **   error);

gboolean nm_g_object_set_property_uint(GObject *   object,
                                       const char *property_name,
                                       guint       value,
                                       GError **   error);

gboolean nm_g_object_set_property_uint64(GObject *   object,
                                         const char *property_name,
                                         guint64     value,
                                         GError **   error);

gboolean nm_g_object_set_property_flags(GObject *   object,
                                        const char *property_name,
                                        GType       gtype,
                                        guint       value,
                                        GError **   error);

gboolean nm_g_object_set_property_enum(GObject *   object,
                                       const char *property_name,
                                       GType       gtype,
                                       int         value,
                                       GError **   error);

GParamSpec *nm_g_object_class_find_property_from_gtype(GType gtype, const char *property_name);

/*****************************************************************************/

#define _NM_G_PARAM_SPEC_CAST(param_spec, _value_type, _c_type)              \
    ({                                                                       \
        const GParamSpec *const _param_spec = (param_spec);                  \
                                                                             \
        nm_assert(!_param_spec || _param_spec->value_type == (_value_type)); \
        ((const _c_type *) _param_spec);                                     \
    })

#define NM_G_PARAM_SPEC_CAST_BOOLEAN(param_spec) \
    _NM_G_PARAM_SPEC_CAST(param_spec, G_TYPE_BOOLEAN, GParamSpecBoolean)
#define NM_G_PARAM_SPEC_CAST_UINT(param_spec) \
    _NM_G_PARAM_SPEC_CAST(param_spec, G_TYPE_UINT, GParamSpecUInt)
#define NM_G_PARAM_SPEC_CAST_UINT64(param_spec) \
    _NM_G_PARAM_SPEC_CAST(param_spec, G_TYPE_UINT64, GParamSpecUInt64)

#define NM_G_PARAM_SPEC_GET_DEFAULT_BOOLEAN(param_spec) \
    (NM_G_PARAM_SPEC_CAST_BOOLEAN(NM_ENSURE_NOT_NULL(param_spec))->default_value)
#define NM_G_PARAM_SPEC_GET_DEFAULT_UINT(param_spec) \
    (NM_G_PARAM_SPEC_CAST_UINT(NM_ENSURE_NOT_NULL(param_spec))->default_value)
#define NM_G_PARAM_SPEC_GET_DEFAULT_UINT64(param_spec) \
    (NM_G_PARAM_SPEC_CAST_UINT64(NM_ENSURE_NOT_NULL(param_spec))->default_value)

/*****************************************************************************/

GType nm_g_type_find_implementing_class_for_property(GType gtype, const char *pname);

/*****************************************************************************/

typedef enum {
    NM_UTILS_STR_UTF8_SAFE_FLAG_NONE = 0,

    /* This flag only has an effect during escaping. */
    NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL = 0x0001,

    /* This flag only has an effect during escaping. */
    NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_NON_ASCII = 0x0002,

    /* This flag only has an effect during escaping to ensure we
     * don't leak secrets in memory. Note that during unescape we
     * know the maximum result size from the beginning, and no
     * reallocation happens. Thus, unescape always avoids leaking
     * secrets already. */
    NM_UTILS_STR_UTF8_SAFE_FLAG_SECRET = 0x0004,

    /* This flag only has an effect during unescaping. It means
     * that non-escaped whitespaces (g_ascii_isspace()) will be
     * stripped from the front and end of the string. Note that
     * this flag is only useful for gracefully accepting user input
     * with spaces. With this flag, escape and unescape may no longer
     * yield the original input. */
    NM_UTILS_STR_UTF8_SAFE_UNESCAPE_STRIP_SPACES = 0x0008,
} NMUtilsStrUtf8SafeFlags;

const char *nm_utils_buf_utf8safe_escape(gconstpointer           buf,
                                         gssize                  buflen,
                                         NMUtilsStrUtf8SafeFlags flags,
                                         char **                 to_free);
char *
nm_utils_buf_utf8safe_escape_cp(gconstpointer buf, gssize buflen, NMUtilsStrUtf8SafeFlags flags);
const char *
nm_utils_buf_utf8safe_escape_bytes(GBytes *bytes, NMUtilsStrUtf8SafeFlags flags, char **to_free);
gconstpointer nm_utils_buf_utf8safe_unescape(const char *            str,
                                             NMUtilsStrUtf8SafeFlags flags,
                                             gsize *                 out_len,
                                             gpointer *              to_free);

const char *
nm_utils_str_utf8safe_escape(const char *str, NMUtilsStrUtf8SafeFlags flags, char **to_free);
const char *
nm_utils_str_utf8safe_unescape(const char *str, NMUtilsStrUtf8SafeFlags flags, char **to_free);

char *nm_utils_str_utf8safe_escape_cp(const char *str, NMUtilsStrUtf8SafeFlags flags);
char *nm_utils_str_utf8safe_unescape_cp(const char *str, NMUtilsStrUtf8SafeFlags flags);

char *nm_utils_str_utf8safe_escape_take(char *str, NMUtilsStrUtf8SafeFlags flags);

GVariant *nm_g_variant_singleton_u_0(void);

static inline void
nm_g_variant_unref_floating(GVariant *var)
{
    /* often a function wants to keep a reference to an input variant.
     * It uses g_variant_ref_sink() to either increase the ref-count,
     * or take ownership of a possibly floating reference.
     *
     * If the function doesn't actually want to do anything with the
     * input variant, it still must make sure that a passed in floating
     * reference is consumed. Hence, this helper which:
     *
     *   - does nothing if @var is not floating
     *   - unrefs (consumes) @var if it is floating. */
    if (g_variant_is_floating(var))
        g_variant_unref(var);
}

#define nm_g_variant_lookup(dictionary, ...)                         \
    ({                                                               \
        GVariant *const _dictionary = (dictionary);                  \
                                                                     \
        (_dictionary && g_variant_lookup(_dictionary, __VA_ARGS__)); \
    })

static inline GVariant *
nm_g_variant_lookup_value(GVariant *dictionary, const char *key, const GVariantType *expected_type)
{
    return dictionary ? g_variant_lookup_value(dictionary, key, expected_type) : NULL;
}

static inline gboolean
nm_g_variant_is_of_type(GVariant *value, const GVariantType *type)
{
    return value && g_variant_is_of_type(value, type);
}

static inline GVariant *
nm_g_variant_new_ay_inaddr(int addr_family, gconstpointer addr)
{
    return g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE,
                                     addr ?: &nm_ip_addr_zero,
                                     nm_utils_addr_family_to_size(addr_family),
                                     1);
}

static inline GVariant *
nm_g_variant_new_ay_in4addr(in_addr_t addr)
{
    return nm_g_variant_new_ay_inaddr(AF_INET, &addr);
}

static inline GVariant *
nm_g_variant_new_ay_in6addr(const struct in6_addr *addr)
{
    return nm_g_variant_new_ay_inaddr(AF_INET6, addr);
}

static inline void
nm_g_variant_builder_add_sv(GVariantBuilder *builder, const char *key, GVariant *val)
{
    g_variant_builder_add(builder, "{sv}", key, val);
}

static inline void
nm_g_variant_builder_add_sv_bytearray(GVariantBuilder *builder,
                                      const char *     key,
                                      const guint8 *   arr,
                                      gsize            len)
{
    g_variant_builder_add(builder,
                          "{sv}",
                          key,
                          g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, arr, len, 1));
}

static inline void
nm_g_variant_builder_add_sv_uint32(GVariantBuilder *builder, const char *key, guint32 val)
{
    nm_g_variant_builder_add_sv(builder, key, g_variant_new_uint32(val));
}

static inline void
nm_g_variant_builder_add_sv_str(GVariantBuilder *builder, const char *key, const char *str)
{
    nm_g_variant_builder_add_sv(builder, key, g_variant_new_string(str));
}

static inline void
nm_g_source_destroy_and_unref(GSource *source)
{
    g_source_destroy(source);
    g_source_unref(source);
}

#define nm_clear_g_source_inst(ptr) (nm_clear_pointer((ptr), nm_g_source_destroy_and_unref))

NM_AUTO_DEFINE_FCN0(GSource *, _nm_auto_destroy_and_unref_gsource, nm_g_source_destroy_and_unref);
#define nm_auto_destroy_and_unref_gsource nm_auto(_nm_auto_destroy_and_unref_gsource)

NM_AUTO_DEFINE_FCN0(GMainContext *, _nm_auto_pop_gmaincontext, g_main_context_pop_thread_default);
#define nm_auto_pop_gmaincontext nm_auto(_nm_auto_pop_gmaincontext)

static inline gboolean
nm_source_func_unref_gobject(gpointer user_data)
{
    nm_assert(G_IS_OBJECT(user_data));
    g_object_unref(user_data);
    return G_SOURCE_REMOVE;
}

GSource *nm_g_idle_source_new(int            priority,
                              GSourceFunc    func,
                              gpointer       user_data,
                              GDestroyNotify destroy_notify);

GSource *nm_g_timeout_source_new(guint          timeout_msec,
                                 int            priority,
                                 GSourceFunc    func,
                                 gpointer       user_data,
                                 GDestroyNotify destroy_notify);

GSource *nm_g_timeout_source_new_seconds(guint          timeout_sec,
                                         int            priority,
                                         GSourceFunc    func,
                                         gpointer       user_data,
                                         GDestroyNotify destroy_notify);

GSource *
         nm_g_unix_fd_source_new(int          fd,
                                 GIOCondition io_condition,
                                 int          priority,
                                 gboolean (*source_func)(int fd, GIOCondition condition, gpointer user_data),
                                 gpointer       user_data,
                                 GDestroyNotify destroy_notify);
GSource *nm_g_unix_signal_source_new(int            signum,
                                     int            priority,
                                     GSourceFunc    handler,
                                     gpointer       user_data,
                                     GDestroyNotify notify);

static inline GSource *
nm_g_source_attach(GSource *source, GMainContext *context)
{
    g_source_attach(source, context);
    return source;
}

static inline GSource *
nm_g_idle_add_source(GSourceFunc func, gpointer user_data)
{
    /* G convenience function to attach a new timeout source to the default GMainContext.
     * In that sense it's very similar to g_idle_add() except that it returns a
     * reference to the new source.  */
    return nm_g_source_attach(nm_g_idle_source_new(G_PRIORITY_DEFAULT, func, user_data, NULL),
                              NULL);
}

static inline GSource *
nm_g_timeout_add_source(guint timeout_msec, GSourceFunc func, gpointer user_data)
{
    /* G convenience function to attach a new timeout source to the default GMainContext.
     * In that sense it's very similar to g_timeout_add() except that it returns a
     * reference to the new source.  */
    return nm_g_source_attach(
        nm_g_timeout_source_new(timeout_msec, G_PRIORITY_DEFAULT, func, user_data, NULL),
        NULL);
}

static inline GSource *
nm_g_timeout_add_source_seconds(guint timeout_sec, GSourceFunc func, gpointer user_data)
{
    /* G convenience function to attach a new timeout source to the default GMainContext.
     * In that sense it's very similar to g_timeout_add_seconds() except that it returns a
     * reference to the new source.  */
    return nm_g_source_attach(
        nm_g_timeout_source_new_seconds(timeout_sec, G_PRIORITY_DEFAULT, func, user_data, NULL),
        NULL);
}

static inline GSource *
nm_g_timeout_add_source_approx(guint       timeout_msec,
                               guint       timeout_sec_threshold,
                               GSourceFunc func,
                               gpointer    user_data)
{
    GSource *source;

    /* If timeout_msec is larger or equal than a threshold, then we use g_timeout_source_new_seconds()
     * instead. */
    if (timeout_msec / 1000u >= timeout_sec_threshold)
        source = nm_g_timeout_source_new_seconds(timeout_msec / 1000u,
                                                 G_PRIORITY_DEFAULT,
                                                 func,
                                                 user_data,
                                                 NULL);
    else
        source = nm_g_timeout_source_new(timeout_msec, G_PRIORITY_DEFAULT, func, user_data, NULL);
    return nm_g_source_attach(source, NULL);
}

NM_AUTO_DEFINE_FCN0(GMainContext *, _nm_auto_unref_gmaincontext, g_main_context_unref);
#define nm_auto_unref_gmaincontext nm_auto(_nm_auto_unref_gmaincontext)

static inline GMainContext *
nm_g_main_context_push_thread_default(GMainContext *context)
{
    /* This function is to work together with nm_auto_pop_gmaincontext. */
    if (G_UNLIKELY(!context))
        context = g_main_context_default();
    g_main_context_push_thread_default(context);
    return context;
}

static inline gboolean
nm_g_main_context_is_thread_default(GMainContext *context)
{
    GMainContext *cur_context;

    cur_context = g_main_context_get_thread_default();
    if (cur_context == context)
        return TRUE;

    if (G_UNLIKELY(!cur_context))
        cur_context = g_main_context_default();
    else if (G_UNLIKELY(!context))
        context = g_main_context_default();
    else
        return FALSE;

    return (cur_context == context);
}

static inline GMainContext *
nm_g_main_context_push_thread_default_if_necessary(GMainContext *context)
{
    GMainContext *cur_context;

    cur_context = g_main_context_get_thread_default();
    if (cur_context == context)
        return NULL;

    if (G_UNLIKELY(!cur_context)) {
        cur_context = g_main_context_default();
        if (cur_context == context)
            return NULL;
    } else if (G_UNLIKELY(!context)) {
        context = g_main_context_default();
        if (cur_context == context)
            return NULL;
    }

    g_main_context_push_thread_default(context);
    return context;
}

/*****************************************************************************/

static inline int
nm_utf8_collate0(const char *a, const char *b)
{
    if (!a)
        return !b ? 0 : -1;
    if (!b)
        return 1;
    return g_utf8_collate(a, b);
}

int nm_strcmp_with_data(gconstpointer a, gconstpointer b, gpointer user_data);
int nm_strcmp_p_with_data(gconstpointer a, gconstpointer b, gpointer user_data);
int nm_strcmp0_p_with_data(gconstpointer a, gconstpointer b, gpointer user_data);
int nm_strcmp_ascii_case_with_data(gconstpointer a, gconstpointer b, gpointer user_data);
int nm_cmp_uint32_p_with_data(gconstpointer p_a, gconstpointer p_b, gpointer user_data);
int nm_cmp_int2ptr_p_with_data(gconstpointer p_a, gconstpointer p_b, gpointer user_data);

/*****************************************************************************/

typedef struct {
    const char *name;
} NMUtilsNamedEntry;

typedef struct {
    union {
        NMUtilsNamedEntry named_entry;
        const char *      name;
    };
    union {
        const char *value_str;
        gpointer    value_ptr;
    };
} NMUtilsNamedValue;

#define NM_UTILS_NAMED_VALUE_INIT(n, v) \
    {                                   \
        .name = (n), .value_ptr = (v)   \
    }

NMUtilsNamedValue *
nm_utils_named_values_from_strdict_full(GHashTable *        hash,
                                        guint *             out_len,
                                        GCompareDataFunc    compare_func,
                                        gpointer            user_data,
                                        NMUtilsNamedValue * provided_buffer,
                                        guint               provided_buffer_len,
                                        NMUtilsNamedValue **out_allocated_buffer);

#define nm_utils_named_values_from_strdict(hash, out_len, array, out_allocated_buffer) \
    nm_utils_named_values_from_strdict_full((hash),                                    \
                                            (out_len),                                 \
                                            nm_strcmp_p_with_data,                     \
                                            NULL,                                      \
                                            (array),                                   \
                                            G_N_ELEMENTS(array),                       \
                                            (out_allocated_buffer))

gssize nm_utils_named_value_list_find(const NMUtilsNamedValue *arr,
                                      gsize                    len,
                                      const char *             name,
                                      gboolean                 sorted);

gboolean nm_utils_named_value_list_is_sorted(const NMUtilsNamedValue *arr,
                                             gsize                    len,
                                             gboolean                 accept_duplicates,
                                             GCompareDataFunc         compare_func,
                                             gpointer                 user_data);

void nm_utils_named_value_list_sort(NMUtilsNamedValue *arr,
                                    gsize              len,
                                    GCompareDataFunc   compare_func,
                                    gpointer           user_data);

void nm_utils_named_value_clear_with_g_free(NMUtilsNamedValue *val);

/*****************************************************************************/

gpointer *nm_utils_hash_keys_to_array(GHashTable *     hash,
                                      GCompareDataFunc compare_func,
                                      gpointer         user_data,
                                      guint *          out_len);

gpointer *nm_utils_hash_values_to_array(GHashTable *     hash,
                                        GCompareDataFunc compare_func,
                                        gpointer         user_data,
                                        guint *          out_len);

static inline const char **
nm_utils_strdict_get_keys(const GHashTable *hash, gboolean sorted, guint *out_length)
{
    return (const char **) nm_utils_hash_keys_to_array((GHashTable *) hash,
                                                       sorted ? nm_strcmp_p_with_data : NULL,
                                                       NULL,
                                                       out_length);
}

gboolean nm_utils_hashtable_equal(const GHashTable *a,
                                  const GHashTable *b,
                                  gboolean          treat_null_as_empty,
                                  GEqualFunc        equal_func);

gboolean nm_utils_hashtable_cmp_equal(const GHashTable *a,
                                      const GHashTable *b,
                                      GCompareDataFunc  cmp_values,
                                      gpointer          user_data);

static inline gboolean
nm_utils_hashtable_same_keys(const GHashTable *a, const GHashTable *b)
{
    return nm_utils_hashtable_cmp_equal(a, b, NULL, NULL);
}

int nm_utils_hashtable_cmp(const GHashTable *a,
                           const GHashTable *b,
                           gboolean          do_fast_precheck,
                           GCompareDataFunc  cmp_keys,
                           GCompareDataFunc  cmp_values,
                           gpointer          user_data);

char **nm_utils_strv_make_deep_copied(const char **strv);

char **nm_utils_strv_make_deep_copied_n(const char **strv, gsize len);

static inline char **
nm_utils_strv_make_deep_copied_nonnull(const char **strv)
{
    return nm_utils_strv_make_deep_copied(strv) ?: g_new0(char *, 1);
}

char **_nm_utils_strv_dup(const char *const *strv, gssize len, gboolean deep_copied);

#define nm_utils_strv_dup(strv, len, deep_copied) \
    _nm_utils_strv_dup(NM_CAST_STRV_CC(strv), (len), (deep_copied))

const char **_nm_utils_strv_dup_packed(const char *const *strv, gssize len);

#define nm_utils_strv_dup_packed(strv, len) _nm_utils_strv_dup_packed(NM_CAST_STRV_CC(strv), (len))

/*****************************************************************************/

GSList *nm_utils_g_slist_find_str(const GSList *list, const char *needle);

int nm_utils_g_slist_strlist_cmp(const GSList *a, const GSList *b);

char *nm_utils_g_slist_strlist_join(const GSList *a, const char *separator);

/*****************************************************************************/

static inline guint
nm_g_array_len(const GArray *arr)
{
    return arr ? arr->len : 0u;
}

static inline void
nm_g_array_unref(GArray *arr)
{
    if (arr)
        g_array_unref(arr);
}

#define nm_g_array_append_new(arr, type)   \
    ({                                     \
        GArray *const _arr = (arr);        \
        guint         _len;                \
                                           \
        nm_assert(_arr);                   \
        _len = _arr->len;                  \
        nm_assert(_len < G_MAXUINT);       \
        g_array_set_size(_arr, _len + 1u); \
        &g_array_index(arr, type, _len);   \
    })

/*****************************************************************************/

static inline GPtrArray *
nm_g_ptr_array_ref(GPtrArray *arr)
{
    return arr ? g_ptr_array_ref(arr) : NULL;
}

static inline void
nm_g_ptr_array_unref(GPtrArray *arr)
{
    if (arr)
        g_ptr_array_unref(arr);
}

#define nm_g_ptr_array_set(pdst, val)                              \
    ({                                                             \
        GPtrArray **_pdst    = (pdst);                             \
        GPtrArray * _val     = (val);                              \
        gboolean    _changed = FALSE;                              \
                                                                   \
        nm_assert(_pdst);                                          \
                                                                   \
        if (*_pdst != _val) {                                      \
            _nm_unused gs_unref_ptrarray GPtrArray *_old = *_pdst; \
                                                                   \
            *_pdst   = nm_g_ptr_array_ref(_val);                   \
            _changed = TRUE;                                       \
        }                                                          \
        _changed;                                                  \
    })

#define nm_g_ptr_array_set_take(pdst, val)                         \
    ({                                                             \
        GPtrArray **_pdst    = (pdst);                             \
        GPtrArray * _val     = (val);                              \
        gboolean    _changed = FALSE;                              \
                                                                   \
        nm_assert(_pdst);                                          \
                                                                   \
        if (*_pdst != _val) {                                      \
            _nm_unused gs_unref_ptrarray GPtrArray *_old = *_pdst; \
                                                                   \
            *_pdst   = _val;                                       \
            _changed = TRUE;                                       \
        } else {                                                   \
            nm_g_ptr_array_unref(_val);                            \
        }                                                          \
        _changed;                                                  \
    })

static inline guint
nm_g_ptr_array_len(const GPtrArray *arr)
{
    return arr ? arr->len : 0u;
}

static inline gpointer *
nm_g_ptr_array_pdata(const GPtrArray *arr)
{
    return arr ? arr->pdata : NULL;
}

GPtrArray *_nm_g_ptr_array_copy(GPtrArray *    array,
                                GCopyFunc      func,
                                gpointer       user_data,
                                GDestroyNotify element_free_func);

/**
 * nm_g_ptr_array_copy:
 * @array: the #GPtrArray to clone.
 * @func: the copy function.
 * @user_data: the user data for the copy function
 * @element_free_func: the free function of the elements. @array MUST have
 *   the same element_free_func. This argument is only used on older
 *   glib, that doesn't support g_ptr_array_copy().
 *
 * This is a replacement for g_ptr_array_copy(), which is not available
 * before glib 2.62. Since GPtrArray does not allow to access the internal
 * element_free_func, we cannot add a compatibility implementation of g_ptr_array_copy()
 * and the user must provide a suitable destroy function.
 *
 * Note that the @element_free_func MUST correspond to free function set in @array.
 */
#if GLIB_CHECK_VERSION(2, 62, 0)
    #define nm_g_ptr_array_copy(array, func, user_data, element_free_func)            \
        ({                                                                            \
            _nm_unused GDestroyNotify const _element_free_func = (element_free_func); \
                                                                                      \
            G_GNUC_BEGIN_IGNORE_DEPRECATIONS;                                         \
            g_ptr_array_copy((array), (func), (user_data));                           \
            G_GNUC_END_IGNORE_DEPRECATIONS;                                           \
        })
#else
    #define nm_g_ptr_array_copy(array, func, user_data, element_free_func) \
        _nm_g_ptr_array_copy((array), (func), (user_data), (element_free_func))
#endif

/*****************************************************************************/

static inline GHashTable *
nm_g_hash_table_ref(GHashTable *hash)
{
    return hash ? g_hash_table_ref(hash) : NULL;
}

static inline void
nm_g_hash_table_unref(GHashTable *hash)
{
    if (hash)
        g_hash_table_unref(hash);
}

static inline guint
nm_g_hash_table_size(GHashTable *hash)
{
    return hash ? g_hash_table_size(hash) : 0u;
}

static inline gpointer
nm_g_hash_table_lookup(GHashTable *hash, gconstpointer key)
{
    return hash ? g_hash_table_lookup(hash, key) : NULL;
}

static inline gboolean
nm_g_hash_table_contains(GHashTable *hash, gconstpointer key)
{
    return hash ? g_hash_table_contains(hash, key) : FALSE;
}

static inline gboolean
nm_g_hash_table_remove(GHashTable *hash, gconstpointer key)
{
    return hash ? g_hash_table_remove(hash, key) : FALSE;
}

/*****************************************************************************/

gssize nm_utils_ptrarray_find_binary_search(gconstpointer *  list,
                                            gsize            len,
                                            gconstpointer    needle,
                                            GCompareDataFunc cmpfcn,
                                            gpointer         user_data,
                                            gssize *         out_idx_first,
                                            gssize *         out_idx_last);

gssize nm_utils_array_find_binary_search(gconstpointer    list,
                                         gsize            elem_size,
                                         gsize            len,
                                         gconstpointer    needle,
                                         GCompareDataFunc cmpfcn,
                                         gpointer         user_data);

/*****************************************************************************/

void _nm_utils_strv_sort(const char **strv, gssize len);
#define nm_utils_strv_sort(strv, len) _nm_utils_strv_sort(NM_CAST_STRV_MC(strv), len)

int
_nm_utils_strv_cmp_n(const char *const *strv1, gssize len1, const char *const *strv2, gssize len2);

#define nm_utils_strv_cmp_n(strv1, len1, strv2, len2) \
    _nm_utils_strv_cmp_n(NM_CAST_STRV_CC(strv1), (len1), NM_CAST_STRV_CC(strv2), (len2))

#define nm_utils_strv_equal(strv1, strv2) (nm_utils_strv_cmp_n((strv1), -1, (strv2), -1) == 0)

/*****************************************************************************/

#define NM_UTILS_NSEC_PER_SEC  ((gint64) 1000000000)
#define NM_UTILS_USEC_PER_SEC  ((gint64) 1000000)
#define NM_UTILS_MSEC_PER_SEC  ((gint64) 1000)
#define NM_UTILS_NSEC_PER_MSEC ((gint64) 1000000)

static inline gint64
NM_UTILS_NSEC_TO_MSEC_CEIL(gint64 nsec)
{
    return (nsec + (NM_UTILS_NSEC_PER_MSEC - 1)) / NM_UTILS_NSEC_PER_MSEC;
}

/*****************************************************************************/

int     nm_utils_fd_wait_for_event(int fd, int event, gint64 timeout_nsec);
ssize_t nm_utils_fd_read_loop(int fd, void *buf, size_t nbytes, bool do_poll);
int     nm_utils_fd_read_loop_exact(int fd, void *buf, size_t nbytes, bool do_poll);

/*****************************************************************************/

#define NM_DEFINE_GDBUS_ARG_INFO_FULL(name_, ...) \
    ((GDBusArgInfo *) (&((const GDBusArgInfo){.ref_count = -1, .name = name_, __VA_ARGS__})))

#define NM_DEFINE_GDBUS_ARG_INFO(name_, a_signature) \
    NM_DEFINE_GDBUS_ARG_INFO_FULL(name_, .signature = a_signature, )

#define NM_DEFINE_GDBUS_ARG_INFOS(...)            \
    ((GDBusArgInfo **) ((const GDBusArgInfo *[]){ \
        __VA_ARGS__ NULL,                         \
    }))

#define NM_DEFINE_GDBUS_PROPERTY_INFO(name_, ...) \
    ((GDBusPropertyInfo *) (&(                    \
        (const GDBusPropertyInfo){.ref_count = -1, .name = name_, __VA_ARGS__})))

#define NM_DEFINE_GDBUS_PROPERTY_INFO_READABLE(name_, m_signature) \
    NM_DEFINE_GDBUS_PROPERTY_INFO(name_,                           \
                                  .signature = m_signature,        \
                                  .flags     = G_DBUS_PROPERTY_INFO_FLAGS_READABLE, )

#define NM_DEFINE_GDBUS_PROPERTY_INFOS(...)                 \
    ((GDBusPropertyInfo **) ((const GDBusPropertyInfo *[]){ \
        __VA_ARGS__ NULL,                                   \
    }))

#define NM_DEFINE_GDBUS_SIGNAL_INFO_INIT(name_, ...) \
    {                                                \
        .ref_count = -1, .name = name_, __VA_ARGS__  \
    }

#define NM_DEFINE_GDBUS_SIGNAL_INFO(name_, ...) \
    ((GDBusSignalInfo *) (&(                    \
        (const GDBusSignalInfo) NM_DEFINE_GDBUS_SIGNAL_INFO_INIT(name_, __VA_ARGS__))))

#define NM_DEFINE_GDBUS_SIGNAL_INFOS(...)               \
    ((GDBusSignalInfo **) ((const GDBusSignalInfo *[]){ \
        __VA_ARGS__ NULL,                               \
    }))

#define NM_DEFINE_GDBUS_METHOD_INFO_INIT(name_, ...) \
    {                                                \
        .ref_count = -1, .name = name_, __VA_ARGS__  \
    }

#define NM_DEFINE_GDBUS_METHOD_INFO(name_, ...) \
    ((GDBusMethodInfo *) (&(                    \
        (const GDBusMethodInfo) NM_DEFINE_GDBUS_METHOD_INFO_INIT(name_, __VA_ARGS__))))

#define NM_DEFINE_GDBUS_METHOD_INFOS(...)               \
    ((GDBusMethodInfo **) ((const GDBusMethodInfo *[]){ \
        __VA_ARGS__ NULL,                               \
    }))

#define NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(name_, ...) \
    {                                                   \
        .ref_count = -1, .name = name_, __VA_ARGS__     \
    }

#define NM_DEFINE_GDBUS_INTERFACE_INFO(name_, ...) \
    ((GDBusInterfaceInfo *) (&(                    \
        (const GDBusInterfaceInfo) NM_DEFINE_GDBUS_INTERFACE_INFO_INIT(name_, __VA_ARGS__))))

#define NM_DEFINE_GDBUS_INTERFACE_VTABLE(...) \
    ((GDBusInterfaceVTable *) (&((const GDBusInterfaceVTable){__VA_ARGS__})))

/*****************************************************************************/

guint64 nm_utils_get_start_time_for_pid(pid_t pid, char *out_state, pid_t *out_ppid);

static inline gboolean
nm_utils_process_state_is_dead(char pstate)
{
    /* "/proc/[pid]/stat" returns a state as the 3rd fields (see `man 5 proc`).
     * Some of these states indicate the process is effectively dead (or a zombie).
     */
    return NM_IN_SET(pstate, 'Z', 'x', 'X');
}

/*****************************************************************************/

typedef struct _NMUtilsUserData NMUtilsUserData;

NMUtilsUserData *_nm_utils_user_data_pack(int nargs, gconstpointer *args);

#define nm_utils_user_data_pack(...) \
    _nm_utils_user_data_pack(NM_NARG(__VA_ARGS__), (gconstpointer[]){__VA_ARGS__})

void _nm_utils_user_data_unpack(NMUtilsUserData *user_data, int nargs, ...);

#define nm_utils_user_data_unpack(user_data, ...) \
    _nm_utils_user_data_unpack(user_data, NM_NARG(__VA_ARGS__), __VA_ARGS__)

/*****************************************************************************/

typedef void (*NMUtilsInvokeOnIdleCallback)(gpointer user_data, GCancellable *cancellable);

void nm_utils_invoke_on_idle(GCancellable *              cancellable,
                             NMUtilsInvokeOnIdleCallback callback,
                             gpointer                    callback_user_data);

void nm_utils_invoke_on_timeout(guint                       timeout_msec,
                                GCancellable *              cancellable,
                                NMUtilsInvokeOnIdleCallback callback,
                                gpointer                    callback_user_data);

/*****************************************************************************/

GSource *nm_utils_g_main_context_create_integrate_source(GMainContext *internal);

/*****************************************************************************/

static inline GPtrArray *
nm_strv_ptrarray_ensure(GPtrArray **p_arr)
{
    nm_assert(p_arr);

    if (G_UNLIKELY(!*p_arr))
        *p_arr = g_ptr_array_new_with_free_func(g_free);

    return *p_arr;
}

static inline const char *const *
nm_strv_ptrarray_get_unsafe(GPtrArray *arr, guint *out_len)
{
    /* warning: the GPtrArray is not NULL terminated. So, it
     * isn't really a strv array (sorry the misnomer). That's why
     * the function is potentially "unsafe" and you must provide a
     * out_len parameter. */
    if (!arr || arr->len == 0) {
        *out_len = 0;
        return NULL;
    }
    *out_len = arr->len;
    return (const char *const *) arr->pdata;
}

static inline GPtrArray *
nm_strv_ptrarray_clone(const GPtrArray *src, gboolean null_if_empty)
{
    if (!src || (null_if_empty && src->len == 0))
        return NULL;
    return nm_g_ptr_array_copy((GPtrArray *) src, nm_copy_func_g_strdup, NULL, g_free);
}

static inline void
nm_strv_ptrarray_add_string_take(GPtrArray *cmd, char *str)
{
    nm_assert(cmd);
    nm_assert(str);

    g_ptr_array_add(cmd, str);
}

static inline void
nm_strv_ptrarray_add_string_dup(GPtrArray *cmd, const char *str)
{
    nm_strv_ptrarray_add_string_take(cmd, g_strdup(str));
}

#define nm_strv_ptrarray_add_string_concat(cmd, ...) \
    nm_strv_ptrarray_add_string_take((cmd), g_strconcat(__VA_ARGS__, NULL))

#define nm_strv_ptrarray_add_string_printf(cmd, ...) \
    nm_strv_ptrarray_add_string_take((cmd), g_strdup_printf(__VA_ARGS__))

#define nm_strv_ptrarray_add_int(cmd, val) \
    nm_strv_ptrarray_add_string_take((cmd), nm_strdup_int(val))

static inline void
nm_strv_ptrarray_take_gstring(GPtrArray *cmd, GString **gstr)
{
    nm_assert(gstr && *gstr);

    nm_strv_ptrarray_add_string_take(cmd, g_string_free(g_steal_pointer(gstr), FALSE));
}

static inline gssize
nm_strv_ptrarray_find_first(const GPtrArray *strv, const char *str)
{
    if (!strv)
        return -1;
    return nm_utils_strv_find_first((char **) strv->pdata, strv->len, str);
}

static inline gboolean
nm_strv_ptrarray_contains(const GPtrArray *strv, const char *str)
{
    return nm_strv_ptrarray_find_first(strv, str) >= 0;
}

static inline int
nm_strv_ptrarray_cmp(const GPtrArray *a, const GPtrArray *b)
{
    /* nm_utils_strv_cmp_n() will treat NULL and empty arrays the same.
     * That means, an empty strv array can both be represented by NULL
     * and an array of length zero.
     * If you need to distinguish between these case, do that yourself. */
    return nm_utils_strv_cmp_n((const char *const *) nm_g_ptr_array_pdata(a),
                               nm_g_ptr_array_len(a),
                               (const char *const *) nm_g_ptr_array_pdata(b),
                               nm_g_ptr_array_len(b));
}

/*****************************************************************************/

int nm_utils_getpagesize(void);

/*****************************************************************************/

extern const char _nm_hexchar_table_lower[16];
extern const char _nm_hexchar_table_upper[16];

static inline char
nm_hexchar(int x, gboolean upper_case)
{
    return upper_case ? _nm_hexchar_table_upper[x & 15] : _nm_hexchar_table_lower[x & 15];
}

char *nm_utils_bin2hexstr_full(gconstpointer addr,
                               gsize         length,
                               char          delimiter,
                               gboolean      upper_case,
                               char *        out);

#define nm_utils_bin2hexstr_a(addr, length, delimiter, upper_case, str_to_free)               \
    ({                                                                                        \
        gconstpointer _addr        = (addr);                                                  \
        gsize         _length      = (length);                                                \
        char          _delimiter   = (delimiter);                                             \
        char **       _str_to_free = (str_to_free);                                           \
        char *        _s;                                                                     \
        gsize         _s_len;                                                                 \
                                                                                              \
        nm_assert(_str_to_free);                                                              \
                                                                                              \
        _s_len = _length == 0 ? 1u : (_delimiter == '\0' ? _length * 2u + 1u : _length * 3u); \
        if (_s_len < 100)                                                                     \
            _s = g_alloca(_s_len);                                                            \
        else {                                                                                \
            _s            = g_malloc(_s_len);                                                 \
            *_str_to_free = _s;                                                               \
        }                                                                                     \
        nm_utils_bin2hexstr_full(_addr, _length, _delimiter, (upper_case), _s);               \
    })

static inline const char *
nm_ether_addr_to_string(const NMEtherAddr *ether_addr, char sbuf[static(sizeof(NMEtherAddr) * 3)])
{
    nm_assert(ether_addr);
    nm_assert(sbuf);

    return nm_utils_bin2hexstr_full(ether_addr, sizeof(NMEtherAddr), ':', TRUE, sbuf);
}

#define nm_ether_addr_to_string_a(ether_addr) \
    nm_ether_addr_to_string((ether_addr), g_alloca(sizeof(NMEtherAddr) * 3))

guint8 *nm_utils_hexstr2bin_full(const char *hexstr,
                                 gboolean    allow_0x_prefix,
                                 gboolean    delimiter_required,
                                 gboolean    hexdigit_pairs_required,
                                 const char *delimiter_candidates,
                                 gsize       required_len,
                                 guint8 *    buffer,
                                 gsize       buffer_len,
                                 gsize *     out_len);

#define nm_utils_hexstr2bin_buf(hexstr,               \
                                allow_0x_prefix,      \
                                delimiter_required,   \
                                delimiter_candidates, \
                                buffer)               \
    nm_utils_hexstr2bin_full((hexstr),                \
                             (allow_0x_prefix),       \
                             (delimiter_required),    \
                             FALSE,                   \
                             (delimiter_candidates),  \
                             G_N_ELEMENTS(buffer),    \
                             (buffer),                \
                             G_N_ELEMENTS(buffer),    \
                             NULL)

guint8 *nm_utils_hexstr2bin_alloc(const char *hexstr,
                                  gboolean    allow_0x_prefix,
                                  gboolean    delimiter_required,
                                  const char *delimiter_candidates,
                                  gsize       required_len,
                                  gsize *     out_len);

/**
 * _nm_utils_hwaddr_aton:
 * @asc: the ASCII representation of a hardware address
 * @buffer: buffer to store the result into. Must have
 *   at least a size of @buffer_length.
 * @buffer_length: the length of the input buffer @buffer.
 *   The result must fit into that buffer, otherwise
 *   the function fails and returns %NULL.
 * @out_length: the output length in case of success.
 *
 * Parses @asc and converts it to binary form in @buffer.
 * Bytes in @asc can be separated by colons (:), or hyphens (-), but not mixed.
 *
 * It is like nm_utils_hwaddr_aton(), but contrary to that it
 * can parse addresses of any length. That is, you don't need
 * to know the length before-hand.
 *
 * Return value: @buffer, or %NULL if @asc couldn't be parsed.
 */
static inline guint8 *
_nm_utils_hwaddr_aton(const char *asc, gpointer buffer, gsize buffer_length, gsize *out_length)
{
    g_return_val_if_fail(asc, NULL);
    g_return_val_if_fail(buffer, NULL);
    g_return_val_if_fail(buffer_length > 0, NULL);
    g_return_val_if_fail(out_length, NULL);

    return nm_utils_hexstr2bin_full(asc,
                                    FALSE,
                                    TRUE,
                                    FALSE,
                                    ":-",
                                    0,
                                    buffer,
                                    buffer_length,
                                    out_length);
}

static inline guint8 *
_nm_utils_hwaddr_aton_exact(const char *asc, gpointer buffer, gsize buffer_length)
{
    g_return_val_if_fail(asc, NULL);
    g_return_val_if_fail(buffer, NULL);
    g_return_val_if_fail(buffer_length > 0, NULL);

    return nm_utils_hexstr2bin_full(asc,
                                    FALSE,
                                    TRUE,
                                    FALSE,
                                    ":-",
                                    buffer_length,
                                    buffer,
                                    buffer_length,
                                    NULL);
}

static inline const char *
_nm_utils_hwaddr_ntoa(gconstpointer addr,
                      gsize         addr_len,
                      gboolean      upper_case,
                      char *        buf,
                      gsize         buf_len)
{
    g_return_val_if_fail(addr, NULL);
    g_return_val_if_fail(addr_len > 0, NULL);
    g_return_val_if_fail(buf, NULL);
    if (buf_len < addr_len * 3)
        g_return_val_if_reached(NULL);

    return nm_utils_bin2hexstr_full(addr, addr_len, ':', upper_case, buf);
}

/*****************************************************************************/

#define _NM_UTILS_STRING_TABLE_LOOKUP_DEFINE(fcn_name,                                         \
                                             value_type,                                       \
                                             value_type_result,                                \
                                             entry_cmd,                                        \
                                             unknown_val_cmd,                                  \
                                             get_operator,                                     \
                                             ...)                                              \
    value_type_result fcn_name(const char *name)                                               \
    {                                                                                          \
        static const struct {                                                                  \
            const char *name;                                                                  \
            value_type  value;                                                                 \
        } LIST[] = {__VA_ARGS__};                                                              \
                                                                                               \
        if (NM_MORE_ASSERT_ONCE(5)) {                                                          \
            int i;                                                                             \
                                                                                               \
            for (i = 0; i < G_N_ELEMENTS(LIST); i++) {                                         \
                nm_assert(LIST[i].name);                                                       \
                if (i > 0)                                                                     \
                    nm_assert(strcmp(LIST[i - 1].name, LIST[i].name) < 0);                     \
            }                                                                                  \
        }                                                                                      \
                                                                                               \
        {                                                                                      \
            entry_cmd;                                                                         \
        }                                                                                      \
                                                                                               \
        if (G_LIKELY(name)) {                                                                  \
            G_STATIC_ASSERT(G_N_ELEMENTS(LIST) > 1);                                           \
            G_STATIC_ASSERT(G_N_ELEMENTS(LIST) < G_MAXINT / 2 - 10);                           \
            int imin = 0;                                                                      \
            int imax = (G_N_ELEMENTS(LIST) - 1);                                               \
            int imid = (G_N_ELEMENTS(LIST) - 1) / 2;                                           \
                                                                                               \
            for (;;) {                                                                         \
                const int cmp = strcmp(LIST[imid].name, name);                                 \
                                                                                               \
                if (G_UNLIKELY(cmp == 0))                                                      \
                    return get_operator(LIST[imid].value);                                     \
                                                                                               \
                if (cmp < 0)                                                                   \
                    imin = imid + 1;                                                           \
                else                                                                           \
                    imax = imid - 1;                                                           \
                                                                                               \
                if (G_UNLIKELY(imin > imax))                                                   \
                    break;                                                                     \
                                                                                               \
                /* integer overflow cannot happen, because LIST is shorter than G_MAXINT/2. */ \
                imid = (imin + imax) / 2;                                                      \
            }                                                                                  \
        }                                                                                      \
                                                                                               \
        {                                                                                      \
            unknown_val_cmd;                                                                   \
        }                                                                                      \
    }                                                                                          \
    _NM_DUMMY_STRUCT_FOR_TRAILING_SEMICOLON

#define NM_UTILS_STRING_TABLE_LOOKUP_STRUCT_DEFINE(fcn_name,        \
                                                   result_type,     \
                                                   entry_cmd,       \
                                                   unknown_val_cmd, \
                                                   ...)             \
    _NM_UTILS_STRING_TABLE_LOOKUP_DEFINE(fcn_name,                  \
                                         result_type,               \
                                         const result_type *,       \
                                         entry_cmd,                 \
                                         unknown_val_cmd,           \
                                             &,                     \
                                         __VA_ARGS__)

#define NM_UTILS_STRING_TABLE_LOOKUP_DEFINE(fcn_name,        \
                                            result_type,     \
                                            entry_cmd,       \
                                            unknown_val_cmd, \
                                            ...)             \
    _NM_UTILS_STRING_TABLE_LOOKUP_DEFINE(fcn_name,           \
                                         result_type,        \
                                         result_type,        \
                                         entry_cmd,          \
                                         unknown_val_cmd,    \
                                         ,                   \
                                         __VA_ARGS__)

/*****************************************************************************/

static inline GTask *
nm_g_task_new(gpointer            source_object,
              GCancellable *      cancellable,
              gpointer            source_tag,
              GAsyncReadyCallback callback,
              gpointer            callback_data)
{
    GTask *task;

    task = g_task_new(source_object, cancellable, callback, callback_data);
    if (source_tag)
        g_task_set_source_tag(task, source_tag);
    return task;
}

static inline gboolean
nm_g_task_is_valid(gpointer task, gpointer source_object, gpointer source_tag)
{
    return g_task_is_valid(task, source_object) && g_task_get_source_tag(task) == source_tag;
}

guint nm_utils_parse_debug_string(const char *string, const GDebugKey *keys, guint nkeys);

/*****************************************************************************/

static inline gboolean
nm_utils_strdup_reset(char **dst, const char *src)
{
    char *old;

    nm_assert(dst);

    if (nm_streq0(*dst, src))
        return FALSE;
    old  = *dst;
    *dst = g_strdup(src);
    g_free(old);
    return TRUE;
}

static inline gboolean
nm_utils_strdup_reset_take(char **dst, char *src)
{
    char *old;

    nm_assert(dst);
    nm_assert(src != *dst);

    if (nm_streq0(*dst, src)) {
        if (src)
            g_free(src);
        return FALSE;
    }
    old  = *dst;
    *dst = src;
    g_free(old);
    return TRUE;
}

void nm_indirect_g_free(gpointer arg);

/*****************************************************************************/

void nm_utils_ifname_cpy(char *dst, const char *name);

typedef enum {
    NMU_IFACE_ANY,
    NMU_IFACE_KERNEL,
    NMU_IFACE_OVS,
    NMU_IFACE_OVS_AND_KERNEL,
} NMUtilsIfaceType;

gboolean nm_utils_ifname_valid_kernel(const char *name, GError **error);

gboolean nm_utils_ifname_valid(const char *name, NMUtilsIfaceType type, GError **error);

/*****************************************************************************/

static inline GArray *
nm_strvarray_ensure(GArray **p)
{
    if (!*p) {
        *p = g_array_new(TRUE, FALSE, sizeof(char *));
        g_array_set_clear_func(*p, nm_indirect_g_free);
    }
    return *p;
}

static inline void
nm_strvarray_add(GArray *array, const char *str)
{
    char *s;

    s = g_strdup(str);
    g_array_append_val(array, s);
}

static inline const char *const *
nm_strvarray_get_strv_non_empty(GArray *arr, guint *length)
{
    if (!arr || arr->len == 0) {
        NM_SET_OUT(length, 0);
        return NULL;
    }

    NM_SET_OUT(length, arr->len);
    return &g_array_index(arr, const char *, 0);
}

static inline const char *const *
nm_strvarray_get_strv(GArray **arr, guint *length)
{
    if (!*arr) {
        NM_SET_OUT(length, 0);
        return (const char *const *) arr;
    }

    NM_SET_OUT(length, (*arr)->len);
    return &g_array_index(*arr, const char *, 0);
}

static inline void
nm_strvarray_set_strv(GArray **array, const char *const *strv)
{
    gs_unref_array GArray *array_old = NULL;

    array_old = g_steal_pointer(array);

    if (!strv || !strv[0])
        return;

    nm_strvarray_ensure(array);
    for (; strv[0]; strv++)
        nm_strvarray_add(*array, strv[0]);
}

static inline gboolean
nm_strvarray_remove_first(GArray *strv, const char *needle)
{
    guint i;

    nm_assert(needle);

    if (strv) {
        for (i = 0; i < strv->len; i++) {
            if (nm_streq(needle, g_array_index(strv, const char *, i))) {
                g_array_remove_index(strv, i);
                return TRUE;
            }
        }
    }
    return FALSE;
}

/*****************************************************************************/

struct _NMVariantAttributeSpec {
    char *              name;
    const GVariantType *type;
    bool                v4 : 1;
    bool                v6 : 1;
    bool                no_value : 1;
    bool                consumes_rest : 1;
    char                str_type;
};

typedef struct _NMVariantAttributeSpec NMVariantAttributeSpec;

void _nm_utils_format_variant_attributes_full(GString *                            str,
                                              const NMUtilsNamedValue *            values,
                                              guint                                num_values,
                                              const NMVariantAttributeSpec *const *spec,
                                              char                                 attr_separator,
                                              char key_value_separator);

char *_nm_utils_format_variant_attributes(GHashTable *                         attributes,
                                          const NMVariantAttributeSpec *const *spec,
                                          char                                 attr_separator,
                                          char                                 key_value_separator);

/*****************************************************************************/

gboolean nm_utils_is_localhost(const char *name);

gboolean nm_utils_is_specific_hostname(const char *name);

char *   nm_utils_uid_to_name(uid_t uid);
gboolean nm_utils_name_to_uid(const char *name, uid_t *out_uid);

/*****************************************************************************/

void nm_utils_thread_local_register_destroy(gpointer tls_data, GDestroyNotify destroy_notify);

#endif /* __NM_SHARED_UTILS_H__ */
