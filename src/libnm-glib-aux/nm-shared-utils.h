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

#define nm_assert_is_bool(value)    nm_assert(NM_IN_SET((value), 0, 1))
#define nm_assert_is_ternary(value) nm_assert(NM_IN_SET((value), -1, 0, 1))

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
#define NM_ASSERT_ON_MAIN_THREAD() nm_assert(_nm_assert_on_main_thread())
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
        _Generic((value), int: TRUE);              \
    })
#else
#define _NM_INT_LE_MAXINT32(value)                   \
    ({                                               \
        _nm_unused typeof(value) _value   = (value); \
        _nm_unused const int    *_p_value = &_value; \
                                                     \
        TRUE;                                        \
    })
#endif

/*****************************************************************************/

typedef enum _nm_packed {
    /* No type, empty value */
    NM_PORT_KIND_NONE,
    NM_PORT_KIND_BOND,
} NMPortKind;

/*****************************************************************************/

typedef enum {

    /* No type, used as error value */
    NM_LINK_TYPE_NONE,

    NM_LINK_TYPE_UNKNOWN,

    NM_LINK_TYPE_ANY,

#define _NM_LINK_TYPE_REAL_FIRST NM_LINK_TYPE_ETHERNET

/* Hardware types */
#define _NM_LINK_TYPE_HW_FIRST NM_LINK_TYPE_ETHERNET
    NM_LINK_TYPE_ETHERNET,
    NM_LINK_TYPE_INFINIBAND,
    NM_LINK_TYPE_OLPC_MESH,
    NM_LINK_TYPE_WIFI,
    NM_LINK_TYPE_WWAN_NET, /* WWAN kernel netdevice */
    NM_LINK_TYPE_WIMAX,
    NM_LINK_TYPE_WPAN,
    NM_LINK_TYPE_6LOWPAN,
    NM_LINK_TYPE_WIFI_P2P,
#define _NM_LINK_TYPE_HW_LAST NM_LINK_TYPE_WIFI_P2P

/* Software types */
#define _NM_LINK_TYPE_SW_FIRST NM_LINK_TYPE_BNEP
    NM_LINK_TYPE_BNEP, /* Bluetooth Ethernet emulation */
    NM_LINK_TYPE_DUMMY,
    NM_LINK_TYPE_GRE,
    NM_LINK_TYPE_GRETAP,
    NM_LINK_TYPE_IFB,
    NM_LINK_TYPE_IP6TNL,
    NM_LINK_TYPE_IP6GRE,
    NM_LINK_TYPE_IP6GRETAP,
    NM_LINK_TYPE_IPIP,
    NM_LINK_TYPE_LOOPBACK,
    NM_LINK_TYPE_MACSEC,
    NM_LINK_TYPE_MACVLAN,
    NM_LINK_TYPE_MACVTAP,
    NM_LINK_TYPE_OPENVSWITCH,
    NM_LINK_TYPE_PPP,
    NM_LINK_TYPE_SIT,
    NM_LINK_TYPE_TUN,
    NM_LINK_TYPE_VETH,
    NM_LINK_TYPE_VLAN,
    NM_LINK_TYPE_VRF,
    NM_LINK_TYPE_VTI,
    NM_LINK_TYPE_VTI6,
    NM_LINK_TYPE_VXLAN,
    NM_LINK_TYPE_WIREGUARD,
#define _NM_LINK_TYPE_SW_LAST NM_LINK_TYPE_WIREGUARD

/* Software types with slaves */
#define _NM_LINK_TYPE_SW_MASTER_FIRST NM_LINK_TYPE_BRIDGE
    NM_LINK_TYPE_BRIDGE,
    NM_LINK_TYPE_BOND,
    NM_LINK_TYPE_TEAM,
#define _NM_LINK_TYPE_SW_MASTER_LAST NM_LINK_TYPE_TEAM

#define _NM_LINK_TYPE_REAL_LAST NM_LINK_TYPE_TEAM

#define _NM_LINK_TYPE_REAL_NUM ((int) (_NM_LINK_TYPE_REAL_LAST - _NM_LINK_TYPE_REAL_FIRST + 1))

} NMLinkType;

static inline gboolean
nm_link_type_is_software(NMLinkType link_type)
{
    G_STATIC_ASSERT(_NM_LINK_TYPE_SW_LAST + 1 == _NM_LINK_TYPE_SW_MASTER_FIRST);

    return link_type >= _NM_LINK_TYPE_SW_FIRST && link_type <= _NM_LINK_TYPE_SW_MASTER_LAST;
}

static inline gboolean
nm_link_type_supports_slaves(NMLinkType link_type)
{
    return link_type >= _NM_LINK_TYPE_SW_MASTER_FIRST && link_type <= _NM_LINK_TYPE_SW_MASTER_LAST;
}

/*****************************************************************************/

gboolean _nm_utils_inet6_is_token(const struct in6_addr *in6addr);

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

union _NMIPAddr;

extern const union _NMIPAddr nm_ip_addr_zero;

/* Let's reuse nm_ip_addr_zero also for nm_ether_addr_zero. It's a union that
 * also contains a NMEtherAddr field. */
#define nm_ether_addr_zero (*((const NMEtherAddr *) &nm_ip_addr_zero))

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

static inline gboolean
nm_ether_addr_is_zero(const NMEtherAddr *a)
{
    return nm_memeq(a, &nm_ether_addr_zero, sizeof(NMEtherAddr));
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

/**
 * NMUtilsIPv6IfaceId:
 * @id: convenience member for validity checking; never use directly
 * @id_u8: the 64-bit Interface Identifier
 *
 * Holds a 64-bit IPv6 Interface Identifier.  The IID is a sequence of bytes
 * and should not normally be treated as a %guint64, but this is done for
 * convenience of validity checking and initialization.
 */
typedef struct _NMUtilsIPv6IfaceId {
    union {
        guint64 id;
        guint8  id_u8[8];
    };
} NMUtilsIPv6IfaceId;

#define NM_UTILS_IPV6_IFACE_ID_INIT \
    {                               \
        {                           \
            .id = 0                 \
        }                           \
    }

/**
 * nm_utils_ipv6_addr_set_interface_identifier:
 * @addr: output token encoded as %in6_addr
 * @iid: %NMUtilsIPv6IfaceId interface identifier
 *
 * Converts the %NMUtilsIPv6IfaceId to an %in6_addr (suitable for use
 * with Linux platform). This only copies the lower 8 bytes, ignoring
 * the /64 network prefix which is expected to be all-zero for a valid
 * token.
 */
static inline void
nm_utils_ipv6_addr_set_interface_identifier(struct in6_addr *addr, const NMUtilsIPv6IfaceId *iid)
{
    memcpy(addr->s6_addr + 8, &iid->id_u8, 8);
}

/**
 * nm_utils_ipv6_interface_identifier_get_from_addr:
 * @iid: output %NMUtilsIPv6IfaceId interface identifier set from the token
 * @addr: token encoded as %in6_addr
 *
 * Converts the %in6_addr encoded token (as used by Linux platform) to
 * the interface identifier.
 */
static inline void
nm_utils_ipv6_interface_identifier_get_from_addr(NMUtilsIPv6IfaceId    *iid,
                                                 const struct in6_addr *addr)
{
    memcpy(iid, addr->s6_addr + 8, 8);
}

gboolean nm_utils_ipv6_interface_identifier_get_from_token(NMUtilsIPv6IfaceId *iid,
                                                           const char         *token);

const char *nm_utils_inet6_interface_identifier_to_token(const NMUtilsIPv6IfaceId *iid,
                                                         char buf[static INET6_ADDRSTRLEN]);

gboolean nm_utils_get_ipv6_interface_identifier(NMLinkType          link_type,
                                                const guint8       *hwaddr,
                                                guint               len,
                                                guint               dev_id,
                                                NMUtilsIPv6IfaceId *out_iid);

/*****************************************************************************/

gboolean nm_utils_memeqzero(gconstpointer data, gsize length);

/*****************************************************************************/

extern const void *const _NM_PTRARRAY_EMPTY[1];

#define NM_PTRARRAY_EMPTY(type) ((type const *) _NM_PTRARRAY_EMPTY)
#define NM_STRV_EMPTY()         ((char **) _NM_PTRARRAY_EMPTY)
#define NM_STRV_EMPTY_CC()      NM_PTRARRAY_EMPTY(const char *)

static inline void
nm_strbuf_init(char *buf, gsize len, char **p_buf_ptr, gsize *p_buf_len)
{
    NM_SET_OUT(p_buf_len, len);
    NM_SET_OUT(p_buf_ptr, buf);
    buf[0] = '\0';
}

#define nm_strbuf_init_arr(buf, p_buf_ptr, p_buf_len)                                      \
    G_STMT_START                                                                           \
    {                                                                                      \
        G_STATIC_ASSERT(G_N_ELEMENTS(buf) == sizeof(buf) && sizeof(buf) > sizeof(char *)); \
        nm_strbuf_init((buf), sizeof(buf), (p_buf_ptr), (p_buf_len));                      \
    }                                                                                      \
    G_STMT_END
void nm_strbuf_append(char **buf, gsize *len, const char *format, ...) _nm_printf(3, 4);
void nm_strbuf_append_c(char **buf, gsize *len, char c);
void nm_strbuf_append_str(char **buf, gsize *len, const char *str);
void nm_strbuf_append_bin(char **buf, gsize *len, gconstpointer str, gsize str_len);
void nm_strbuf_seek_end(char **buf, gsize *len);

const char *nm_strquote(char *buf, gsize buf_len, const char *str);

static inline gboolean
nm_utils_is_separator(const char c)
{
    return NM_IN_SET(c, ' ', '\t');
}

/*****************************************************************************/

static inline GBytes *
nm_g_bytes_ref(GBytes *b)
{
    if (b)
        g_bytes_ref(b);
    return b;
}

/*****************************************************************************/

GBytes *nm_g_bytes_get_empty(void);

GBytes *nm_g_bytes_new_from_str(const char *str);
GBytes *nm_g_bytes_new_from_variant_ay(GVariant *var);

static inline gboolean
nm_g_bytes_equal0(const GBytes *a, const GBytes *b)
{
    return a == b || (a && b && g_bytes_equal(a, b));
}

gboolean nm_g_bytes_equal_mem(GBytes *bytes, gconstpointer mem_data, gsize mem_len);

GVariant *nm_g_bytes_to_variant_ay(const GBytes *bytes);

GHashTable *nm_strdict_clone(GHashTable *src);

GVariant *nm_strdict_to_variant_ass(GHashTable *strdict);
GVariant *nm_strdict_to_variant_asv(GHashTable *strdict);

/*****************************************************************************/

GVariant *nm_utils_gvariant_vardict_filter(GVariant *src,
                                           gboolean (*filter_fcn)(const char *key,
                                                                  GVariant   *val,
                                                                  char      **out_key,
                                                                  GVariant  **out_val,
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
    NM_STRSPLIT_SET_FLAGS_NONE = 0,

    /* by default, strsplit will coalesce consecutive delimiters and remove
     * them from the result. If this flag is present, empty values are preserved
     * and returned.
     *
     * When combined with %NM_STRSPLIT_SET_FLAGS_STRSTRIP, if a value gets
     * empty after strstrip(), it also gets removed. */
    NM_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY = (1u << 0),

    /* %NM_STRSPLIT_SET_FLAGS_ALLOW_ESCAPING means that delimiters prefixed
     * by a backslash are not treated as a separator. Such delimiters and their escape
     * character are copied to the current word without unescaping them. In general,
     * nm_strsplit_set_full() does not remove any backslash escape characters
     * and does no unescaping. It only considers them for skipping to split at
     * an escaped delimiter.
     *
     * If this is combined with (or implied by %NM_STRSPLIT_SET_FLAGS_ESCAPED), then
     * the backslash escapes are removed from the result.
     */
    NM_STRSPLIT_SET_FLAGS_ALLOW_ESCAPING = (1u << 1),

    /* If flag is set, does the same as g_strstrip() on the returned tokens.
     * This will remove leading and trailing ascii whitespaces (g_ascii_isspace()
     * and NM_ASCII_SPACES).
     *
     * - when combined with !%NM_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY,
     *   empty tokens will be removed (and %NULL will be returned if that
     *   results in an empty string array).
     * - when combined with %NM_STRSPLIT_SET_FLAGS_ALLOW_ESCAPING,
     *   trailing whitespace escaped by backslash are not stripped. */
    NM_STRSPLIT_SET_FLAGS_STRSTRIP = (1u << 2),

    /* This implies %NM_STRSPLIT_SET_FLAGS_ALLOW_ESCAPING.
     *
     * This will do a final run over all tokens and remove all backslash
     * escape characters that
     *   - precede a delimiter.
     *   - precede a backslash.
     *   - precede a whitespace (only with %NM_STRSPLIT_SET_FLAGS_STRSTRIP).
     *
     *  Note that with %NM_STRSPLIT_SET_FLAGS_STRSTRIP, it is only
     *  necessary to escape the very last whitespace (if the delimiters
     *  are not whitespace themself). So, technically, it would be sufficient
     *  to only unescape a backslash before the last whitespace and the user
     *  still could express everything. However, such a rule would be complicated
     *  to understand, so when using backslash escaping with nm_strsplit_set_full(),
     *  then all characters (including backslash) are treated verbatim, except:
     *
     *    - "\\$DELIMITER" (escaped delimiter)
     *    - "\\\\" (escaped backslash)
     *    - "\\$SPACE" (escaped space) (only with %NM_STRSPLIT_SET_FLAGS_STRSTRIP).
     *
     * Note that all other escapes like "\\n" or "\\001" are left alone.
     * That makes the escaping/unescaping rules simple. Also, for the most part
     * a text is just taken as-is, with little additional rules. Only backslashes
     * need extra care, and then only if they proceed one of the relevant characters.
     */
    NM_STRSPLIT_SET_FLAGS_ESCAPED = (1u << 3),

} NMUtilsStrsplitSetFlags;

const char **
nm_strsplit_set_full(const char *str, const char *delimiter, NMUtilsStrsplitSetFlags flags);

static inline const char **
nm_strsplit_set_with_empty(const char *str, const char *delimiters)
{
    /* this returns the same result as g_strsplit_set(str, delimiters, -1), except
     * it does not deep-clone the strv array.
     * Also, for @str == "", this returns %NULL while g_strsplit_set() would return
     * an empty strv array. */
    return nm_strsplit_set_full(str, delimiters, NM_STRSPLIT_SET_FLAGS_PRESERVE_EMPTY);
}

static inline const char **
nm_strsplit_set(const char *str, const char *delimiters)
{
    return nm_strsplit_set_full(str, delimiters, NM_STRSPLIT_SET_FLAGS_NONE);
}

gssize _nm_strv_find_first(const char *const *list, gssize len, const char *needle);

#define nm_strv_find_first(list, len, needle) \
    _nm_strv_find_first(NM_CAST_STRV_CC(list), (len), (needle))

#define nm_strv_contains(list, len, needle) (nm_strv_find_first((list), (len), (needle)) >= 0)

gboolean nm_strv_has_duplicate(const char *const *list, gssize len, gboolean is_sorted);

const char **nm_strv_cleanup_const(const char **strv, gboolean skip_empty, gboolean skip_repeated);

char **nm_strv_cleanup(char   **strv,
                       gboolean strip_whitespace,
                       gboolean skip_empty,
                       gboolean skip_repeated);

gboolean nm_strv_is_same_unordered(const char *const *strv1,
                                   gssize             len1,
                                   const char *const *strv2,
                                   gssize             len2);

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
    return nm_strsplit_set_full(str,
                                delimiters,
                                NM_STRSPLIT_SET_FLAGS_ESCAPED | NM_STRSPLIT_SET_FLAGS_STRSTRIP);
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
                                                char                          **out_to_free);

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
        const char   *str0;

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
                                           GString    *gstring)
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
    return nm_strsplit_set_full(str,
                                ",",
                                NM_STRSPLIT_SET_FLAGS_STRSTRIP
                                    | NM_STRSPLIT_SET_FLAGS_ALLOW_ESCAPING);
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

gboolean nm_utils_parse_next_line(const char **inout_ptr,
                                  gsize       *inout_len,
                                  const char **out_line,
                                  gsize       *out_line_len);

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

gint64 _nm_utils_ascii_str_to_int64_bin(const char *str,
                                        gssize      len,
                                        guint       base,
                                        gint64      min,
                                        gint64      max,
                                        gint64      fallback);

int _nm_utils_ascii_str_to_bool(const char *str, int default_value);

/*****************************************************************************/

#define NM_UTILS_TO_STRING_BUFFER_SIZE 2096

extern _nm_thread_local char _nm_utils_to_string_buffer[NM_UTILS_TO_STRING_BUFFER_SIZE];

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
                               char                       *buf,
                               gsize                       len);

/*****************************************************************************/

#define NM_UTILS_ENUM2STR(v, n) \
    case v:                     \
        s = "" n "";            \
        break;
#define NM_UTILS_ENUM2STR_IGNORE(v) \
    case v:                         \
        break;

#define NM_UTILS_ENUM2STR_DEFINE_FULL(fcn_name, lookup_type, int_fmt, ...) \
    const char *fcn_name(lookup_type val, char *buf, gsize len)            \
    {                                                                      \
        nm_utils_to_string_buffer_init(&buf, &len);                        \
        if (len) {                                                         \
            const char *s = NULL;                                          \
            switch (val) {                                                 \
                NM_VA_ARGS_JOIN(, __VA_ARGS__)                             \
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
    }                                                                      \
    _NM_DUMMY_STRUCT_FOR_TRAILING_SEMICOLON

_nm_g_slice_free_fcn_define(1);
_nm_g_slice_free_fcn_define(2);
_nm_g_slice_free_fcn_define(4);
_nm_g_slice_free_fcn_define(8);
_nm_g_slice_free_fcn_define(10);
_nm_g_slice_free_fcn_define(12);
_nm_g_slice_free_fcn_define(16);
_nm_g_slice_free_fcn_define(32);

_nm_warn_unused_result static inline GDestroyNotify
_nm_get_warn_unused_result_gdestroynotify(GDestroyNotify f)
{
    return f;
}

#define nm_g_slice_free_fcn1(mem_size)                                                        \
    _nm_get_warn_unused_result_gdestroynotify(({                                              \
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
                                                                                              \
        _fcn;                                                                                 \
    }))

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

static inline void
nm_g_set_error_take(GError **error, GError *error_take)
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

    NM_UTILS_ERROR_COMMAND_FAILED, /*< nick=CommandFailed >*/

    NM_UTILS_ERROR_AMBIGUOUS, /*< nick=Ambiguous >*/

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
    NM_UTILS_ERROR_CONNECTION_AVAILABLE_STRICTLY_UNMANAGED_DEVICE,
    NM_UTILS_ERROR_CONNECTION_AVAILABLE_INCOMPATIBLE,
    NM_UTILS_ERROR_CONNECTION_AVAILABLE_UNMANAGED_DEVICE,
    NM_UTILS_ERROR_CONNECTION_AVAILABLE_TEMPORARY,
    NM_UTILS_ERROR_CONNECTION_AVAILABLE_DISALLOWED,

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

gboolean nm_g_object_set_property(GObject      *object,
                                  const char   *property_name,
                                  const GValue *value,
                                  GError      **error);

gboolean nm_g_object_set_property_string(GObject    *object,
                                         const char *property_name,
                                         const char *value,
                                         GError    **error);

gboolean nm_g_object_set_property_string_static(GObject    *object,
                                                const char *property_name,
                                                const char *value,
                                                GError    **error);

gboolean nm_g_object_set_property_string_take(GObject    *object,
                                              const char *property_name,
                                              char       *value,
                                              GError    **error);

gboolean nm_g_object_set_property_boolean(GObject    *object,
                                          const char *property_name,
                                          gboolean    value,
                                          GError    **error);

gboolean nm_g_object_set_property_char(GObject    *object,
                                       const char *property_name,
                                       gint8       value,
                                       GError    **error);

gboolean nm_g_object_set_property_uchar(GObject    *object,
                                        const char *property_name,
                                        guint8      value,
                                        GError    **error);

gboolean
nm_g_object_set_property_int(GObject *object, const char *property_name, int value, GError **error);

gboolean nm_g_object_set_property_int64(GObject    *object,
                                        const char *property_name,
                                        gint64      value,
                                        GError    **error);

gboolean nm_g_object_set_property_uint(GObject    *object,
                                       const char *property_name,
                                       guint       value,
                                       GError    **error);

gboolean nm_g_object_set_property_uint64(GObject    *object,
                                         const char *property_name,
                                         guint64     value,
                                         GError    **error);

gboolean nm_g_object_set_property_flags(GObject    *object,
                                        const char *property_name,
                                        GType       gtype,
                                        guint       value,
                                        GError    **error);

gboolean nm_g_object_set_property_enum(GObject    *object,
                                       const char *property_name,
                                       GType       gtype,
                                       int         value,
                                       GError    **error);

GParamSpec *nm_g_object_class_find_property_from_gtype(GType gtype, const char *property_name);

/*****************************************************************************/

#define _NM_G_PARAM_SPEC_CAST(param_spec, _value_type, _c_type)              \
    ({                                                                       \
        const GParamSpec *const _param_spec = (param_spec);                  \
                                                                             \
        nm_assert(!_param_spec || _param_spec->value_type == (_value_type)); \
        ((const _c_type *) _param_spec);                                     \
    })

#define _NM_G_PARAM_SPEC_CAST_IS_A(param_spec, _value_type, _c_type)                  \
    ({                                                                                \
        const GParamSpec *const _param_spec = (param_spec);                           \
                                                                                      \
        nm_assert(!_param_spec || g_type_is_a(_param_spec->value_type, _value_type)); \
        ((const _c_type *) _param_spec);                                              \
    })

#define NM_G_PARAM_SPEC_CAST_BOOLEAN(param_spec) \
    _NM_G_PARAM_SPEC_CAST(param_spec, G_TYPE_BOOLEAN, GParamSpecBoolean)
#define NM_G_PARAM_SPEC_CAST_INT(param_spec) \
    _NM_G_PARAM_SPEC_CAST(param_spec, G_TYPE_INT, GParamSpecInt)
#define NM_G_PARAM_SPEC_CAST_UINT(param_spec) \
    _NM_G_PARAM_SPEC_CAST(param_spec, G_TYPE_UINT, GParamSpecUInt)
#define NM_G_PARAM_SPEC_CAST_INT64(param_spec) \
    _NM_G_PARAM_SPEC_CAST(param_spec, G_TYPE_INT64, GParamSpecInt64)
#define NM_G_PARAM_SPEC_CAST_UINT64(param_spec) \
    _NM_G_PARAM_SPEC_CAST(param_spec, G_TYPE_UINT64, GParamSpecUInt64)
#define NM_G_PARAM_SPEC_CAST_ENUM(param_spec) \
    _NM_G_PARAM_SPEC_CAST_IS_A(param_spec, G_TYPE_ENUM, GParamSpecEnum)
#define NM_G_PARAM_SPEC_CAST_FLAGS(param_spec) \
    _NM_G_PARAM_SPEC_CAST_IS_A(param_spec, G_TYPE_FLAGS, GParamSpecFlags)
#define NM_G_PARAM_SPEC_CAST_STRING(param_spec) \
    _NM_G_PARAM_SPEC_CAST(param_spec, G_TYPE_STRING, GParamSpecString)

#define NM_G_PARAM_SPEC_GET_DEFAULT_BOOLEAN(param_spec) \
    (NM_G_PARAM_SPEC_CAST_BOOLEAN(NM_ENSURE_NOT_NULL(param_spec))->default_value)
#define NM_G_PARAM_SPEC_GET_DEFAULT_INT(param_spec) \
    (NM_G_PARAM_SPEC_CAST_INT(NM_ENSURE_NOT_NULL(param_spec))->default_value)
#define NM_G_PARAM_SPEC_GET_DEFAULT_UINT(param_spec) \
    (NM_G_PARAM_SPEC_CAST_UINT(NM_ENSURE_NOT_NULL(param_spec))->default_value)
#define NM_G_PARAM_SPEC_GET_DEFAULT_INT64(param_spec) \
    (NM_G_PARAM_SPEC_CAST_INT64(NM_ENSURE_NOT_NULL(param_spec))->default_value)
#define NM_G_PARAM_SPEC_GET_DEFAULT_UINT64(param_spec) \
    (NM_G_PARAM_SPEC_CAST_UINT64(NM_ENSURE_NOT_NULL(param_spec))->default_value)
#define NM_G_PARAM_SPEC_GET_DEFAULT_ENUM(param_spec) \
    (NM_G_PARAM_SPEC_CAST_ENUM(NM_ENSURE_NOT_NULL(param_spec))->default_value)
#define NM_G_PARAM_SPEC_GET_DEFAULT_FLAGS(param_spec) \
    (NM_G_PARAM_SPEC_CAST_FLAGS(NM_ENSURE_NOT_NULL(param_spec))->default_value)
#define NM_G_PARAM_SPEC_GET_DEFAULT_STRING(param_spec) \
    (NM_G_PARAM_SPEC_CAST_STRING(NM_ENSURE_NOT_NULL(param_spec))->default_value)

/*****************************************************************************/

GType nm_g_type_find_implementing_class_for_property(GType gtype, const char *pname);

/*****************************************************************************/

typedef enum {
    NM_UTILS_STR_UTF8_SAFE_FLAG_NONE = 0,

    /* This flag only has an effect during escaping.
     *
     * It will backslash escape ascii characters according to nm_ascii_is_ctrl_or_del(). */
    NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL = 0x0001,

    /* This flag only has an effect during escaping.
     *
     * It will backslash escape ascii characters according to nm_ascii_is_non_ascii(). */
    NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_NON_ASCII = 0x0002,

    /* Escape '"' as ASCII "\\042". This is useful when escaping a string so that
     * it can be unescaped with `echo -e $PASTE_TEXT`. */
    NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_DOUBLE_QUOTE = 0x0004,

    /* This flag only has an effect during escaping to ensure we
     * don't leak secrets in memory. Note that during unescape we
     * know the maximum result size from the beginning, and no
     * reallocation happens. Thus, unescape always avoids leaking
     * secrets already. */
    NM_UTILS_STR_UTF8_SAFE_FLAG_SECRET = 0x0008,

    /* This flag only has an effect during unescaping. It means
     * that non-escaped whitespaces (g_ascii_isspace()) will be
     * stripped from the front and end of the string. Note that
     * this flag is only useful for gracefully accepting user input
     * with spaces. With this flag, escape and unescape may no longer
     * yield the original input. */
    NM_UTILS_STR_UTF8_SAFE_UNESCAPE_STRIP_SPACES = 0x0010,
} NMUtilsStrUtf8SafeFlags;

const char *nm_utils_buf_utf8safe_escape(gconstpointer           buf,
                                         gssize                  buflen,
                                         NMUtilsStrUtf8SafeFlags flags,
                                         char                  **to_free);
char *
nm_utils_buf_utf8safe_escape_cp(gconstpointer buf, gssize buflen, NMUtilsStrUtf8SafeFlags flags);
const char *
nm_utils_buf_utf8safe_escape_bytes(GBytes *bytes, NMUtilsStrUtf8SafeFlags flags, char **to_free);
gconstpointer nm_utils_buf_utf8safe_unescape(const char             *str,
                                             NMUtilsStrUtf8SafeFlags flags,
                                             gsize                  *out_len,
                                             gpointer               *to_free);

const char *
nm_utils_str_utf8safe_escape(const char *str, NMUtilsStrUtf8SafeFlags flags, char **to_free);
const char *
nm_utils_str_utf8safe_unescape(const char *str, NMUtilsStrUtf8SafeFlags flags, char **to_free);

char *nm_utils_str_utf8safe_escape_cp(const char *str, NMUtilsStrUtf8SafeFlags flags);
char *nm_utils_str_utf8safe_unescape_cp(const char *str, NMUtilsStrUtf8SafeFlags flags);

char *nm_utils_str_utf8safe_escape_take(char *str, NMUtilsStrUtf8SafeFlags flags);

GVariant *nm_g_variant_singleton_b(gboolean value);
GVariant *nm_g_variant_singleton_u_0(void);
GVariant *nm_g_variant_singleton_i_0(void);
GVariant *nm_g_variant_singleton_s_empty(void);
GVariant *nm_g_variant_singleton_au(void);
GVariant *nm_g_variant_singleton_aay(void);
GVariant *nm_g_variant_singleton_as(void);
GVariant *nm_g_variant_singleton_aLsvI(void);
GVariant *nm_g_variant_singleton_aLsaLsvII(void);
GVariant *nm_g_variant_singleton_aaLsvI(void);
GVariant *nm_g_variant_singleton_ao(void);

GVariant *nm_g_variant_maybe_singleton_i(gint32 v);

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
nm_g_variant_new_ay(const guint8 *data, gsize len)
{
    return g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, data, len, 1);
}

static inline GVariant *
nm_g_variant_new_au(const guint32 *data, gsize len)
{
    return g_variant_new_fixed_array(G_VARIANT_TYPE_UINT32, data, len, sizeof(guint32));
}

static inline GVariant *
nm_g_variant_new_ay_inaddr(int addr_family, gconstpointer addr)
{
    return nm_g_variant_new_ay(addr ?: &nm_ip_addr_zero, nm_utils_addr_family_to_size(addr_family));
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
                                      const char      *key,
                                      const guint8    *arr,
                                      gsize            len)
{
    g_variant_builder_add(builder, "{sv}", key, nm_g_variant_new_ay(arr, len));
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
    /* Note that calling g_source_destroy() on a currently attached source,
     * will destroy the user-data of the callback right away (and not only
     * during the last g_source_unref()).
     *
     * This means for example, if the user data itself has the reference to the
     * source, then the following would lead to a crash:
     *
     *     g_source_destroy(user_data->my_source);
     *     // ups, user_data was destroyed (if source was attached).
     *     g_source_unref(user_data->my_source);
     *
     *  nm_g_source_destroy_and_unref(user_data->my_source) and nm_clear_g_source_inst(&user_data->my_source)
     *  does not have this problem (of course, afterwards, user_data would be a dangling
     *  pointer). */
    g_source_destroy(source);
    g_source_unref(source);
}

#define nm_clear_g_source_inst(ptr) (nm_clear_pointer((ptr), nm_g_source_destroy_and_unref))

NM_AUTO_DEFINE_FCN0(GSource *, _nm_auto_destroy_and_unref_gsource, nm_g_source_destroy_and_unref);
#define nm_auto_destroy_and_unref_gsource nm_auto(_nm_auto_destroy_and_unref_gsource)

NM_AUTO_DEFINE_FCN0(GMainContext *, _nm_auto_pop_gmaincontext, g_main_context_pop_thread_default);
#define nm_auto_pop_gmaincontext nm_auto(_nm_auto_pop_gmaincontext)

static inline void
nm_g_main_context_pop_and_unref(GMainContext *context)
{
    g_main_context_pop_thread_default(context);
    g_main_context_unref(context);
}

NM_AUTO_DEFINE_FCN0(GMainContext *,
                    _nm_auto_pop_and_unref_gmaincontext,
                    nm_g_main_context_pop_and_unref);
#define nm_auto_pop_and_unref_gmaincontext nm_auto(_nm_auto_pop_and_unref_gmaincontext)

static inline gboolean
nm_source_func_unref_gobject(gpointer user_data)
{
    nm_assert(G_IS_OBJECT(user_data));
    g_object_unref(user_data);
    return G_SOURCE_REMOVE;
}

extern GSource *_nm_g_source_sentinel[1];

GSource *_nm_g_source_sentinel_get_init(GSource **p_source);

/* Get a GSource sentinel (dummy instance). This instance should never be
 * attached to a GMainContext. The only currently known purpose is to use it
 * as dummy value instead of an infinity timeout. That is, if we configurably
 * want to schedule a timeout that might be infinity, we might set the GSource
 * instance to nm_g_source_sentinel_get(). On this instance, we still may
 * call g_source_ref(), g_source_unref() and g_source_destroy(). But nothing
 * else. */
#define nm_g_source_sentinel_get(idx)                                         \
    ({                                                                        \
        GSource *_s;                                                          \
                                                                              \
        G_STATIC_ASSERT((idx) >= 0);                                          \
        G_STATIC_ASSERT((idx) < G_N_ELEMENTS(_nm_g_source_sentinel));         \
                                                                              \
        _s = g_atomic_pointer_get(&_nm_g_source_sentinel[idx]);               \
        if (G_UNLIKELY(!_s))                                                  \
            _s = _nm_g_source_sentinel_get_init(&_nm_g_source_sentinel[idx]); \
                                                                              \
        _s;                                                                   \
    })

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

GSource *nm_g_unix_fd_source_new(int               fd,
                                 GIOCondition      io_condition,
                                 int               priority,
                                 GUnixFDSourceFunc source_func,
                                 gpointer          user_data,
                                 GDestroyNotify    destroy_notify);

GSource *nm_g_unix_signal_source_new(int            signum,
                                     int            priority,
                                     GSourceFunc    handler,
                                     gpointer       user_data,
                                     GDestroyNotify notify);

GSource *nm_g_child_watch_source_new(GPid            pid,
                                     int             priority,
                                     GChildWatchFunc handler,
                                     gpointer        user_data,
                                     GDestroyNotify  notify);

static inline GSource *
nm_g_source_attach(GSource *source, GMainContext *context)
{
    g_source_attach(source, context);
    return source;
}

static inline void
nm_g_idle_add(GSourceFunc func, gpointer user_data)
{
    /* g_idle_add() is discouraged because it relies on the guint source IDs.
     *
     * Usually, you would want to use nm_g_idle_add_source() which returns a GSource*
     * instance.
     *
     * However, if you don't care to ever call g_source_remove() on the source ID, then
     * g_idle_add() is fine. But our checkpatch script would complain about it. In
     * that case use nm_g_idle_add(), which makes it clear that you really want to
     * use g_idle_add() and ignore the source ID. */
    g_idle_add(func, user_data);
}

static inline GSource *
nm_g_idle_add_source(GSourceFunc func, gpointer user_data)
{
    /* A convenience function to attach a new timeout source to the default GMainContext.
     * In that sense it's very similar to g_idle_add() except that it returns a
     * reference to the new source.  */
    return nm_g_source_attach(nm_g_idle_source_new(G_PRIORITY_DEFAULT_IDLE, func, user_data, NULL),
                              NULL);
}

static inline GSource *
nm_g_timeout_add_source(guint timeout_msec, GSourceFunc func, gpointer user_data)
{
    /* A convenience function to attach a new timeout source to the default GMainContext.
     * In that sense it's very similar to g_timeout_add() except that it returns a
     * reference to the new source.  */
    return nm_g_source_attach(
        nm_g_timeout_source_new(timeout_msec, G_PRIORITY_DEFAULT, func, user_data, NULL),
        NULL);
}

gboolean nm_g_timeout_reschedule(GSource   **src,
                                 gint64     *p_expiry_msec,
                                 gint64      expiry_msec,
                                 GSourceFunc func,
                                 gpointer    user_data);

static inline GSource *
nm_g_timeout_add_seconds_source(guint timeout_sec, GSourceFunc func, gpointer user_data)
{
    /* A convenience function to attach a new timeout source to the default GMainContext.
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

static inline GSource *
nm_g_unix_fd_add_source(int               fd,
                        GIOCondition      condition,
                        GUnixFDSourceFunc function,
                        gpointer          user_data)
{
    /* A convenience function to attach a new unix-fd source to the default GMainContext.
     * In that sense it's very similar to g_unix_fd_add() except that it returns a
     * reference to the new source.  */
    return nm_g_source_attach(
        nm_g_unix_fd_source_new(fd, condition, G_PRIORITY_DEFAULT, function, user_data, NULL),
        NULL);
}

static inline GSource *
nm_g_unix_signal_add_source(int signum, GSourceFunc handler, gpointer user_data)
{
    return nm_g_source_attach(
        nm_g_unix_signal_source_new(signum, G_PRIORITY_DEFAULT, handler, user_data, NULL),
        NULL);
}

static inline GSource *
nm_g_child_watch_add_source(GPid pid, GChildWatchFunc handler, gpointer user_data)
{
    return nm_g_source_attach(
        nm_g_child_watch_source_new(pid, G_PRIORITY_DEFAULT, handler, user_data, NULL),
        NULL);
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

static inline void
nm_g_main_context_iterate_ready(GMainContext *context)
{
    while (g_main_context_iteration(context, FALSE)) {
        ;
    }
}

void nm_g_main_context_iterate_for_msec(GMainContext *context, guint timeout_msec);

gboolean nm_g_main_context_can_acquire(GMainContext *context);

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
        const char       *name;
        char             *name_mutable;
        gpointer          name_ptr;
    };
    union {
        const char *value_str;
        char       *value_str_mutable;
        gpointer    value_ptr;
    };
} NMUtilsNamedValue;

#define NM_UTILS_NAMED_VALUE_INIT(n, v) \
    {                                   \
        .name = (n), .value_ptr = (v)   \
    }

NMUtilsNamedValue *nm_utils_hash_to_array_full(GHashTable         *hash,
                                               guint              *out_len,
                                               GCompareDataFunc    compare_func,
                                               gpointer            user_data,
                                               NMUtilsNamedValue  *provided_buffer,
                                               guint               provided_buffer_len,
                                               NMUtilsNamedValue **out_allocated_buffer);

#define nm_utils_named_values_from_strdict_full(hash,                 \
                                                out_len,              \
                                                compare_func,         \
                                                user_data,            \
                                                provided_buffer,      \
                                                provided_buffer_len,  \
                                                out_allocated_buffer) \
    nm_utils_hash_to_array_full((hash),                               \
                                (out_len),                            \
                                (compare_func),                       \
                                (user_data),                          \
                                (provided_buffer),                    \
                                (provided_buffer_len),                \
                                (out_allocated_buffer))

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
                                      const char              *name,
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

gpointer *nm_utils_hash_keys_to_array(GHashTable      *hash,
                                      GCompareDataFunc compare_func,
                                      gpointer         user_data,
                                      guint           *out_len);

gpointer *nm_utils_hash_values_to_array(GHashTable      *hash,
                                        GCompareDataFunc compare_func,
                                        gpointer         user_data,
                                        guint           *out_len);

static inline NMUtilsNamedValue *
nm_utils_hash_to_array(GHashTable      *hash,
                       GCompareDataFunc compare_func,
                       gpointer         user_data,
                       guint           *out_len)
{
    return nm_utils_hash_to_array_full(hash, out_len, compare_func, user_data, NULL, 0, NULL);
}

#define nm_utils_hash_to_array_with_buffer(hash,                 \
                                           out_len,              \
                                           compare_func,         \
                                           user_data,            \
                                           array,                \
                                           out_allocated_buffer) \
    nm_utils_hash_to_array_full((hash),                          \
                                (out_len),                       \
                                (compare_func),                  \
                                (user_data),                     \
                                (array),                         \
                                G_N_ELEMENTS(array),             \
                                (out_allocated_buffer))

static inline const char **
nm_strdict_get_keys(const GHashTable *hash, gboolean sorted, guint *out_length)
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

char **nm_strv_make_deep_copied(const char **strv);

char **nm_strv_make_deep_copied_n(const char **strv, gsize len);

static inline char **
nm_strv_make_deep_copied_nonnull(const char **strv)
{
    return nm_strv_make_deep_copied(strv) ?: g_new0(char *, 1);
}

char **_nm_strv_dup(const char *const *strv, gssize len, gboolean deep_copied);

#define nm_strv_dup(strv, len, deep_copied) \
    _nm_strv_dup(NM_CAST_STRV_CC(strv), (len), (deep_copied))

const char **_nm_strv_dup_packed(const char *const *strv, gssize len);

#define nm_strv_dup_packed(strv, len) _nm_strv_dup_packed(NM_CAST_STRV_CC(strv), (len))

#define nm_strv_dup_shallow_maybe_a(alloca_maxlen, strv, len, to_free)             \
    ({                                                                             \
        const char *const *const _strv    = NM_CAST_STRV_CC(strv);                 \
        const gssize             _len     = (len);                                 \
        const char             **_result  = NULL;                                  \
        const char ***const      _to_free = (to_free);                             \
                                                                                   \
        G_STATIC_ASSERT_EXPR((alloca_maxlen) <= 500u / sizeof(const char *));      \
        G_STATIC_ASSERT_EXPR((alloca_maxlen) > 0u);                                \
        nm_assert(_to_free && !*_to_free);                                         \
                                                                                   \
        if (_len >= 0 || _strv) {                                                  \
            const gsize _l = (_len < 0) ? NM_PTRARRAY_LEN(_strv) : ((gsize) _len); \
                                                                                   \
            if (G_LIKELY(_l < (alloca_maxlen))) {                                  \
                _result = g_newa(const char *, _l + 1);                            \
            } else {                                                               \
                _result   = g_new(const char *, _l + 1);                           \
                *_to_free = _result;                                               \
            }                                                                      \
            if (_l > 0)                                                            \
                memcpy(_result, _strv, _l * sizeof(const char *));                 \
            _result[_l] = NULL;                                                    \
        }                                                                          \
                                                                                   \
        _result;                                                                   \
    })

/*****************************************************************************/

GSList *nm_utils_g_slist_find_str(const GSList *list, const char *needle);

int nm_utils_g_slist_strlist_cmp(const GSList *a, const GSList *b);

char *nm_utils_g_slist_strlist_join(const GSList *a, const char *separator);

/*****************************************************************************/

static inline gpointer
nm_g_array_data(const GArray *arr)
{
    /* You may want to use nm_g_array_first_p() instead, which can assert
     * for the expected type. */
    return arr ? arr->data : NULL;
}

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

/* Similar to g_array_index(). The differences are
 * - this does nm_assert() checks that the arguments are valid.
 * - returns a pointer to the element.
 * - it asserts that @idx is <= arr->len. That is, it allows
 *   to get a pointer after the data, of course, you are not
 *   allowed to dereference in that case.
 * - in particular, unlike nm_g_array_index(), you are allowed to call this
 *   with "arr" NULL (for index zero) or with "arr->data" NULL
 *   (for index zero). In that case, NULL is returned.
 *
 * When accessing index zero, then this returns NULL if-and-only-if
 * "arr" is NULL or "arr->data" is NULL. In all other cases, this
 * returns the pointer &((Type*) arr->data)[idx]. Note that the pointer
 * may not be followed, if "idx" is equal to "arr->len". */
#define nm_g_array_index_p(arr, Type, idx)                                                       \
    ({                                                                                           \
        const GArray *const _arr_55 = (arr);                                                     \
        const guint         _idx_55 = (idx);                                                     \
                                                                                                 \
        nm_assert(_arr_55 || _idx_55 == 0);                                                      \
        nm_assert(_idx_55 <= (_arr_55 ? _arr_55->len : 0u));                                     \
        nm_assert(!_arr_55 || sizeof(Type) == g_array_get_element_size((GArray *) _arr_55));     \
                                                                                                 \
        ((_arr_55 && _arr_55->data) ? &(((Type *) ((gpointer) _arr_55->data))[_idx_55]) : NULL); \
    })

/* Very similar to g_array_index().
 * - nm_assert() that arguments are valid.
 * - returns an lvalue to the element.
 * - similar to nm_g_array_index_p(), but dereferences the pointer.
 * - one difference to nm_g_array_index_p() is that it @idx MUST be
 *   smaller than arr->len (unlike nm_g_array_index_p() which allows
 *   access one element past the buffer. */
#define nm_g_array_index(arr, Type, idx)                                         \
    (*({                                                                         \
        const GArray *const _arr_55 = (arr);                                     \
        const guint         _idx_55 = (idx);                                     \
                                                                                 \
        nm_assert(_arr_55);                                                      \
        nm_assert(sizeof(Type) == g_array_get_element_size((GArray *) _arr_55)); \
        nm_assert(_idx_55 < _arr_55->len);                                       \
                                                                                 \
        &g_array_index((GArray *) _arr_55, Type, _idx_55);                       \
    }))

#define nm_g_array_first(arr, Type) nm_g_array_index(arr, Type, 0)

#define nm_g_array_first_p(arr, Type) nm_g_array_index_p(arr, Type, 0)

/* Same as g_array_index(arr, Type, arr->len-1). */
#define nm_g_array_last(arr, Type)                                            \
    (*({                                                                      \
        const GArray *const _arr = (arr);                                     \
                                                                              \
        nm_assert(_arr);                                                      \
        nm_assert(sizeof(Type) == g_array_get_element_size((GArray *) _arr)); \
        nm_assert(_arr->len > 0);                                             \
                                                                              \
        &g_array_index((GArray *) arr, Type, _arr->len - 1u);                 \
    }))

#define nm_g_array_append_new(arr, Type)                           \
    ({                                                             \
        GArray *const _arr = (arr);                                \
        guint         _len;                                        \
                                                                   \
        nm_assert(_arr);                                           \
        nm_assert(sizeof(Type) == g_array_get_element_size(_arr)); \
                                                                   \
        _len = _arr->len;                                          \
                                                                   \
        nm_assert(_len < G_MAXUINT);                               \
                                                                   \
        g_array_set_size(_arr, _len + 1u);                         \
        &g_array_index(arr, Type, _len);                           \
    })

#define nm_g_array_append_simple(arr, val)                               \
    G_STMT_START                                                         \
    {                                                                    \
        /* Similar to `g_array_append_val()`, but `g_array_append_val()`
         * only works with lvalues. That makes sense if the value is a larger
         * struct and you anyway have a pointer to it. It doesn't make sense
         * if you have a list of int and want to append a number literal.
         *
         * nm_g_array_append_simple() is different. It depends on typeof(val)
         * to be compatible. */ \
        (*nm_g_array_append_new((arr), typeof(val))) = (val);            \
    }                                                                    \
    G_STMT_END

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
        GPtrArray  *_val     = (val);                              \
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
        GPtrArray  *_val     = (val);                              \
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

/**
 * nm_g_ptr_array_new_clone:
 * @array: the #GPtrArray to clone.
 * @func: the copy function.
 * @user_data: the user data for the copy function
 * @element_free_func: the free function of the elements. This function
 *   must agree with the owner-ship semantics of @func.
 *
 * This is a replacement for g_ptr_array_copy(), which is not available
 * before glib 2.62. Since GPtrArray does not allow to access the internal
 * element_free_func, we cannot add a compatibility implementation of g_ptr_array_copy()
 * as the caller must provide the correct element_free_func.
 *
 * So this is not the same as g_ptr_array_copy() (hence the different name) because
 * g_ptr_array_copy() uses the free func of the source array, which we cannot access.
 * With g_ptr_array_copy() the copy func must agree with the array's free func.
 * Here, it must agree with the provided @element_free_func. This allows for example
 * to do a shallow-copy without cloning the elements (which you cannot do with g_ptr_array_copy()).
 */
GPtrArray *nm_g_ptr_array_new_clone(GPtrArray     *array,
                                    GCopyFunc      func,
                                    gpointer       user_data,
                                    GDestroyNotify element_free_func);

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

#define nm_g_hash_table_contains_any(hash, ...)                              \
    ({                                                                       \
        GHashTable *const   _hash   = (hash);                                \
        gconstpointer const _keys[] = {__VA_ARGS__};                         \
        int                 _i_key;                                          \
        gboolean            _contains = FALSE;                               \
                                                                             \
        if (_hash) {                                                         \
            for (_i_key = 0; _i_key < (int) G_N_ELEMENTS(_keys); _i_key++) { \
                if (g_hash_table_contains(_hash, _keys[_i_key])) {           \
                    _contains = TRUE;                                        \
                    break;                                                   \
                }                                                            \
            }                                                                \
        }                                                                    \
                                                                             \
        _contains;                                                           \
    })

static inline gboolean
nm_g_hash_table_remove(GHashTable *hash, gconstpointer key)
{
    return hash ? g_hash_table_remove(hash, key) : FALSE;
}

/*****************************************************************************/

gboolean nm_utils_ptrarray_is_sorted(gconstpointer   *list,
                                     gsize            len,
                                     gboolean         require_strict,
                                     GCompareDataFunc cmpfcn,
                                     gpointer         user_data);

gssize nm_ptrarray_find_bsearch(gconstpointer   *list,
                                gsize            len,
                                gconstpointer    needle,
                                GCompareDataFunc cmpfcn,
                                gpointer         user_data);

gssize nm_ptrarray_find_bsearch_range(gconstpointer   *list,
                                      gsize            len,
                                      gconstpointer    needle,
                                      GCompareDataFunc cmpfcn,
                                      gpointer         user_data,
                                      gssize          *out_idx_first,
                                      gssize          *out_idx_last);

#define nm_strv_find_binary_search(strv, len, needle)             \
    ({                                                            \
        const char *const *const _strv   = NM_CAST_STRV_CC(strv); \
        const gsize              _len    = (len);                 \
        const char *const        _needle = (needle);              \
                                                                  \
        nm_assert(_len == 0 || _strv);                            \
        nm_assert(_needle);                                       \
                                                                  \
        nm_ptrarray_find_bsearch((gconstpointer *) _strv,         \
                                 _len,                            \
                                 _needle,                         \
                                 nm_strcmp_with_data,             \
                                 NULL);                           \
    })

/*****************************************************************************/

#ifdef NM_WANT_NM_ARRAY_FIND_BSEARCH_INLINE
/**
 * nm_array_find_bsearch_inline:
 *
 * An inlined version of nm_array_find_bsearch(). See there.
 * Define NM_WANT_NM_ARRAY_FIND_BSEARCH_INLINE to get it.
 */
_nm_always_inline static inline gssize
nm_array_find_bsearch_inline(gconstpointer    list,
                             gsize            len,
                             gsize            elem_size,
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
    nm_assert(elem_size > 0);

    imin = 0;
    if (len == 0)
        return ~imin;

    imax = len - 1;

    while (imin <= imax) {
        imid = imin + (imax - imin) / 2;

        cmp = cmpfcn(&((const char *) list)[elem_size * imid], needle, user_data);
        if (cmp == 0)
            return imid;

        if (cmp < 0)
            imin = imid + 1;
        else
            imax = imid - 1;
    }

    /* return the inverse of @imin. This is a negative number, but
     * also is ~imin the position where the value should be inserted. */
    return ~imin;
}
#endif

gssize nm_array_find_bsearch(gconstpointer    list,
                             gsize            len,
                             gsize            elem_size,
                             gconstpointer    needle,
                             GCompareDataFunc cmpfcn,
                             gpointer         user_data);

/*****************************************************************************/

gssize nm_utils_ptrarray_find_first(gconstpointer *list, gssize len, gconstpointer needle);

/*****************************************************************************/

void _nm_strv_sort(const char **strv, gssize len);
#define nm_strv_sort(strv, len) _nm_strv_sort(NM_CAST_STRV_MC(strv), len)

int _nm_strv_cmp_n(const char *const *strv1, gssize len1, const char *const *strv2, gssize len2);

#define nm_strv_cmp_n(strv1, len1, strv2, len2) \
    _nm_strv_cmp_n(NM_CAST_STRV_CC(strv1), (len1), NM_CAST_STRV_CC(strv2), (len2))

/* This is like nm_strv_cmp_n(). The difference is that a NULL strv array (strv=NULL,len=-1)
 * is treated the same as an empty one (with len=0). */
#define nm_strv_cmp_n_null(strv1, len1, strv2, len2)              \
    ({                                                            \
        const char *const *const _strv1 = NM_CAST_STRV_CC(strv1); \
        const char *const *const _strv2 = NM_CAST_STRV_CC(strv2); \
        const gssize             _len1  = (len1);                 \
        const gssize             _len2  = (len2);                 \
                                                                  \
        _nm_strv_cmp_n(_strv1,                                    \
                       (_len1 >= 0 ? _len1 : (_strv1 ? -1 : 0)),  \
                       _strv2,                                    \
                       (_len2 >= 0 ? _len2 : (_strv2 ? -1 : 0))); \
    })

#define nm_strv_equal_n(strv1, len1, strv2, len2) \
    (nm_strv_cmp_n((strv1), (len1), (strv2), (len2)) == 0)

#define nm_strv_equal(strv1, strv2) nm_strv_equal_n((strv1), -1, (strv2), -1)

#define nm_strv_equal_n_null(strv1, len1, strv2, len2) \
    (nm_strv_cmp_n_null((strv1), (len1), (strv2), (len2)) == 0)

/*****************************************************************************/

/* nm_arr_insert_at() does @arr[@idx] = @value, but first memmove's
 * the elements @arr[@idx..@len-1] one element up. That means, @arr currently
 * has @len valid elements, but it must have space for one more element,
 * which will be overwritten.
 *
 * The use case is to have a sorted array (nm_strv_find_binary_search()) and
 * to insert the element at he desired index. The caller must make sure that
 * @len is large enough to contain one more element. */
#define nm_arr_insert_at(arr, len, idx, value)                                           \
    G_STMT_START                                                                         \
    {                                                                                    \
        typeof(*(arr)) *const _arr  = (arr);                                             \
        typeof(len)           _len  = (len);                                             \
        typeof(idx)           _idx  = (idx);                                             \
        const gsize           _len2 = (_len);                                            \
        const gsize           _idx2 = (_idx);                                            \
                                                                                         \
        nm_assert(_arr);                                                                 \
        nm_assert(_NM_INT_NOT_NEGATIVE(_len));                                           \
        nm_assert(_NM_INT_NOT_NEGATIVE(_idx));                                           \
        nm_assert(_idx <= _len);                                                         \
                                                                                         \
        if (_idx2 != _len2)                                                              \
            memmove(&_arr[_idx2 + 1u], &_arr[_idx2], sizeof(_arr[0]) * (_len2 - _idx2)); \
                                                                                         \
        _arr[_idx2] = (value);                                                           \
    }                                                                                    \
    G_STMT_END

/* nm_arr_remove_at() removes the element at arr[idx], by memmove'ing
 * the elements from arr[idx+1..len-1] down. All it does is one memmove(),
 * if there is anything to move. */
#define nm_arr_remove_at(arr, len, idx)                                                         \
    G_STMT_START                                                                                \
    {                                                                                           \
        typeof(*(arr)) *const _arr  = (arr);                                                    \
        typeof(len)           _len  = (len);                                                    \
        typeof(idx)           _idx  = (idx);                                                    \
        const gsize           _len2 = (_len);                                                   \
        const gsize           _idx2 = (_idx);                                                   \
                                                                                                \
        nm_assert(_arr);                                                                        \
        nm_assert(_len > 0);                                                                    \
        nm_assert(_NM_INT_NOT_NEGATIVE(_idx));                                                  \
        nm_assert(_idx < _len);                                                                 \
                                                                                                \
        if (_idx2 != _len2 - 1u)                                                                \
            memmove(&_arr[_idx2], &_arr[_idx2 + 1u], sizeof(_arr[0]) * ((_len2 - 1u) - _idx2)); \
    }                                                                                           \
    G_STMT_END

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

void nm_utils_invoke_on_idle(GCancellable               *cancellable,
                             NMUtilsInvokeOnIdleCallback callback,
                             gpointer                    callback_user_data);

void nm_utils_invoke_on_timeout(guint                       timeout_msec,
                                GCancellable               *cancellable,
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
    return nm_g_ptr_array_new_clone((GPtrArray *) src, nm_copy_func_g_strdup, NULL, g_free);
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
    return nm_strv_find_first((const char *const *) strv->pdata, strv->len, str);
}

static inline gboolean
nm_strv_ptrarray_contains(const GPtrArray *strv, const char *str)
{
    return nm_strv_ptrarray_find_first(strv, str) >= 0;
}

static inline int
nm_strv_ptrarray_cmp(const GPtrArray *a, const GPtrArray *b)
{
    /* nm_strv_cmp_n() will treat NULL and empty arrays the same.
     * That means, an empty strv array can both be represented by NULL
     * and an array of length zero.
     * If you need to distinguish between these case, do that yourself. */
    return nm_strv_cmp_n((const char *const *) nm_g_ptr_array_pdata(a),
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

static inline gboolean
nm_ascii_is_ctrl(char ch)
{
    /* 0 to ' '-1 is the C0 range.
     *
     * Other ranges may also be considered control characters, but NOT
     * CONSIDERED by this function. For example:
     *   - DEL (127) is also a control character.
     *   - SP (' ', 0x20) is also considered a control character.
     *   - DEL+1 (0x80) to 0x9F is C1 range.
     *   - NBSP (0xA0) and SHY (0xAD) are ISO 8859 special characters
     */
    return ((guchar) ch) < ' ';
}

static inline gboolean
nm_ascii_is_ctrl_or_del(char ch)
{
    return ((guchar) ch) < ' ' || ch == 127;
}

static inline gboolean
nm_ascii_is_non_ascii(char ch)
{
    return ((guchar) ch) > 127;
}

static inline gboolean
nm_ascii_is_regular(char ch)
{
    /* same as(!nm_ascii_is_ctrl_or_del(ch) && !nm_ascii_is_non_ascii(ch)) */
    return ch >= ' ' && ch < 127;
}

char *nm_utils_bin2hexstr_fuller(gconstpointer addr,
                                 gsize         length,
                                 char          delimiter,
                                 gboolean      upper_case,
                                 gboolean      with_leading_zero,
                                 char         *out);

static inline char *
nm_utils_bin2hexstr_full(gconstpointer addr,
                         gsize         length,
                         char          delimiter,
                         gboolean      upper_case,
                         char         *out)
{
    return nm_utils_bin2hexstr_fuller(addr, length, delimiter, upper_case, TRUE, out);
}

char *_nm_utils_bin2hexstr(gconstpointer src, gsize len, int final_len);

#define nm_utils_bin2hexstr_a(addr, length, delimiter, upper_case, str_to_free)               \
    ({                                                                                        \
        gconstpointer _addr        = (addr);                                                  \
        gsize         _length      = (length);                                                \
        char          _delimiter   = (delimiter);                                             \
        char        **_str_to_free = (str_to_free);                                           \
        char         *_s;                                                                     \
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

#define nm_ether_addr_to_string_dup(ether_addr) \
    ((char *) nm_ether_addr_to_string((ether_addr), g_malloc(sizeof(NMEtherAddr) * 3)))

NMEtherAddr *nm_ether_addr_from_string(NMEtherAddr *addr, const char *str);

guint8 *nm_utils_hexstr2bin_full(const char *hexstr,
                                 gboolean    allow_0x_prefix,
                                 gboolean    delimiter_required,
                                 gboolean    hexdigit_pairs_required,
                                 const char *delimiter_candidates,
                                 gsize       required_len,
                                 guint8     *buffer,
                                 gsize       buffer_len,
                                 gsize      *out_len);

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
                                  gsize      *out_len);

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
 * Returns: @buffer, or %NULL if @asc couldn't be parsed.
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
                      char         *buf,
                      gsize         buf_len)
{
    g_return_val_if_fail(addr, NULL);
    g_return_val_if_fail(addr_len > 0, NULL);
    g_return_val_if_fail(buf, NULL);
    if (buf_len < addr_len * 3)
        g_return_val_if_reached(NULL);

    return nm_utils_bin2hexstr_full(addr, addr_len, ':', upper_case, buf);
}

#define _nm_utils_hwaddr_ntoa_maybe_a(addr, addr_len, buf_to_free)                       \
    ({                                                                                   \
        gconstpointer const _addr        = (addr);                                       \
        const gsize         _addr_len    = (addr_len);                                   \
        char **const        _buf_to_free = (buf_to_free);                                \
                                                                                         \
        nm_utils_bin2hexstr_full(                                                        \
            _addr,                                                                       \
            _addr_len,                                                                   \
            ':',                                                                         \
            TRUE,                                                                        \
            nm_malloc_maybe_a(3 * 20, _addr_len ? (_addr_len * 3u) : 1u, _buf_to_free)); \
    })

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
              GCancellable       *cancellable,
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
nm_strdup_reset(char **dst, const char *src)
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
nm_strdup_reset_take(char **dst, char *src)
{
    char *old;

    nm_assert(dst);
    nm_assert(!src || src != *dst);

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
    nm_assert(p);

    if (!*p) {
        *p = g_array_new(TRUE, FALSE, sizeof(char *));
        g_array_set_clear_func(*p, nm_indirect_g_free);
    } else
        nm_assert(g_array_get_element_size(*p) == sizeof(char *));

    return *p;
}

static inline void
nm_strvarray_add(GArray *array, const char *str)
{
    char *s;

    nm_assert(array);
    nm_assert(g_array_get_element_size(array) == sizeof(char *));

    s = g_strdup(str);
    g_array_append_val(array, s);
}

static inline const char *
nm_strvarray_get_idx(GArray *array, guint idx)
{
    return nm_g_array_index(array, const char *, idx);
}

static inline const char *const *
nm_strvarray_get_strv_non_empty(GArray *arr, guint *length)
{
    nm_assert(!arr || g_array_get_element_size(arr) == sizeof(char *));

    if (!arr || arr->len == 0) {
        NM_SET_OUT(length, 0);
        return NULL;
    }

    NM_SET_OUT(length, arr->len);
    return &g_array_index(arr, const char *, 0);
}

static inline char **
nm_strvarray_get_strv_non_empty_dup(GArray *arr, guint *length)
{
    const char *const *strv;

    nm_assert(!arr || g_array_get_element_size(arr) == sizeof(char *));

    if (!arr || arr->len == 0) {
        NM_SET_OUT(length, 0);
        return NULL;
    }

    NM_SET_OUT(length, arr->len);
    strv = &g_array_index(arr, const char *, 0);
    return nm_strv_dup(strv, arr->len, TRUE);
}

static inline const char *const *
nm_strvarray_get_strv(GArray **arr, guint *length)
{
    if (!*arr) {
        NM_SET_OUT(length, 0);
        return (const char *const *) arr;
    }

    nm_assert(g_array_get_element_size(*arr) == sizeof(char *));

    NM_SET_OUT(length, (*arr)->len);
    return &g_array_index(*arr, const char *, 0);
}

static inline void
nm_strvarray_set_strv(GArray **array, const char *const *strv)
{
    gs_unref_array GArray *array_old = NULL;

    array_old = g_steal_pointer(array);

    nm_assert(!array_old || g_array_get_element_size(array_old) == sizeof(char *));

    if (!strv || !strv[0])
        return;

    nm_strvarray_ensure(array);
    for (; strv[0]; strv++)
        nm_strvarray_add(*array, strv[0]);
}

static inline gssize
nm_strvarray_find_first(GArray *strv, const char *needle)
{
    guint i;

    nm_assert(needle);

    if (strv) {
        nm_assert(g_array_get_element_size(strv) == sizeof(char *));
        for (i = 0; i < strv->len; i++) {
            if (nm_streq(needle, g_array_index(strv, const char *, i)))
                return i;
        }
    }
    return -1;
}

static inline gboolean
nm_strvarray_remove_first(GArray *strv, const char *needle)
{
    gssize idx;

    nm_assert(needle);

    idx = nm_strvarray_find_first(strv, needle);
    if (idx < 0)
        return FALSE;
    g_array_remove_index(strv, idx);
    return TRUE;
}

static inline int
nm_strvarray_cmp(const GArray *a, const GArray *b)
{
    nm_assert(!a || sizeof(const char *const *) == g_array_get_element_size((GArray *) a));
    nm_assert(!b || sizeof(const char *const *) == g_array_get_element_size((GArray *) b));

    NM_CMP_SELF(a, b);

    return nm_strv_cmp_n(nm_g_array_data(a), a->len, nm_g_array_data(b), b->len);
}

#define nm_strvarray_equal(a, b) (nm_strvarray_cmp((a), (b)) == 0)

static inline int
_nm_strvarray_cmp_strv(const GArray *strv, const char *const *ss, gsize ss_len)
{
    nm_assert(!strv || sizeof(const char *const *) == g_array_get_element_size((GArray *) strv));

    return nm_strv_cmp_n(nm_g_array_data(strv), strv ? ((gssize) strv->len) : -1, ss, ss_len);
}
#define nm_strvarray_cmp_strv(strv, ss, ss_len) \
    _nm_strvarray_cmp_strv((strv), NM_CAST_STRV_CC(ss), (ss_len))

#define nm_strvarray_equal_strv(strv, ss, ss_len) \
    (nm_strvarray_cmp_strv((strv), (ss), (ss_len)) == 0)

/*****************************************************************************/

struct _NMVariantAttributeSpec {
    char               *name;
    const GVariantType *type;
    bool                v4 : 1;
    bool                v6 : 1;
    bool                no_value : 1;
    bool                consumes_rest : 1;

    /* This indicates a non-standard parsing behavior. What this is,
     * depends on the actual validation and how to handle it.
     *
     * Note that the entire NMVariantAttributeSpec is internal API,
     * so we can change behavior and adjust it as it fits. */
    char type_detail;
};

typedef struct _NMVariantAttributeSpec NMVariantAttributeSpec;

void _nm_utils_format_variant_attributes_full(GString                             *str,
                                              const NMUtilsNamedValue             *values,
                                              guint                                num_values,
                                              const NMVariantAttributeSpec *const *spec,
                                              char                                 attr_separator,
                                              char key_value_separator);

char *_nm_utils_format_variant_attributes(GHashTable                          *attributes,
                                          const NMVariantAttributeSpec *const *spec,
                                          char                                 attr_separator,
                                          char                                 key_value_separator);

/*****************************************************************************/

/* glibc defines HOST_NAME_MAX as 64. Also Linux' sethostname() enforces
 * that (__NEW_UTS_LEN). However, musl sets this to 255.
 *
 * At some places, we want to follow Linux. Hardcode our own define. */
#define NM_HOST_NAME_MAX 64

gboolean nm_utils_is_localhost(const char *name);

gboolean nm_utils_is_specific_hostname(const char *name);

char    *nm_utils_uid_to_name(uid_t uid);
gboolean nm_utils_name_to_uid(const char *name, uid_t *out_uid);

/*****************************************************************************/

double nm_utils_exp10(gint16 e);

/*****************************************************************************/

gboolean _nm_utils_is_empty_ssid_arr(const guint8 *ssid, gsize len);
gboolean _nm_utils_is_empty_ssid_gbytes(GBytes *ssid);
char    *_nm_utils_ssid_to_string_arr(const guint8 *ssid, gsize len);
char    *_nm_utils_ssid_to_string_gbytes(GBytes *ssid);

/*****************************************************************************/

gboolean    nm_utils_is_valid_path_component(const char *name);
const char *NM_ASSERT_VALID_PATH_COMPONENT(const char *name);

#define NM_UTILS_SYSCTL_IP_CONF_PATH_BUFSIZE 100

const char *
nm_utils_sysctl_ip_conf_path(int addr_family, char *buf, const char *ifname, const char *property);

gboolean nm_utils_sysctl_ip_conf_is_path(int         addr_family,
                                         const char *path,
                                         const char *ifname,
                                         const char *property);

/*****************************************************************************/

void nm_crypto_md5_hash(const guint8 *salt,
                        gsize         salt_len,
                        const guint8 *password,
                        gsize         password_len,
                        guint8       *buffer,
                        gsize         buflen);

/*****************************************************************************/

#define NM_UTILS_GET_PROCESS_EXIT_STATUS_BUF_LEN 41

const char *nm_utils_get_process_exit_status_desc_buf(int status, char *buf, gsize buf_len);

char *nm_utils_get_process_exit_status_desc(int status);

gboolean nm_utils_validate_hostname(const char *hostname);

/*****************************************************************************/

void nm_utils_thread_local_register_destroy(gpointer tls_data, GDestroyNotify destroy_notify);

/*****************************************************************************/

int nm_unbase64char(char c);
int nm_unbase64mem_full(const char *p, gsize l, gboolean secure, guint8 **ret, gsize *ret_size);

/*****************************************************************************/

static inline gboolean
nm_path_is_absolute(const char *p)
{
    /* Copied from systemd's path_is_absolute()
     * https://github.com/systemd/systemd/blob/bc85f8b51d962597360e982811e674c126850f56/src/basic/path-util.h#L50 */

    nm_assert(p);
    return p[0] == '/';
}

int nm_path_find_first_component(const char **p, gboolean accept_dot_dot, const char **ret);

int nm_path_compare(const char *a, const char *b);

static inline gboolean
nm_path_equal(const char *a, const char *b)
{
    return nm_path_compare(a, b) == 0;
}

char *nm_path_simplify(char *path);

char *
nm_path_startswith_full(const char *path, const char *prefix, gboolean accept_dot_dot) _nm_pure;

static inline char *
nm_path_startswith(const char *path, const char *prefix)
{
    return nm_path_startswith_full(path, prefix, TRUE);
}

/*****************************************************************************/

gboolean nm_hostname_is_valid(const char *s, gboolean trailing_dot);

/*****************************************************************************/

typedef void (*NMUtilsPollProbeRegisterObjectFcn)(GObject *object, gpointer user_data);

typedef void (*NMUtilsPollProbeStartFcn)(GCancellable       *cancellable,
                                         gpointer            probe_user_data,
                                         GAsyncReadyCallback callback,
                                         gpointer            user_data);

typedef gboolean (*NMUtilsPollProbeFinishFcn)(GObject      *source,
                                              GAsyncResult *result,
                                              gpointer      probe_user_data,
                                              GError      **error);

void nm_utils_poll(int                               poll_timeout_ms,
                   int                               ratelimit_timeout_ms,
                   int                               sleep_timeout_ms,
                   NMUtilsPollProbeRegisterObjectFcn probe_register_object_fcn,
                   NMUtilsPollProbeStartFcn          probe_start_fcn,
                   NMUtilsPollProbeFinishFcn         probe_finish_fcn,
                   gpointer                          probe_user_data,
                   GCancellable                     *cancellable,
                   GAsyncReadyCallback               callback,
                   gpointer                          user_data);

gboolean nm_utils_poll_finish(GAsyncResult *result, gpointer *probe_user_data, GError **error);

#endif /* __NM_SHARED_UTILS_H__ */
