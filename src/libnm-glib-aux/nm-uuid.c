/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-glib-aux/nm-default-glib.h"

#include "nm-uuid.h"

#include "libnm-glib-aux/nm-random-utils.h"
#include "libnm-glib-aux/nm-str-buf.h"

/*****************************************************************************/

const NMUuid nm_uuid_ns_zero =
    NM_UUID_INIT(00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00);

/* arbitrarily chosen namespace UUID for some uses of nm_uuid_generate_from_strings_old().
 * Try not to re-use this namespace, instead, generate a unique one. */
const NMUuid nm_uuid_ns_1 =
    NM_UUID_INIT(b4, 25, e9, fb, 75, 98, 44, b4, 9e, 3b, 5a, 2e, 3a, aa, 49, 05);

char *
nm_uuid_unparse_case(const NMUuid *uuid, char out_str[static 37], gboolean upper_case)
{
    char *s;
    int   i;

    nm_assert(uuid);
    nm_assert(out_str);

    s = out_str;
    for (i = 0; i < 16; i++) {
        const guint8 c = uuid->uuid[i];

        if (NM_IN_SET(i, 4, 6, 8, 10))
            *(s++) = '-';
        *(s++) = nm_hexchar(c >> 4, upper_case);
        *(s++) = nm_hexchar(c, upper_case);
    }
    *s = '\0';

    return out_str;
}

/*****************************************************************************/

gboolean
nm_uuid_parse_full(const char *str, NMUuid *out_uuid, gboolean *out_is_normalized)
{
    NMUuid   uuid;
    guint8  *p;
    int      i;
    gboolean is_normalized = TRUE;

    nm_assert(str);

    p = uuid.uuid;

    for (i = 0; TRUE;) {
        int v0;
        int v1;

        if (NM_IN_SET(i, 8, 13, 18, 23)) {
            if (str[i] != '-')
                return FALSE;
            i++;
            continue;
        }

        if (i == 36) {
            if (str[i] != '\0')
                return FALSE;

            NM_SET_OUT(out_is_normalized, is_normalized);
            NM_SET_OUT(out_uuid, uuid);
            return TRUE;
        }

#define _hexchar(ch, out_is_normalized2)                                    \
    ({                                                                      \
        const char _ch     = (ch);                                          \
        int        _result = -1;                                            \
                                                                            \
        if (_ch >= '0') {                                                   \
            if (_ch <= '9')                                                 \
                _result = (_ch - '0');                                      \
            else if (_ch >= 'A') {                                          \
                if (_ch <= 'F') {                                           \
                    *(out_is_normalized2) = FALSE;                          \
                    _result               = ((int) _ch) + (10 - (int) 'A'); \
                } else if (_ch >= 'a' && _ch <= 'f')                        \
                    _result = ((int) _ch) + (10 - (int) 'a');               \
            }                                                               \
        }                                                                   \
                                                                            \
        _result;                                                            \
    })

        v0 = _hexchar(str[i++], &is_normalized);
        if (v0 < 0)
            return FALSE;
        v1 = _hexchar(str[i++], &is_normalized);
        if (v1 < 0)
            return FALSE;

        *(p++) = (v0 << 4) + v1;
    }
}

/*****************************************************************************/

NMUuid *
nm_uuid_generate_random(NMUuid *out_uuid)
{
    nm_assert(out_uuid);

    /* https://tools.ietf.org/html/rfc4122#section-4.4 */

    /* See also, systemd's id128_make_v4_uuid() */

    /* nm_random_get_bytes() is supposed to try hard to give good
     * randomness. If it fails, it still makes an effort to fill
     * random data into the buffer. There is not much we can do about
     * that case, except making sure that it does not happen in the
     * first place. */
    nm_random_get_bytes(out_uuid, sizeof(*out_uuid));

    /* Set the four most significant bits (bits 12 through 15) of the
     * time_hi_and_version field to the 4-bit version number from
     * Section 4.1.3. */
    out_uuid->uuid[6] = (out_uuid->uuid[6] & 0x0Fu) | 0x40u;

    /* Set the two most significant bits (bits 6 and 7) of the
     * clock_seq_hi_and_reserved to zero and one, respectively. */
    out_uuid->uuid[8] = (out_uuid->uuid[8] & 0x3Fu) | 0x80u;

    return out_uuid;
}

/*****************************************************************************/

gboolean
nm_uuid_is_normalized_full(const char *str)
{
    /* The only reason why this exists is that nm_uuid_is_normalized() is an inline function.
     * If you need to forward declare the function, that won't work.
     *
     * Usually, you wouldn't use this variant! */
    return nm_uuid_is_normalized(str);
}

/*****************************************************************************/

/**
 * nm_uuid_is_valid_nmlegacy()
 * @str: the string to check whether it's a valid UUID.
 *
 * Note that this does not perform a strict check.
 * Instead, it checks a more relaxed format (including
 * non valid UUID strings). This is for backward compatibility,
 * where older code did not perform a strict check.
 *
 * Returns: %TRUE, if the string is a valid legacy format.
 *   This may not be a valid UUID!
 */
gboolean
nm_uuid_is_valid_nmlegacy(const char *str)
{
    const char *p          = str;
    int         num_dashes = 0;

    if (!p)
        return FALSE;

    while (*p) {
        if (*p == '-')
            num_dashes++;
        else if (!g_ascii_isxdigit(*p))
            return FALSE;
        p++;
    }

    /* While we accept here bogus strings as UUIDs, they must contain only
     * hexdigits and '-', and they must be either 36 or 40 chars long. */

    if ((num_dashes == 4) && (p - str == 36))
        return TRUE;

    /* Backwards compat for older configurations */
    if ((num_dashes == 0) && (p - str == 40))
        return TRUE;

    return FALSE;
}

/*****************************************************************************/

gboolean
nm_uuid_is_valid_nm(const char *str,
                    gboolean   *out_normalized,
                    char       *out_normalized_str /* [static 37] */)
{
    NMUuid   uuid;
    gboolean is_normalized;

    /* @out_normalized_str is only set, if normalization was necessary
     * and possible. The caller cannot request @out_normalized_str, without
     * also requesting @out_normalized. Otherwise, they couldn't know whether
     * a normalized string was returned. */
    nm_assert(!out_normalized_str || out_normalized);

    if (!str)
        return FALSE;

    if (nm_uuid_parse_full(str, &uuid, &is_normalized)) {
        if (is_normalized) {
            /* @str is already normalized. No need to normalize again, so
             * @out_normalized is FALSE. */
            NM_SET_OUT(out_normalized, FALSE);
        } else {
            NM_SET_OUT(out_normalized, TRUE);
            if (out_normalized_str) {
                /* we need to normalize the UUID */
                nm_uuid_unparse(&uuid, out_normalized_str);
            }
        }
        return TRUE;
    }

    if (nm_uuid_is_valid_nmlegacy(str)) {
        /* This is not a valid UUID, but something that we used to
         * accept according to nm_uuid_is_valid_nmlegacy().
         *
         * Normalize it by sha1 hashing the string. Upper case characters
         * are made lower case first. */
        NM_SET_OUT(out_normalized, TRUE);
        if (out_normalized_str) {
            char str_lower[40];
            int  i;

            nm_assert(strlen(str) <= G_N_ELEMENTS(str_lower));

            /* normalize first to lower-case. */
            for (i = 0; str[i]; i++) {
                nm_assert(i < G_N_ELEMENTS(str_lower));
                str_lower[i] = g_ascii_tolower(str[i]);
            }
            nm_assert(i <= G_N_ELEMENTS(str_lower));

            /* The namespace UUID is chosen randomly. */
            nm_uuid_generate_from_string(
                &uuid,
                str_lower,
                i,
                NM_UUID_TYPE_VERSION5,
                &NM_UUID_INIT(4e, 72, f7, 09, ca, 95, 44, 05, 90, 53, 1f, 43, 29, 4a, 61, 8c));
            nm_uuid_unparse(&uuid, out_normalized_str);
        }
        return TRUE;
    }

    /* UUID is not valid. */
    return FALSE;
}

/*****************************************************************************/

gboolean
nm_uuid_is_null(const NMUuid *uuid)
{
    int i;

    if (!uuid)
        return TRUE;

    for (i = 0; i < (int) G_N_ELEMENTS(uuid->uuid); i++) {
        if (uuid->uuid[i])
            return FALSE;
    }
    return TRUE;
}

char *
nm_uuid_generate_random_str(char buf[static 37])
{
    NMUuid uuid;

    nm_assert(buf);

    nm_uuid_generate_random(&uuid);
    return nm_uuid_unparse(&uuid, buf);
}

/*****************************************************************************/

/**
 * nm_uuid_generate_from_string:
 * @uuid: the UUID to update inplace. This function cannot
 *   fail to succeed.
 * @s: a string to use as the seed for the UUID
 * @slen: if negative, treat @s as zero terminated C string.
 *   Otherwise, assume the length as given (and allow @s to be
 *   non-null terminated or contain '\0').
 * @uuid_type: a type identifier which UUID format to generate.
 * @type_args: additional arguments, depending on the uuid_type
 *
 * For a given @s, this function will always return the same UUID.
 *
 * Returns: the input @uuid. This function cannot fail.
 **/
NMUuid *
nm_uuid_generate_from_string(NMUuid       *uuid,
                             const char   *s,
                             gssize        slen,
                             NMUuidType    uuid_type,
                             const NMUuid *type_args)
{
    nm_auto_free_checksum GChecksum *sum = NULL;
    union {
        guint8 sha1[NM_UTILS_CHECKSUM_LENGTH_SHA1];
        guint8 md5[NM_UTILS_CHECKSUM_LENGTH_MD5];
        NMUuid uuid;
    } digest;
    gsize         digest_len;
    GChecksumType checksum_type;

    G_STATIC_ASSERT_EXPR(sizeof(digest.md5) >= sizeof(digest.uuid));
    G_STATIC_ASSERT_EXPR(sizeof(digest.sha1) >= sizeof(digest.uuid));

    g_return_val_if_fail(uuid, NULL);
    g_return_val_if_fail(slen <= 0 || s, NULL);

    if (slen < 0)
        slen = s ? strlen(s) : 0;

    switch (uuid_type) {
    case NM_UUID_TYPE_LEGACY:
        nm_assert(!type_args);
        type_args     = NULL;
        checksum_type = G_CHECKSUM_MD5;
        break;
    case NM_UUID_TYPE_VERSION3:
        if (!type_args)
            type_args = &nm_uuid_ns_zero;
        checksum_type = G_CHECKSUM_MD5;
        break;
    case NM_UUID_TYPE_VERSION5:
        if (!type_args)
            type_args = &nm_uuid_ns_zero;
        checksum_type = G_CHECKSUM_SHA1;
        break;
    default:
        g_return_val_if_reached(NULL);
    }

    sum = g_checksum_new(checksum_type);
    if (type_args)
        g_checksum_update(sum, (guchar *) type_args, sizeof(*type_args));
    g_checksum_update(sum, (guchar *) s, slen);

    digest_len = sizeof(digest);
    g_checksum_get_digest(sum, (guint8 *) &digest, &digest_len);

    nm_assert(digest_len >= sizeof(digest.uuid));
    nm_assert(digest_len
              == ((checksum_type == G_CHECKSUM_MD5 ? NM_UTILS_CHECKSUM_LENGTH_MD5
                                                   : NM_UTILS_CHECKSUM_LENGTH_SHA1)));

    *uuid = digest.uuid;

    if (uuid_type != NM_UUID_TYPE_LEGACY) {
        uuid->uuid[6] = (uuid->uuid[6] & 0x0F) | (uuid_type << 4);
        uuid->uuid[8] = (uuid->uuid[8] & 0x3F) | 0x80;
    }

    return uuid;
}

/**
 * nm_uuid_generate_from_string_str:
 * @s: a string to use as the seed for the UUID
 * @slen: if negative, treat @s as zero terminated C string.
 *   Otherwise, assume the length as given (and allow @s to be
 *   non-null terminated or contain '\0').
 * @uuid_type: a type identifier which UUID format to generate.
 * @type_args: additional arguments, depending on the uuid_type
 *
 * For a given @s, this function will always return the same UUID.
 *
 * Returns: a newly allocated UUID suitable for use as the #NMSettingConnection
 * object's #NMSettingConnection:id: property
 **/
char *
nm_uuid_generate_from_string_str(const char   *s,
                                 gssize        slen,
                                 NMUuidType    uuid_type,
                                 const NMUuid *type_args)
{
    NMUuid        uuid;
    const NMUuid *u;

    u = nm_uuid_generate_from_string(&uuid, s, slen, uuid_type, type_args);

    if (G_UNLIKELY(!u))
        return nm_assert_unreachable_val(NULL);
    nm_assert(u == &uuid);

    return nm_uuid_unparse(&uuid, g_new(char, 37));
}

/**
 * nm_uuid_generate_from_strings_strv:
 * @uuid_type: the UUID type to use. Prefer version 5 unless you have
 *   good reasons.
 * @type_args: the namespace UUID.
 * @strv: (nullable): the strv list to hash. Can be NULL, in which
 *   case the result is different from an empty array.
 * @len: if negative, @strv is a NULL terminated array. Otherwise,
 *   it is the length of the strv array. In the latter case it may
 *   also contain NULL strings. The result hashes differently depending
 *   on whether we have a NULL terminated strv array or given length.
 *
 * Returns a @uuid_type UUID based on the concatenated C strings.
 * It does not simply concatenate them, but also includes the
 * terminating '\0' character. For example "a", "b", gives
 * "a\0b\0".
 * This has the advantage, that the following invocations
 * all give different UUIDs: (NULL), (""), ("",""), ("","a"), ("a",""),
 * ("aa"), ("aa", ""), ("", "aa"), ...
 */
char *
nm_uuid_generate_from_strings_strv(NMUuidType         uuid_type,
                                   const NMUuid      *type_args,
                                   const char *const *strv,
                                   gssize             len)
{
    nm_auto_str_buf NMStrBuf str = NM_STR_BUF_INIT_A(NM_UTILS_GET_NEXT_REALLOC_SIZE_232, TRUE);
    gsize                    slen;
    const char              *s;

    if (len >= 0) {
        gboolean has_nulls = FALSE;
        gssize   i;

        nm_assert(len == 0 || strv);

        for (i = 0; i < len; i++) {
            if (strv[i])
                nm_str_buf_append_len(&str, strv[i], strlen(strv[i]) + 1u);
            else
                has_nulls = TRUE;
        }
        if (has_nulls) {
            /* We either support a NULL terminated strv array, or a ptr array of fixed
             * length (@len argument).
             *
             * If there are no NULLs within the first @len strings, then the result
             * is the same. If there are any NULL strings, we need to encode that
             * in a unique way. We do that by appending a bitmap of the elements
             * whether they were set, plus one 'n' character (without NUL termination).
             * None of the other branches below hashes to that, so this will uniquely
             * encoded the NULL strings.
             */
            for (i = 0; i < len; i++)
                nm_str_buf_append_c(&str, strv[i] ? '1' : '_');
            nm_str_buf_append_c(&str, 'n');
        }
        slen = str.len;
        s    = nm_str_buf_get_str_unsafe(&str);
    } else if (!strv) {
        /* NULL is treated differently from an empty strv. We achieve that
         * by using a non-empty, non-NUL terminated string (which cannot happen
         * in the other cases). */
        slen = 1;
        s    = "x";
    } else if (!strv[0]) {
        slen = 0;
        s    = "";
    } else if (!strv[1]) {
        slen = strlen(strv[0]) + 1u;
        s    = strv[0];
    } else {
        /* We concatenate the NUL termiated string, including the NUL
         * character. This way, ("a","a"), ("aa"), ("aa","") all hash
         * differently. */
        for (; strv[0]; strv++)
            nm_str_buf_append_len(&str, strv[0], strlen(strv[0]) + 1u);
        slen = str.len;
        s    = nm_str_buf_get_str_unsafe(&str);
    }

    return nm_uuid_generate_from_string_str(s, slen, uuid_type, type_args);
}
