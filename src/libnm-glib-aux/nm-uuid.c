/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-glib-aux/nm-default-glib.h"

#include "nm-uuid.h"

#include "libnm-glib-aux/nm-random-utils.h"
#include "libnm-glib-aux/nm-str-buf.h"

/*****************************************************************************/

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
    guint8 * p;
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

    /* nm_utils_random_bytes() is supposed to try hard to give good
     * randomness. If it fails, it still makes an effort to fill
     * random data into the buffer. There is not much we can do about
     * that case, except making sure that it does not happen in the
     * first place. */
    nm_utils_random_bytes(out_uuid, sizeof(*out_uuid));

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
     * hexdigits and '-', and they must be eithr 36 or 40 chars long. */

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
                    gboolean *  out_normalized,
                    char *      out_normalized_str /* [static 37] */)
{
    NMUuid   uuid;
    gboolean is_normalized;

    /* @out_normalized_str is only set, if normalization was necessary
     * and possible. The caller cannot request @out_normalized_str, without
     * also getting @out_normalized. */
    nm_assert(!out_normalized_str || out_normalized);

    if (!str)
        return FALSE;

    if (nm_uuid_parse_full(str, &uuid, &is_normalized)) {
        /* Note that:
         *   @is_normalized means that "str" contains a normalized UUID
         *   @out_normalized: indicates whether str requires normalization
         *     and whether @out_normalized_str was set to contain the normalized
         *     UUID.
         * With this, we get the slightly odd assignment: */
        NM_SET_OUT(out_normalized, !is_normalized);

        if (!is_normalized && out_normalized_str) {
            /* we need to normalize the UUID */
            nm_uuid_unparse(&uuid, out_normalized_str);
        }

        /* regardless whether normalization was necessary, the UUID is
         * essentially valid. */
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
            char str_lower[40 + 1];
            int  i;

            nm_assert(strlen(str) < G_N_ELEMENTS(str_lower));

            /* normalize first to lower-case. */
            g_strlcpy(str_lower, str, sizeof(str_lower));
            for (i = 0; str_lower[i]; i++)
                str_lower[i] = g_ascii_tolower(str_lower[i]);

            /* The namespace UUID is chosen randomly. */
            nm_uuid_generate_from_string(&uuid,
                                         str_lower,
                                         -1,
                                         NM_UUID_TYPE_VERSION5,
                                         "4e72f709-ca95-4405-9053-1f43294a618c");
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
nm_uuid_generate_from_string(NMUuid *    uuid,
                             const char *s,
                             gssize      slen,
                             NMUuidType  uuid_type,
                             gpointer    type_args)
{
    g_return_val_if_fail(uuid, FALSE);
    g_return_val_if_fail(slen == 0 || s, FALSE);

    if (slen < 0)
        slen = s ? strlen(s) : 0;

    switch (uuid_type) {
    case NM_UUID_TYPE_LEGACY:
        g_return_val_if_fail(!type_args, NULL);
        nm_crypto_md5_hash(NULL, 0, (guint8 *) s, slen, (guint8 *) uuid, sizeof(*uuid));
        break;
    case NM_UUID_TYPE_VERSION3:
    case NM_UUID_TYPE_VERSION5:
    {
        NMUuid ns_uuid;

        if (type_args) {
            /* type_args can be a name space UUID. Interpret it as (char *) */
            if (!nm_uuid_parse(type_args, &ns_uuid))
                g_return_val_if_reached(NULL);
        } else
            ns_uuid = (NMUuid){};

        if (uuid_type == NM_UUID_TYPE_VERSION3) {
            nm_crypto_md5_hash((guint8 *) s,
                               slen,
                               (guint8 *) &ns_uuid,
                               sizeof(ns_uuid),
                               (guint8 *) uuid,
                               sizeof(*uuid));
        } else {
            nm_auto_free_checksum GChecksum *sum = NULL;
            union {
                guint8 sha1[NM_UTILS_CHECKSUM_LENGTH_SHA1];
                NMUuid uuid;
            } digest;

            sum = g_checksum_new(G_CHECKSUM_SHA1);
            g_checksum_update(sum, (guchar *) &ns_uuid, sizeof(ns_uuid));
            g_checksum_update(sum, (guchar *) s, slen);
            nm_utils_checksum_get_digest(sum, digest.sha1);

            G_STATIC_ASSERT_EXPR(sizeof(digest.sha1) > sizeof(digest.uuid));
            *uuid = digest.uuid;
        }

        uuid->uuid[6] = (uuid->uuid[6] & 0x0F) | (uuid_type << 4);
        uuid->uuid[8] = (uuid->uuid[8] & 0x3F) | 0x80;
        break;
    }
    default:
        g_return_val_if_reached(NULL);
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
nm_uuid_generate_from_string_str(const char *s,
                                 gssize      slen,
                                 NMUuidType  uuid_type,
                                 gpointer    type_args)
{
    NMUuid uuid;

    nm_uuid_generate_from_string(&uuid, s, slen, uuid_type, type_args);
    return nm_uuid_unparse(&uuid, g_new(char, 37));
}

/**
 * nm_uuid_generate_from_strings:
 * @string1: a variadic list of strings. Must be NULL terminated.
 *
 * Returns a variant3 UUID based on the concatenated C strings.
 * It does not simply concatenate them, but also includes the
 * terminating '\0' character. For example "a", "b", gives
 * "a\0b\0".
 *
 * This has the advantage, that the following invocations
 * all give different UUIDs: (NULL), (""), ("",""), ("","a"), ("a",""),
 * ("aa"), ("aa", ""), ("", "aa"), ...
 */
char *
nm_uuid_generate_from_strings(const char *string1, ...)
{
    if (!string1)
        return nm_uuid_generate_from_string_str(NULL, 0, NM_UUID_TYPE_VERSION3, NM_UUID_NS1);

    {
        nm_auto_str_buf NMStrBuf str = NM_STR_BUF_INIT(NM_UTILS_GET_NEXT_REALLOC_SIZE_104, FALSE);
        va_list                  args;
        const char *             s;

        nm_str_buf_append_len(&str, string1, strlen(string1) + 1u);

        va_start(args, string1);
        s = va_arg(args, const char *);
        while (s) {
            nm_str_buf_append_len(&str, s, strlen(s) + 1u);
            s = va_arg(args, const char *);
        }
        va_end(args);

        return nm_uuid_generate_from_string_str(nm_str_buf_get_str_unsafe(&str),
                                                str.len,
                                                NM_UUID_TYPE_VERSION3,
                                                NM_UUID_NS1);
    }
}
