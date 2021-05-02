/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-glib-aux/nm-default-glib.h"

#include "nm-uuid.h"

#include "libnm-glib-aux/nm-random-utils.h"

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
