/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-glib-aux/nm-default-glib.h"

#include "nm-uuid.h"

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
