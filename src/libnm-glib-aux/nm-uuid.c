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
