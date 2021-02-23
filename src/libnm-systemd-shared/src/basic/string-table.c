/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nm-sd-adapt-shared.h"

#include "string-table.h"
#include "string-util.h"

ssize_t string_table_lookup(const char * const *table, size_t len, const char *key) {
        if (!key)
                return -1;

        for (size_t i = 0; i < len; ++i)
                if (streq_ptr(table[i], key))
                        return (ssize_t) i;

        return -1;
}
