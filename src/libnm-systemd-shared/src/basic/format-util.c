/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nm-sd-adapt-shared.h"

#include "format-util.h"
#include "memory-util.h"
#include "stdio-util.h"

assert_cc(DECIMAL_STR_MAX(int) + 1 <= IF_NAMESIZE + 1);
char *format_ifname_full(int ifindex, char buf[static IF_NAMESIZE + 1], FormatIfnameFlag flag) {
        /* Buffer is always cleared */
        memzero(buf, IF_NAMESIZE + 1);
        if (if_indextoname(ifindex, buf))
                return buf;

        if (!FLAGS_SET(flag, FORMAT_IFNAME_IFINDEX))
                return NULL;

        if (FLAGS_SET(flag, FORMAT_IFNAME_IFINDEX_WITH_PERCENT))
                snprintf(buf, IF_NAMESIZE + 1, "%%%d", ifindex);
        else
                snprintf(buf, IF_NAMESIZE + 1, "%d", ifindex);

        return buf;
}

char *format_bytes_full(char *buf, size_t l, uint64_t t, FormatBytesFlag flag) {
        typedef struct {
                const char *suffix;
                uint64_t factor;
        } suffix_table;
        static const suffix_table table_iec[] = {
                { "E", UINT64_C(1024)*UINT64_C(1024)*UINT64_C(1024)*UINT64_C(1024)*UINT64_C(1024)*UINT64_C(1024) },
                { "P", UINT64_C(1024)*UINT64_C(1024)*UINT64_C(1024)*UINT64_C(1024)*UINT64_C(1024) },
                { "T", UINT64_C(1024)*UINT64_C(1024)*UINT64_C(1024)*UINT64_C(1024) },
                { "G", UINT64_C(1024)*UINT64_C(1024)*UINT64_C(1024) },
                { "M", UINT64_C(1024)*UINT64_C(1024) },
                { "K", UINT64_C(1024) },
        }, table_si[] = {
                { "E", UINT64_C(1000)*UINT64_C(1000)*UINT64_C(1000)*UINT64_C(1000)*UINT64_C(1000)*UINT64_C(1000) },
                { "P", UINT64_C(1000)*UINT64_C(1000)*UINT64_C(1000)*UINT64_C(1000)*UINT64_C(1000) },
                { "T", UINT64_C(1000)*UINT64_C(1000)*UINT64_C(1000)*UINT64_C(1000) },
                { "G", UINT64_C(1000)*UINT64_C(1000)*UINT64_C(1000) },
                { "M", UINT64_C(1000)*UINT64_C(1000) },
                { "K", UINT64_C(1000) },
        };
        const suffix_table *table;
        size_t n, i;

        assert_cc(ELEMENTSOF(table_iec) == ELEMENTSOF(table_si));

        if (t == (uint64_t) -1)
                return NULL;

        table = flag & FORMAT_BYTES_USE_IEC ? table_iec : table_si;
        n = ELEMENTSOF(table_iec);

        for (i = 0; i < n; i++)
                if (t >= table[i].factor) {
                        if (flag & FORMAT_BYTES_BELOW_POINT) {
                                snprintf(buf, l,
                                         "%" PRIu64 ".%" PRIu64 "%s",
                                         t / table[i].factor,
                                         i != n - 1 ?
                                         (t / table[i + 1].factor * UINT64_C(10) / table[n - 1].factor) % UINT64_C(10):
                                         (t * UINT64_C(10) / table[i].factor) % UINT64_C(10),
                                         table[i].suffix);
                        } else
                                snprintf(buf, l,
                                         "%" PRIu64 "%s",
                                         t / table[i].factor,
                                         table[i].suffix);

                        goto finish;
                }

        snprintf(buf, l, "%" PRIu64 "%s", t, flag & FORMAT_BYTES_TRAILING_B ? "B" : "");

finish:
        buf[l-1] = 0;
        return buf;

}
