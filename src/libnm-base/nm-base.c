/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-base.h"

/*****************************************************************************/

NM_CACHED_QUARK_FCN("nm-crypto-error-quark", _nm_crypto_error_quark);

/*****************************************************************************/

char *
nm_dhcp_iaid_to_hexstr(guint32 iaid, char buf[static NM_DHCP_IAID_TO_HEXSTR_BUF_LEN])
{
    iaid = htobe32(iaid);
    return nm_utils_bin2hexstr_full(&iaid, sizeof(iaid), ':', FALSE, buf);
}

gboolean
nm_dhcp_iaid_from_hexstr(const char *str, guint32 *out_value)
{
    union {
        guint32 num;
        guint8  bin[sizeof(guint32)];
    } iaid;

    if (!nm_utils_hexstr2bin_full(str,
                                  TRUE,
                                  FALSE,
                                  FALSE,
                                  ":",
                                  sizeof(iaid),
                                  iaid.bin,
                                  sizeof(iaid),
                                  NULL))
        return FALSE;

    NM_SET_OUT(out_value, be32toh(iaid.num));
    return TRUE;
}
