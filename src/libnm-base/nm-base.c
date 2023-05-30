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

/*****************************************************************************/

/* nm_net_devname_infiniband:
 * @name: the output-buffer where the value will be written. Must be
 *   not %NULL and point to a string buffer of at least IFNAMSIZ bytes.
 * @parent_name: the parent interface name
 * @p_key: the partition key.
 *
 * Returns: the infiniband name will be written to @name and @name
 *   is returned.
 */
const char *
nm_net_devname_infiniband(char name[static NM_IFNAMSIZ], const char *parent_name, int p_key)
{
    g_return_val_if_fail(name, NULL);
    g_return_val_if_fail(parent_name && parent_name[0], NULL);
    g_return_val_if_fail(strlen(parent_name) < NM_IFNAMSIZ, NULL);

    /* technically, p_key of 0x0000 and 0x8000 is not allowed either. But we don't
     * want to assert against that in nm_net_devname_infiniband(). So be more
     * resilient here, and accept those. */
    g_return_val_if_fail(p_key >= 0 && p_key <= 0xffff, NULL);

    nm_assert(nm_utils_ifname_valid_kernel(parent_name, NULL));

    /* If parent+suffix is too long, kernel would just truncate
     * the name. We do the same. See ipoib_vlan_add().  */
    g_snprintf(name, NM_IFNAMSIZ, "%s.%04x", parent_name, p_key);

    nm_assert(nm_utils_ifname_valid_kernel(name, NULL));

    return name;
}
