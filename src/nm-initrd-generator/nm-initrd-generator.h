/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2014, 2018 Red Hat, Inc.
 */

#ifndef __NM_INITRD_GENERATOR_H__
#define __NM_INITRD_GENERATOR_H__

#include "nm-connection.h"
#include "nm-utils.h"

#define NMI_WAIT_DEVICE_TIMEOUT_MS 60000

static inline int
get_ip_address_family(const char *str, gboolean with_prefix)
{
    int addr_family;

    if (!str)
        return AF_UNSPEC;

    if (with_prefix) {
        if (nm_utils_parse_inaddr_prefix_bin(AF_UNSPEC, str, &addr_family, NULL, NULL))
            return addr_family;
    } else {
        if (nm_utils_parse_inaddr_bin(AF_UNSPEC, str, &addr_family, NULL))
            return addr_family;
    }

    return AF_UNSPEC;
}

GHashTable *nmi_ibft_read(const char *sysfs_dir);

gboolean
nmi_ibft_update_connection_from_nic(NMConnection *connection, GHashTable *nic, GError **error);

NMConnection *nmi_dt_reader_parse(const char *sysfs_dir);

GHashTable *nmi_cmdline_reader_parse(const char *       sysfs_dir,
                                     const char *const *argv,
                                     char **            hostname,
                                     gint64 *           carrier_timeout_sec);

#endif /* __NM_INITRD_GENERATOR_H__ */
