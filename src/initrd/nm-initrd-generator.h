// SPDX-License-Identifier: LGPL-2.1+
/* NetworkManager initrd configuration generator
 *
 * Copyright (C) 2014, 2018 Red Hat, Inc.
 */

#ifndef __NM_INITRD_GENERATOR_H__
#define __NM_INITRD_GENERATOR_H__

#include "nm-connection.h"
#include "nm-utils.h"

static inline gboolean
guess_ip_address_family (const char *str)
{
	if (str == NULL)
		return AF_UNSPEC;
	else if (strchr (str, '.'))
		return AF_INET;
	else if (strchr (str, ':'))
		return AF_INET6;
	else
		return AF_UNSPEC;
}

GHashTable *nmi_ibft_read (const char *sysfs_dir);

gboolean nmi_ibft_update_connection_from_nic (NMConnection *connection, GHashTable *nic, GError **error);

NMConnection *nmi_dt_reader_parse (const char *sysfs_dir);

GHashTable *nmi_cmdline_reader_parse (const char *sysfs_dir, char **argv);

#endif  /* __NM_INITRD_GENERATOR_H__ */
