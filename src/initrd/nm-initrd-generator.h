/* NetworkManager initrd configuration generator
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
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

GHashTable *nmi_cmdline_reader_parse (const char *sysfs_dir, char **argv);

#endif  /* __NM_INITRD_GENERATOR_H__ */
