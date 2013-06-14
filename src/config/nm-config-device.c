/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright 2013 Red Hat, Inc.
 */

#include "config.h"

#include "nm-config-device.h"

#include <net/if_arp.h>

#include <nm-utils.h>

G_DEFINE_INTERFACE (NMConfigDevice, nm_config_device, G_TYPE_OBJECT)

static void
nm_config_device_default_init (NMConfigDeviceInterface *iface)
{
}

gboolean
nm_config_device_spec_match_list (NMConfigDevice *self, const char **config_specs)
{
	GSList *specs = NULL;
	gboolean match;
	char buf[NM_UTILS_HWADDR_LEN_MAX + 1], *tmp;
	int i;

	g_return_val_if_fail (NM_IS_CONFIG_DEVICE (self), FALSE);

	if (!config_specs)
		return FALSE;

	/* For compatibility, we allow an untagged MAC address, and for convenience,
	 * we allow untagged interface names as well.
	 */
	for (i = 0; config_specs[i]; i++) {
		if (g_strcmp0 (config_specs[i], "*") == 0)
			specs = g_slist_prepend (specs, g_strdup (config_specs[i]));
		else if (nm_utils_iface_valid_name (config_specs[i]))
			specs = g_slist_prepend (specs, g_strdup_printf ("interface-name:%s", config_specs[i]));
		else if (   nm_utils_hwaddr_aton (config_specs[i], ARPHRD_ETHER, buf)
		         || nm_utils_hwaddr_aton (config_specs[i], ARPHRD_INFINIBAND, buf)) {
			tmp = g_ascii_strdown (config_specs[i], -1);
			specs = g_slist_prepend (specs, g_strdup_printf ("mac:%s", tmp));
			g_free (tmp);
		} else
			specs = g_slist_prepend (specs, g_strdup (config_specs[i]));
	}

	specs = g_slist_reverse (specs);

	match = NM_CONFIG_DEVICE_GET_INTERFACE (self)->spec_match_list (self, specs);

	g_slist_free_full (specs, g_free);
	return match;
}

char *
nm_config_device_get_hwaddr (NMConfigDevice *self)
{
	const guint8 *bytes;
	guint len = 0;

	bytes = NM_CONFIG_DEVICE_GET_INTERFACE (self)->get_hw_address (self, &len);
	return nm_utils_hwaddr_ntoa_len (bytes, len);
}
