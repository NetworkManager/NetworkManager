// SPDX-License-Identifier: GPL-2.0+
/* (C) Copyright 2011 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-ethernet-utils.h"

#include "settings/nm-settings-connection.h"

char *
nm_device_ethernet_utils_get_default_wired_name (GHashTable *existing_ids)
{
	char *temp;
	int i;

	/* Find the next available unique connection name */
	for (i = 1; i < G_MAXINT; i++) {
		temp = g_strdup_printf (_("Wired connection %d"), i);
		if (   !existing_ids
		    || !g_hash_table_contains (existing_ids, temp))
			return temp;
		g_free (temp);
	}
	return NULL;
}

