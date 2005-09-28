/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2005 Red Hat, Inc.
 */


#include <glib.h>
#include <stdio.h>
#include <string.h>
#include "NetworkManager.h"
#include "nm-ip4-config.h"


struct NMIP4Config
{
	guint	refcount;
	guint32	ip4_address;
	guint32	ip4_gateway;
	guint32	ip4_netmask;
	guint32	ip4_broadcast;
	GSList *	nameservers;
	GSList *	domains;

	/* If this is a VPN/etc config that requires
	 * another device (like Ethernet) to already have
	 * an IP4Config before it can be used.
	 */
	gboolean	secondary;
};


NMIP4Config *nm_ip4_config_new (void)
{
	NMIP4Config *config = g_malloc0 (sizeof (NMIP4Config));

	config->refcount = 1;

	return config;
}

NMIP4Config *nm_ip4_config_copy (NMIP4Config *src_config)
{
	NMIP4Config *	dst_config;
	int			i, len;

	g_return_val_if_fail (src_config != NULL, NULL);

	dst_config = g_malloc0 (sizeof (NMIP4Config));
	dst_config->refcount = 1;

	dst_config->ip4_address = nm_ip4_config_get_address (src_config);
	dst_config->ip4_gateway = nm_ip4_config_get_gateway (src_config);
	dst_config->ip4_netmask = nm_ip4_config_get_netmask (src_config);
	dst_config->ip4_broadcast = nm_ip4_config_get_broadcast (src_config);

	len = nm_ip4_config_get_num_nameservers (src_config);
	for (i = 0; i < len; i++)
		nm_ip4_config_add_nameserver (dst_config, nm_ip4_config_get_nameserver (src_config, i));

	len = nm_ip4_config_get_num_domains (src_config);
	for (i = 0; i < len; i++)
		nm_ip4_config_add_domain (dst_config, nm_ip4_config_get_domain (src_config, i));

	return dst_config;
}

void nm_ip4_config_ref (NMIP4Config *config)
{
	g_return_if_fail (config != NULL);

	config->refcount++;
}

void nm_ip4_config_unref (NMIP4Config *config)
{
	g_return_if_fail (config != NULL);

	config->refcount--;
	if (config->refcount <= 0)
	{
		g_slist_free (config->nameservers);
		g_slist_foreach (config->domains, (GFunc) g_free, NULL);
		g_slist_free (config->domains);

		memset (config, 0, sizeof (NMIP4Config));
		g_free (config);
	}
}

gboolean nm_ip4_config_get_secondary (NMIP4Config *config)
{
	g_return_val_if_fail (config != NULL, FALSE);

	return config->secondary;
}

void nm_ip4_config_set_secondary (NMIP4Config *config, gboolean secondary)
{
	g_return_if_fail (config != NULL);

	config->secondary = secondary;
}

guint32 nm_ip4_config_get_address (NMIP4Config *config)
{
	g_return_val_if_fail (config != NULL, 0);

	return config->ip4_address;
}

void nm_ip4_config_set_address (NMIP4Config *config, guint32 addr)
{
	g_return_if_fail (config != NULL);

	config->ip4_address = addr;
}

guint32 nm_ip4_config_get_gateway (NMIP4Config *config)
{
	g_return_val_if_fail (config != NULL, 0);

	return config->ip4_gateway;
}

void nm_ip4_config_set_gateway (NMIP4Config *config, guint32 gateway)
{
	g_return_if_fail (config != NULL);

	config->ip4_gateway = gateway;
}

guint32 nm_ip4_config_get_netmask (NMIP4Config *config)
{
	g_return_val_if_fail (config != NULL, 0);

	return config->ip4_netmask;
}

void nm_ip4_config_set_netmask (NMIP4Config *config, guint32 netmask)
{
	g_return_if_fail (config != NULL);

	config->ip4_netmask = netmask;
}

guint32 nm_ip4_config_get_broadcast (NMIP4Config *config)
{
	g_return_val_if_fail (config != NULL, 0);

	return config->ip4_broadcast;
}

void nm_ip4_config_set_broadcast (NMIP4Config *config, guint32 broadcast)
{
	g_return_if_fail (config != NULL);

	config->ip4_broadcast = broadcast;
}

void nm_ip4_config_add_nameserver (NMIP4Config *config, guint32 nameserver)
{
	g_return_if_fail (config != NULL);

	config->nameservers = g_slist_append (config->nameservers, GINT_TO_POINTER (nameserver));
}

guint32 nm_ip4_config_get_nameserver (NMIP4Config *config, guint index)
{
	guint32 nameserver;

	g_return_val_if_fail (config != NULL, 0);
	g_return_val_if_fail (index < g_slist_length (config->nameservers), 0);

	if ((nameserver = (guint32) g_slist_nth_data (config->nameservers, index)))
		return nameserver;
	return 0;
}

guint32 nm_ip4_config_get_num_nameservers (NMIP4Config *config)
{
	g_return_val_if_fail (config != NULL, 0);

	return (g_slist_length (config->nameservers));
}


void nm_ip4_config_add_domain (NMIP4Config *config, const char *domain)
{
	g_return_if_fail (config != NULL);
	g_return_if_fail (domain != NULL);

	if (!strlen (domain))
		return;

	config->domains = g_slist_append (config->domains, g_strdup (domain));
}

const char *nm_ip4_config_get_domain (NMIP4Config *config, guint index)
{
	const char *domain;

	g_return_val_if_fail (config != NULL, NULL);
	g_return_val_if_fail (index < g_slist_length (config->domains), NULL);

	if ((domain = (const char *) g_slist_nth_data (config->domains, index)))
		return domain;
	return NULL;
}

guint32 nm_ip4_config_get_num_domains (NMIP4Config *config)
{
	g_return_val_if_fail (config != NULL, 0);

	return (g_slist_length (config->domains));
}
