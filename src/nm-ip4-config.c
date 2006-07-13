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
#include "NetworkManagerUtils.h"
#include "nm-ip4-config.h"

#include <netlink/route/addr.h>
#include <netlink/utils.h>
#include <netinet/in.h>

struct NMIP4Config
{
	guint	refcount;

	guint32	ip4_address;
	guint32	ip4_ptp_address;
	guint32	ip4_gateway;
	guint32	ip4_netmask;
	guint32	ip4_broadcast;

	guint32	mtu;	/* Maximum Transmission Unit of the interface */
	guint32	mss;	/* Maximum Segment Size of the route */

	GSList *	nameservers;
	GSList *	domains;

	gchar *	hostname;
	gchar *	nis_domain;
	GSList *	nis_servers;

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
	dst_config->ip4_ptp_address = nm_ip4_config_get_ptp_address (src_config);
	dst_config->ip4_gateway = nm_ip4_config_get_gateway (src_config);
	dst_config->ip4_netmask = nm_ip4_config_get_netmask (src_config);
	dst_config->ip4_broadcast = nm_ip4_config_get_broadcast (src_config);

	dst_config->hostname = g_strdup (nm_ip4_config_get_hostname (src_config));
	dst_config->nis_domain = g_strdup (nm_ip4_config_get_nis_domain (src_config));

	len = nm_ip4_config_get_num_nameservers (src_config);
	for (i = 0; i < len; i++)
		nm_ip4_config_add_nameserver (dst_config, nm_ip4_config_get_nameserver (src_config, i));

	len = nm_ip4_config_get_num_domains (src_config);
	for (i = 0; i < len; i++)
		nm_ip4_config_add_domain (dst_config, nm_ip4_config_get_domain (src_config, i));

	len = nm_ip4_config_get_num_nis_servers (src_config);
	for (i = 0; i < len; i++)
		nm_ip4_config_add_nis_server (dst_config, nm_ip4_config_get_nis_server (src_config, i));

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
		g_free (config->hostname);
		g_free (config->nis_domain);
		g_slist_free (config->nameservers);
		g_slist_foreach (config->domains, (GFunc) g_free, NULL);
		g_slist_free (config->domains);
		g_slist_free (config->nis_servers);

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

guint32 nm_ip4_config_get_ptp_address (NMIP4Config *config)
{
	g_return_val_if_fail (config != NULL, 0);

	return config->ip4_ptp_address;
}

void nm_ip4_config_set_ptp_address (NMIP4Config *config, guint32 ptp_addr)
{
	g_return_if_fail (config != NULL);

	config->ip4_ptp_address = ptp_addr;
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

guint32 nm_ip4_config_get_nameserver (NMIP4Config *config, guint i)
{
	guint nameserver;

	g_return_val_if_fail (config != NULL, 0);
	g_return_val_if_fail (i < g_slist_length (config->nameservers), 0);

	if ((nameserver = GPOINTER_TO_UINT (g_slist_nth_data (config->nameservers, i))))
		return nameserver;
	return 0;
}

guint32 nm_ip4_config_get_num_nameservers (NMIP4Config *config)
{
	g_return_val_if_fail (config != NULL, 0);

	return (g_slist_length (config->nameservers));
}

void nm_ip4_config_add_nis_server (NMIP4Config *config, guint32 nis_server)
{
	g_return_if_fail (config != NULL);

	config->nis_servers = g_slist_append (config->nis_servers, GINT_TO_POINTER (nis_server));
}

guint32 nm_ip4_config_get_nis_server (NMIP4Config *config, guint i)
{
	guint nis_server;

	g_return_val_if_fail (config != NULL, 0);
	g_return_val_if_fail (i < g_slist_length (config->nis_servers), 0);

	if ((nis_server = GPOINTER_TO_UINT (g_slist_nth_data (config->nis_servers, i))))
		return nis_server;
	return 0;
}

guint32 nm_ip4_config_get_num_nis_servers (NMIP4Config *config)
{
	g_return_val_if_fail (config != NULL, 0);

	return (g_slist_length (config->nis_servers));
}

void nm_ip4_config_add_domain (NMIP4Config *config, const char *domain)
{
	g_return_if_fail (config != NULL);
	g_return_if_fail (domain != NULL);

	if (!strlen (domain))
		return;

	config->domains = g_slist_append (config->domains, g_strdup (domain));
}

void nm_ip4_config_set_hostname (NMIP4Config *config, const char *hostname)
{
	g_return_if_fail (config != NULL);
	g_return_if_fail (hostname != NULL);

	if (!strlen (hostname))
		return;

	config->hostname = g_strdup (hostname);
}

const char *nm_ip4_config_get_hostname (NMIP4Config *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return config->hostname;
}

void nm_ip4_config_set_nis_domain (NMIP4Config *config, const char *domain) 
{
	g_return_if_fail (config != NULL);
	g_return_if_fail (domain != NULL);
	
	if (!strlen (domain))
		return;
	
	config->nis_domain = g_strdup (domain);
}

const char *nm_ip4_config_get_nis_domain (NMIP4Config *config)
{
	g_return_val_if_fail( config != NULL, NULL);
	return config->nis_domain;
}

const char *nm_ip4_config_get_domain (NMIP4Config *config, guint i)
{
	const char *domain;

	g_return_val_if_fail (config != NULL, NULL);
	g_return_val_if_fail (i < g_slist_length (config->domains), NULL);

	if ((domain = (const char *) g_slist_nth_data (config->domains, i)))
		return domain;
	return NULL;
}

guint32 nm_ip4_config_get_num_domains (NMIP4Config *config)
{
	g_return_val_if_fail (config != NULL, 0);

	return (g_slist_length (config->domains));
}

guint32 nm_ip4_config_get_mtu (NMIP4Config *config)
{
	g_return_val_if_fail (config != NULL, 0);

	return config->mtu;
}

void nm_ip4_config_set_mtu (NMIP4Config *config, guint32 mtu)
{
	g_return_if_fail (config != NULL);

	config->mtu = mtu;
}

guint32 nm_ip4_config_get_mss (NMIP4Config *config)
{
	g_return_val_if_fail (config != NULL, 0);

	return config->mss;
}

void nm_ip4_config_set_mss (NMIP4Config *config, guint32 mss)
{
	g_return_if_fail (config != NULL);

	config->mss = mss;
}

/* libnl convenience/conversion functions */

static int ip4_addr_to_rtnl_local (guint32 ip4_address, struct rtnl_addr *addr)
{
	struct nl_addr * local = NULL;
	int err = 0;

	g_return_val_if_fail (addr != NULL, -1);

	local = nm_utils_ip4_addr_to_nl_addr (ip4_address);
	err = rtnl_addr_set_local (addr, local);
	nl_addr_put (local);

	return err;
}

static int ip4_addr_to_rtnl_peer (guint32 ip4_address, struct rtnl_addr *addr)
{
	struct nl_addr * peer = NULL;
	int err = 0;

	g_return_val_if_fail (addr != NULL, -1);

	peer = nm_utils_ip4_addr_to_nl_addr (ip4_address);
	err = rtnl_addr_set_peer (addr, peer);
	nl_addr_put (peer);

	return err;
}

static void ip4_addr_to_rtnl_prefixlen (guint32 ip4_netmask, struct rtnl_addr *addr)
{
	g_return_if_fail (addr != NULL);

	rtnl_addr_set_prefixlen (addr, nm_utils_ip4_netmask_to_prefix (ip4_netmask));
}

static int ip4_addr_to_rtnl_broadcast (guint32 ip4_broadcast, struct rtnl_addr *addr)
{
	struct nl_addr	* local = NULL;
	int err = 0;

	g_return_val_if_fail (addr != NULL, -1);

	local = nm_utils_ip4_addr_to_nl_addr (ip4_broadcast);
	err = rtnl_addr_set_broadcast (addr, local);
	nl_addr_put (local);

	return err;
}


struct rtnl_addr * nm_ip4_config_to_rtnl_addr (NMIP4Config *config, guint32 flags)
{
	struct rtnl_addr *	addr = NULL;
	gboolean			success = TRUE;

	g_return_val_if_fail (config != NULL, NULL);

	if (!(addr = rtnl_addr_alloc()))
		return NULL;

	if (flags & NM_RTNL_ADDR_ADDR)
		success = (ip4_addr_to_rtnl_local (config->ip4_address, addr) >= 0);

	if (flags & NM_RTNL_ADDR_PTP_ADDR)
		success = (ip4_addr_to_rtnl_peer (config->ip4_ptp_address, addr) >= 0);

	if (flags & NM_RTNL_ADDR_NETMASK)
		ip4_addr_to_rtnl_prefixlen (config->ip4_netmask, addr);

	if (flags & NM_RTNL_ADDR_BROADCAST)
		success = (ip4_addr_to_rtnl_broadcast (config->ip4_broadcast, addr) >= 0);

	if (!success)
	{
		rtnl_addr_put (addr);
		addr = NULL;
	}

	return addr;
}
