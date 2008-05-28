/* NetworkManager -- Network link manager
 *
 * Timothee Lecomte <timothee.lecomte@ens.fr>
 *
 * Heavily based on NetworkManagerRedhat.c by Dan Williams <dcbw@redhat.com>
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
 * (C) Copyright 2004 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <signal.h>
#include <arpa/inet.h>
#include <string.h>

#include "NetworkManagerGeneric.h"
#include "NetworkManagerSystem.h"
#include "NetworkManagerUtils.h"
#include "nm-device.h"
#include "nm-device-802-3-ethernet.h"
#include "nm-device-802-11-wireless.h"
#include "nm-utils.h"
#include "nm-netlink.h"

/* Because of a bug in libnl, rtnl.h should be included before route.h */
#include <netlink/route/rtnl.h>

#include <netlink/route/addr.h>
#include <netlink/netlink.h>

/*
 * nm_generic_init
 *
 * Initializes the distribution-specific system backend
 *
 */
void nm_generic_init (void)
{
	/* Kill any dhclients lying around */
	nm_system_kill_all_dhcp_daemons ();
}

/*
 * nm_generic_enable_loopback
 *
 * Bring up the loopback interface
 *
 */
void nm_generic_enable_loopback (void)
{
	struct nl_handle *	nlh = NULL;
	struct rtnl_addr *	addr = NULL;
	struct nl_addr *	nl_addr = NULL;
	guint32			binaddr = 0;
	int			iface_idx = -1;
	int			err;

	nm_system_device_set_up_down_with_iface ("lo", TRUE);

	nlh = nm_netlink_get_default_handle ();
	if (!nlh)
		return;

	iface_idx = nm_netlink_iface_to_index ("lo");
	if (iface_idx < 0)
		return;

	addr = rtnl_addr_alloc ();
	if (!addr)
		return;

	binaddr = htonl (0x7f000001); /* 127.0.0.1 */
	nl_addr = nl_addr_build (AF_INET, &binaddr, sizeof(binaddr));
	if (!nl_addr)
		goto out;
	rtnl_addr_set_local (addr, nl_addr);
	nl_addr_put (nl_addr);

	binaddr = htonl (0x7fffffff); /* 127.255.255.255 */
	nl_addr = nl_addr_build (AF_INET, &binaddr, sizeof(binaddr));
	if (!nl_addr)
		goto out;
	rtnl_addr_set_broadcast (addr, nl_addr);
	nl_addr_put (nl_addr);

	rtnl_addr_set_prefixlen (addr, 8);
	rtnl_addr_set_ifindex (addr, iface_idx);
	rtnl_addr_set_scope (addr, RT_SCOPE_HOST);
	rtnl_addr_set_label (addr, "lo");

	if ((err = rtnl_addr_add (nlh, addr, 0)) < 0)
		nm_warning ("error %d returned from rtnl_addr_add():\n%s", err, nl_geterror());
out:
	if (addr)
		rtnl_addr_put (addr);
}

/*
 * nm_generic_kill_all_dhcp_daemons
 *
 * Kill all DHCP daemons currently running, done at startup.
 *
 */
void nm_generic_kill_all_dhcp_daemons (void)
{
}


/*
 * nm_generic_update_dns
 *
 * Make glibc/nscd aware of any changes to the resolv.conf file by
 * restarting nscd.
 *
 */
void nm_generic_update_dns (void)
{
}

/*
 * nm_generic_set_ip4_config_from_resolv_conf
 *
 * Add nameservers and search names from a resolv.conf format file.
 *
 */
void nm_generic_set_ip4_config_from_resolv_conf (const char *filename, NMIP4Config *ip4_config)
{
	char *	contents = NULL;
	char **	split_contents = NULL;
	int		i, len;

	g_return_if_fail (filename != NULL);
	g_return_if_fail (ip4_config != NULL);

	if (!g_file_get_contents (filename, &contents, NULL, NULL) || (contents == NULL))
		return;

	if (!(split_contents = g_strsplit (contents, "\n", 0)))
		goto out;
	
	len = g_strv_length (split_contents);
	for (i = 0; i < len; i++)
	{
		char *line = split_contents[i];

		/* Ignore comments */
		if (!line || (line[0] == ';') || (line[0] == '#'))
			continue;

		line = g_strstrip (line);
		if ((strncmp (line, "search", 6) == 0) && (strlen (line) > 6))
		{
			char *searches = g_strdup (line + 7);
			char **split_searches = NULL;

			if (!searches || !strlen (searches))
				continue;

			/* Allow space-separated search domains */
			if ((split_searches = g_strsplit (searches, " ", 0)))
			{
				int m, srch_len;

				srch_len = g_strv_length (split_searches);
				for (m = 0; m < srch_len; m++)
				{
					if (split_searches[m])
						nm_ip4_config_add_domain	(ip4_config, split_searches[m]);
				}
				g_strfreev (split_searches);
			}
			else
			{
				/* Only 1 item, add the whole line */
				nm_ip4_config_add_domain	(ip4_config, searches);
			}

			g_free (searches);
		}
		else if ((strncmp (line, "nameserver", 10) == 0) && (strlen (line) > 10))
		{
			guint32	addr = (guint32) (inet_addr (line + 11));

			if (addr != (guint32) -1)
				nm_ip4_config_add_nameserver (ip4_config, addr);
		}
	}

	g_strfreev (split_contents);

out:
	g_free (contents);
}


/*
 * nm_generic_device_get_system_config
 *
 * Retrieve any relevant configuration info for a particular device
 * from the system network configuration information.  Clear out existing
 * info before setting stuff too.
 *
 */
void* nm_generic_device_get_system_config (NMDevice *dev)
{
	return NULL;
}

/*
 * nm_generic_device_free_system_config
 *
 * Free stored system config data
 *
 */
void nm_generic_device_free_system_config (NMDevice *dev, void *system_config_data)
{
	return;
}


/*
 * nm_generic_device_get_disabled
 *
 * Return whether the distro-specific system config tells us to use
 * dhcp for this device.
 *
 */
gboolean nm_generic_device_get_disabled (NMDevice *dev)
{
	return FALSE;
}


NMIP4Config *nm_generic_device_new_ip4_system_config (NMDevice *dev)
{
	return NULL;
}

/*
 * nm_generic_activate_nis
 *
 * set up the nis domain and write a yp.conf
 *
 */
void nm_generic_activate_nis (NMIP4Config *config)
{
}

/*
 * nm_generic_shutdown_nis
 *
 * shutdown ypbind
 *
 */
void nm_generic_shutdown_nis (void)
{
}

/*
 * nm_generic_set_hostname
 *
 * set the hostname
 *
 */
void nm_generic_set_hostname (NMIP4Config *config)
{
}

/*
 * nm_generic_should_modify_resolv_conf
 *
 * Can NM update resolv.conf, or is it locked down?
 */
gboolean nm_generic_should_modify_resolv_conf (void)
{
	return TRUE;
}

