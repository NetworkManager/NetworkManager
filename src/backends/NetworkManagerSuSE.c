/*
 * NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
 * Kay Sievers <kay.sievers@suse.de>
 * Robert Love <rml@novell.com>
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
 * (C) Copyright 2004 Red Hat, Inc.
 * (C) Copyright 2005-2006 SuSE GmbH
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>

#include "NetworkManagerGeneric.h"
#include "NetworkManagerSystem.h"
#include "NetworkManagerUtils.h"
#include "nm-device.h"
#include "NetworkManagerPolicy.h"
#include "nm-utils.h"
#include "shvar.h"

/*
 * nm_system_enable_loopback
 *
 * Bring up the loopback interface
 *
 */
void nm_system_enable_loopback (void)
{
	nm_generic_enable_loopback ();
}

/*
 * nm_system_update_dns
 *
 * Invalidate the nscd host cache, if it exists, since
 * we changed resolv.conf.
 *
 */
void nm_system_update_dns (void)
{
	nm_info ("Clearing nscd hosts cache.");
	nm_spawn_process ("/usr/sbin/nscd -i hosts");
}

/*
 * nm_system_set_hostname
 *
 * set the hostname
 *
 */
void nm_system_set_hostname (NMIP4Config *config)
{
	char *filename, *h_name = NULL, *buf;
	shvarFile *file;

	g_return_if_fail (config != NULL);

	filename = g_strdup_printf (SYSCONFDIR"/sysconfig/network/dhcp");
	file = svNewFile (filename);
	if (!file)
		goto out_gfree;

	buf = svGetValue (file, "DHCLIENT_SET_HOSTNAME");
	if (!buf)
		goto out_close;

	if (!strcmp (buf, "yes")) 
	{
		const char *hostname;

		hostname = nm_ip4_config_get_hostname (config);
		if (!hostname)
		{
			struct in_addr temp_addr;
			struct hostent *host;
			const NMSettingIP4Address *ip_address;

			/* try to get hostname via dns */
			ip_address = nm_ip4_config_get_address (config, 0);
			temp_addr.s_addr = ip_address->address;
			host = gethostbyaddr ((char *) &temp_addr, sizeof (temp_addr), AF_INET);
			if (host)
			{
				h_name = g_strdup (host->h_name);
				hostname = strtok (h_name, ".");
			}
			else
				nm_warning ("nm_system_set_hostname(): gethostbyaddr failed, h_errno = %d", h_errno);
		}

		if (hostname)
		{
			nm_info ("Setting hostname to '%s'", hostname);
			if (sethostname (hostname, strlen (hostname)) < 0)
				nm_warning ("Could not set hostname.");
		}
	}

	g_free (h_name);
	free (buf);
out_close:
	svCloseFile (file);
out_gfree:
	g_free (filename);
}

/*
 * nm_system_should_modify_resolv_conf
 *
 * Can NM update resolv.conf, or is it locked down?
 */
gboolean nm_system_should_modify_resolv_conf (void)
{
	char *name, *buf;
	shvarFile *file;
	gboolean ret = TRUE;

	name = g_strdup_printf (SYSCONFDIR"/sysconfig/network/dhcp");
	file = svNewFile (name);
	if (!file)
		goto out_gfree;

	buf = svGetValue (file, "DHCLIENT_MODIFY_RESOLV_CONF");
	if (!buf)
		goto out_close;

	if (strcmp (buf, "no") == 0)
		ret = FALSE;

	free (buf);
out_close:
	svCloseFile (file);
out_gfree:
	g_free (name);

	return ret;
}

