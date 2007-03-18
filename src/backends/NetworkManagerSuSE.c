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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
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

#include "NetworkManagerSystem.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerMain.h"
#include "nm-device.h"
#include "nm-ap-security.h"
#include "nm-ap-security-private.h"
#include "nm-ap-security-wep.h"
#include "nm-ap-security-wpa-psk.h"
#include "NetworkManagerAPList.h"
#include "NetworkManagerPolicy.h"
#include "cipher.h"
#include "cipher-wep-ascii.h"
#include "cipher-wep-hex.h"
#include "cipher-wep-passphrase.h"
#include "cipher-wpa-psk-passphrase.h"
#include "nm-device-802-3-ethernet.h"
#include "nm-device-802-11-wireless.h"
#include "NetworkManagerDialup.h"
#include "nm-utils.h"
#include "shvar.h"

/*
 * nm_system_init
 *
 * Initializes the distribution-specific system backend
 *
 */
void nm_system_init (void)
{
	/* Kill any dhclients lying around */
	nm_system_kill_all_dhcp_daemons ();
}


/*
 * nm_system_device_flush_routes
 *
 * Flush all routes associated with a network device
 *
 */
void nm_system_device_flush_routes (NMDevice *dev)
{
	g_return_if_fail (dev != NULL);

	/* Not really applicable for test devices */
	if (nm_device_is_test_device (dev))
		return;

	nm_system_device_flush_routes_with_iface (nm_device_get_iface (dev));
}


/*
 * nm_system_device_flush_routes_with_iface
 *
 * Flush all routes associated with a network device
 *
 */
void nm_system_device_flush_routes_with_iface (const char *iface)
{
	char	*buf;

	g_return_if_fail (iface != NULL);

	/* Remove routing table entries */
	buf = g_strdup_printf (IP_BINARY_PATH " route flush dev %s", iface);
	nm_spawn_process (buf);
	g_free (buf);
}


/*
 * nm_system_device_add_default_route_via_device
 *
 * Add default route to the given device
 *
 */
void nm_system_device_add_default_route_via_device (NMDevice *dev)
{
	g_return_if_fail (dev != NULL);

	/* Not really applicable for test devices */
	if (nm_device_is_test_device (dev))
		return;

	nm_system_device_add_default_route_via_device_with_iface (nm_device_get_iface (dev));
}


/*
 * nm_system_device_add_default_route_via_device_with_iface
 *
 * Add default route to the given device
 *
 */
void nm_system_device_add_default_route_via_device_with_iface (const char *iface)
{
	char	*buf;

	g_return_if_fail (iface != NULL);

	/* Add default gateway */
	buf = g_strdup_printf (IP_BINARY_PATH " route add default dev %s", iface);
	nm_spawn_process (buf);
	g_free (buf);
}


/*
 * nm_system_device_add_route_via_device_with_iface
 *
 * Add route to the given device
 *
 */
void nm_system_device_add_route_via_device_with_iface (const char *iface, const char *route)
{
	char	*buf;

	g_return_if_fail (iface != NULL);

	/* Add default gateway */
	buf = g_strdup_printf (IP_BINARY_PATH " route add %s dev %s", route, iface);
	nm_spawn_process (buf);
	g_free (buf);
}


/*
 * nm_system_device_has_active_routes
 *
 * Find out whether the specified device has any routes in the routing
 * table.
 *
 */
gboolean nm_system_device_has_active_routes (NMDevice *dev)
{
	return FALSE;
}


/*
 * nm_system_device_flush_addresses
 *
 * Flush all network addresses associated with a network device
 *
 */
void nm_system_device_flush_addresses (NMDevice *dev)
{
	g_return_if_fail (dev != NULL);

	/* Not really applicable for test devices */
	if (nm_device_is_test_device (dev))
		return;

	nm_system_device_flush_addresses_with_iface (nm_device_get_iface (dev));
}


/*
 * nm_system_device_flush_addresses_with_iface
 *
 * Flush all network addresses associated with a network device
 *
 */
void nm_system_device_flush_addresses_with_iface (const char *iface)
{
	char *buf;

	g_return_if_fail (iface != NULL);

	/* Remove all IP addresses for a device */
	buf = g_strdup_printf (IP_BINARY_PATH " addr flush dev %s", iface);
	nm_spawn_process (buf);
	g_free (buf);
}


/*
 * nm_system_enable_loopback
 *
 * Bring up the loopback interface
 *
 */
void nm_system_enable_loopback (void)
{
	nm_system_device_set_up_down_with_iface ("lo", TRUE);
	nm_spawn_process (IP_BINARY_PATH " addr add 127.0.0.1/8 brd 127.255.255.255 dev lo scope host label loopback");
}


/*
 * nm_system_flush_loopback_routes
 *
 * Flush all routes associated with the loopback device, because it
 * sometimes gets the first route for ZeroConf/Link-Local traffic.
 *
 */
void nm_system_flush_loopback_routes (void)
{
	nm_system_device_flush_routes_with_iface ("lo");
}


/*
 * nm_system_delete_default_route
 *
 * Remove the old default route in preparation for a new one
 *
 */
void nm_system_delete_default_route (void)
{
	nm_spawn_process (IP_BINARY_PATH " route del default");
}


/*
 * nm_system_flush_arp_cache
 *
 * Flush all entries in the arp cache.
 *
 */
void nm_system_flush_arp_cache (void)
{
	nm_spawn_process (IP_BINARY_PATH " neigh flush all");
}


/*
 * nm_system_kill_all_dhcp_daemons
 *
 * Kill all DHCP daemons currently running, done at startup.
 *
 */
void nm_system_kill_all_dhcp_daemons (void)
{
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
 * nm_system_restart_mdns_responder
 *
 * Restart the multicast DNS responder so that it knows about new
 * network interfaces and IP addresses.
 *
 */
void nm_system_restart_mdns_responder (void)
{
	pid_t pid;
	FILE *fp;
	int res;

	fp = fopen ("/var/run/mdnsd.pid", "rt");
	if (!fp)
		return;

	res = fscanf (fp, "%d", &pid);
	if (res == 1)
	{
		nm_info ("Restarting mdnsd (pid=%d).", pid);
		kill (pid, SIGUSR1);
	}

	fclose (fp);
}


/*
 * nm_system_device_add_ip6_link_address
 *
 * Add a default link-local IPv6 address to a device.
 *
 */
void nm_system_device_add_ip6_link_address (NMDevice *dev)
{
	char *buf;
	struct ether_addr hw_addr;
	unsigned char eui[8];

	nm_device_get_hw_address (dev, &hw_addr);
	memcpy (eui, &(hw_addr.ether_addr_octet), sizeof (hw_addr.ether_addr_octet));
	memmove (eui+5, eui+3, 3);
	eui[3] = 0xff;
	eui[4] = 0xfe;
	eui[0] ^= 2;

	/* Add the default link-local IPv6 address to a device */
	buf = g_strdup_printf (IP_BINARY_PATH " -6 addr add fe80::%x%02x:%x%02x:%x%02x:%x%02x/64 dev %s",
						eui[0], eui[1], eui[2], eui[3], eui[4], eui[5],
						eui[6], eui[7], nm_device_get_iface (dev));
	nm_spawn_process (buf);
	g_free (buf);
}


typedef struct SuSEDeviceConfigData
{
	NMIP4Config *	config;
	gboolean		use_dhcp;
	gboolean		system_disabled;
	guint32		mtu;
} SuSEDeviceConfigData;

/*
 * set_ip4_config_from_resolv_conf
 *
 * Add nameservers and search names from a resolv.conf format file.
 *
 */
static void set_ip4_config_from_resolv_conf (const char *filename, NMIP4Config *ip4_config)
{
	char *contents = NULL;
	char **split_contents = NULL;
	int i, len;

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
			guint32 addr = (guint32) (inet_addr (line + 11));

			if (addr != (guint32) -1)
				nm_ip4_config_add_nameserver (ip4_config, addr);
		}
	}

	g_strfreev (split_contents);

out:
	g_free (contents);
}


/*
 * nm_system_device_get_system_config
 *
 * Read in the config file for a device.
 *
 * SuSE stores this information in /etc/sysconfig/network/ifcfg-*-<MAC address>
 *
 */
void *nm_system_device_get_system_config (NMDevice *dev, NMData *app_data)
{
	char *cfg_file_path = NULL;
	char mac[18];
	struct stat statbuf;
	shvarFile *file;
	char *buf = NULL;
	SuSEDeviceConfigData *sys_data = NULL;
	struct ether_addr hw_addr;
	FILE *f = NULL;
	char buffer[512];
	gboolean error = FALSE;
	int i, len;
	struct in_addr temp_addr;
	char *ip_str;

	g_return_val_if_fail (dev != NULL, NULL);

	sys_data = g_malloc0 (sizeof (SuSEDeviceConfigData));
	sys_data->use_dhcp = TRUE;

	nm_device_get_hw_address (dev, &hw_addr);
	sprintf (mac, "%02x:%02x:%02x:%02x:%02x:%02x",
			hw_addr.ether_addr_octet[0], hw_addr.ether_addr_octet[1],
			hw_addr.ether_addr_octet[2], hw_addr.ether_addr_octet[3],
			hw_addr.ether_addr_octet[4], hw_addr.ether_addr_octet[5]);
	cfg_file_path = g_strdup_printf (SYSCONFDIR"/sysconfig/network/ifcfg-eth-id-%s", mac);
	if (!cfg_file_path)
		return sys_data;
	if (stat(cfg_file_path, &statbuf) == 0)
		goto found;

	g_free(cfg_file_path);
	cfg_file_path = g_strdup_printf (SYSCONFDIR"/sysconfig/network/ifcfg-wlan-id-%s", mac);
	if (!cfg_file_path)
		return sys_data;
	if (stat(cfg_file_path, &statbuf) == 0)
		goto found;

	g_free(cfg_file_path);
	cfg_file_path = g_strdup_printf (SYSCONFDIR"/sysconfig/network/ifcfg-%s", nm_device_get_iface (dev));
	if (!cfg_file_path)
		return sys_data;
	if (stat(cfg_file_path, &statbuf) == 0)
		goto found;

	g_free (cfg_file_path);
	return sys_data;

found:
	nm_debug ("found config '%s' for interface '%s'", cfg_file_path, nm_device_get_iface (dev));
	if (!(file = svNewFile (cfg_file_path)))
	{
		g_free (cfg_file_path);
		return sys_data;
	}
	g_free (cfg_file_path);

	if ((buf = svGetValue (file, "BOOTPROTO")))
	{
		nm_debug ("BOOTPROTO=%s", buf);
		if (strcasecmp (buf, "dhcp"))
			sys_data->use_dhcp = FALSE;
		free (buf);
	}

	if ((buf = svGetValue (file, "NM_CONTROLLED")))
	{
		nm_debug ("NM_CONTROLLED=%s", buf);
		if (!strcasecmp (buf, "no"))
		{
			nm_info ("System configuration disables device %s", nm_device_get_iface (dev));
			sys_data->system_disabled = TRUE;
		}
		free (buf);
	}

	if ((buf = svGetValue (file, "MTU")))
	{
		guint32 mtu;

		errno = 0;
		mtu = strtoul (buf, NULL, 10);
		if (!errno && mtu > 500 && mtu < INT_MAX)
			sys_data->mtu = mtu;
		free (buf);
	}

	if ((buf = svGetValue (file, "WIRELESS_ESSID")) && strlen (buf) > 1)
	{
		NMAccessPoint *	ap;
		NMAccessPoint *	list_ap;
		char *			key;
		char *			mode;

		ap = nm_ap_new ();
		nm_ap_set_essid (ap, buf);
		nm_ap_set_timestamp (ap, time (NULL), 0);
		nm_ap_set_trusted (ap, TRUE);

		if ((mode = svGetValue (file, "WIRELESS_AUTH_MODE")) && !strcmp (mode, "psk"))
		{
			if ((key = svGetValue (file, "WIRELESS_WPA_PSK")))
			{
				IEEE_802_11_Cipher *	cipher;
				NMAPSecurityWPA_PSK *	security;
				char *				hash;

				cipher = cipher_wpa_psk_passphrase_new ();
				nm_ap_set_capabilities (ap, NM_802_11_CAP_PROTO_WPA);
				security = nm_ap_security_wpa_psk_new_from_ap (ap, NM_AUTH_TYPE_WPA_PSK_AUTO);
				hash = ieee_802_11_cipher_hash (cipher, buf, key);
				if (hash)
				{
					nm_ap_security_set_key (NM_AP_SECURITY (security), hash, strlen (hash));
					nm_ap_set_security (ap, NM_AP_SECURITY (security));
				}

				ieee_802_11_cipher_unref (cipher);
				g_object_unref (G_OBJECT (security));
			}
		}
		else if ((key = svGetValue (file, "WIRELESS_KEY_0")) && strlen (key) > 3)
		{
			IEEE_802_11_Cipher *	cipher;
			NMAPSecurityWEP *		security;
			char *				key_type;
			char *				hash;
			char *				real_key;

			key_type = svGetValue (file, "WIRELESS_KEY_LENGTH");
			if (key_type && strcmp (key_type, "128") != 0)
			{
				if (key[0] == 'h' && key[1] == ':')
				{
					cipher = cipher_wep64_passphrase_new ();
					real_key = key + 2;
				}
				else if (key[0] == 's' && key[1] == ':')
				{
					cipher = cipher_wep64_ascii_new ();
					real_key = key + 2;
				}
				else
				{
					cipher = cipher_wep64_hex_new ();
					real_key = key;
				}
				security = nm_ap_security_wep_new_from_ap (ap, IW_AUTH_CIPHER_WEP40);
			}
			else
			{
				if (key[0] == 'h' && key[1] == ':')
				{
					cipher = cipher_wep128_passphrase_new ();
					real_key = key + 2;
				}
				else if (key[0] == 's' && key[1] == ':')
				{
					cipher = cipher_wep128_ascii_new ();
					real_key = key + 2;
				}
				else
				{
					char **keyv;

					cipher = cipher_wep128_hex_new ();

					keyv = g_strsplit (key, "-", 0);
					real_key = g_strjoinv (NULL, keyv);
					g_strfreev (keyv);
				}
				security = nm_ap_security_wep_new_from_ap (ap, IW_AUTH_CIPHER_WEP104);
			}
			hash = ieee_802_11_cipher_hash (cipher, buf, real_key);
			if (hash)
			{
				nm_ap_security_set_key (NM_AP_SECURITY (security), hash, strlen (hash));
				nm_ap_set_security (ap, NM_AP_SECURITY (security));
			}

			ieee_802_11_cipher_unref (cipher);
			g_object_unref (G_OBJECT (security));

			free (key_type);
		}
		else
		{
			NMAPSecurity *	security;

			security = nm_ap_security_new (IW_AUTH_CIPHER_NONE);
			nm_ap_set_security (ap, security);
			g_object_unref (G_OBJECT (security));
		}

		if ((list_ap = nm_ap_list_get_ap_by_essid (app_data->allowed_ap_list, buf)))
		{
			nm_ap_set_essid (list_ap, nm_ap_get_essid (ap));
			nm_ap_set_timestamp_via_timestamp (list_ap, nm_ap_get_timestamp (ap));
			nm_ap_set_trusted (list_ap, nm_ap_get_trusted (ap));
			nm_ap_set_security (list_ap, nm_ap_get_security (ap));
		}
		else
		{
			/* New AP, just add it to the list */
			nm_ap_list_append_ap (app_data->allowed_ap_list, ap);
		}
		nm_ap_unref (ap);

		nm_debug ("Adding '%s' to the list of trusted networks", buf);

		/* Ensure all devices get new information copied into their device lists */
		nm_policy_schedule_device_ap_lists_update_from_allowed (app_data);

		free (key);
		free (mode);
		free (buf);
	}
	else if (buf)
		g_free (buf);

	sys_data->config = nm_ip4_config_new ();

	if (!sys_data->use_dhcp || sys_data->system_disabled)
	{
		buf = svGetValue (file, "IPADDR");
		if (buf)
		{
			struct in_addr ip;
			int ret;

			ret = inet_aton (buf, &ip);
			if (ret)
				nm_ip4_config_set_address (sys_data->config, ip.s_addr);
			else
				error = TRUE;
			free (buf);
		}
		else
			error = TRUE;

		if (error)
		{
			nm_warning ("Network configuration for device '%s' was invalid: Non-DHCP configuration, "
					  "but no IP address specified.  Will use DHCP instead.", nm_device_get_iface (dev));
			goto out;
		}

		if ((buf = svGetValue (file, "NETMASK")))
		{
			nm_ip4_config_set_netmask (sys_data->config, inet_addr (buf));
			free (buf);
		}
		else
		{
			guint32	ip4addr = nm_ip4_config_get_address (sys_data->config);

			/* Make a default netmask if we have an IP address */
			if (((ntohl (ip4addr) & 0xFF000000) >> 24) <= 127)
				nm_ip4_config_set_netmask (sys_data->config, htonl (0xFF000000));
			else if (((ntohl (ip4addr) & 0xFF000000) >> 24) <= 191)
				nm_ip4_config_set_netmask (sys_data->config, htonl (0xFFFF0000));
			else
				nm_ip4_config_set_netmask (sys_data->config, htonl (0xFFFFFF00));
		}

		if ((buf = svGetValue (file, "BROADCAST")))
		{
			nm_ip4_config_set_broadcast (sys_data->config, inet_addr (buf));
			free (buf);
		}
		else
		{
			guint32 broadcast = ((nm_ip4_config_get_address (sys_data->config) & nm_ip4_config_get_netmask (sys_data->config))
									| ~nm_ip4_config_get_netmask (sys_data->config));
			nm_ip4_config_set_broadcast (sys_data->config, broadcast);
		}

		nm_ip4_config_set_mtu (sys_data->config, sys_data->mtu);

		buf = NULL;
		if ((f = fopen (SYSCONFDIR"/sysconfig/network/routes", "r")))
		{
			while (fgets (buffer, 512, f) && !feof (f))
			{
				buf = strtok(buffer, " ");
				if (strcmp(buf, "default") == 0)
				{
					buf = strtok(NULL, " ");
					if (buf)
						nm_ip4_config_set_gateway (sys_data->config, inet_addr (buf));
					break;
				}
			}
			fclose (f);
		}
		if (!buf)
			nm_info ("Network configuration for device '%s' does not specify a gateway but is "
				 "statically configured (non-DHCP).", nm_device_get_iface (dev));

		set_ip4_config_from_resolv_conf (SYSCONFDIR"/resolv.conf", sys_data->config);
	}

out:
	svCloseFile (file);

	if (error)
	{
		nm_debug ("error, enable dhcp");
		sys_data->use_dhcp = TRUE;
		/* Clear out the config */
		nm_ip4_config_unref (sys_data->config);
		sys_data->config = NULL;
	}

	nm_debug ("------ Config (%s)", nm_device_get_iface (dev));
	nm_debug ("dhcp=%u", sys_data->use_dhcp);

	temp_addr.s_addr = nm_ip4_config_get_address (sys_data->config);
	ip_str = g_strdup (inet_ntoa (temp_addr));
	nm_debug ("addr=%s", ip_str);
	g_free (ip_str);

	temp_addr.s_addr = nm_ip4_config_get_gateway (sys_data->config);
	ip_str = g_strdup (inet_ntoa (temp_addr));
	nm_debug ("gw=%s", ip_str);
	g_free (ip_str);

	temp_addr.s_addr = nm_ip4_config_get_netmask (sys_data->config);
	ip_str = g_strdup (inet_ntoa (temp_addr));
	nm_debug ("mask=%s", ip_str);
	g_free (ip_str);

	if (sys_data->mtu)
		nm_debug ("mtu=%u", sys_data->mtu);

	len = nm_ip4_config_get_num_nameservers (sys_data->config);
	for (i = 0; i < len; i++)
	{
		guint ns_addr = nm_ip4_config_get_nameserver (sys_data->config, i);

		temp_addr.s_addr = ns_addr;
		ip_str = g_strdup (inet_ntoa (temp_addr));
		nm_debug ("ns_%u=%s", i, ip_str);
		g_free (ip_str);
	}
	nm_debug ("---------------------\n");

	return sys_data;
}


/*
 * nm_system_device_free_system_config
 *
 * Free stored system config data
 *
 */
void nm_system_device_free_system_config (NMDevice *dev, void *system_config_data)
{
	SuSEDeviceConfigData *sys_data = (SuSEDeviceConfigData *)system_config_data;

	g_return_if_fail (dev != NULL);

	if (!sys_data)
		return;

	if (sys_data->config)
		nm_ip4_config_unref (sys_data->config);

	g_free (sys_data);
}


/*
 * nm_system_device_get_use_dhcp
 *
 * Return whether the distro-specific system config tells us to use
 * dhcp for this device.
 *
 */
gboolean nm_system_device_get_use_dhcp (NMDevice *dev)
{
	SuSEDeviceConfigData *sys_data;

	g_return_val_if_fail (dev != NULL, FALSE);

	if ((sys_data = nm_device_get_system_config_data (dev)))
		return sys_data->use_dhcp;

	return FALSE;
}


/*
 * nm_system_device_get_disabled
 *
 * Return whether the distribution has flagged this device as disabled.
 *
 */
gboolean nm_system_device_get_disabled (NMDevice *dev)
{
	SuSEDeviceConfigData *sys_data;

	g_return_val_if_fail (dev != NULL, FALSE);

	if ((sys_data = nm_device_get_system_config_data (dev)))
		return sys_data->system_disabled;

	return FALSE;
}


NMIP4Config *nm_system_device_new_ip4_system_config (NMDevice *dev)
{
	SuSEDeviceConfigData *sys_data;
	NMIP4Config *new_config = NULL;

	g_return_val_if_fail (dev != NULL, NULL);

	if ((sys_data = nm_device_get_system_config_data (dev)))
		new_config = nm_ip4_config_copy (sys_data->config);

	return new_config;
}


void nm_system_deactivate_all_dialup (GSList *list)
{
	GSList *elt;

	for (elt = list; elt; elt = g_slist_next (elt))
	{
		NMDialUpConfig *config = (NMDialUpConfig *) elt->data;
		char *cmd;

		if (config->type == NM_DIALUP_TYPE_ISDN)
		{
			cmd = g_strdup_printf ("/sbin/isdnctrl hangup %s", (char *) config->data);
			nm_spawn_process (cmd);
			g_free (cmd);
		}

		cmd = g_strdup_printf ("/sbin/ifdown %s", (char *) config->data);
		nm_spawn_process (cmd);
		g_free (cmd);
	}
}


gboolean nm_system_deactivate_dialup (GSList *list, const char *dialup)
{
	GSList *elt;
	gboolean ret = FALSE;

	for (elt = list; elt; elt = g_slist_next (elt))
	{
		NMDialUpConfig *config = (NMDialUpConfig *) elt->data;
		if (strcmp (dialup, config->name) == 0)
		{
			char *cmd;

			nm_info ("Deactivating dialup device %s (%s) ...", dialup, (char *) config->data);

			cmd = g_strdup_printf ("/sbin/ifdown %s", (char *) config->data);
			nm_spawn_process (cmd);
			g_free (cmd);

			if (config->type == NM_DIALUP_TYPE_ISDN)
			{
				cmd = g_strdup_printf ("/sbin/isdnctrl hangup %s", (char *) config->data);
				nm_spawn_process (cmd);
				g_free (cmd);
			}

			ret = TRUE;
			break;
		}
	}

	return ret;
}


gboolean nm_system_activate_dialup (GSList *list, const char *dialup)
{
	GSList *elt;
	gboolean ret = FALSE;

	for (elt = list; elt; elt = g_slist_next (elt))
	{
		NMDialUpConfig *config = (NMDialUpConfig *) elt->data;
		if (strcmp (dialup, config->name) == 0)
		{
			char *cmd;

			nm_info ("Activating dialup device %s (%s) ...", dialup, (char *) config->data);

			cmd = g_strdup_printf ("/sbin/ifup %s", (char *) config->data);
			nm_spawn_process (cmd);
			g_free (cmd);

			if (config->type == NM_DIALUP_TYPE_ISDN)
			{
				cmd = g_strdup_printf ("/sbin/isdnctrl dial %s", (char *) config->data);
				nm_spawn_process (cmd);
				g_free (cmd);
			}

			ret = TRUE;
			break;
		}
	}

	return ret;
}


/*
 * verify_and_return_provider - given a provider identifier, verify that it is able to dial without
 * prompting and return the provider name.  On failure, return NULL.  Caller is responsible for
 * free'ing the return.
*/
static char * verify_and_return_provider (const char *provider)
{
	shvarFile *file;
	char *name, *buf = NULL;
	int ret;

	name = g_strdup_printf (SYSCONFDIR"/sysconfig/network/providers/%s", provider);

	file = svNewFile (name);
	if (!file)
		goto out_gfree;

	buf = svGetValue (file, "ASKPASSWORD");
	if (!buf)
		goto out_close;
	ret = strcmp (buf, "no");
	free (buf);
	if (ret)
	{
		buf = NULL;
		goto out_close;
	}

	buf = svGetValue (file, "PROVIDER");

out_close:
	svCloseFile (file);
out_gfree:
	g_free (name);

	return buf;
}


/*
 * nm_system_get_dialup_config
 *
 * Enumerate dial up options on this system, allocate NMDialUpConfig's,
 * fill them out, and return.
 *
 */
GSList * nm_system_get_dialup_config (void)
{
	GSList *list = NULL;
	const char *dentry;
	GError *err = NULL;
	GDir *dir;

	dir = g_dir_open (SYSCONFDIR "/sysconfig/network", 0, &err);
	if (!dir)
	{
		nm_warning ("Could not open directory " SYSCONFDIR "/sysconfig/network: %s", err->message);
		return NULL;
	}

	while ((dentry = g_dir_read_name (dir)))
	{
		NMDialUpConfig *config;
		shvarFile *modem_file;
		char *name, *buf, *provider_name;
		int type;

		/* we only want modems and isdn */
		if (g_str_has_prefix (dentry, "ifcfg-modem"))
			type = NM_DIALUP_TYPE_MODEM;
		else if (g_str_has_prefix (dentry, "ifcfg-ippp"))
			type = NM_DIALUP_TYPE_ISDN;
		else if (g_str_has_prefix (dentry, "ifcfg-dsl"))
			type = NM_DIALUP_TYPE_DSL;
		else
			continue;

		/* open the configuration file */
		name = g_strdup_printf (SYSCONFDIR"/sysconfig/network/%s", dentry);
		modem_file = svNewFile (name);
		if (!modem_file)
			 goto out_gfree;
		/* get the name of the provider used for this entry */
		buf = svGetValue (modem_file, "PROVIDER");
		if (!buf)
			 goto out_close;

		provider_name = verify_and_return_provider (buf);
		if (!provider_name)
			 goto out_free;

		config = g_malloc (sizeof (NMDialUpConfig));
		config->data = g_strdup (dentry + 6); /* skip the "ifcfg-" prefix */
		if (type == NM_DIALUP_TYPE_MODEM)
		{
			config->name = g_strdup_printf ("%s via modem (%s)", provider_name, (char *) config->data);
			config->type = NM_DIALUP_TYPE_MODEM;
		}
		else if (type == NM_DIALUP_TYPE_ISDN)
		{
			config->name = g_strdup_printf ("%s via ISDN (%s)", provider_name, (char *) config->data);
			config->type = NM_DIALUP_TYPE_ISDN;
		}
		else if (type == NM_DIALUP_TYPE_DSL)
		{
			config->name = g_strdup_printf ("%s via DSL (%s)", provider_name, (char *) config->data);
			config->type = NM_DIALUP_TYPE_DSL;
		}

		list = g_slist_append (list, config);

		nm_info ("Found dial up configuration for %s: %s", config->name, (char *) config->data);

		free (provider_name);
out_free:
		free (buf);
out_close:
		svCloseFile (modem_file);
out_gfree:
		g_free (name);
	}

	g_dir_close (dir);

	return list;
}


/*
 * nm_system_activate_nis
 *
 * set up the nis domain and write a yp.conf
 *
 */
void nm_system_activate_nis (NMIP4Config *config)
{
	shvarFile *file;
	const char *nis_domain;
	char *name, *buf;
	struct in_addr	temp_addr;
	int i;
	FILE *ypconf = NULL;

	g_return_if_fail (config != NULL);

	nis_domain = nm_ip4_config_get_nis_domain(config);

	name = g_strdup_printf (SYSCONFDIR"/sysconfig/network/dhcp");
	file = svNewFile (name);
	if (!file)
		goto out_gfree;

	buf = svGetValue (file, "DHCLIENT_SET_DOMAINNAME");
	if (!buf)
		goto out_close;

	if ((!strcmp (buf, "yes")) && nis_domain && (setdomainname (nis_domain, strlen (nis_domain)) < 0))
			nm_warning ("Could not set nis domain name.");
	free (buf);

	buf = svGetValue (file, "DHCLIENT_MODIFY_NIS_CONF");
	if (!buf)
		goto out_close;

	if (!strcmp (buf, "yes")) {
		int num_nis_servers;

		num_nis_servers = nm_ip4_config_get_num_nis_servers(config);
		if (num_nis_servers > 0)
		{
			struct stat sb;

			/* write out yp.conf and restart the daemon */

			ypconf = fopen ("/etc/yp.conf", "w");

			if (ypconf)
			{
				fprintf (ypconf, "# generated by NetworkManager, do not edit!\n\n");
				for (i = 0; i < num_nis_servers; i++) {
					temp_addr.s_addr = nm_ip4_config_get_nis_server (config, i);
					fprintf (ypconf, "domain %s server %s\n", nis_domain, inet_ntoa (temp_addr));
				}
				fprintf (ypconf, "\n");
				fclose (ypconf);
			} else
				nm_warning ("Could not commit NIS changes to /etc/yp.conf.");

			if (stat ("/usr/sbin/rcautofs", &sb) != -1)
			{
				nm_info ("Restarting autofs.");
				nm_spawn_process ("/usr/sbin/rcautofs reload");
			}
		}
	}
	free (buf);

out_close:
	svCloseFile (file);
out_gfree:
	g_free (name);
}


/*
 * nm_system_shutdown_nis
 *
 * shutdown ypbind
 *
 */
void nm_system_shutdown_nis (void)
{
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

			/* try to get hostname via dns */
			temp_addr.s_addr = nm_ip4_config_get_address (config);
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


/*
 * nm_system_get_mtu
 *
 * Return a user-provided or system-mandated MTU for this device or zero if
 * no such MTU is provided.
 */
guint32 nm_system_get_mtu (NMDevice *dev)
{
	SuSEDeviceConfigData *	sys_data;

	sys_data = nm_device_get_system_config_data (dev);
	if (!sys_data)
		return 0;

	return sys_data->mtu;
}
