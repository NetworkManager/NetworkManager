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
 * (C) Copyright 2004 Red Hat, Inc.
 */

#include <glib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <syslog.h>

#include "NetworkManager.h"
#include "NetworkManagerUtils.h"


/*#define LOCKING_DEBUG */

/*
 * nm_try_acquire_mutex
 *
 * Tries to acquire a given mutex, sleeping a bit between tries.
 *
 * Returns:	FALSE if mutex was not acquired
 *			TRUE  if mutex was successfully acquired
 */
gboolean nm_try_acquire_mutex (GMutex *mutex, const char *func)
{
	gint	i = 5;

	g_return_val_if_fail (mutex != NULL, FALSE);

	while (i > 0)
	{
		if (g_mutex_trylock (mutex))
		{
#ifdef LOCKING_DEBUG
			if (func) syslog (LOG_DEBUG, "MUTEX: %s got mutex 0x%X", func, mutex);
#endif
			return (TRUE);
		}
		g_usleep (G_USEC_PER_SEC / 2);
		i++;
	}

#ifdef LOCKING_DEBUG
	if (func) syslog (LOG_DEBUG, "MUTEX: %s FAILED to get mutex 0x%X", func, mutex);
#endif
	return (FALSE);
}


/*
 * nm_unlock_mutex
 *
 * Simply unlocks a mutex, balances nm_try_acquire_mutex()
 *
 */
void nm_unlock_mutex (GMutex *mutex, const char *func)
{
	g_return_if_fail (mutex != NULL);

#ifdef LOCKING_DEBUG	
	if (func) syslog (LOG_DEBUG, "MUTEX: %s released mutex 0x%X", func, mutex);
#endif

	g_mutex_unlock (mutex);
}


/*
 * nm_null_safe_strcmp
 *
 * Doesn't freaking segfault if s1/s2 are NULL
 *
 */
int nm_null_safe_strcmp (const char *s1, const char *s2)
{
	if (!s1 && !s2)
		return 0;
	if (!s1 && s2)
		return -1;
	if (s1 && !s2)
		return 1;
		
	return (strcmp (s1, s2));
}



/*
 * nm_get_network_control_socket
 *
 * Get a control socket for network operations.
 *
 */
int nm_get_network_control_socket (void)
{
	int	fd;

	/* Try to grab a control socket */
	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd >= 0)
		return (fd);
	fd = socket(PF_PACKET, SOCK_DGRAM, 0);
	if (fd >= 0)
		return (fd);
	fd = socket(PF_INET6, SOCK_DGRAM, 0);
	if (fd >= 0)
		return (fd);

	syslog (LOG_ERR, "nm_get_network_control_socket() could not get network control socket.");
	return (-1);
}


/*
 * nm_ethernet_address_is_valid
 *
 * Compares an ethernet address against known invalid addresses.
 *
 */
gboolean nm_ethernet_address_is_valid (struct ether_addr *test_addr)
{
	gboolean			valid = FALSE;
	struct ether_addr	invalid_addr1 = { {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} };
	struct ether_addr	invalid_addr2 = { {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} };
	struct ether_addr	invalid_addr3 = { {0x44, 0x44, 0x44, 0x44, 0x44, 0x44} };

	g_return_val_if_fail (test_addr != NULL, FALSE);

	/* Compare the AP address the card has with invalid ethernet MAC addresses. */
	if (    (memcmp(test_addr, &invalid_addr1, sizeof(struct ether_addr)) != 0)
		&& (memcmp(test_addr, &invalid_addr2, sizeof(struct ether_addr)) != 0)
		&& (memcmp(test_addr, &invalid_addr3, sizeof(struct ether_addr)) != 0))
		valid = TRUE;

	return (valid);
}


/*
 * nm_dispose_scan_results
 *
 * Free memory used by the wireless scan results structure
 *
 */
void nm_dispose_scan_results (wireless_scan *result_list)
{
	wireless_scan *tmp = result_list;

	while (tmp)
	{
		wireless_scan *tmp2 = tmp;

		tmp = tmp->next;
		free (tmp2);
	}
}


/*
 * nm_spawn_process
 *
 * Wrap g_spawn_sync in a usable manner
 *
 */
int nm_spawn_process (char *args)
{
	gint		  num_args;
	char		**argv;
	int		  exit_status;
	GError	 *error = NULL;
	
	g_return_val_if_fail (args != NULL, -1);

	if (g_shell_parse_argv (args, &num_args, &argv, NULL))
	{
		if (g_spawn_sync ("/", argv, NULL, 0, NULL, NULL, NULL, NULL, &exit_status, &error))
		{
			g_strfreev (argv);
			return (exit_status);
		}
		else
			syslog (LOG_ERR, "nm_spawn_process('%s'): could not spawn process. (%s)\n", args, error->message);

		g_strfreev (argv);
		if (error)
			g_error_free (error);
	}
		else
			syslog (LOG_ERR, "nm_spawn_process('%s'): could not parse arguments (%s)\n", args, error->message);

	return (-1);
}


typedef struct driver_support
{
	char *name;
	NMDriverSupportLevel level;
} driver_support;

/* The list of wireless drivers we support and how well we support each */
static driver_support wireless_driver_support_list[] =
{
/* Fully supported drivers */
	{"airo_cs",		NM_DRIVER_FULLY_SUPPORTED},
	{"airo",			NM_DRIVER_FULLY_SUPPORTED},
	{"atmel_cs",		NM_DRIVER_FULLY_SUPPORTED},
	{"atmel",			NM_DRIVER_FULLY_SUPPORTED},
	{"atmel_pci",		NM_DRIVER_FULLY_SUPPORTED},
	{"prism54",		NM_DRIVER_FULLY_SUPPORTED},
	{"wl3501_cs",		NM_DRIVER_FULLY_SUPPORTED},
	{"ipw2100",		NM_DRIVER_FULLY_SUPPORTED},
	{"ipw2200",		NM_DRIVER_FULLY_SUPPORTED},
	{"ath_pci",		NM_DRIVER_FULLY_SUPPORTED},
	{"ath_cs",		NM_DRIVER_FULLY_SUPPORTED},
/* Semi-supported drivers, for example ones that don't support
 * wireless scanning yet in-kernel
 */
	{"hermes",		NM_DRIVER_SEMI_SUPPORTED},
	{"netwave_cs",		NM_DRIVER_SEMI_SUPPORTED},
	{"orinoco_cs",		NM_DRIVER_SEMI_SUPPORTED},
	{"orinoco",		NM_DRIVER_SEMI_SUPPORTED},
	{"orinoco_pci",	NM_DRIVER_SEMI_SUPPORTED},
	{"orinoco_plx",	NM_DRIVER_SEMI_SUPPORTED},
	{"orinoco_tmd",	NM_DRIVER_SEMI_SUPPORTED},
	{"wavelan_cs",		NM_DRIVER_SEMI_SUPPORTED},
	{"wavelan",		NM_DRIVER_SEMI_SUPPORTED},
	{NULL,			NM_DRIVER_UNSUPPORTED}
};


/* Blacklist of unsupported wired drivers */
static driver_support wired_driver_blacklist[] =
{
/* Completely unsupported drivers */
	{NULL,			NM_DRIVER_UNSUPPORTED}
};



/*
 * nm_get_device_driver_name
 *
 * Checks either /proc/sys/bus/devices or /var/lib/pcmcia/stab to determine
 * which driver is bound to the device.
 *
 */
char *nm_get_device_driver_name (LibHalContext *ctx, NMDevice *dev)
{
	FILE					*f;
	char					*driver_name = NULL;
	int					 vendor;
	int					 product;

	g_return_val_if_fail (ctx != NULL, NULL);
	g_return_val_if_fail (dev != NULL, NULL);

	vendor = hal_device_get_property_int (ctx, nm_device_get_udi (dev), "pci.vendor_id");
	product = hal_device_get_property_int (ctx, nm_device_get_udi (dev), "pci.product_id");

	if (vendor && product)
	{
		if ((f = fopen ("/proc/bus/pci/devices", "r")))
		{
			char	buf[200];
			char	id[9];

			snprintf (&id[0], 9, "%4x%4x", vendor, product);
			id[8] = '\0';
			while (fgets (&buf[0], 200, f) && !feof (f))
			{
				char *p;
				char s[9];
				int len;

				/* Whack newline */
				buf[199] = '\0';
				len = strlen (buf);
				if ((buf[len-1] == '\n') || (buf[len-1] == '\r'))
				{
					buf[len-1] = '\0';
					len--;
				}

				p = strchr (buf, '\t');
				s[8] = '\0';
				strncpy (&s[0], p+1, 8);

				if (!strcmp (&s[0], &id[0]))
				{
					/* Yay, we've got a match.  Pull the driver name from the
					 * last word in the line.
					 */
					char *m = strrchr (&buf[0], '\t');
					if (m && (m > &buf[0]) && (m < &buf[len]))
					{
						driver_name = strdup (m+1);
						syslog (LOG_INFO, "PCI driver for '%s' is '%s'", nm_device_get_iface (dev), driver_name);
						break;
					}
				}
			}
			fclose (f);
		}
	}

	/* Might be a PCMCIA card, try /var/lib/pcmcia/stab and match the interface name.
	 *
	 * stab has a format like this:
	 *   Socket 0: Belkin F5D6020 rev.2
	 *   0       network atmel_cs        0       eth2
	 *   Socket 1: Belkin-5020
	 *   1       network pcnet_cs        0       eth1
	 */
	if (!driver_name && (f = fopen ("/var/lib/pcmcia/stab", "r")))
	{
		char	buf[200];

		while (fgets (&buf[0], 200, f) && !feof (f))
		{
			int len;
			char *p;

			/* Whack newline */
			buf[199] = '\0';
			len = strlen (buf);
			if ((buf[len-1] == '\n') || (buf[len-1] == '\r'))
			{
				buf[len-1] = '\0';
				len--;
			}

			/* Ignore lines that start with "Socket" */
			if (strncmp (&buf[0], "Socket", 6) && (p = strrchr (&buf[0], '\t')))
			{
				/* See if this device's interface matches our device's interface */
				if (!strcmp (++p, nm_device_get_iface (dev)))
				{
					char *end;
					/* Pull out driver name by seeking to _second_ tab */
					if ((p = strchr (&buf[0], '\t')) && *(p++) && (p = strchr (p, '\t')))
					{
						p++;
						end = strchr (p, '\t');
						if (p && end)
						{
							*end = '\0';
							driver_name = strdup (p);
							syslog (LOG_INFO, "PCMCIA driver for '%s' is '%s'", nm_device_get_iface (dev), driver_name);
						}
					}
				}
			}
		}
		fclose (f);
	}

	return (driver_name);
}

/*
 * nm_get_wireless_driver_support_level
 *
 * Checks either /proc/sys/bus/devices or /var/lib/pcmcia/stab to determine
 * wether or not the card's driver is supported and how well, using a whitelist.
 *
 */
NMDriverSupportLevel nm_get_wireless_driver_support_level (LibHalContext *ctx, NMDevice *dev)
{
	NMDriverSupportLevel	 level = NM_DRIVER_UNSUPPORTED;
	char					*driver_name = NULL;

	g_return_val_if_fail (ctx != NULL, FALSE);
	g_return_val_if_fail (dev != NULL, FALSE);

	if ((driver_name = nm_get_device_driver_name (ctx, dev)))
	{
		driver_support *driver = &wireless_driver_support_list[0];
		while (driver->name != NULL)
		{
			if (!strcmp (driver->name, driver_name))
			{
				level = driver->level;
				break;
			}
			driver++;
		}
		g_free (driver_name);
	}

	return (level);
}


/*
 * nm_get_wired_driver_support_level
 *
 * Blacklist certain devices.
 *
 */
NMDriverSupportLevel nm_get_wired_driver_support_level (LibHalContext *ctx, NMDevice *dev)
{
	NMDriverSupportLevel	 level = NM_DRIVER_FULLY_SUPPORTED;
	char					*driver_name = NULL;
	char					*usb_test;

	g_return_val_if_fail (ctx != NULL, FALSE);
	g_return_val_if_fail (dev != NULL, FALSE);

	if ((driver_name = nm_get_device_driver_name (ctx, dev)))
	{
		driver_support *driver = &wired_driver_blacklist[0];
		while (driver->name != NULL)
		{
			if (!strcmp (driver->name, driver_name))
			{
				level = driver->level;
				break;
			}
			driver++;
		}
		g_free (driver_name);
	}

	/* cipsec devices are also explicitly unsupported at this time */
	if (strstr (nm_device_get_iface (dev), "cipsec"))
		level = NM_DRIVER_UNSUPPORTED;

	/* Ignore Ethernet-over-USB devices too for the moment (Red Hat #135722) */
	if ((usb_test = hal_device_get_property_string (ctx, nm_device_get_udi (dev), "usb.interface.class")))
	{
		hal_free_string (usb_test);
		level = NM_DRIVER_UNSUPPORTED;
	}

	return (level);
}


/*
 * nm_get_driver_support_level
 *
 * Return the driver support level for a particular device.
 *
 */
NMDriverSupportLevel nm_get_driver_support_level (LibHalContext *ctx, NMDevice *dev)
{
	NMDriverSupportLevel	level = NM_DRIVER_UNSUPPORTED;

	g_return_val_if_fail (ctx != NULL, NM_DRIVER_UNSUPPORTED);
	g_return_val_if_fail (dev != NULL, NM_DRIVER_UNSUPPORTED);

	if (nm_device_is_wireless (dev))
		level = nm_get_wireless_driver_support_level (ctx, dev);
	else if (nm_device_is_wired (dev))
		level = nm_get_wired_driver_support_level (ctx, dev);

	switch (level)
	{
		case NM_DRIVER_SEMI_SUPPORTED:
			syslog (LOG_INFO, "%s: Driver support level is semi-supported", nm_device_get_iface (dev));
			break;
		case NM_DRIVER_FULLY_SUPPORTED:
			syslog (LOG_INFO, "%s: Driver support level is fully-supported", nm_device_get_iface (dev));
			break;
		default:
			syslog (LOG_INFO, "%s: Driver support level is unsupported", nm_device_get_iface (dev));
			break;
	}

	return (level);
}
