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

#include "NetworkManager.h"
#include "NetworkManagerUtils.h"

extern gboolean	debug;


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
/*
			if (func)
				NM_DEBUG_PRINT_1 ("MUTEX: %s got mutex\n", func);
*/
			return (TRUE);
		}
		usleep (500);
		i++;
	}

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

/*
	if (func)
		NM_DEBUG_PRINT_1 ("MUTEX: %s released mutex\n", func);
*/
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

	NM_DEBUG_PRINT ("nm_get_network_control_socket() could not get network control socket.\n");
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

	g_return_if_fail (test_addr != NULL);

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
 * nm_get_ip4_address_for_device
 *
 * Get a device's IPv4 address
 *
 */
guint32 nm_get_ip4_address_for_device(NMDevice *dev)
{
	struct ifreq		 req;
	int				 socket;
	
	g_return_val_if_fail (dev != NULL, 0);
	g_return_val_if_fail (nm_device_get_iface (dev) != NULL, 0);

	socket = nm_get_network_control_socket ();
	if (socket < 0)
		return (0);
	
	strncpy ((char *)(&req.ifr_name), nm_device_get_iface (dev), 16);	// 16 == IF_NAMESIZE
	if (ioctl (socket, SIOCGIFADDR, &req) != 0)
		return (0);

	return (((struct sockaddr_in *)(&req.ifr_addr))->sin_addr.s_addr);
}


/*
 * nm_get_ip6_address_for_device
 *
 * Get a device's IPv6 address
 *
 */
void nm_get_ip6_address_for_device(NMDevice *dev)
{
	/* FIXME
	 * Implement
	 */
}
