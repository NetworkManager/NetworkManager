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


/*#define LOCKING_DEBUG	/**/

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
	
	g_return_val_if_fail (args != NULL, -1);

	if (g_shell_parse_argv (args, &num_args, &argv, NULL))
	{
		if (g_spawn_sync ("/", argv, NULL, 0, NULL, NULL, NULL, NULL, &exit_status, NULL))
		{
			g_strfreev (argv);
			return (exit_status);
		}
		g_strfreev (argv);
	}

	return (-1);
}

