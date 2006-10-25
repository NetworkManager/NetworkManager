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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/sockios.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/time.h>
#include <string.h>
#include <signal.h>
#include <iwlib.h>

#include "NetworkManager.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-device.h"
#include "nm-device-802-11-wireless.h"
#include "nm-device-802-3-ethernet.h"
#include "wpa_ctrl.h"

#include <netlink/addr.h>
#include <netinet/in.h>


struct NMSock
{
	int	fd;
	char *func;
	char *desc;
	NMDevice *dev;
};

static GSList		*sock_list = NULL;
static GStaticMutex	 sock_list_mutex = G_STATIC_MUTEX_INIT;

typedef struct MutexDesc
{
	GMutex	*mutex;
	char		*desc;
} MutexDesc;

GSList	*mutex_descs = NULL;

/*#define LOCKING_DEBUG*/


static MutexDesc *nm_find_mutex_desc (GMutex *mutex)
{
	GSList	*elt;

	for (elt = mutex_descs; elt; elt = g_slist_next (elt))
	{
		MutexDesc	*desc = (MutexDesc *)(elt->data);
		if (desc && (desc->mutex == mutex))
			return desc;
	}

	return NULL;
}


/*
 * nm_register_mutex_desc
 * 
 * Associate a description with a particular mutex.
 *
 */
void nm_register_mutex_desc (GMutex *mutex, const char *string)
{
	if (!(nm_find_mutex_desc (mutex)))
	{
		MutexDesc	*desc = g_malloc0 (sizeof (MutexDesc));
		desc->mutex = mutex;
		desc->desc = g_strdup (string);
		mutex_descs = g_slist_append (mutex_descs, desc);
	}
}


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
	g_return_val_if_fail (mutex != NULL, FALSE);

	if (g_mutex_trylock (mutex))
	{
#ifdef LOCKING_DEBUG
		if (func)
		{
			MutexDesc	*desc = nm_find_mutex_desc (mutex);
			nm_debug ("MUTEX: <%s %p> acquired by %s", desc ? desc->desc : "(none)", mutex, func);
		}
#endif
		return (TRUE);
	}

#ifdef LOCKING_DEBUG
	if (func)
	{
		MutexDesc	*desc = nm_find_mutex_desc (mutex);
		nm_debug ("MUTEX: <%s %p> FAILED to be acquired by %s", desc ? desc->desc : "(none)", mutex, func);
	}
#endif
	return (FALSE);
}


/*
 * nm_lock_mutex
 *
 * Blocks until a mutex is grabbed, with debugging.
 *
 */
void nm_lock_mutex (GMutex *mutex, const char *func)
{
#ifdef LOCKING_DEBUG
	if (func)
	{
		MutexDesc	*desc = nm_find_mutex_desc (mutex);
		nm_debug ("MUTEX: <%s %p> being acquired by %s", desc ? desc->desc : "(none)", mutex, func);
	}
#endif
	g_mutex_lock (mutex);
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
	if (func)
	{
		MutexDesc	*desc = nm_find_mutex_desc (mutex);
		nm_debug ("MUTEX: <%s %p> released by %s", desc ? desc->desc : "(none)", mutex, func);
	}
#endif

	g_mutex_unlock (mutex);
}


/*
 * nm_dev_sock_open
 *
 * Open a socket to a network device and store some debug info about it.
 *
 */
NMSock *nm_dev_sock_open (NMDevice *dev, SockType type, const char *func_name, const char *desc)
{
	NMSock	*sock = NULL;

	sock = g_malloc0 (sizeof (NMSock));

	sock->fd = -1;

	switch (type)
	{
		case DEV_WIRELESS:
			sock->fd = iw_sockets_open ();
			break;

		case DEV_GENERAL:
			if ((sock->fd = socket (PF_INET, SOCK_DGRAM, 0)) < 0)
				if ((sock->fd = socket (PF_PACKET, SOCK_DGRAM, 0)) < 0)
					sock->fd = socket (PF_INET6, SOCK_DGRAM, 0);
			break;

		case NETWORK_CONTROL:
			sock->fd = socket (AF_PACKET, SOCK_PACKET, htons (ETH_P_ALL));
			break;

		default:
			break;
	}

	if (sock->fd < 0)
	{
		g_free (sock);
		nm_warning ("Could not open control socket for device '%s'.", dev ? nm_device_get_iface (dev) : "none");
		return NULL;
	}

	sock->func = func_name ? g_strdup (func_name) : NULL;
	sock->desc = desc ? g_strdup (desc) : NULL;
	sock->dev = dev;
	if (sock->dev)
		g_object_ref (G_OBJECT (sock->dev));

	/* Add the sock to our global sock list for tracking */
	g_static_mutex_lock (&sock_list_mutex);
	sock_list = g_slist_append (sock_list, sock);
	g_static_mutex_unlock (&sock_list_mutex);

	return sock;
}


/*
 * nm_dev_sock_close
 *
 * Close a socket and free its debug data.
 *
 */
void nm_dev_sock_close (NMSock *sock)
{
	GSList	*elt;

	g_return_if_fail (sock != NULL);

	close (sock->fd);
	g_free (sock->func);
	g_free (sock->desc);
	if (sock->dev)
		g_object_unref (G_OBJECT (sock->dev));

	memset (sock, 0, sizeof (NMSock));

	g_static_mutex_lock (&sock_list_mutex);
	for (elt = sock_list; elt; elt = g_slist_next (elt))
	{
		NMSock	*temp_sock = (NMSock *)(elt->data);
		if (temp_sock == sock)
		{
			sock_list = g_slist_remove_link (sock_list, elt);
			g_slist_free (elt);
			break;
		}
	}
	g_static_mutex_unlock (&sock_list_mutex);

	g_free (sock);
}


/*
 * nm_dev_sock_get_fd
 *
 * Return the fd associated with an NMSock
 *
 */
int nm_dev_sock_get_fd (NMSock *sock)
{
	g_return_val_if_fail (sock != NULL, -1);

	return sock->fd;
}


/*
 * nm_print_open_socks
 *
 * Print a list of currently open and registered NMSocks.
 *
 */
void nm_print_open_socks (void)
{
	GSList	*elt = NULL;
	int		 i = 0;

	nm_debug ("Open Sockets List:");
	g_static_mutex_lock (&sock_list_mutex);
	for (elt = sock_list; elt; elt = g_slist_next (elt))
	{
		NMSock	*sock = (NMSock *)(elt->data);
		if (sock)
		{
			i++;
			nm_debug ("  %d: %s fd:%d F:'%s' D:'%s'", i, sock->dev ? nm_device_get_iface (sock->dev) : "",
				sock->fd, sock->func, sock->desc);
		}
	}
	g_static_mutex_unlock (&sock_list_mutex);
	nm_debug ("Open Sockets List Done.");
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
 * nm_ethernet_address_is_valid
 *
 * Compares an Ethernet address against known invalid addresses.
 *
 */
gboolean nm_ethernet_address_is_valid (const struct ether_addr *test_addr)
{
	gboolean			valid = FALSE;
	struct ether_addr	invalid_addr1 = { {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} };
	struct ether_addr	invalid_addr2 = { {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} };
	struct ether_addr	invalid_addr3 = { {0x44, 0x44, 0x44, 0x44, 0x44, 0x44} };
	struct ether_addr	invalid_addr4 = { {0x00, 0x30, 0xb4, 0x00, 0x00, 0x00} }; /* prism54 dummy MAC */

	g_return_val_if_fail (test_addr != NULL, FALSE);

	/* Compare the AP address the card has with invalid ethernet MAC addresses. */
	if (    (memcmp(test_addr, &invalid_addr1, sizeof(struct ether_addr)) != 0)
		&& (memcmp(test_addr, &invalid_addr2, sizeof(struct ether_addr)) != 0)
		&& (memcmp(test_addr, &invalid_addr3, sizeof(struct ether_addr)) != 0)
		&& (memcmp(test_addr, &invalid_addr4, sizeof(struct ether_addr)) != 0)
		&& ((test_addr->ether_addr_octet[0] & 1) == 0))			/* Multicast addresses */
		valid = TRUE;

	return (valid);
}


/*
 * nm_ethernet_addresses_are_equal
 *
 * Compare two Ethernet addresses and return TRUE if equal and FALSE if not.
 */
gboolean nm_ethernet_addresses_are_equal (const struct ether_addr *a, const struct ether_addr *b)
{
	if (memcmp (a, b, sizeof (struct ether_addr)))
		return FALSE;
	return TRUE;
}


/*
 * nm_spawn_process
 *
 * Wrap g_spawn_sync in a usable manner
 *
 */
int nm_spawn_process (const char *args)
{
	gint		  num_args;
	char		**argv = NULL;
	int		  exit_status = -1;
	GError	 *error = NULL;
	char		 *so = NULL;
	char		 *se = NULL;

	g_return_val_if_fail (args != NULL, -1);

	if (g_shell_parse_argv (args, &num_args, &argv, &error))
	{
		GError *error2 = NULL;

		if (!g_spawn_sync ("/", argv, NULL, 0, NULL, NULL, &so, &se, &exit_status, &error2))
			nm_warning ("nm_spawn_process('%s'): could not spawn process. (%s)\n", args, error2->message);

		if (so)    g_free(so);
		if (se)    g_free(se);
		if (argv)  g_strfreev (argv);
		if (error2) g_error_free (error2);
	} else nm_warning ("nm_spawn_process('%s'): could not parse arguments (%s)\n", args, error->message);

	if (error) g_error_free (error);

	return (exit_status);
}


/*
 * nm_print_device_capabilities
 *
 * Return the capabilities for a particular device.
 *
 */
void nm_print_device_capabilities (NMDevice *dev)
{
	gboolean		full_support = TRUE;
	guint32		caps;
	const char *	driver = NULL;

	g_return_if_fail (dev != NULL);

	caps = nm_device_get_capabilities (dev);
	driver = nm_device_get_driver (dev);

	if (caps == NM_DEVICE_CAP_NONE || !(NM_DEVICE_CAP_NM_SUPPORTED))
	{
		nm_info ("%s: Driver support level for '%s' is unsupported",
				nm_device_get_iface (dev), driver);
		return;
	}

	if (nm_device_is_802_3_ethernet (dev))
	{
		if (!(caps & NM_DEVICE_CAP_CARRIER_DETECT))
		{
			nm_info ("%s: Driver '%s' does not support carrier detection.\n"
					"\tYou must switch to it manually.",
					nm_device_get_iface (dev), driver);
			full_support = FALSE;
		}
	}
	else if (nm_device_is_802_11_wireless (dev))
	{
		if (!(caps & NM_DEVICE_CAP_WIRELESS_SCAN))
		{
			nm_info ("%s: Driver '%s' does not support wireless scanning.\n"
					"\tSome features will not be available.",
						nm_device_get_iface (dev), driver);
			full_support = FALSE;
		}
	}

	if (full_support)
	{
		nm_info ("%s: Device is fully-supported using driver '%s'.",
				nm_device_get_iface (dev), driver);
	}
}

static inline int nm_timeval_cmp(const struct timeval *a,
				 const struct timeval *b)
{
	int x;
	x = a->tv_sec - b->tv_sec;
	x *= G_USEC_PER_SEC;
	if (x)
		return x;
	x = a->tv_usec - b->tv_usec;
	if (x)
		return x;
	return 0;
}

static inline int nm_timeval_has_passed(const struct timeval *a)
{
	struct timeval current;

	gettimeofday(&current, NULL);

	return (nm_timeval_cmp(&current, a) >= 0);
}

static inline void nm_timeval_add(struct timeval *a,
				  const struct timeval *b)
{
	struct timeval b1;

	memmove(&b1, b, sizeof b1);

	/* normalize a and b to be positive for everything */
	while (a->tv_usec < 0)
	{
		a->tv_sec--;
		a->tv_usec += G_USEC_PER_SEC;
	}
	while (b1.tv_usec < 0)
	{
		b1.tv_sec--;
		b1.tv_usec += G_USEC_PER_SEC;
	}

	/* now add secs and usecs */
	a->tv_sec += b1.tv_sec;
	a->tv_usec += b1.tv_usec;

	/* and handle our overflow */
	if (a->tv_usec > G_USEC_PER_SEC)
	{
		a->tv_sec++;
		a->tv_usec -= G_USEC_PER_SEC;
	}
}

static void nm_v_wait_for_completion_or_timeout(
		const int max_tries,
		const struct timeval *max_time,
		const guint interval_usecs,
		nm_completion_func test_func,
		nm_completion_func action_func,
		nm_completion_args args)
{
	int try;
	gboolean finished = FALSE;
	struct timeval finish_time;

	g_return_if_fail (test_func || action_func);

	if (max_time) {
		gettimeofday(&finish_time, NULL);
		nm_timeval_add(&finish_time, max_time);
	}

	try = -1;
	while (!finished &&
		(max_tries == NM_COMPLETION_TRIES_INFINITY || try < max_tries))
	{
		if (max_time && nm_timeval_has_passed(&finish_time))
			break;
		try++;
		if (test_func)
		{
			finished = (*test_func)(try, args);
			if (finished)
				break;
		}

/* #define NM_SLEEP_DEBUG */
#ifdef NM_SLEEP_DEBUG
		syslog (LOG_INFO, "sleeping for %d usecs", interval_usecs);
#endif
		g_usleep(interval_usecs);
		if (action_func)
			finished = (*action_func)(try, args);
	}
}

/* these should probably be moved to NetworkManagerUtils.h as macros
 * since they don't do varargs stuff any more */
void nm_wait_for_completion_or_timeout(
	const int max_tries,
	const struct timeval *max_time,
	const guint interval_usecs,
	nm_completion_func test_func,
	nm_completion_func action_func,
	nm_completion_args args)
{
	nm_v_wait_for_completion_or_timeout(max_tries, max_time,
					    interval_usecs, test_func,
					    action_func, args);
}

void nm_wait_for_completion(
		const int max_tries,
		const guint interval_usecs,
		nm_completion_func test_func,
		nm_completion_func action_func,
		nm_completion_args args)
{
	nm_v_wait_for_completion_or_timeout(max_tries, NULL,
					    interval_usecs, test_func,
					    action_func, args);
}

void nm_wait_for_timeout(
		const struct timeval *max_time,
		const guint interval_usecs,
		nm_completion_func test_func,
		nm_completion_func action_func,
		nm_completion_args args)
{
	nm_v_wait_for_completion_or_timeout(NM_COMPLETION_TRIES_INFINITY, max_time,
			interval_usecs, test_func, action_func, args);
}

/* you can use these, but they're really just examples */
gboolean nm_completion_boolean_test(int tries, nm_completion_args args)
{
	gboolean *condition = (gboolean *)args[0];
	char *message = (char *)args[1];
	int log_level = GPOINTER_TO_INT (args[2]);
	int log_interval = GPOINTER_TO_INT (args[3]);

	g_return_val_if_fail (condition != NULL, TRUE);

	if (message)
		if ((log_interval == 0 && tries == 0) || (log_interval != 0 && tries % log_interval == 0))
		{
			if (log_level == LOG_WARNING)
				nm_warning_str (message);
			else if (log_level == LOG_ERR)
				nm_error_str (message);
			else if (log_level == LOG_DEBUG)
				nm_debug_str (message);
			else
				nm_info_str (message);
		}

	if (*condition)
		return TRUE;
	return FALSE;
}

gboolean nm_completion_boolean_function1_test(int tries,
		nm_completion_args args)
{
	nm_completion_boolean_function_1 condition = args[0];
	char *message = args[1];
	int log_level = GPOINTER_TO_INT (args[2]);
	int log_interval = GPOINTER_TO_INT (args[3]);
	u_int64_t arg0;
	
	memcpy(&arg0, &args[4], sizeof (arg0));

	g_return_val_if_fail (condition, TRUE);

	if (message)
		if ((log_interval == 0 && tries == 0)
			   || (log_interval != 0 && tries % log_interval == 0))
			syslog(log_level, "%s", message);

	if (!(*condition)(arg0))
		return TRUE;
	return FALSE;
}

gboolean nm_completion_boolean_function2_test(int tries,
		nm_completion_args args)
{
	nm_completion_boolean_function_2 condition = args[0];
	char *message = args[1];
	int log_level = GPOINTER_TO_INT (args[2]);
	int log_interval = GPOINTER_TO_INT (args[3]);
	u_int64_t arg0, arg1;

	memcpy(&arg0, &args[4], sizeof (arg0));
	memcpy(&arg1, &args[4]+sizeof (arg0), sizeof (arg1));

	g_return_val_if_fail (condition, TRUE);

	if (message)
		if ((log_interval == 0 && tries == 0)
			   || (log_interval != 0 && tries % log_interval == 0))
			syslog(log_level, "%s", message);

	if (!(*condition)(arg0, arg1))
		return TRUE;
	return FALSE;
}


gchar *nm_utils_inet_ip4_address_as_string (guint32 ip)
{
	struct in_addr tmp_addr;
	gchar *ip_string;

	tmp_addr.s_addr = ip;
	ip_string = inet_ntoa (tmp_addr);

	return g_strdup (ip_string);
}


struct nl_addr * nm_utils_ip4_addr_to_nl_addr (guint32 ip4_addr)
{
	struct nl_addr * nla = NULL;

	if (!(nla = nl_addr_alloc (sizeof (in_addr_t))))
		return NULL;
	nl_addr_set_family (nla, AF_INET);
	nl_addr_set_binary_addr (nla, &ip4_addr, sizeof (guint32));

	return nla;
}

/*
 * nm_utils_ip4_netmask_to_prefix
 *
 * Figure out the network prefix from a netmask.  Netmask
 * MUST be in network byte order.
 *
 */
int nm_utils_ip4_netmask_to_prefix (guint32 ip4_netmask)
{
	int i = 1;

	g_return_val_if_fail (ip4_netmask != 0, 0);

	/* Just count how many bit shifts we need */
	ip4_netmask = ntohl (ip4_netmask);
	while (!(ip4_netmask & 0x1) && ++i)
		ip4_netmask = ip4_netmask >> 1;
	return (32 - (i-1));
}


#define SUPPLICANT_DEBUG
#define RESPONSE_SIZE	2048


static char *
kill_newline (char *s, size_t *l)
{
	g_return_val_if_fail (l != NULL, s);

	while ((--(*l) > 0) && (s[*l] != '\n'))
		;
	if (s[*l] == '\n')
		s[*l] = '\0';
	return s;
}


char *
nm_utils_supplicant_request (struct wpa_ctrl *ctrl,
                             const char *format,
                             ...)
{
	va_list	args;
	size_t	len;
	char *	response = NULL;
	char *	command;

	g_return_val_if_fail (ctrl != NULL, NULL);
	g_return_val_if_fail (format != NULL, NULL);

	va_start (args, format);
	if (!(command = g_strdup_vprintf (format, args)))
		return NULL;
	va_end (args);

	response = g_malloc (RESPONSE_SIZE);
	len = RESPONSE_SIZE;
#ifdef SUPPLICANT_DEBUG
	nm_info ("SUP: sending command '%s'", command);
#endif
	wpa_ctrl_request (ctrl, command, strlen (command), response, &len, NULL);
	g_free (command);
	response[len] = '\0';
#ifdef SUPPLICANT_DEBUG
	{
		response = kill_newline (response, &len);
		nm_info ("SUP: response was '%s'", response);
	}
#endif
	return response;
}


gboolean
nm_utils_supplicant_request_with_check (struct wpa_ctrl *ctrl,
                                        const char *expected,
                                        const char *func,
								const char *err_msg_cmd,
                                        const char *format,
                                        ...)
{
	va_list	args;
	gboolean	success = FALSE;
	size_t	len;
	char *	response = NULL;
	char *	command;
	char *	temp;

	g_return_val_if_fail (ctrl != NULL, FALSE);
	g_return_val_if_fail (expected != NULL, FALSE);
	g_return_val_if_fail (format != NULL, FALSE);

	va_start (args, format);
	if (!(command = g_strdup_vprintf (format, args)))
		goto out;

	response = g_malloc (RESPONSE_SIZE);
	len = RESPONSE_SIZE;
#ifdef SUPPLICANT_DEBUG
	/* Hack: don't print anything out for SCAN commands since they
	 * happen so often.
	 */
	if (strcmp (command, "SCAN") != 0)
		nm_info ("SUP: sending command '%s'", err_msg_cmd ? err_msg_cmd : command);
#endif
	wpa_ctrl_request (ctrl, command, strlen (command), response, &len, NULL);
	response[len] = '\0';
#ifdef SUPPLICANT_DEBUG
	/* Hack: don't print anything out for SCAN commands since they
	 * happen so often.
	 */
	if (strcmp (command, "SCAN") != 0) {
		response = kill_newline (response, &len);
		nm_info ("SUP: response was '%s'", response);
	}
#endif

	if (response)
	{
		if (strncmp (response, expected, strlen (expected)) == 0)
			success = TRUE;
		else
		{
			response = kill_newline (response, &len);
			temp = g_strdup_printf ("%s: supplicant error for '%s'.  Response: '%s'",
						func, err_msg_cmd ? err_msg_cmd : command, response);
			nm_warning_str (temp);
			g_free (temp);
		}
		g_free (response);
	}
	else
	{
		temp = g_strdup_printf ("%s: supplicant error for '%s'.  No response.",
					func, err_msg_cmd ? err_msg_cmd : command);
		nm_warning_str (temp);
		g_free (temp);
	}
	g_free (command);

out:
	va_end (args);
	return success;
}

