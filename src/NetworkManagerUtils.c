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
void nm_register_mutex_desc (GMutex *mutex, char *string)
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
			syslog (LOG_DEBUG, "MUTEX: <%s %p> acquired by %s", desc ? desc->desc : "(none)", mutex, func);
		}
#endif
		return (TRUE);
	}

#ifdef LOCKING_DEBUG
	if (func)
	{
		MutexDesc	*desc = nm_find_mutex_desc (mutex);
		syslog (LOG_DEBUG, "MUTEX: <%s %p> FAILED to be acquired by %s", desc ? desc->desc : "(none)", mutex, func);
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
		syslog (LOG_DEBUG, "MUTEX: <%s %p> being acquired by %s", desc ? desc->desc : "(none)", mutex, func);
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
		syslog (LOG_DEBUG, "MUTEX: <%s %p> released by %s", desc ? desc->desc : "(none)", mutex, func);
	}
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
			syslog (LOG_ERR, "nm_spawn_process('%s'): could not spawn process. (%s)\n", args, error2->message);

		if (so)    g_free(so);
		if (se)    g_free(se);
		if (argv)  g_strfreev (argv);
		if (error2) g_error_free (error2);
	} else syslog (LOG_ERR, "nm_spawn_process('%s'): could not parse arguments (%s)\n", args, error->message);

	if (error) g_error_free (error);

	return (exit_status);
}


typedef struct driver_support
{
	char *name;
	NMDriverSupportLevel level;
} driver_support;


/* Blacklist of unsupported wireless drivers */
static driver_support wireless_driver_blacklist[] =
{
	{NULL,			NM_DRIVER_UNSUPPORTED}
};


/* Blacklist of unsupported wired drivers.  Drivers/cards that don't support
 * link detection should be blacklisted.
 */
static driver_support wired_driver_blacklist[] =
{
/* Completely unsupported drivers */
	{NULL,			NM_DRIVER_UNSUPPORTED}
};


/*
 * nm_get_device_driver_name
 *
 *
 */
char *nm_get_device_driver_name (LibHalContext *ctx, NMDevice *dev)
{
	char	*udi = NULL;
	char	*driver_name = NULL;

	g_return_val_if_fail (ctx != NULL, NULL);
	g_return_val_if_fail (dev != NULL, NULL);

	if (    (udi = nm_device_get_udi (dev))
		&& hal_device_property_exists (ctx, udi, "net.linux.driver"))
	{
		driver_name = hal_device_get_property_string (ctx, udi, "net.linux.driver");
	}

	return (driver_name);
}

/*
 * nm_get_wireless_driver_support_level
 *
 * Blacklist certain wireless devices.
 *
 */
NMDriverSupportLevel nm_get_wireless_driver_support_level (LibHalContext *ctx, NMDevice *dev, char **driver)
{
	NMDriverSupportLevel	 level = NM_DRIVER_FULLY_SUPPORTED;
	char					*driver_name = NULL;

	g_return_val_if_fail (ctx != NULL, NM_DRIVER_UNSUPPORTED);
	g_return_val_if_fail (dev != NULL, NM_DRIVER_UNSUPPORTED);
	g_return_val_if_fail (driver != NULL, NM_DRIVER_UNSUPPORTED);
	g_return_val_if_fail (*driver == NULL, NM_DRIVER_UNSUPPORTED);

	if ((driver_name = nm_get_device_driver_name (ctx, dev)))
	{
		driver_support *drv;
		for (drv = &wireless_driver_blacklist[0]; drv->name; drv++)
		{
			if (!strcmp (drv->name, driver_name))
			{
				level = drv->level;
				break;
			}
		}
		*driver = g_strdup (driver_name);
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
NMDriverSupportLevel nm_get_wired_driver_support_level (LibHalContext *ctx, NMDevice *dev, char **driver)
{
	NMDriverSupportLevel	 level = NM_DRIVER_FULLY_SUPPORTED;
	char					*driver_name = NULL;
	char					*usb_test;
	char					*udi;

	g_return_val_if_fail (ctx != NULL, NM_DRIVER_UNSUPPORTED);
	g_return_val_if_fail (dev != NULL, NM_DRIVER_UNSUPPORTED);
	g_return_val_if_fail (driver != NULL, NM_DRIVER_UNSUPPORTED);
	g_return_val_if_fail (*driver == NULL, NM_DRIVER_UNSUPPORTED);

	if ((driver_name = nm_get_device_driver_name (ctx, dev)))
	{
		driver_support *drv;
		for (drv = &wired_driver_blacklist[0]; drv->name; drv++)
		{
			if (!strcmp (drv->name, driver_name))
			{
				level = drv->level;
				break;
			}
		}
		*driver = g_strdup (driver_name);
		g_free (driver_name);
	}

	/* cipsec devices are also explicitly unsupported at this time */
	if (strstr (nm_device_get_iface (dev), "cipsec"))
		level = NM_DRIVER_UNSUPPORTED;

	/* Ignore Ethernet-over-USB devices too for the moment (Red Hat #135722) */
	udi = nm_device_get_udi (dev);
	if (    hal_device_property_exists (ctx, udi, "usb.interface.class")
		&& (usb_test = hal_device_get_property_string (ctx, udi, "usb.interface.class")))
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
	char					*driver = NULL;
	NMDriverSupportLevel	 level = NM_DRIVER_UNSUPPORTED;

	g_return_val_if_fail (ctx != NULL, NM_DRIVER_UNSUPPORTED);
	g_return_val_if_fail (dev != NULL, NM_DRIVER_UNSUPPORTED);

	if (nm_device_is_wireless (dev))
		level = nm_get_wireless_driver_support_level (ctx, dev, &driver);
	else if (nm_device_is_wired (dev))
		level = nm_get_wired_driver_support_level (ctx, dev, &driver);

	switch (level)
	{
		case NM_DRIVER_SEMI_SUPPORTED:
			syslog (LOG_INFO, "%s: Driver support level for '%s' is semi-supported",
						nm_device_get_iface (dev), driver);
			break;
		case NM_DRIVER_FULLY_SUPPORTED:
			syslog (LOG_INFO, "%s: Driver support level for '%s' is fully-supported",
						nm_device_get_iface (dev), driver);
			break;
		default:
			syslog (LOG_INFO, "%s: Driver support level for '%s' is unsupported",
						nm_device_get_iface (dev), driver);
			break;
	}

	g_free (driver);
	return (level);
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
		va_list args)
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

#if 0
#define NM_SLEEP_DEBUG
#endif
#ifdef NM_SLEEP_DEBUG
		syslog (LOG_INFO, "sleeping or %d usecs", interval_usecs);
#endif
		g_usleep(interval_usecs);
		if (action_func)
			finished = (*action_func)(try, args);
	}
}

void nm_wait_for_completion_or_timeout(
	const int max_tries,
	const struct timeval *max_time,
	const guint interval_usecs,
	nm_completion_func test_func,
	nm_completion_func action_func,
	...)
{
	va_list ap;
	va_start(ap, action_func);

	nm_v_wait_for_completion_or_timeout(max_tries, max_time,
					    interval_usecs, test_func,
					    action_func, ap);
	va_end(ap);
}

void nm_wait_for_completion(
		const int max_tries,
		const guint interval_usecs,
		nm_completion_func test_func,
		nm_completion_func action_func,
		...)
{
	va_list ap;
	va_start(ap, action_func);

	nm_v_wait_for_completion_or_timeout(max_tries, NULL,
					    interval_usecs, test_func,
					    action_func, ap);
	va_end(ap);
}

void nm_wait_for_timeout(
		const struct timeval *max_time,
		const guint interval_usecs,
		nm_completion_func test_func,
		nm_completion_func action_func,
		...)
{
	va_list ap;
	va_start(ap, action_func);

	nm_v_wait_for_completion_or_timeout(-1, max_time,
					    interval_usecs, test_func,
					    action_func, ap);
	va_end(ap);
}

/* you can use these, but they're really just examples */
gboolean nm_completion_boolean_test(int tries, va_list args)
{
	gboolean *condition = va_arg(args, gboolean *);
	char *message = va_arg(args, char *);
	int log_level = va_arg(args, int);
	int log_interval = va_arg(args, int);

	g_return_val_if_fail (condition != NULL, TRUE);

	if (message)
		if ((log_interval == 0 && tries == 0) || (log_interval != 0 && tries % log_interval == 0))
			syslog (log_level, message);

	if (*condition)
		return TRUE;
	return FALSE;
}

gboolean nm_completion_boolean_function1_test(int tries, va_list args)
{
	nm_completion_boolean_function_1 condition =
		va_arg(args, nm_completion_boolean_function_1);
	char *message = va_arg(args, char *);
	int log_level = va_arg(args, int);
	int log_interval = va_arg(args, int);
	u_int64_t arg0 = va_arg(args, unsigned long long);

	g_return_val_if_fail (condition, TRUE);

	if (message)
		if ((log_interval == 0 && tries == 0)
			   || (log_interval != 0 && tries % log_interval == 0))
			syslog(log_level, message);

	if (!(*condition)(arg0))
		return TRUE;
	return FALSE;
}

gboolean nm_completion_boolean_function2_test(int tries, va_list args)
{
	nm_completion_boolean_function_2 condition =
		va_arg(args, nm_completion_boolean_function_2);
	char *message = va_arg(args, char *);
	int log_level = va_arg(args, int);
	int log_interval = va_arg(args, int);
	u_int64_t arg0 = va_arg(args, unsigned long long);
	u_int64_t arg1 = va_arg(args, unsigned long long);

	g_return_val_if_fail (condition, TRUE);

	if (message)
		if ((log_interval == 0 && tries == 0)
			   || (log_interval != 0 && tries % log_interval == 0))
			syslog(log_level, message);

	if (!(*condition)(arg0, arg1))
		return TRUE;
	return FALSE;
}

