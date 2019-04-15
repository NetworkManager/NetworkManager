/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright 2004 - 2018 Red Hat, Inc.
 * Copyright 2005 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-core-utils.h"

#include <fcntl.h>
#include <fnmatch.h>
#include <unistd.h>
#include <stdlib.h>
#include <resolv.h>
#include <byteswap.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <linux/if.h>
#include <linux/if_infiniband.h>
#include <net/if_arp.h>
#include <net/ethernet.h>

#include "nm-std-aux/unaligned.h"
#include "nm-glib-aux/nm-random-utils.h"
#include "nm-glib-aux/nm-io-utils.h"
#include "nm-glib-aux/nm-secret-utils.h"
#include "nm-utils.h"
#include "nm-core-internal.h"
#include "nm-setting-connection.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wireless-security.h"

#ifdef __NM_SD_UTILS_H__
#error "nm-core-utils.c should stay independent of systemd utils. Are you looking for NetworkMangerUtils.c? "
#endif

G_STATIC_ASSERT (sizeof (NMUtilsTestFlags) <= sizeof (int));

/* we read _nm_utils_testing without memory barrier. This is thread-safe,
 * because the static variable is initialized to zero, and only reset
 * once to a non-zero value (via g_atomic_int_compare_and_exchange()).
 *
 * Since there is only one integer that contains the data, there is no
 * caching problem reading this (atomic int) variable without
 * synchronization/memory-barrier. Contrary to a double-checked locking,
 * where one needs a memory barrier to read the variable and ensure
 * that also the related data is coherent in cache. Here there is no
 * related data. */
static int _nm_utils_testing = 0;

gboolean
nm_utils_get_testing_initialized ()
{
	NMUtilsTestFlags flags;

	flags = (NMUtilsTestFlags) _nm_utils_testing;
	if (flags == NM_UTILS_TEST_NONE)
		flags = (NMUtilsTestFlags) g_atomic_int_get (&_nm_utils_testing);
	return flags != NM_UTILS_TEST_NONE;
}

NMUtilsTestFlags
nm_utils_get_testing ()
{
	NMUtilsTestFlags flags;

again:
	flags = (NMUtilsTestFlags) _nm_utils_testing;
	if (flags != NM_UTILS_TEST_NONE) {
		/* Flags already initialized. Return them. */
		return flags & NM_UTILS_TEST_ALL;
	}

	/* Accessing nm_utils_get_testing() causes us to set the flags to initialized.
	 * Detecting running tests also based on g_test_initialized(). */
	flags = _NM_UTILS_TEST_INITIALIZED;
	if (g_test_initialized ())
		flags |= _NM_UTILS_TEST_GENERAL;

	g_atomic_int_compare_and_exchange (&_nm_utils_testing, 0, (int) flags);

	/* regardless of whether we won the race of initializing _nm_utils_testing,
	 * go back and read the value again. It must be non-zero by now. */
	goto again;
}

void
_nm_utils_set_testing (NMUtilsTestFlags flags)
{
	g_assert (!NM_FLAGS_ANY (flags, ~NM_UTILS_TEST_ALL));

	/* mask out everything except ALL, and always set GENERAL. */
	flags = (flags & NM_UTILS_TEST_ALL) | (_NM_UTILS_TEST_GENERAL | _NM_UTILS_TEST_INITIALIZED);

	if (!g_atomic_int_compare_and_exchange (&_nm_utils_testing, 0, (int) flags)) {
		/* We only allow setting _nm_utils_set_testing() once, before fetching the
		 * value with nm_utils_get_testing(). */
		g_return_if_reached ();
	}
}

/*****************************************************************************/

static GSList *_singletons = NULL;
static gboolean _singletons_shutdown = FALSE;

static void
_nm_singleton_instance_weak_cb (gpointer data,
                                GObject *where_the_object_was)
{
	_singletons = g_slist_remove (_singletons, where_the_object_was);
}

static void __attribute__((destructor))
_nm_singleton_instance_destroy (void)
{
	_singletons_shutdown = TRUE;

	while (_singletons) {
		GObject *instance = _singletons->data;

		_singletons = g_slist_delete_link (_singletons, _singletons);

		g_object_weak_unref (instance, _nm_singleton_instance_weak_cb, NULL);

		if (instance->ref_count > 1)
			nm_log_dbg (LOGD_CORE, "disown %s singleton (%p)", G_OBJECT_TYPE_NAME (instance), instance);

		g_object_unref (instance);
	}
}

void
_nm_singleton_instance_register_destruction (GObject *instance)
{
	g_return_if_fail (G_IS_OBJECT (instance));

	/* Don't allow registration after shutdown. We only destroy the singletons
	 * once. */
	g_return_if_fail (!_singletons_shutdown);

	g_object_weak_ref (instance, _nm_singleton_instance_weak_cb, NULL);

	_singletons = g_slist_prepend (_singletons, instance);
}

/*****************************************************************************/

static double
_exp10 (guint16 ex)
{
	double v;

	if (ex == 0)
		return 1.0;

	v = _exp10 (ex / 2);
	v = v * v;
	if (ex % 2)
		v *= 10;
	return v;
}

/*
 * nm_utils_exp10:
 * @ex: the exponent
 *
 * Returns: 10^ex, or pow(10, ex), or exp10(ex).
 */
double
nm_utils_exp10 (gint16 ex)
{
	if (ex >= 0)
		return _exp10 (ex);
	return 1.0 / _exp10 (- ((gint32) ex));
}

/*****************************************************************************/

/*
 * nm_ethernet_address_is_valid:
 * @addr: pointer to a binary or ASCII Ethernet address
 * @len: length of @addr, or -1 if @addr is ASCII
 *
 * Compares an Ethernet address against known invalid addresses.

 * Returns: %TRUE if @addr is a valid Ethernet address, %FALSE if it is not.
 */
gboolean
nm_ethernet_address_is_valid (gconstpointer addr, gssize len)
{
	guint8 invalid_addr[4][ETH_ALEN] = {
	    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
	    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	    {0x44, 0x44, 0x44, 0x44, 0x44, 0x44},
	    {0x00, 0x30, 0xb4, 0x00, 0x00, 0x00}, /* prism54 dummy MAC */
	};
	guint8 addr_bin[ETH_ALEN];
	guint i;

	if (!addr) {
		g_return_val_if_fail (len == -1 || len == ETH_ALEN, FALSE);
		return FALSE;
	}

	if (len == -1) {
		if (!nm_utils_hwaddr_aton (addr, addr_bin, ETH_ALEN))
			return FALSE;
		addr = addr_bin;
	} else if (len != ETH_ALEN)
		g_return_val_if_reached (FALSE);

	/* Check for multicast address */
	if ((((guint8 *) addr)[0]) & 0x01)
		return FALSE;

	for (i = 0; i < G_N_ELEMENTS (invalid_addr); i++) {
		if (nm_utils_hwaddr_matches (addr, ETH_ALEN, invalid_addr[i], ETH_ALEN))
			return FALSE;
	}

	return TRUE;
}

gconstpointer
nm_utils_ipx_address_clear_host_address (int family, gpointer dst, gconstpointer src, guint8 plen)
{
	g_return_val_if_fail (dst, NULL);

	switch (family) {
	case AF_INET:
		g_return_val_if_fail (plen <= 32, NULL);

		if (!src) {
			/* allow "self-assignment", by specifying %NULL as source. */
			src = dst;
		}

		*((guint32 *) dst) = nm_utils_ip4_address_clear_host_address (*((guint32 *) src), plen);
		break;
	case AF_INET6:
		nm_utils_ip6_address_clear_host_address (dst, src, plen);
		break;
	default:
		g_return_val_if_reached (NULL);
	}
	return dst;
}

/* nm_utils_ip4_address_clear_host_address:
 * @addr: source ip6 address
 * @plen: prefix length of network
 *
 * returns: the input address, with the host address set to 0.
 */
in_addr_t
nm_utils_ip4_address_clear_host_address (in_addr_t addr, guint8 plen)
{
	return addr & _nm_utils_ip4_prefix_to_netmask (plen);
}

/* nm_utils_ip6_address_clear_host_address:
 * @dst: destination output buffer, will contain the network part of the @src address
 * @src: source ip6 address
 * @plen: prefix length of network
 *
 * Note: this function is self assignment safe, to update @src inplace, set both
 * @dst and @src to the same destination or set @src NULL.
 */
const struct in6_addr *
nm_utils_ip6_address_clear_host_address (struct in6_addr *dst, const struct in6_addr *src, guint8 plen)
{
	g_return_val_if_fail (plen <= 128, NULL);
	g_return_val_if_fail (dst, NULL);

	if (!src)
		src = dst;

	if (plen < 128) {
		guint nbytes = plen / 8;
		guint nbits = plen % 8;

		if (nbytes && dst != src)
			memcpy (dst, src, nbytes);
		if (nbits) {
			dst->s6_addr[nbytes] = (src->s6_addr[nbytes] & (0xFF << (8 - nbits)));
			nbytes++;
		}
		if (nbytes <= 15)
			memset (&dst->s6_addr[nbytes], 0, 16 - nbytes);
	} else if (src != dst)
		*dst = *src;

	return dst;
}

int
nm_utils_ip6_address_same_prefix_cmp (const struct in6_addr *addr_a, const struct in6_addr *addr_b, guint8 plen)
{
	int nbytes;
	guint8 va, vb, m;

	if (plen >= 128)
		NM_CMP_DIRECT_MEMCMP (addr_a, addr_b, sizeof (struct in6_addr));
	else {
		nbytes = plen / 8;
		if (nbytes)
			NM_CMP_DIRECT_MEMCMP (addr_a, addr_b, nbytes);

		plen = plen % 8;
		if (plen != 0) {
			m = ~((1 << (8 - plen)) - 1);
			va = ((((const guint8 *) addr_a))[nbytes]) & m;
			vb = ((((const guint8 *) addr_b))[nbytes]) & m;
			NM_CMP_DIRECT (va, vb);
		}
	}
	return 0;
}

/*****************************************************************************/

void
nm_utils_array_remove_at_indexes (GArray *array, const guint *indexes_to_delete, gsize len)
{
	gsize elt_size;
	guint index_to_delete;
	guint i_src;
	guint mm_src, mm_dst, mm_len;
	gsize i_itd;
	guint res_length;

	g_return_if_fail (array);
	if (!len)
		return;
	g_return_if_fail (indexes_to_delete);

	elt_size = g_array_get_element_size (array);

	i_itd = 0;
	index_to_delete = indexes_to_delete[0];
	if (index_to_delete >= array->len)
		g_return_if_reached ();

	res_length = array->len - 1;

	mm_dst = index_to_delete;
	mm_src = index_to_delete;
	mm_len = 0;

	for (i_src = index_to_delete; i_src < array->len; i_src++) {
		if (i_src < index_to_delete)
			mm_len++;
		else {
			/* we require indexes_to_delete to contain non-repeated, ascending
			 * indexes. Otherwise we would need to presort the indexes. */
			while (TRUE) {
				guint dd;

				if (i_itd + 1 >= len) {
					index_to_delete = G_MAXUINT;
					break;
				}

				dd = indexes_to_delete[++i_itd];
				if (dd > index_to_delete) {
					if (dd >= array->len)
						g_warn_if_reached ();
					else {
						g_assert (res_length > 0);
						res_length--;
					}
					index_to_delete = dd;
					break;
				}
				g_warn_if_reached ();
			}

			if (mm_len) {
				memmove (&array->data[mm_dst * elt_size],
				         &array->data[mm_src * elt_size],
				         mm_len * elt_size);
				mm_dst += mm_len;
				mm_src += mm_len + 1;
				mm_len = 0;
			} else
				mm_src++;
		}
	}
	if (mm_len) {
		memmove (&array->data[mm_dst * elt_size],
		         &array->data[mm_src * elt_size],
		         mm_len * elt_size);
	}
	g_array_set_size (array, res_length);
}

static const char *
_trunk_first_line (char *str)
{
	char *s;

	s = strchr (str, '\n');
	if (s)
		s[0] = '\0';
	return str;
}

int
nm_utils_modprobe (GError **error, gboolean suppress_error_logging, const char *arg1, ...)
{
	gs_unref_ptrarray GPtrArray *argv = NULL;
	int exit_status;
	gs_free char *_log_str = NULL;
#define ARGV_TO_STR(argv)   (_log_str ? _log_str : (_log_str = g_strjoinv (" ", (char **) argv->pdata)))
	GError *local = NULL;
	va_list ap;
	NMLogLevel llevel = suppress_error_logging ? LOGL_DEBUG : LOGL_ERR;
	gs_free char *std_out = NULL, *std_err = NULL;

	g_return_val_if_fail (!error || !*error, -1);
	g_return_val_if_fail (arg1, -1);

	/* construct the argument list */
	argv = g_ptr_array_sized_new (4);
	g_ptr_array_add (argv, "/sbin/modprobe");
	g_ptr_array_add (argv, "--use-blacklist");
	g_ptr_array_add (argv, (char *) arg1);

	va_start (ap, arg1);
	while ((arg1 = va_arg (ap, const char *)))
		g_ptr_array_add (argv, (char *) arg1);
	va_end (ap);

	g_ptr_array_add (argv, NULL);

	nm_log_dbg (LOGD_CORE, "modprobe: '%s'", ARGV_TO_STR (argv));
	if (!g_spawn_sync (NULL, (char **) argv->pdata, NULL, 0, NULL, NULL, &std_out, &std_err, &exit_status, &local)) {
		nm_log (llevel, LOGD_CORE, NULL, NULL, "modprobe: '%s' failed: %s", ARGV_TO_STR (argv), local->message);
		g_propagate_error (error, local);
		return -1;
	} else if (exit_status != 0) {
		nm_log (llevel, LOGD_CORE, NULL, NULL, "modprobe: '%s' exited with error %d%s%s%s%s%s%s", ARGV_TO_STR (argv), exit_status,
		        std_out&&*std_out ? " (" : "", std_out&&*std_out ? _trunk_first_line (std_out) : "", std_out&&*std_out ? ")" : "",
		        std_err&&*std_err ? " (" : "", std_err&&*std_err ? _trunk_first_line (std_err) : "", std_err&&*std_err ? ")" : "");
	}

	return exit_status;
}

/*****************************************************************************/

typedef struct {
	pid_t pid;
	NMLogDomain log_domain;
	union {
		struct {
			gint64 wait_start_us;
			guint source_timeout_kill_id;
		} async;
		struct {
			gboolean success;
			int child_status;
		} sync;
	};
	NMUtilsKillChildAsyncCb callback;
	void *user_data;

	char log_name[1]; /* variable-length object, must be last element!! */
} KillChildAsyncData;

#define LOG_NAME_FMT "kill child process '%s' (%ld)"
#define LOG_NAME_PROCESS_FMT "kill process '%s' (%ld)"
#define LOG_NAME_ARGS log_name,(long)pid

static KillChildAsyncData *
_kc_async_data_alloc (pid_t pid, NMLogDomain log_domain, const char *log_name, NMUtilsKillChildAsyncCb callback, void *user_data)
{
	KillChildAsyncData *data;
	size_t log_name_len;

	/* append the name at the end of our KillChildAsyncData. */
	log_name_len = strlen (LOG_NAME_FMT) + 20 + strlen (log_name);
	data = g_malloc (sizeof (KillChildAsyncData) - 1 + log_name_len);
	g_snprintf (data->log_name, log_name_len, LOG_NAME_FMT, LOG_NAME_ARGS);

	data->pid = pid;
	data->user_data = user_data;
	data->callback = callback;
	data->log_domain = log_domain;

	return data;
}

#define KC_EXIT_TO_STRING_BUF_SIZE 128
static const char *
_kc_exit_to_string (char *buf, int exit)
#define _kc_exit_to_string(buf, exit) ( G_STATIC_ASSERT_EXPR(sizeof (buf) == KC_EXIT_TO_STRING_BUF_SIZE && sizeof ((buf)[0]) == 1), _kc_exit_to_string (buf, exit) )
{
	if (WIFEXITED (exit))
		g_snprintf (buf, KC_EXIT_TO_STRING_BUF_SIZE, "normally with status %d", WEXITSTATUS (exit));
	else if (WIFSIGNALED (exit))
		g_snprintf (buf, KC_EXIT_TO_STRING_BUF_SIZE, "by signal %d", WTERMSIG (exit));
	else
		g_snprintf (buf, KC_EXIT_TO_STRING_BUF_SIZE, "with unexpected status %d", exit);
	return buf;
}

static const char *
_kc_signal_to_string (int sig)
{
	switch (sig) {
	case 0:  return "no signal (0)";
	case SIGKILL:  return "SIGKILL (" G_STRINGIFY (SIGKILL) ")";
	case SIGTERM:  return "SIGTERM (" G_STRINGIFY (SIGTERM) ")";
	default:
		return "Unexpected signal";
	}
}

#define KC_WAITED_TO_STRING 100
static const char *
_kc_waited_to_string (char *buf, gint64 wait_start_us)
#define _kc_waited_to_string(buf, wait_start_us) ( G_STATIC_ASSERT_EXPR(sizeof (buf) == KC_WAITED_TO_STRING && sizeof ((buf)[0]) == 1), _kc_waited_to_string (buf, wait_start_us) )
{
	g_snprintf (buf, KC_WAITED_TO_STRING, " (%ld usec elapsed)", (long) (nm_utils_get_monotonic_timestamp_us () - wait_start_us));
	return buf;
}

static void
_kc_cb_watch_child (GPid pid, int status, gpointer user_data)
{
	KillChildAsyncData *data = user_data;
	char buf_exit[KC_EXIT_TO_STRING_BUF_SIZE], buf_wait[KC_WAITED_TO_STRING];

	if (data->async.source_timeout_kill_id)
		g_source_remove (data->async.source_timeout_kill_id);

	nm_log_dbg (data->log_domain, "%s: terminated %s%s",
	            data->log_name, _kc_exit_to_string (buf_exit, status),
	            _kc_waited_to_string (buf_wait, data->async.wait_start_us));

	if (data->callback)
		data->callback (pid, TRUE, status, data->user_data);

	g_free (data);
}

static gboolean
_kc_cb_timeout_grace_period (void *user_data)
{
	KillChildAsyncData *data = user_data;
	int ret, errsv;

	data->async.source_timeout_kill_id = 0;

	if ((ret = kill (data->pid, SIGKILL)) != 0) {
		errsv = errno;
		/* ESRCH means, process does not exist or is already a zombie. */
		if (errsv != ESRCH) {
			nm_log_err (LOGD_CORE | data->log_domain, "%s: kill(SIGKILL) returned unexpected return value %d: (%s, %d)",
			            data->log_name, ret, nm_strerror_native (errsv), errsv);
		}
	} else {
		nm_log_dbg (data->log_domain, "%s: process not terminated after %ld usec. Sending SIGKILL signal",
		            data->log_name, (long) (nm_utils_get_monotonic_timestamp_us () - data->async.wait_start_us));
	}

	return G_SOURCE_REMOVE;
}

static gboolean
_kc_invoke_callback_idle (gpointer user_data)
{
	KillChildAsyncData *data = user_data;

	if (data->sync.success) {
		char buf_exit[KC_EXIT_TO_STRING_BUF_SIZE];

		nm_log_dbg (data->log_domain, "%s: invoke callback: terminated %s",
		            data->log_name, _kc_exit_to_string (buf_exit, data->sync.child_status));
	} else
		nm_log_dbg (data->log_domain, "%s: invoke callback: killing child failed", data->log_name);

	data->callback (data->pid, data->sync.success, data->sync.child_status, data->user_data);
	g_free (data);

	return G_SOURCE_REMOVE;
}

static void
_kc_invoke_callback (pid_t pid, NMLogDomain log_domain, const char *log_name, NMUtilsKillChildAsyncCb callback, void *user_data, gboolean success, int child_status)
{
	KillChildAsyncData *data;

	if (!callback)
		return;

	data = _kc_async_data_alloc (pid, log_domain, log_name, callback, user_data);
	data->sync.success = success;
	data->sync.child_status = child_status;

	g_idle_add (_kc_invoke_callback_idle, data);
}

/* nm_utils_kill_child_async:
 * @pid: the process id of the process to kill
 * @sig: signal to send initially. Set to 0 to send not signal.
 * @log_domain: the logging domain used for logging (LOGD_NONE to suppress logging)
 * @log_name: for logging, the name of the processes to kill
 * @wait_before_kill_msec: Waittime in milliseconds before sending %SIGKILL signal. Set this value
 * to zero, not to send %SIGKILL. If @sig is already %SIGKILL, this parameter is ignored.
 * @callback: (allow-none): callback after the child terminated. This function will always
 *   be invoked asynchronously.
 * @user_data: passed on to callback
 *
 * Uses g_child_watch_add(), so note the glib comment: if you obtain pid from g_spawn_async() or
 * g_spawn_async_with_pipes() you will need to pass %G_SPAWN_DO_NOT_REAP_CHILD as flag to the spawn
 * function for the child watching to work.
 * Also note, that you must g_source_remove() any other child watchers for @pid because glib
 * supports only one watcher per child.
 **/
void
nm_utils_kill_child_async (pid_t pid, int sig, NMLogDomain log_domain,
                           const char *log_name, guint32 wait_before_kill_msec,
                           NMUtilsKillChildAsyncCb callback, void *user_data)
{
	int status = 0, errsv;
	pid_t ret;
	KillChildAsyncData *data;
	char buf_exit[KC_EXIT_TO_STRING_BUF_SIZE];

	g_return_if_fail (pid > 0);
	g_return_if_fail (log_name != NULL);

	/* let's see if the child already terminated... */
	ret = waitpid (pid, &status, WNOHANG);
	if (ret > 0) {
		nm_log_dbg (log_domain, LOG_NAME_FMT ": process %ld already terminated %s",
		            LOG_NAME_ARGS, (long) ret, _kc_exit_to_string (buf_exit, status));
		_kc_invoke_callback (pid, log_domain, log_name, callback, user_data, TRUE, status);
		return;
	} else if (ret != 0) {
		errsv = errno;
		/* ECHILD means, the process is not a child/does not exist or it has SIGCHILD blocked. */
		if (errsv != ECHILD) {
			nm_log_err (LOGD_CORE | log_domain, LOG_NAME_FMT ": unexpected error while waitpid: %s (%d)",
			            LOG_NAME_ARGS, nm_strerror_native (errsv), errsv);
			_kc_invoke_callback (pid, log_domain, log_name, callback, user_data, FALSE, -1);
			return;
		}
	}

	/* send the first signal. */
	if (kill (pid, sig) != 0) {
		errsv = errno;
		/* ESRCH means, process does not exist or is already a zombie. */
		if (errsv != ESRCH) {
			nm_log_err (LOGD_CORE | log_domain, LOG_NAME_FMT ": unexpected error sending %s: %s (%d)",
			            LOG_NAME_ARGS, _kc_signal_to_string (sig), nm_strerror_native (errsv), errsv);
			_kc_invoke_callback (pid, log_domain, log_name, callback, user_data, FALSE, -1);
			return;
		}

		/* let's try again with waitpid, probably there was a race... */
		ret = waitpid (pid, &status, 0);
		if (ret > 0) {
			nm_log_dbg (log_domain, LOG_NAME_FMT ": process %ld already terminated %s",
			            LOG_NAME_ARGS, (long) ret, _kc_exit_to_string (buf_exit, status));
			_kc_invoke_callback (pid, log_domain, log_name, callback, user_data, TRUE, status);
		} else {
			errsv = errno;
			nm_log_err (LOGD_CORE | log_domain, LOG_NAME_FMT ": failed due to unexpected return value %ld by waitpid (%s, %d) after sending %s",
			            LOG_NAME_ARGS, (long) ret, nm_strerror_native (errsv), errsv, _kc_signal_to_string (sig));
			_kc_invoke_callback (pid, log_domain, log_name, callback, user_data, FALSE, -1);
		}
		return;
	}

	data = _kc_async_data_alloc (pid, log_domain, log_name, callback, user_data);
	data->async.wait_start_us = nm_utils_get_monotonic_timestamp_us ();

	if (sig != SIGKILL && wait_before_kill_msec > 0) {
		data->async.source_timeout_kill_id = g_timeout_add (wait_before_kill_msec, _kc_cb_timeout_grace_period, data);
		nm_log_dbg (log_domain, "%s: wait for process to terminate after sending %s (send SIGKILL in %ld milliseconds)...",
		            data->log_name,  _kc_signal_to_string (sig), (long) wait_before_kill_msec);
	} else {
		data->async.source_timeout_kill_id = 0;
		nm_log_dbg (log_domain, "%s: wait for process to terminate after sending %s...",
		            data->log_name, _kc_signal_to_string (sig));
	}

	g_child_watch_add (pid, _kc_cb_watch_child, data);
}

static gulong
_sleep_duration_convert_ms_to_us (guint32 sleep_duration_msec)
{
	if (sleep_duration_msec > 0) {
		guint64 x = (gint64) sleep_duration_msec * (guint64) 1000L;

		return x < G_MAXULONG ? (gulong) x : G_MAXULONG;
	}
	return G_USEC_PER_SEC / 20;
}

/* nm_utils_kill_child_sync:
 * @pid: process id to kill
 * @sig: signal to sent initially. If 0, no signal is sent. If %SIGKILL, the
 * second %SIGKILL signal is not sent after @wait_before_kill_msec milliseconds.
 * @log_domain: log debug information for this domain. Errors and warnings are logged both
 * as %LOGD_CORE and @log_domain.
 * @log_name: name of the process to kill for logging.
 * @child_status: (out) (allow-none): return the exit status of the child, if no error occurred.
 * @wait_before_kill_msec: Waittime in milliseconds before sending %SIGKILL signal. Set this value
 * to zero, not to send %SIGKILL. If @sig is already %SIGKILL, this parameter has not effect.
 * @sleep_duration_msec: the synchronous function sleeps repeatedly waiting for the child to terminate.
 * Set to zero, to use the default (meaning 20 wakeups per seconds).
 *
 * Kill a child process synchronously and wait. The function first checks if the child already terminated
 * and if it did, return the exit status. Otherwise send one @sig signal. @sig  will always be
 * sent unless the child already exited. If the child does not exit within @wait_before_kill_msec milliseconds,
 * the function will send %SIGKILL and waits for the child indefinitely. If @wait_before_kill_msec is zero, no
 * %SIGKILL signal will be sent.
 *
 * In case of error, errno is preserved to contain the last reason of failure.
 **/
gboolean
nm_utils_kill_child_sync (pid_t pid, int sig, NMLogDomain log_domain, const char *log_name,
                          int *child_status, guint32 wait_before_kill_msec,
                          guint32 sleep_duration_msec)
{
	int status = 0, errsv = 0;
	pid_t ret;
	gboolean success = FALSE;
	gboolean was_waiting = FALSE, send_kill = FALSE;
	char buf_exit[KC_EXIT_TO_STRING_BUF_SIZE];
	char buf_wait[KC_WAITED_TO_STRING];
	gint64 wait_start_us;

	g_return_val_if_fail (pid > 0, FALSE);
	g_return_val_if_fail (log_name != NULL, FALSE);

	/* check if the child process already terminated... */
	ret = waitpid (pid, &status, WNOHANG);
	if (ret > 0) {
		nm_log_dbg (log_domain, LOG_NAME_FMT ": process %ld already terminated %s",
		            LOG_NAME_ARGS, (long) ret, _kc_exit_to_string (buf_exit, status));
		success = TRUE;
		goto out;
	} else if (ret != 0) {
		errsv = errno;
		/* ECHILD means, the process is not a child/does not exist or it has SIGCHILD blocked. */
		if (errsv != ECHILD) {
			nm_log_err (LOGD_CORE | log_domain, LOG_NAME_FMT ": unexpected error while waitpid: %s (%d)",
			            LOG_NAME_ARGS, nm_strerror_native (errsv), errsv);
			goto out;
		}
	}

	/* send first signal @sig */
	if (kill (pid, sig) != 0) {
		errsv = errno;
		/* ESRCH means, process does not exist or is already a zombie. */
		if (errsv != ESRCH) {
			nm_log_err (LOGD_CORE | log_domain, LOG_NAME_FMT ": failed to send %s: %s (%d)",
			            LOG_NAME_ARGS, _kc_signal_to_string (sig), nm_strerror_native (errsv), errsv);
		} else {
			/* let's try again with waitpid, probably there was a race... */
			ret = waitpid (pid, &status, 0);
			if (ret > 0) {
				nm_log_dbg (log_domain, LOG_NAME_FMT ": process %ld already terminated %s",
				            LOG_NAME_ARGS, (long) ret, _kc_exit_to_string (buf_exit, status));
				success = TRUE;
			} else {
				errsv = errno;
				nm_log_err (LOGD_CORE | log_domain, LOG_NAME_FMT ": failed due to unexpected return value %ld by waitpid (%s, %d) after sending %s",
				            LOG_NAME_ARGS, (long) ret, nm_strerror_native (errsv), errsv, _kc_signal_to_string (sig));
			}
		}
		goto out;
	}

	wait_start_us = nm_utils_get_monotonic_timestamp_us ();

	/* wait for the process to terminated... */
	if (sig != SIGKILL) {
		gint64 wait_until, now;
		gulong sleep_time, sleep_duration_usec;
		int loop_count = 0;

		sleep_duration_usec = _sleep_duration_convert_ms_to_us (sleep_duration_msec);
		wait_until = wait_before_kill_msec <= 0 ? 0 : wait_start_us + (((gint64) wait_before_kill_msec) * 1000L);

		while (TRUE) {
			ret = waitpid (pid, &status, WNOHANG);
			if (ret > 0) {
				nm_log_dbg (log_domain, LOG_NAME_FMT ": after sending %s, process %ld exited %s%s",
				            LOG_NAME_ARGS, _kc_signal_to_string (sig), (long) ret, _kc_exit_to_string (buf_exit, status),
				            was_waiting ? _kc_waited_to_string (buf_wait, wait_start_us) : "");
				success = TRUE;
				goto out;
			}
			if (ret == -1) {
				errsv = errno;
				/* ECHILD means, the process is not a child/does not exist or it has SIGCHILD blocked. */
				if (errsv != ECHILD) {
					nm_log_err (LOGD_CORE | log_domain, LOG_NAME_FMT ": after sending %s, waitpid failed with %s (%d)%s",
					            LOG_NAME_ARGS, _kc_signal_to_string (sig), nm_strerror_native (errsv), errsv,
					           was_waiting ? _kc_waited_to_string (buf_wait, wait_start_us) : "");
					goto out;
				}
			}

			if (!wait_until)
				break;

			now = nm_utils_get_monotonic_timestamp_us ();
			if (now >= wait_until)
				break;

			if (!was_waiting) {
				nm_log_dbg (log_domain, LOG_NAME_FMT ": waiting up to %ld milliseconds for process to terminate normally after sending %s...",
				            LOG_NAME_ARGS, (long) MAX (wait_before_kill_msec, 0), _kc_signal_to_string (sig));
				was_waiting = TRUE;
			}

			sleep_time = MIN (wait_until - now, sleep_duration_usec);
			if (loop_count < 20) {
				/* At the beginning we expect the process to die fast.
				 * Limit the sleep time, the limit doubles with every iteration. */
				sleep_time = MIN (sleep_time, (((guint64) 1) << loop_count) * G_USEC_PER_SEC / 2000);
				loop_count++;
			}
			g_usleep (sleep_time);
		}

		/* send SIGKILL, if called with @wait_before_kill_msec > 0 */
		if (wait_until) {
			nm_log_dbg (log_domain, LOG_NAME_FMT ": sending SIGKILL...", LOG_NAME_ARGS);

			send_kill = TRUE;
			if (kill (pid, SIGKILL) != 0) {
				errsv = errno;
				/* ESRCH means, process does not exist or is already a zombie. */
				if (errsv != ESRCH) {
					nm_log_err (LOGD_CORE | log_domain, LOG_NAME_FMT ": failed to send SIGKILL (after sending %s), %s (%d)",
								LOG_NAME_ARGS, _kc_signal_to_string (sig), nm_strerror_native (errsv), errsv);
					goto out;
				}
			}
		}
	}

	if (!was_waiting) {
		nm_log_dbg (log_domain, LOG_NAME_FMT ": waiting for process to terminate after sending %s%s...",
		            LOG_NAME_ARGS, _kc_signal_to_string (sig), send_kill ? " and SIGKILL" : "");
	}

	/* block until the child terminates. */
	while ((ret = waitpid (pid, &status, 0)) <= 0) {
		errsv = errno;

		if (errsv != EINTR) {
			nm_log_err (LOGD_CORE | log_domain, LOG_NAME_FMT ": after sending %s%s, waitpid failed with %s (%d)%s",
			            LOG_NAME_ARGS, _kc_signal_to_string (sig), send_kill ? " and SIGKILL" : "", nm_strerror_native (errsv), errsv,
			            _kc_waited_to_string (buf_wait, wait_start_us));
			goto out;
		}
	}

	nm_log_dbg (log_domain, LOG_NAME_FMT ": after sending %s%s, process %ld exited %s%s",
	            LOG_NAME_ARGS, _kc_signal_to_string (sig), send_kill ? " and SIGKILL" : "", (long) ret,
	            _kc_exit_to_string (buf_exit, status), _kc_waited_to_string (buf_wait, wait_start_us));
	success = TRUE;
out:
	if (child_status)
		*child_status = success ? status : -1;
	errno = success ? 0 : errsv;
	return success;
}

/* nm_utils_kill_process_sync:
 * @pid: process id to kill
 * @start_time: the start time of the process to kill (as obtained by nm_utils_get_start_time_for_pid()).
 *   This is an optional argument, to avoid (somewhat) killing the wrong process as @pid
 *   might get recycled. You can pass 0, to not provide this parameter.
 * @sig: signal to sent initially. If 0, no signal is sent. If %SIGKILL, the
 *   second %SIGKILL signal is not sent after @wait_before_kill_msec milliseconds.
 * @log_domain: log debug information for this domain. Errors and warnings are logged both
 *   as %LOGD_CORE and @log_domain.
 * @log_name: name of the process to kill for logging.
 * @wait_before_kill_msec: Waittime in milliseconds before sending %SIGKILL signal. Set this value
 *   to zero, not to send %SIGKILL. If @sig is already %SIGKILL, this parameter has no effect.
 *   If @max_wait_msec is set but less then @wait_before_kill_msec, the final %SIGKILL will also
 *   not be send.
 * @sleep_duration_msec: the synchronous function sleeps repeatedly waiting for the child to terminate.
 *   Set to zero, to use the default (meaning 20 wakeups per seconds).
 * @max_wait_msec: if 0, waits indefinitely until the process is gone (or a zombie). Otherwise, this
 *   is the maximum wait time until returning. If @max_wait_msec is non-zero but smaller then @wait_before_kill_msec,
 *   we will not send a final %SIGKILL.
 *
 * Kill a non-child process synchronously and wait. This function will not return before the
 * process with PID @pid is gone, the process is a zombie, or @max_wait_msec expires.
 **/
void
nm_utils_kill_process_sync (pid_t pid, guint64 start_time, int sig, NMLogDomain log_domain,
                            const char *log_name, guint32 wait_before_kill_msec,
                            guint32 sleep_duration_msec, guint32 max_wait_msec)
{
	int errsv;
	guint64 start_time0;
	gint64 wait_until_sigkill, now, wait_start_us, max_wait_until;
	gulong sleep_time, sleep_duration_usec;
	int loop_count = 0;
	gboolean was_waiting = FALSE;
	char buf_wait[KC_WAITED_TO_STRING];
	char p_state;

	g_return_if_fail (pid > 0);
	g_return_if_fail (log_name != NULL);

	start_time0 = nm_utils_get_start_time_for_pid (pid, &p_state, NULL);
	if (start_time0 == 0) {
		nm_log_dbg (log_domain, LOG_NAME_PROCESS_FMT ": cannot kill process %ld because it seems already gone",
		            LOG_NAME_ARGS, (long int) pid);
		return;
	}
	if (start_time != 0 && start_time != start_time0) {
		nm_log_dbg (log_domain, LOG_NAME_PROCESS_FMT ": don't kill process %ld because the start_time is unexpectedly %lu instead of %ld",
		            LOG_NAME_ARGS, (long int) pid, (unsigned long) start_time0, (unsigned long) start_time);
		return;
	}

	switch (p_state) {
	case 'Z':
	case 'x':
	case 'X':
		nm_log_dbg (log_domain, LOG_NAME_PROCESS_FMT ": cannot kill process %ld because it is already a zombie (%c)",
		            LOG_NAME_ARGS, (long int) pid, p_state);
		return;
	default:
		break;
	}

	if (kill (pid, sig) != 0) {
		errsv = errno;
		/* ESRCH means, process does not exist or is already a zombie. */
		if (errsv == ESRCH) {
			nm_log_dbg (log_domain, LOG_NAME_PROCESS_FMT ": failed to send %s because process seems gone",
			            LOG_NAME_ARGS, _kc_signal_to_string (sig));
		} else {
			nm_log_warn (LOGD_CORE | log_domain, LOG_NAME_PROCESS_FMT ": failed to send %s: %s (%d)",
			             LOG_NAME_ARGS, _kc_signal_to_string (sig), nm_strerror_native (errsv), errsv);
		}
		return;
	}

	/* wait for the process to terminate... */

	wait_start_us = nm_utils_get_monotonic_timestamp_us ();

	sleep_duration_usec = _sleep_duration_convert_ms_to_us (sleep_duration_msec);
	if (sig != SIGKILL && wait_before_kill_msec)
		wait_until_sigkill = wait_start_us + (((gint64) wait_before_kill_msec) * 1000L);
	else
		wait_until_sigkill = 0;
	if (max_wait_msec > 0) {
		max_wait_until = wait_start_us + (((gint64) max_wait_msec) * 1000L);
		if (wait_until_sigkill > 0 && wait_until_sigkill > max_wait_msec)
			wait_until_sigkill = 0;
	} else
		max_wait_until = 0;

	while (TRUE) {
		start_time = nm_utils_get_start_time_for_pid (pid, &p_state, NULL);

		if (start_time != start_time0) {
			nm_log_dbg (log_domain, LOG_NAME_PROCESS_FMT ": process is gone after sending signal %s%s",
			            LOG_NAME_ARGS, _kc_signal_to_string (sig),
			            was_waiting ? _kc_waited_to_string (buf_wait, wait_start_us) : "");
			return;
		}
		switch (p_state) {
		case 'Z':
		case 'x':
		case 'X':
			nm_log_dbg (log_domain, LOG_NAME_PROCESS_FMT ": process is a zombie (%c) after sending signal %s%s",
			            LOG_NAME_ARGS, p_state, _kc_signal_to_string (sig),
			            was_waiting ? _kc_waited_to_string (buf_wait, wait_start_us) : "");
			return;
		default:
			break;
		}

		if (kill (pid, 0) != 0) {
			errsv = errno;
			/* ESRCH means, process does not exist or is already a zombie. */
			if (errsv == ESRCH) {
				nm_log_dbg (log_domain, LOG_NAME_PROCESS_FMT ": process is gone or a zombie after sending signal %s%s",
				            LOG_NAME_ARGS, _kc_signal_to_string (sig),
				            was_waiting ? _kc_waited_to_string (buf_wait, wait_start_us) : "");
			} else {
				nm_log_warn (LOGD_CORE | log_domain, LOG_NAME_PROCESS_FMT ": failed to kill(%ld, 0): %s (%d)%s",
				             LOG_NAME_ARGS, (long int) pid, nm_strerror_native (errsv), errsv,
				             was_waiting ? _kc_waited_to_string (buf_wait, wait_start_us) : "");
			}
			return;
		}

		sleep_time = sleep_duration_usec;
		now = nm_utils_get_monotonic_timestamp_us ();

		if (   max_wait_until != 0
		    && now >= max_wait_until) {
			if (wait_until_sigkill != 0) {
				/* wait_before_kill_msec is not larger then max_wait_until but we did not yet send
				 * SIGKILL. Although we already reached our timeout, we don't want to skip sending
				 * the signal. Even if we don't wait for the process to disappear. */
				nm_log_dbg (log_domain, LOG_NAME_PROCESS_FMT ": sending SIGKILL", LOG_NAME_ARGS);
				kill (pid, SIGKILL);
			}
			nm_log_warn (log_domain, LOG_NAME_PROCESS_FMT ": timeout %u msec waiting for process to disappear (after sending %s)%s",
			             LOG_NAME_ARGS, (unsigned) max_wait_until, _kc_signal_to_string (sig),
			             was_waiting ? _kc_waited_to_string (buf_wait, wait_start_us) : "");
			return;
		}

		if (wait_until_sigkill != 0) {
			if (now >= wait_until_sigkill) {
				/* Still not dead. SIGKILL now... */
				nm_log_dbg (log_domain, LOG_NAME_PROCESS_FMT ": sending SIGKILL", LOG_NAME_ARGS);
				if (kill (pid, SIGKILL) != 0) {
					errsv = errno;
					/* ESRCH means, process does not exist or is already a zombie. */
					if (errsv != ESRCH) {
						nm_log_dbg (log_domain, LOG_NAME_PROCESS_FMT ": process is gone or a zombie%s",
						            LOG_NAME_ARGS, _kc_waited_to_string (buf_wait, wait_start_us));
					} else {
						nm_log_warn (LOGD_CORE | log_domain, LOG_NAME_PROCESS_FMT ": failed to send SIGKILL (after sending %s), %s (%d)%s",
						             LOG_NAME_ARGS, _kc_signal_to_string (sig), nm_strerror_native (errsv), errsv,
						             _kc_waited_to_string (buf_wait, wait_start_us));
					}
					return;
				}
				sig = SIGKILL;
				wait_until_sigkill = 0;
				loop_count = 0; /* reset the loop_count. Now we really expect the process to die quickly. */
			} else
				sleep_time = MIN (wait_until_sigkill - now, sleep_duration_usec);
		}

		if (!was_waiting) {
			if (wait_until_sigkill != 0) {
				nm_log_dbg (log_domain, LOG_NAME_PROCESS_FMT ": waiting up to %ld milliseconds for process to disappear before sending KILL signal after sending %s...",
				            LOG_NAME_ARGS, (long) wait_before_kill_msec, _kc_signal_to_string (sig));
			} else if (max_wait_until != 0) {
				nm_log_dbg (log_domain, LOG_NAME_PROCESS_FMT ": waiting up to %ld milliseconds for process to disappear after sending %s...",
				            LOG_NAME_ARGS, (long) max_wait_msec, _kc_signal_to_string (sig));
			} else {
				nm_log_dbg (log_domain, LOG_NAME_PROCESS_FMT ": waiting for process to disappear after sending %s...",
				            LOG_NAME_ARGS, _kc_signal_to_string (sig));
			}
			was_waiting = TRUE;
		}

		if (loop_count < 20) {
			/* At the beginning we expect the process to die fast.
			 * Limit the sleep time, the limit doubles with every iteration. */
			sleep_time = MIN (sleep_time, (((guint64) 1) << loop_count) * G_USEC_PER_SEC / 2000);
			loop_count++;
		}
		g_usleep (sleep_time);
	}
}
#undef LOG_NAME_FMT
#undef LOG_NAME_PROCESS_FMT
#undef LOG_NAME_ARGS

const char *const NM_PATHS_DEFAULT[] = {
	PREFIX "/sbin/",
	PREFIX "/bin/",
	"/usr/local/sbin/",
	"/sbin/",
	"/usr/sbin/",
	"/usr/local/bin/",
	"/bin/",
	"/usr/bin/",
	NULL,
};

const char *
nm_utils_find_helper(const char *progname, const char *try_first, GError **error)
{
	return nm_utils_file_search_in_paths (progname, try_first, NM_PATHS_DEFAULT, G_FILE_TEST_IS_EXECUTABLE, NULL, NULL, error);
}

/*****************************************************************************/

/**
 * nm_utils_read_link_absolute:
 * @link_file: file name of the symbolic link
 * @error: error reason in case of failure
 *
 * Uses to g_file_read_link()/readlink() to read the symlink
 * and returns the result as absolute path.
 **/
char *
nm_utils_read_link_absolute (const char *link_file, GError **error)
{
	char *ln, *dirname, *ln_abs;

	ln = g_file_read_link (link_file, error);
	if (!ln)
		return NULL;
	if (g_path_is_absolute (ln))
		return ln;

	dirname = g_path_get_dirname (link_file);
	if (!g_path_is_absolute (dirname)) {
		gs_free char *current_dir = g_get_current_dir ();

		/* @link_file argument was not an absolute path in the first place.
		 * That actually may be a bug, because the CWD is not well defined
		 * in most cases. Anyway, apparently we were able to load the file
		 * even from a relative path. So, when making the link absolute, we
		 * also need to prepend the CWD. */
		ln_abs = g_build_filename (current_dir, dirname, ln, NULL);
	} else
		ln_abs = g_build_filename (dirname, ln, NULL);
	g_free (dirname);
	g_free (ln);
	return ln_abs;
}

/*****************************************************************************/

#define MAC_TAG "mac:"
#define INTERFACE_NAME_TAG "interface-name:"
#define DEVICE_TYPE_TAG "type:"
#define DRIVER_TAG "driver:"
#define SUBCHAN_TAG "s390-subchannels:"
#define DHCP_PLUGIN_TAG "dhcp-plugin:"
#define EXCEPT_TAG "except:"
#define MATCH_TAG_CONFIG_NM_VERSION             "nm-version:"
#define MATCH_TAG_CONFIG_NM_VERSION_MIN         "nm-version-min:"
#define MATCH_TAG_CONFIG_NM_VERSION_MAX         "nm-version-max:"
#define MATCH_TAG_CONFIG_ENV                    "env:"

typedef struct {
	const char *interface_name;
	const char *device_type;
	const char *driver;
	const char *driver_version;
	const char *dhcp_plugin;
	struct {
		const char *value;
		gboolean is_parsed;
		guint len;
		guint8 bin[NM_UTILS_HWADDR_LEN_MAX];
	} hwaddr;
	struct {
		const char *value;
		gboolean is_parsed;
		guint32 a;
		guint32 b;
		guint32 c;
	} s390_subchannels;
} MatchDeviceData;

static gboolean
match_device_s390_subchannels_parse (const char *s390_subchannels, guint32 *out_a, guint32 *out_b, guint32 *out_c)
{
	char buf[30 + 1];
	const int BUFSIZE = G_N_ELEMENTS (buf) - 1;
	guint i = 0;
	char *pa = NULL, *pb = NULL, *pc = NULL;
	gint64 a, b, c;

	nm_assert (s390_subchannels);
	nm_assert (out_a);
	nm_assert (out_b);
	nm_assert (out_c);

	if (!g_ascii_isxdigit (s390_subchannels[0]))
		return FALSE;

	/* Get the first channel */
	for (i = 0; s390_subchannels[i]; i++) {
		char ch = s390_subchannels[i];

		if (!g_ascii_isxdigit (ch) && ch != '.') {
			if (ch == ',') {
				/* FIXME: currently we consider the first channel and ignore
				 * everything after the first ',' separator. Maybe we should
				 * validate all present channels? */
				break;
			}
			return FALSE;  /* Invalid chars */
		}
		if (i >= BUFSIZE)
			return FALSE;  /* Too long to be a subchannel */
		buf[i] = ch;
	}
	buf[i] = '\0';

	/* and grab each of its elements, there should be 3 */
	pa = &buf[0];
	pb = strchr (pa, '.');
	if (pb)
		pc = strchr (pb + 1, '.');
	if (!pb || !pc)
		return FALSE;
	*pb++ = '\0';
	*pc++ = '\0';

	a = _nm_utils_ascii_str_to_int64 (pa, 16, 0, G_MAXUINT32, -1);
	if (a == -1)
		return FALSE;
	b = _nm_utils_ascii_str_to_int64 (pb, 16, 0, G_MAXUINT32, -1);
	if (b == -1)
		return FALSE;
	c = _nm_utils_ascii_str_to_int64 (pc, 16, 0, G_MAXUINT32, -1);
	if (c == -1)
		return FALSE;

	*out_a = (guint32) a;
	*out_b = (guint32) b;
	*out_c = (guint32) c;
	return TRUE;
}

static gboolean
match_data_s390_subchannels_eval (const char *spec_str,
                                  MatchDeviceData *match_data)
{
	guint32 a, b, c;

	if (G_UNLIKELY (!match_data->s390_subchannels.is_parsed)) {
		match_data->s390_subchannels.is_parsed = TRUE;

		if (   !match_data->s390_subchannels.value
		    || !match_device_s390_subchannels_parse (match_data->s390_subchannels.value,
		                                             &match_data->s390_subchannels.a,
		                                             &match_data->s390_subchannels.b,
		                                             &match_data->s390_subchannels.c)) {
			match_data->s390_subchannels.value = NULL;
			return FALSE;
		}
	} else if (!match_data->s390_subchannels.value)
		return FALSE;

	if (!match_device_s390_subchannels_parse (spec_str, &a, &b, &c))
		return FALSE;
	return    match_data->s390_subchannels.a == a
	       && match_data->s390_subchannels.b == b
	       && match_data->s390_subchannels.c == c;
}

static gboolean
match_device_hwaddr_eval (const char *spec_str,
                          MatchDeviceData *match_data)
{
	if (G_UNLIKELY (!match_data->hwaddr.is_parsed)) {
		match_data->hwaddr.is_parsed = TRUE;

		if (match_data->hwaddr.value) {
			gsize l;

			if (!_nm_utils_hwaddr_aton (match_data->hwaddr.value, match_data->hwaddr.bin, sizeof (match_data->hwaddr.bin), &l))
				g_return_val_if_reached (FALSE);
			match_data->hwaddr.len = l;
		} else
			return FALSE;
	} else if (!match_data->hwaddr.len)
		return FALSE;

	return nm_utils_hwaddr_matches (spec_str, -1, match_data->hwaddr.bin, match_data->hwaddr.len);
}

#define _MATCH_CHECK(spec_str, tag) \
	({ \
		gboolean _has = FALSE; \
		\
		if (!g_ascii_strncasecmp (spec_str, (""tag""), NM_STRLEN (tag))) { \
			spec_str += NM_STRLEN (tag); \
			_has = TRUE; \
		} \
		_has; \
	})

static NMMatchSpecMatchType
_match_result (gboolean has_except,
               gboolean has_not_except,
               gboolean has_match,
               gboolean has_match_except)
{
	if (   has_except
	    && !has_not_except) {
		/* a match spec that only consists of a list of except matches is treated specially. */
		nm_assert (!has_match);
		if (has_match_except) {
			/* one of the "except:" matches matched. The result is an explicit
			 * negative match. */
			return NM_MATCH_SPEC_NEG_MATCH;
		} else {
			/* none of the "except:" matches matched. The result is a positive match,
			 * despite there being no positive match. */
			return NM_MATCH_SPEC_MATCH;
		}
	}

	if (has_match_except)
		return NM_MATCH_SPEC_NEG_MATCH;
	if (has_match)
		return NM_MATCH_SPEC_MATCH;
	return NM_MATCH_SPEC_NO_MATCH;
}

static const char *
match_except (const char *spec_str, gboolean *out_except)
{
	if (_MATCH_CHECK (spec_str, EXCEPT_TAG))
		*out_except = TRUE;
	else
		*out_except = FALSE;
	return spec_str;
}

static gboolean
match_device_eval (const char *spec_str,
                   gboolean allow_fuzzy,
                   MatchDeviceData *match_data)
{
	if (spec_str[0] == '*' && spec_str[1] == '\0')
		return TRUE;

	if (_MATCH_CHECK (spec_str, DEVICE_TYPE_TAG)) {
		return    match_data->device_type
		       && nm_streq (spec_str, match_data->device_type);
	}

	if (_MATCH_CHECK (spec_str, MAC_TAG))
		return match_device_hwaddr_eval (spec_str, match_data);

	if (_MATCH_CHECK (spec_str, INTERFACE_NAME_TAG)) {
		gboolean use_pattern = FALSE;

		if (spec_str[0] == '=')
			spec_str += 1;
		else {
			if (spec_str[0] == '~')
				spec_str += 1;
			use_pattern = TRUE;
		}

		if (match_data->interface_name) {
			if (nm_streq (spec_str, match_data->interface_name))
				return TRUE;
			if (use_pattern && g_pattern_match_simple (spec_str, match_data->interface_name))
				return TRUE;
		}
		return FALSE;
	}

	if (_MATCH_CHECK (spec_str, DRIVER_TAG)) {
		const char *t;

		if (!match_data->driver)
			return FALSE;

		/* support:
		 * 1) "${DRIVER}"
		 *   In this case, DRIVER may not contain a '/' character.
		 *   It matches any driver version.
		 * 2) "${DRIVER}/${DRIVER_VERSION}"
		 *   In this case, DRIVER may contains '/' but DRIVER_VERSION
		 *   may not. A '/' in DRIVER_VERSION may be replaced by '?'.
		 *
		 * It follows, that "${DRIVER}/""*" is like 1), but allows
		 * '/' inside DRIVER.
		 *
		 * The fields match to what `nmcli -f GENERAL.DRIVER,GENERAL.DRIVER-VERSION device show`
		 * gives. However, DRIVER matches literally, while DRIVER_VERSION is a glob
		 * supporting ? and *.
		 */

		t = strrchr (spec_str, '/');

		if (!t)
			return nm_streq (spec_str, match_data->driver);

		return    (strncmp (spec_str, match_data->driver, t - spec_str) == 0)
		       && g_pattern_match_simple (&t[1],
		                                  match_data->driver_version ?: "");
	}

	if (_MATCH_CHECK (spec_str, SUBCHAN_TAG))
		return match_data_s390_subchannels_eval (spec_str, match_data);

	if (_MATCH_CHECK (spec_str, DHCP_PLUGIN_TAG))
		return nm_streq0 (spec_str, match_data->dhcp_plugin);

	if (allow_fuzzy) {
		if (match_device_hwaddr_eval (spec_str, match_data))
			return TRUE;
		if (   match_data->interface_name
		    && nm_streq (spec_str, match_data->interface_name))
			return TRUE;
	}

	return FALSE;
}

NMMatchSpecMatchType
nm_match_spec_device (const GSList *specs,
                      const char *interface_name,
                      const char *device_type,
                      const char *driver,
                      const char *driver_version,
                      const char *hwaddr,
                      const char *s390_subchannels,
                      const char *dhcp_plugin)
{
	const GSList *iter;
	gboolean has_match = FALSE;
	gboolean has_match_except = FALSE;
	gboolean has_except = FALSE;
	gboolean has_not_except = FALSE;
	const char *spec_str;
	MatchDeviceData match_data = {
	    .interface_name = interface_name,
	    .device_type = nm_str_not_empty (device_type),
	    .driver = nm_str_not_empty (driver),
	    .driver_version = nm_str_not_empty (driver_version),
	    .dhcp_plugin = nm_str_not_empty (dhcp_plugin),
	    .hwaddr = {
	        .value = hwaddr,
	    },
	    .s390_subchannels = {
	        .value = s390_subchannels,
	    },
	};

	nm_assert (!hwaddr || nm_utils_hwaddr_valid (hwaddr, -1));

	if (!specs)
		return NM_MATCH_SPEC_NO_MATCH;

	for (iter = specs; iter; iter = iter->next) {
		gboolean except;

		spec_str = iter->data;

		if (!spec_str || !*spec_str)
			continue;

		spec_str = match_except (spec_str, &except);

		if (except)
			has_except = TRUE;
		else
			has_not_except = TRUE;

		if (   ( except && has_match_except)
		    || (!except && has_match)) {
			/* evaluating the match does not give new information. Skip it. */
			continue;
		}

		if (!match_device_eval (spec_str,
		                        !except,
		                        &match_data))
			continue;

		if (except)
			has_match_except = TRUE;
		else
			has_match = TRUE;
	}

	return _match_result (has_except, has_not_except, has_match, has_match_except);
}

static gboolean
match_config_eval (const char *str, const char *tag, guint cur_nm_version)
{
	gs_free char *s_ver = NULL;
	gs_strfreev char **s_ver_tokens = NULL;
	int v_maj = -1, v_min = -1, v_mic = -1;
	guint c_maj = -1, c_min = -1, c_mic = -1;
	guint n_tokens;

	s_ver = g_strdup (str);
	g_strstrip (s_ver);

	/* Let's be strict with the accepted format here. No funny stuff!! */

	if (s_ver[strspn (s_ver, ".0123456789")] != '\0')
		return FALSE;

	s_ver_tokens = g_strsplit (s_ver, ".", -1);
	n_tokens = g_strv_length (s_ver_tokens);
	if (n_tokens == 0 || n_tokens > 3)
		return FALSE;

	v_maj = _nm_utils_ascii_str_to_int64 (s_ver_tokens[0], 10, 0, 0xFFFF, -1);
	if (v_maj < 0)
		return FALSE;
	if (n_tokens >= 2) {
		v_min = _nm_utils_ascii_str_to_int64 (s_ver_tokens[1], 10, 0, 0xFF, -1);
		if (v_min < 0)
			return FALSE;
	}
	if (n_tokens >= 3) {
		v_mic = _nm_utils_ascii_str_to_int64 (s_ver_tokens[2], 10, 0, 0xFF, -1);
		if (v_mic < 0)
			return FALSE;
	}

	nm_decode_version (cur_nm_version, &c_maj, &c_min, &c_mic);

#define CHECK_AND_RETURN_FALSE(cur, val, tag, is_last_digit) \
	G_STMT_START { \
		if (!strcmp (tag, MATCH_TAG_CONFIG_NM_VERSION_MIN)) { \
			if (cur < val) \
				return FALSE; \
		} else if (!strcmp (tag, MATCH_TAG_CONFIG_NM_VERSION_MAX)) { \
			if (cur > val) \
				return FALSE; \
		} else { \
			if (cur != val) \
				return FALSE; \
		} \
		if (!(is_last_digit)) { \
			if (cur != val) \
				return FALSE; \
		} \
	} G_STMT_END
	if (v_mic >= 0)
		CHECK_AND_RETURN_FALSE (c_mic, v_mic, tag, TRUE);
	if (v_min >= 0)
		CHECK_AND_RETURN_FALSE (c_min, v_min, tag, v_mic < 0);
	CHECK_AND_RETURN_FALSE (c_maj, v_maj, tag, v_min < 0);
	return TRUE;
}

NMMatchSpecMatchType
nm_match_spec_config (const GSList *specs, guint cur_nm_version, const char *env)
{
	const GSList *iter;
	gboolean has_match = FALSE;
	gboolean has_match_except = FALSE;
	gboolean has_except = FALSE;
	gboolean has_not_except = FALSE;

	if (!specs)
		return NM_MATCH_SPEC_NO_MATCH;

	for (iter = specs; iter; iter = g_slist_next (iter)) {
		const char *spec_str = iter->data;
		gboolean except;
		gboolean v_match;

		if (!spec_str || !*spec_str)
			continue;

		spec_str = match_except (spec_str, &except);

		if (except)
			has_except = TRUE;
		else
			has_not_except = TRUE;

		if (   ( except && has_match_except)
		    || (!except && has_match)) {
			/* evaluating the match does not give new information. Skip it. */
			continue;
		}

		if (_MATCH_CHECK (spec_str, MATCH_TAG_CONFIG_NM_VERSION))
			v_match = match_config_eval (spec_str, MATCH_TAG_CONFIG_NM_VERSION, cur_nm_version);
		else if (_MATCH_CHECK (spec_str, MATCH_TAG_CONFIG_NM_VERSION_MIN))
			v_match = match_config_eval (spec_str, MATCH_TAG_CONFIG_NM_VERSION_MIN, cur_nm_version);
		else if (_MATCH_CHECK (spec_str, MATCH_TAG_CONFIG_NM_VERSION_MAX))
			v_match = match_config_eval (spec_str, MATCH_TAG_CONFIG_NM_VERSION_MAX, cur_nm_version);
		else if (_MATCH_CHECK (spec_str, MATCH_TAG_CONFIG_ENV))
			v_match = env && env[0] && !strcmp (spec_str, env);
		else
			v_match = FALSE;

		if (!v_match)
			continue;

		if (except)
			has_match_except = TRUE;
		else
			has_match = TRUE;
	}

	return _match_result (has_except, has_not_except, has_match, has_match_except);
}

#undef _MATCH_CHECK

/**
 * nm_match_spec_split:
 * @value: the string of device specs
 *
 * Splits the specs from the string and returns them as individual
 * entries in a #GSList.
 *
 * It does not validate any specs, it basically just does a special
 * strsplit with ',' or ';' as separators and supporting '\\' as
 * escape character.
 *
 * Leading and trailing spaces of each entry are removed. But the user
 * can preserve them by specifying "\\s has 2 leading" or "has 2 trailing \\s".
 *
 * Specs can have a qualifier like "interface-name:". We still don't strip
 * any whitespace after the colon, so "interface-name: X" matches an interface
 * named " X".
 *
 * Returns: (transfer full): the list of device specs.
 */
GSList *
nm_match_spec_split (const char *value)
{
	char *string_value, *p, *q0, *q;
	GSList *pieces = NULL;
	int trailing_ws;

	if (!value || !*value)
		return NULL;

	/* Copied from glibs g_key_file_parse_value_as_string() function
	 * and adjusted. */

	string_value = g_new (char, strlen (value) + 1);

	p = (char *) value;

	/* skip over leading whitespace */
	while (g_ascii_isspace (*p))
		p++;

	q0 = q = string_value;
	trailing_ws = 0;
	while (*p) {
		if (*p == '\\') {
			p++;

			switch (*p) {
			case 's':
				*q = ' ';
				break;
			case 'n':
				*q = '\n';
				break;
			case 't':
				*q = '\t';
				break;
			case 'r':
				*q = '\r';
				break;
			case '\\':
				*q = '\\';
				break;
			case '\0':
				break;
			default:
				if (NM_IN_SET (*p, ',', ';'))
					*q = *p;
				else {
					*q++ = '\\';
					*q = *p;
				}
				break;
			}
			if (*p == '\0')
				break;
			p++;
			trailing_ws = 0;
		} else {
			*q = *p;
			if (*p == '\0')
				break;
			if (g_ascii_isspace (*p)) {
				trailing_ws++;
				p++;
			} else if (NM_IN_SET (*p, ',', ';')) {
				if (q0 < q - trailing_ws)
					pieces = g_slist_prepend (pieces, g_strndup (q0, (q - q0) - trailing_ws));
				q0 = q + 1;
				p++;
				trailing_ws = 0;
				while (g_ascii_isspace (*p))
					p++;
			} else
				p++;
		}
		q++;
	}

	*q = '\0';
	if (q0 < q - trailing_ws)
		pieces = g_slist_prepend (pieces, g_strndup (q0, (q - q0) - trailing_ws));
	g_free (string_value);
	return g_slist_reverse (pieces);
}

/**
 * nm_match_spec_join:
 * @specs: the device specs to join
 *
 * This is based on g_key_file_parse_string_as_value(), analog to
 * nm_match_spec_split() which is based on g_key_file_parse_value_as_string().
 *
 * Returns: (transfer full): a joined list of device specs that can be
 *   split again with nm_match_spec_split(). Note that
 *   nm_match_spec_split (nm_match_spec_join (specs)) yields the original
 *   result (which is not true the other way around because there are multiple
 *   ways to encode the same joined specs string).
 */
char *
nm_match_spec_join (GSList *specs)
{
	const char *p;
	GString *str;

	str = g_string_new ("");

	for (; specs; specs = specs->next) {
		p = specs->data;

		if (!p || !*p)
			continue;

		if (str->len > 0)
			g_string_append_c (str, ',');

		/* escape leading whitespace */
		switch (*p) {
		case ' ':
			g_string_append (str, "\\s");
			p++;
			break;
		case '\t':
			g_string_append (str, "\\t");
			p++;
			break;
		}

		for (; *p; p++) {
			switch (*p) {
			case '\n':
				g_string_append (str, "\\n");
				break;
			case '\r':
				g_string_append (str, "\\r");
				break;
			case '\\':
				g_string_append (str, "\\\\");
				break;
			case ',':
				g_string_append (str, "\\,");
				break;
			case ';':
				g_string_append (str, "\\;");
				break;
			default:
				g_string_append_c (str, *p);
				break;
			}
		}

		/* escape trailing whitespaces */
		switch (str->str[str->len - 1]) {
		case ' ':
			g_string_overwrite (str, str->len - 1, "\\s");
			break;
		case '\t':
			g_string_overwrite (str, str->len - 1, "\\t");
			break;
		}
	}

	return g_string_free (str, FALSE);
}

gboolean
nm_wildcard_match_check (const char *str,
                         const char *const *patterns,
                         guint num_patterns)
{
	guint i, neg = 0;

	for (i = 0; i < num_patterns; i++) {
		if (patterns[i][0] == '!') {
			neg++;
			if (!fnmatch (patterns[i] + 1, str, 0))
				return FALSE;
		}
	}

	if (neg == num_patterns)
		return TRUE;

	for (i = 0; i < num_patterns; i++) {
		if (   patterns[i][0] != '!'
		    && !fnmatch (patterns[i], str, 0))
			return TRUE;
	}

	return FALSE;
}

/*****************************************************************************/

char *
nm_utils_new_vlan_name (const char *parent_iface, guint32 vlan_id)
{
	guint id_len;
	gsize parent_len;
	char *ifname;

	g_return_val_if_fail (parent_iface && *parent_iface, NULL);

	if (vlan_id < 10)
		id_len = 2;
	else if (vlan_id < 100)
		id_len = 3;
	else if (vlan_id < 1000)
		id_len = 4;
	else {
		g_return_val_if_fail (vlan_id < 4095, NULL);
		id_len = 5;
	}

	ifname = g_new (char, IFNAMSIZ);

	parent_len = strlen (parent_iface);
	parent_len = MIN (parent_len, IFNAMSIZ - 1 - id_len);
	memcpy (ifname, parent_iface, parent_len);
	g_snprintf (&ifname[parent_len], IFNAMSIZ - parent_len, ".%u", vlan_id);

	return ifname;
}

/* nm_utils_new_infiniband_name:
 * @name: the output-buffer where the value will be written. Must be
 *   not %NULL and point to a string buffer of at least IFNAMSIZ bytes.
 * @parent_name: the parent interface name
 * @p_key: the partition key.
 *
 * Returns: the infiniband name will be written to @name and @name
 *   is returned.
 */
const char *
nm_utils_new_infiniband_name (char *name, const char *parent_name, int p_key)
{
	g_return_val_if_fail (name, NULL);
	g_return_val_if_fail (parent_name && parent_name[0], NULL);
	g_return_val_if_fail (strlen (parent_name) < IFNAMSIZ, NULL);

	/* technically, p_key of 0x0000 and 0x8000 is not allowed either. But we don't
	 * want to assert against that in nm_utils_new_infiniband_name(). So be more
	 * resilient here, and accept those. */
	g_return_val_if_fail (p_key >= 0 && p_key <= 0xffff, NULL);

	/* If parent+suffix is too long, kernel would just truncate
	 * the name. We do the same. See ipoib_vlan_add().  */
	g_snprintf (name, IFNAMSIZ, "%s.%04x", parent_name, p_key);
	return name;
}

/*****************************************************************************/

/**
 * nm_utils_cmp_connection_by_autoconnect_priority:
 * @a:
 * @b:
 *
 * compare connections @a and @b for their autoconnect property
 * (with sorting the connection that has autoconnect enabled before
 * the other)
 * If they both have autoconnect enabled, sort them depending on their
 * autoconnect-priority (with the higher priority first).
 *
 * If their autoconnect/autoconnect-priority is the same, 0 is returned.
 * That is, they compare equal.
 *
 * Returns: -1, 0, or 1
 */
int
nm_utils_cmp_connection_by_autoconnect_priority (NMConnection *a, NMConnection *b)
{
	NMSettingConnection *a_s_con;
	NMSettingConnection *b_s_con;
	int a_ap, b_ap;
	gboolean can_autoconnect;

	if (a == b)
		return 0;
	if (!a)
		return 1;
	if (!b)
		return -1;

	a_s_con = nm_connection_get_setting_connection (a);
	b_s_con = nm_connection_get_setting_connection (b);

	if (!a_s_con)
		return !b_s_con ? 0 : 1;
	if (!b_s_con)
		return -1;

	can_autoconnect = !!nm_setting_connection_get_autoconnect (a_s_con);
	if (can_autoconnect != (!!nm_setting_connection_get_autoconnect (b_s_con)))
		return can_autoconnect ? -1 : 1;

	if (can_autoconnect) {
		a_ap = nm_setting_connection_get_autoconnect_priority (a_s_con);
		b_ap = nm_setting_connection_get_autoconnect_priority (b_s_con);
		if (a_ap != b_ap)
			return (a_ap > b_ap) ? -1 : 1;
	}

	return 0;
}

/*****************************************************************************/

typedef struct
{
	const char *name;
	NMSetting *setting;
	NMSetting *diff_base_setting;
	GHashTable *setting_diff;
} LogConnectionSettingData;

typedef struct
{
	const char *item_name;
	NMSettingDiffResult diff_result;
} LogConnectionSettingItem;

static int
_log_connection_sort_hashes_fcn (gconstpointer a, gconstpointer b)
{
	const LogConnectionSettingData *v1 = a;
	const LogConnectionSettingData *v2 = b;
	NMSettingPriority p1, p2;
	NMSetting *s1, *s2;

	s1 = v1->setting ?: v1->diff_base_setting;
	s2 = v2->setting ?: v2->diff_base_setting;

	g_assert (s1 && s2);

	p1 = _nm_setting_get_setting_priority (s1);
	p2 = _nm_setting_get_setting_priority (s2);

	if (p1 != p2)
		return p1 > p2 ? 1 : -1;

	return strcmp (v1->name, v2->name);
}

static GArray *
_log_connection_sort_hashes (NMConnection *connection, NMConnection *diff_base, GHashTable *connection_diff)
{
	GHashTableIter iter;
	GArray *sorted_hashes;
	LogConnectionSettingData setting_data;

	sorted_hashes = g_array_sized_new (TRUE, FALSE, sizeof (LogConnectionSettingData), g_hash_table_size (connection_diff));

	g_hash_table_iter_init (&iter, connection_diff);
	while (g_hash_table_iter_next (&iter, (gpointer) &setting_data.name, (gpointer) &setting_data.setting_diff)) {
		setting_data.setting = nm_connection_get_setting_by_name (connection, setting_data.name);
		setting_data.diff_base_setting = diff_base ? nm_connection_get_setting_by_name (diff_base, setting_data.name) : NULL;
		g_assert (setting_data.setting || setting_data.diff_base_setting);
		g_array_append_val (sorted_hashes, setting_data);
	}

	g_array_sort (sorted_hashes, _log_connection_sort_hashes_fcn);
	return sorted_hashes;
}

static int
_log_connection_sort_names_fcn (gconstpointer a, gconstpointer b)
{
	const LogConnectionSettingItem *v1 = a;
	const LogConnectionSettingItem *v2 = b;

	/* we want to first show the items, that disappeared, then the one that changed and
	 * then the ones that were added. */

	if ((v1->diff_result & NM_SETTING_DIFF_RESULT_IN_A) != (v2->diff_result & NM_SETTING_DIFF_RESULT_IN_A))
		return (v1->diff_result & NM_SETTING_DIFF_RESULT_IN_A) ? -1 : 1;
	if ((v1->diff_result & NM_SETTING_DIFF_RESULT_IN_B) != (v2->diff_result & NM_SETTING_DIFF_RESULT_IN_B))
		return (v1->diff_result & NM_SETTING_DIFF_RESULT_IN_B) ? 1 : -1;
	return strcmp (v1->item_name, v2->item_name);
}

static char *
_log_connection_get_property (NMSetting *setting, const char *name)
{
	GValue val = G_VALUE_INIT;
	char *s;

	g_return_val_if_fail (setting, NULL);

	if (   !NM_IS_SETTING_VPN (setting)
	    && nm_setting_get_secret_flags (setting, name, NULL, NULL))
		return g_strdup ("****");

	if (!_nm_setting_get_property (setting, name, &val))
		return g_strdup ("<unknown>");

	if (G_VALUE_HOLDS_STRING (&val)) {
		const char *val_s;

		val_s = g_value_get_string (&val);
		if (!val_s) {
			/* for NULL, we want to return the unquoted string "NULL". */
			s = g_strdup ("NULL");
		} else {
			char *escaped = g_strescape (val_s, "'");

			s = g_strdup_printf ("'%s'", escaped);
			g_free (escaped);
		}
	} else {
		s = g_strdup_value_contents (&val);
		if (s == NULL)
			s = g_strdup ("NULL");
		else {
			char *escaped = g_strescape (s, "'");

			g_free (s);
			s = escaped;
		}
	}
	g_value_unset(&val);
	return s;
}

static void
_log_connection_sort_names (LogConnectionSettingData *setting_data, GArray *sorted_names)
{
	GHashTableIter iter;
	LogConnectionSettingItem item;
	gpointer p;

	g_array_set_size (sorted_names, 0);

	g_hash_table_iter_init (&iter, setting_data->setting_diff);
	while (g_hash_table_iter_next (&iter, (gpointer) &item.item_name, &p)) {
		item.diff_result = GPOINTER_TO_UINT (p);
		g_array_append_val (sorted_names, item);
	}

	g_array_sort (sorted_names, _log_connection_sort_names_fcn);
}

void
nm_utils_log_connection_diff (NMConnection *connection,
                              NMConnection *diff_base,
                              guint32 level,
                              guint64 domain,
                              const char *name,
                              const char *prefix,
                              const char *dbus_path)
{
	GHashTable *connection_diff = NULL;
	GArray *sorted_hashes;
	GArray *sorted_names = NULL;
	int i, j;
	gboolean connection_diff_are_same;
	gboolean print_header = TRUE;
	gboolean print_setting_header;
	GString *str1;

	g_return_if_fail (NM_IS_CONNECTION (connection));
	g_return_if_fail (!diff_base || (NM_IS_CONNECTION (diff_base) && diff_base != connection));

	/* For VPN setting types, this is broken, because we cannot (generically) print the content of data/secrets. Bummer... */

	if (!nm_logging_enabled (level, domain))
		return;

	if (!prefix)
		prefix = "";
	if (!name)
		name = "";

	connection_diff_are_same = nm_connection_diff (connection, diff_base,
	                                               NM_SETTING_COMPARE_FLAG_EXACT | NM_SETTING_COMPARE_FLAG_DIFF_RESULT_NO_DEFAULT,
	                                               &connection_diff);
	if (connection_diff_are_same) {
		const char *t1, *t2;

		t1 = nm_connection_get_connection_type (connection);
		if (diff_base) {
			t2 = nm_connection_get_connection_type (diff_base);
			nm_log (level, domain, NULL, NULL,
			        "%sconnection '%s' (%p/%s/%s%s%s and %p/%s/%s%s%s): no difference",
			        prefix, name,
			        connection, G_OBJECT_TYPE_NAME (connection), NM_PRINT_FMT_QUOTE_STRING (t1),
			        diff_base, G_OBJECT_TYPE_NAME (diff_base), NM_PRINT_FMT_QUOTE_STRING (t2));
		} else {
			nm_log (level, domain, NULL, NULL,
			        "%sconnection '%s' (%p/%s/%s%s%s): no properties set",
			        prefix, name,
			        connection, G_OBJECT_TYPE_NAME (connection), NM_PRINT_FMT_QUOTE_STRING (t1));
		}
		g_assert (!connection_diff);
		return;
	}

	/* FIXME: it doesn't nicely show the content of NMSettingVpn, because nm_connection_diff() does not
	 * expand the hash values. */

	sorted_hashes = _log_connection_sort_hashes (connection, diff_base, connection_diff);
	if (sorted_hashes->len <= 0)
		goto out;

	sorted_names = g_array_new (FALSE, FALSE, sizeof (LogConnectionSettingItem));
	str1 = g_string_new (NULL);

	for (i = 0; i < sorted_hashes->len; i++) {
		LogConnectionSettingData *setting_data = &g_array_index (sorted_hashes, LogConnectionSettingData, i);

		_log_connection_sort_names (setting_data, sorted_names);
		print_setting_header = TRUE;
		for (j = 0; j < sorted_names->len; j++) {
			char *str_conn, *str_diff;
			LogConnectionSettingItem *item = &g_array_index (sorted_names, LogConnectionSettingItem, j);

			str_conn = (item->diff_result & NM_SETTING_DIFF_RESULT_IN_A)
			           ? _log_connection_get_property (setting_data->setting, item->item_name)
			           : NULL;
			str_diff = (item->diff_result & NM_SETTING_DIFF_RESULT_IN_B)
			           ? _log_connection_get_property (setting_data->diff_base_setting, item->item_name)
			           : NULL;

			if (print_header) {
				GError *err_verify = NULL;
				const char *t1, *t2;

				t1 = nm_connection_get_connection_type (connection);
				if (diff_base) {
					t2 = nm_connection_get_connection_type (diff_base);
					nm_log (level, domain, NULL, NULL, "%sconnection '%s' (%p/%s/%s%s%s < %p/%s/%s%s%s)%s%s%s:",
					        prefix, name,
					        connection, G_OBJECT_TYPE_NAME (connection), NM_PRINT_FMT_QUOTE_STRING (t1),
					        diff_base, G_OBJECT_TYPE_NAME (diff_base), NM_PRINT_FMT_QUOTE_STRING (t2),
					        NM_PRINT_FMT_QUOTED (dbus_path, " [", dbus_path, "]", ""));
				} else {
					nm_log (level, domain, NULL, NULL, "%sconnection '%s' (%p/%s/%s%s%s):%s%s%s",
					        prefix, name,
					        connection, G_OBJECT_TYPE_NAME (connection), NM_PRINT_FMT_QUOTE_STRING (t1),
					        NM_PRINT_FMT_QUOTED (dbus_path, " [", dbus_path, "]", ""));
				}
				print_header = FALSE;

				if (!nm_connection_verify (connection, &err_verify)) {
					nm_log (level, domain, NULL, NULL, "%sconnection %p does not verify: %s", prefix, connection, err_verify->message);
					g_clear_error (&err_verify);
				}
			}
#define _NM_LOG_ALIGN "-25"
			if (print_setting_header) {
				if (diff_base) {
					if (setting_data->setting && setting_data->diff_base_setting)
						g_string_printf (str1, "%p < %p", setting_data->setting, setting_data->diff_base_setting);
					else if (setting_data->diff_base_setting)
						g_string_printf (str1, "*missing* < %p", setting_data->diff_base_setting);
					else
						g_string_printf (str1, "%p < *missing*", setting_data->setting);
					nm_log (level, domain, NULL, NULL, "%s%"_NM_LOG_ALIGN"s [ %s ]", prefix, setting_data->name, str1->str);
				} else
					nm_log (level, domain, NULL, NULL, "%s%"_NM_LOG_ALIGN"s [ %p ]", prefix, setting_data->name, setting_data->setting);
				print_setting_header = FALSE;
			}
			g_string_printf (str1, "%s.%s", setting_data->name, item->item_name);
			switch (item->diff_result & (NM_SETTING_DIFF_RESULT_IN_A | NM_SETTING_DIFF_RESULT_IN_B)) {
				case NM_SETTING_DIFF_RESULT_IN_B:
					nm_log (level, domain, NULL, NULL, "%s%"_NM_LOG_ALIGN"s < %s", prefix, str1->str, str_diff ?: "NULL");
					break;
				case NM_SETTING_DIFF_RESULT_IN_A:
					nm_log (level, domain, NULL, NULL, "%s%"_NM_LOG_ALIGN"s = %s", prefix, str1->str, str_conn ?: "NULL");
					break;
				default:
					nm_log (level, domain, NULL, NULL, "%s%"_NM_LOG_ALIGN"s = %s < %s", prefix, str1->str, str_conn ?: "NULL", str_diff ?: "NULL");
					break;
#undef _NM_LOG_ALIGN
			}
			g_free (str_conn);
			g_free (str_diff);
		}
	}

	g_array_free (sorted_names, TRUE);
	g_string_free (str1, TRUE);
out:
	g_hash_table_destroy (connection_diff);
	g_array_free (sorted_hashes, TRUE);
}

#define IPV6_PROPERTY_DIR "/proc/sys/net/ipv6/conf/"
#define IPV4_PROPERTY_DIR "/proc/sys/net/ipv4/conf/"
G_STATIC_ASSERT (sizeof (IPV4_PROPERTY_DIR) == sizeof (IPV6_PROPERTY_DIR));
G_STATIC_ASSERT (NM_STRLEN (IPV6_PROPERTY_DIR) + IFNAMSIZ + 60 == NM_UTILS_SYSCTL_IP_CONF_PATH_BUFSIZE);

/**
 * nm_utils_sysctl_ip_conf_path:
 * @addr_family: either AF_INET or AF_INET6.
 * @buf: the output buffer where to write the path. It
 *   must be at least NM_UTILS_SYSCTL_IP_CONF_PATH_BUFSIZE bytes
 *   long.
 * @ifname: an interface name
 * @property: a property name
 *
 * Returns: the path to IPv6 property @property on @ifname. Note that
 * this returns the input argument @buf.
 */
const char *
nm_utils_sysctl_ip_conf_path (int addr_family, char *buf, const char *ifname, const char *property)
{
	int len;

	nm_assert (buf);
	nm_assert_addr_family (addr_family);

	g_assert (nm_utils_is_valid_iface_name (ifname, NULL));
	property = NM_ASSERT_VALID_PATH_COMPONENT (property);

	len = g_snprintf (buf,
	                  NM_UTILS_SYSCTL_IP_CONF_PATH_BUFSIZE,
	                  "%s%s/%s",
	                  addr_family == AF_INET6 ? IPV6_PROPERTY_DIR : IPV4_PROPERTY_DIR,
	                  ifname,
	                  property);
	g_assert (len < NM_UTILS_SYSCTL_IP_CONF_PATH_BUFSIZE - 1);
	return buf;
}

gboolean
nm_utils_sysctl_ip_conf_is_path (int addr_family, const char *path, const char *ifname, const char *property)
{
	g_return_val_if_fail (path, FALSE);
	NM_ASSERT_VALID_PATH_COMPONENT (property);
	g_assert (!ifname || nm_utils_is_valid_iface_name (ifname, NULL));

	if (addr_family == AF_INET) {
		if (!g_str_has_prefix (path, IPV4_PROPERTY_DIR))
			return FALSE;
		path += NM_STRLEN (IPV4_PROPERTY_DIR);
	} else if (addr_family == AF_INET6) {
		if (!g_str_has_prefix (path, IPV6_PROPERTY_DIR))
			return FALSE;
		path += NM_STRLEN (IPV6_PROPERTY_DIR);
	} else
		g_return_val_if_reached (FALSE);

	if (ifname) {
		if (!g_str_has_prefix (path, ifname))
			return FALSE;
		path += strlen (ifname);
		if (path[0] != '/')
			return FALSE;
		path++;
	} else {
		const char *slash;
		char buf[IFNAMSIZ];
		gsize l;

		slash = strchr (path, '/');
		if (!slash)
			return FALSE;
		l = slash - path;
		if (l >= IFNAMSIZ)
			return FALSE;
		memcpy (buf, path, l);
		buf[l] = '\0';
		if (!nm_utils_is_valid_iface_name (buf, NULL))
			return FALSE;
		path = slash + 1;
	}

	if (!nm_streq (path, property))
		return FALSE;

	return TRUE;
}

gboolean
nm_utils_is_valid_path_component (const char *name)
{
	const char *n;

	if (name == NULL || name[0] == '\0')
		return FALSE;

	if (name[0] == '.') {
		if (name[1] == '\0')
			return FALSE;
		if (name[1] == '.' && name[2] == '\0')
			return FALSE;
	}
	n = name;
	do {
		if (*n == '/')
			return FALSE;
	} while (*(++n) != '\0');

	return TRUE;
}

const char *
NM_ASSERT_VALID_PATH_COMPONENT (const char *name)
{
	if (G_LIKELY (nm_utils_is_valid_path_component (name)))
		return name;

	nm_log_err (LOGD_CORE, "Failed asserting path component: %s%s%s",
	            NM_PRINT_FMT_QUOTED (name, "\"", name, "\"", "(null)"));
	g_error ("FATAL: Failed asserting path component: %s%s%s",
	         NM_PRINT_FMT_QUOTED (name, "\"", name, "\"", "(null)"));
	g_assert_not_reached ();
}

gboolean
nm_utils_is_specific_hostname (const char *name)
{
	if (!name)
		return FALSE;
	if (   strcmp (name, "(none)")
	    && strcmp (name, "localhost")
	    && strcmp (name, "localhost6")
	    && strcmp (name, "localhost.localdomain")
	    && strcmp (name, "localhost6.localdomain6"))
		return TRUE;
	return FALSE;
}

/*****************************************************************************/

typedef struct {
	NMUuid bin;
	char _nul_sentinel; /* just for safety, if somebody accidentally uses the binary in a string context. */

	/* depending on whether the string is packed or not (with/without hyphens),
	 * it's 32 or 36 characters long (plus the trailing NUL).
	 *
	 * The difference is that boot-id is a valid RFC 4211 UUID and represented
	 * as a 36 ascii string (with hyphens). The machine-id technically is not
	 * a UUID, but just a 32 byte sequence of hexchars. */
	char str[37];
	bool is_fake;
} UuidData;

static UuidData *
_uuid_data_init (UuidData *uuid_data,
                 gboolean packed,
                 gboolean is_fake,
                 const NMUuid *uuid)
{
	nm_assert (uuid_data);
	nm_assert (uuid);

	uuid_data->bin = *uuid;
	uuid_data->_nul_sentinel = '\0';
	uuid_data->is_fake = is_fake;
	if (packed) {
		G_STATIC_ASSERT_EXPR (sizeof (uuid_data->str) >= (sizeof (*uuid) * 2 + 1));
		nm_utils_bin2hexstr_full (uuid,
		                          sizeof (*uuid),
		                          '\0',
		                          FALSE,
		                          uuid_data->str);
	} else {
		G_STATIC_ASSERT_EXPR (sizeof (uuid_data->str) >= 37);
		_nm_utils_uuid_unparse (uuid, uuid_data->str);
	}
	return uuid_data;
}

/*****************************************************************************/

static const UuidData *
_machine_id_get (gboolean allow_fake)
{
	static const UuidData *volatile p_uuid_data;
	const UuidData *d;

again:
	d = g_atomic_pointer_get (&p_uuid_data);
	if (G_UNLIKELY (!d)) {
		static gsize lock;
		static UuidData uuid_data;
		gs_free char *content = NULL;
		gboolean is_fake = TRUE;
		const char *fake_type = NULL;
		NMUuid uuid;

		/* Get the machine ID from /etc/machine-id; it's always in /etc no matter
		 * where our configured SYSCONFDIR is.  Alternatively, it might be in
		 * LOCALSTATEDIR /lib/dbus/machine-id.
		 */
		if (   nm_utils_file_get_contents (-1, "/etc/machine-id", 100*1024, 0, &content, NULL, NULL) >= 0
		    || nm_utils_file_get_contents (-1, LOCALSTATEDIR"/lib/dbus/machine-id", 100*1024, 0, &content, NULL, NULL) >= 0) {
			g_strstrip (content);
			if (nm_utils_hexstr2bin_full (content,
			                              FALSE,
			                              FALSE,
			                              NULL,
			                              16,
			                              (guint8 *) &uuid,
			                              sizeof (uuid),
			                              NULL)) {
				if (!nm_utils_uuid_is_null (&uuid)) {
					/* an all-zero machine-id is not valid. */
					is_fake = FALSE;
				}
			}
		}

		if (is_fake) {
			const guint8 *seed_bin;
			const char *hash_seed;
			gsize seed_len;

			if (!allow_fake) {
				/* we don't allow generating (and memoizing) a fake key.
				 * Signal that no valid machine-id exists. */
				return NULL;
			}

			if (nm_utils_host_id_get (&seed_bin, &seed_len)) {
				/* we have no valid machine-id. Generate a fake one by hashing
				 * the secret-key. This key is commonly persisted, so it should be
				 * stable across reboots (despite having a broken system without
				 * proper machine-id). */
				fake_type = "secret-key";
				hash_seed = "ab085f06-b629-46d1-a553-84eeba5683b6";
			} else {
				/* the secret-key is not valid/persistent either. That happens when we fail
				 * to read/write the secret-key to disk. Fallback to boot-id. The boot-id
				 * itself may be fake and randomly generated ad-hoc, but that is as best
				 * as it gets.  */
				seed_bin = (const guint8 *) nm_utils_boot_id_bin ();
				seed_len = sizeof (NMUuid);
				fake_type = "boot-id";
				hash_seed = "7ff0c8f5-5399-4901-ab63-61bf594abe8b";
			}

			/* the fake machine-id is based on secret-key/boot-id, but we hash it
			 * again, so that they are not literally the same. */
			nm_utils_uuid_generate_from_string_bin (&uuid,
			                                        (const char *) seed_bin,
			                                        seed_len,
			                                        NM_UTILS_UUID_TYPE_VERSION5,
			                                        (gpointer) hash_seed);
		}

		if (!g_once_init_enter (&lock))
			goto again;

		d = _uuid_data_init (&uuid_data, TRUE, is_fake, &uuid);
		g_atomic_pointer_set (&p_uuid_data, d);
		g_once_init_leave (&lock, 1);

		if (is_fake) {
			nm_log_err (LOGD_CORE,
			            "/etc/machine-id: no valid machine-id. Use fake one based on %s: %s",
			            fake_type,
			            d->str);
		} else
			nm_log_dbg (LOGD_CORE, "/etc/machine-id: %s", d->str);
	}

	return d;
}

const char *
nm_utils_machine_id_str (void)
{
	return _machine_id_get (TRUE)->str;
}

const NMUuid *
nm_utils_machine_id_bin (void)
{
	return &_machine_id_get (TRUE)->bin;
}

gboolean
nm_utils_machine_id_is_fake (void)
{
	return _machine_id_get (TRUE)->is_fake;
}

/*****************************************************************************/

/* prefix for version2 secret key. The secret key is hashed with /etc/machine-id. */
#define SECRET_KEY_V2_PREFIX "nm-v2:"
#define SECRET_KEY_FILE      NMSTATEDIR"/secret_key"

static gboolean
_host_id_read_timestamp (gboolean use_secret_key_file,
                         const guint8 *host_id,
                         gsize host_id_len,
                         gint64 *out_timestamp_ns)
{
	struct stat st;
	gint64 now;
	guint64 v;

	if (   use_secret_key_file
	    && stat (SECRET_KEY_FILE, &st) == 0) {
		/* don't check for overflow or timestamps in the future. We get whatever
		 * (bogus) date is on the file. */
		*out_timestamp_ns = (st.st_mtim.tv_sec * NM_UTILS_NS_PER_SECOND) + st.st_mtim.tv_nsec;
		return TRUE;
	}

	/* generate a fake timestamp based on the host-id.
	 *
	 * This really should never happen under normal circumstances. We already
	 * are in a code path, where the system has a problem (unable to get good randomness
	 * and/or can't access the secret_key). In such a scenario, a fake timestamp is the
	 * least of our problems.
	 *
	 * At least, generate something sensible so we don't have to worry about the
	 * timestamp. It is wrong to worry about using a fake timestamp (which is tied to
	 * the secret_key) if we are unable to access the secret_key file in the first place.
	 *
	 * Pick a random timestamp from the past two years. Yes, this timestamp
	 * is not stable across restarts, but apparently neither is the host-id
	 * nor the secret_key itself. */

#define EPOCH_TWO_YEARS  (G_GINT64_CONSTANT (2 * 365 * 24 * 3600) * NM_UTILS_NS_PER_SECOND)

	v = nm_hash_siphash42 (1156657133u, host_id, host_id_len);

	now = time (NULL);
	*out_timestamp_ns = NM_MAX ((gint64) 1,
	                            (now * NM_UTILS_NS_PER_SECOND) - ((gint64) (v % ((guint64) (EPOCH_TWO_YEARS)))));
	return FALSE;
}

static const guint8 *
_host_id_hash_v2 (const guint8 *seed_arr,
                  gsize seed_len,
                  guint8 *out_digest /* 32 bytes (NM_UTILS_CHECKSUM_LENGTH_SHA256) */)
{
	nm_auto_free_checksum GChecksum *sum = g_checksum_new (G_CHECKSUM_SHA256);
	const UuidData *machine_id_data;
	char slen[100];

	/*
	    (stat -c '%s' /var/lib/NetworkManager/secret_key;
	     echo -n ' ';
	     cat /var/lib/NetworkManager/secret_key;
	     cat /etc/machine-id | tr -d '\n' | sed -n 's/[a-f0-9-]/\0/pg') | sha256sum
	*/

	nm_sprintf_buf (slen, "%"G_GSIZE_FORMAT" ", seed_len);
	g_checksum_update (sum, (const guchar *) slen, strlen (slen));

	g_checksum_update (sum, (const guchar *) seed_arr, seed_len);

	machine_id_data = _machine_id_get (FALSE);
	if (   machine_id_data
	    && !machine_id_data->is_fake)
		g_checksum_update (sum, (const guchar *) machine_id_data->str, strlen (machine_id_data->str));

	nm_utils_checksum_get_digest_len (sum, out_digest, NM_UTILS_CHECKSUM_LENGTH_SHA256);
	return out_digest;
}

static gboolean
_host_id_read (guint8 **out_host_id,
               gsize *out_host_id_len)
{
#define SECRET_KEY_LEN 32u
	guint8 sha256_digest[NM_UTILS_CHECKSUM_LENGTH_SHA256];
	nm_auto_clear_secret_ptr NMSecretPtr file_content = { 0 };
	const guint8 *secret_arr;
	gsize secret_len;
	GError *error = NULL;
	gboolean success;

	if (nm_utils_file_get_contents (-1,
	                                SECRET_KEY_FILE,
	                                10*1024,
	                                NM_UTILS_FILE_GET_CONTENTS_FLAG_SECRET,
	                                (char **) &file_content.str,
	                                &file_content.len,
	                                &error) < 0) {
		if (!nm_utils_error_is_notfound (error)) {
			nm_log_warn (LOGD_CORE, "secret-key: failure reading secret key in \"%s\": %s (generate new key)",
			             SECRET_KEY_FILE, error->message);
		}
		g_clear_error (&error);
	} else if (   file_content.len >= NM_STRLEN (SECRET_KEY_V2_PREFIX) + SECRET_KEY_LEN
	           && memcmp (file_content.bin, SECRET_KEY_V2_PREFIX, NM_STRLEN (SECRET_KEY_V2_PREFIX)) == 0) {
		/* for this type of secret key, we require a prefix followed at least SECRET_KEY_LEN (32) bytes. We
		 * (also) do that, because older versions of NetworkManager wrote exactly 32 bytes without
		 * prefix, so we won't wrongly interpret such legacy keys as v2 (if they accidentally have
		 * a SECRET_KEY_V2_PREFIX prefix, they'll still have the wrong size).
		 *
		 * Note that below we generate the random seed in base64 encoding. But that is only done
		 * to write an ASCII file. There is no base64 decoding and the ASCII is hashed as-is.
		 * We would accept any binary data just as well (provided a suitable prefix and at least
		 * 32 bytes).
		 *
		 * Note that when hashing the v2 content, we also hash the prefix. There is no strong reason,
		 * except that it seems simpler not to distinguish between the v2 prefix and the content.
		 * It's all just part of the seed. */

		secret_arr = _host_id_hash_v2 (file_content.bin, file_content.len, sha256_digest);
		secret_len = NM_UTILS_CHECKSUM_LENGTH_SHA256;
		success = TRUE;
		goto out;
	} else if (file_content.len >= 16) {
		secret_arr = file_content.bin;
		secret_len = file_content.len;
		success = TRUE;
		goto out;
	} else {
		/* the secret key is borked. Log a warning, but proceed below to generate
		 * a new one. */
		nm_log_warn (LOGD_CORE, "secret-key: too short secret key in \"%s\" (generate new key)", SECRET_KEY_FILE);
	}

	/* generate and persist new key */
	{
#define SECRET_KEY_LEN_BASE64 ((((SECRET_KEY_LEN / 3) + 1) * 4) + 4)
		guint8 rnd_buf[SECRET_KEY_LEN];
		guint8 new_content[NM_STRLEN (SECRET_KEY_V2_PREFIX) + SECRET_KEY_LEN_BASE64];
		int base64_state = 0;
		int base64_save = 0;
		gsize len;

		success = nm_utils_random_bytes (rnd_buf, sizeof (rnd_buf));

		/* Our key is really binary data. But since we anyway generate a random seed
		 * (with 32 random bytes), don't write it in binary, but instead create
		 * an pure ASCII (base64) representation. Note that the ASCII will still be taken
		 * as-is (no base64 decoding is done). The sole purpose is to write a ASCII file
		 * instead of a binary. The content is gibberish either way. */
		memcpy (new_content, SECRET_KEY_V2_PREFIX, NM_STRLEN (SECRET_KEY_V2_PREFIX));
		len = NM_STRLEN (SECRET_KEY_V2_PREFIX);
		len += g_base64_encode_step (rnd_buf,
		                             sizeof (rnd_buf),
		                             FALSE,
		                             (char *) &new_content[len],
		                             &base64_state,
		                             &base64_save);
		len += g_base64_encode_close (FALSE,
		                              (char *) &new_content[len],
		                              &base64_state,
		                              &base64_save);
		nm_assert (len <= sizeof (new_content));

		secret_arr = _host_id_hash_v2 (new_content, len, sha256_digest);
		secret_len = NM_UTILS_CHECKSUM_LENGTH_SHA256;

		if (!success)
			nm_log_warn (LOGD_CORE, "secret-key: failure to generate good random data for secret-key (use non-persistent key)");
		else if (nm_utils_get_testing ()) {
			/* for test code, we don't write the generated secret-key to disk. */
		} else if (!nm_utils_file_set_contents (SECRET_KEY_FILE,
		                                        (const char *) new_content,
		                                        len,
		                                        0077,
		                                        &error)) {
			nm_log_warn (LOGD_CORE, "secret-key: failure to persist secret key in \"%s\" (%s) (use non-persistent key)",
			             SECRET_KEY_FILE, error->message);
			g_clear_error (&error);
			success = FALSE;
		} else
			nm_log_dbg (LOGD_CORE, "secret-key: persist new secret key to \"%s\"", SECRET_KEY_FILE);

		nm_explicit_bzero (rnd_buf, sizeof (rnd_buf));
		nm_explicit_bzero (new_content, sizeof (new_content));
	}

out:
	*out_host_id_len = secret_len;
	*out_host_id = nm_memdup (secret_arr, secret_len);
	return success;
}

typedef struct {
	guint8 *host_id;
	gsize host_id_len;
	gint64 timestamp_ns;
	bool is_good:1;
	bool timestamp_is_good:1;
} HostIdData;

static const HostIdData *
_host_id_get (void)
{
	static const HostIdData *volatile host_id_static;
	const HostIdData *host_id;

again:
	host_id = g_atomic_pointer_get (&host_id_static);
	if (G_UNLIKELY (!host_id)) {
		static HostIdData host_id_data;
		static gsize init_value = 0;

		if (!g_once_init_enter (&init_value))
			goto again;

		host_id_data.is_good = _host_id_read (&host_id_data.host_id,
		                                      &host_id_data.host_id_len);

		host_id_data.timestamp_is_good = _host_id_read_timestamp (host_id_data.is_good,
		                                                          host_id_data.host_id,
		                                                          host_id_data.host_id_len,
		                                                          &host_id_data.timestamp_ns);
		if (   !host_id_data.timestamp_is_good
		    && host_id_data.is_good)
			nm_log_warn (LOGD_CORE, "secret-key: failure reading host timestamp (use fake one)");

		host_id = &host_id_data;
		g_atomic_pointer_set (&host_id_static, host_id);
		g_once_init_leave (&init_value, 1);
	}

	return host_id;
}

/**
 * nm_utils_host_id_get:
 * @out_host_id: (out) (transfer none): the binary host key
 * @out_host_id_len: the length of the host key.
 *
 * This returns a per-host key that depends on /var/lib/NetworkManage/secret_key
 * and (depending on the version) on /etc/machine-id. If /var/lib/NetworkManage/secret_key
 * does not exist, it will be generated and persisted for next boot.
 *
 * Returns: %TRUE, if the host key is "good". Note that this function
 *   will always succeed to return a host-key, and that this key
 *   won't change during the run of the program (no matter what).
 *   A %FALSE return possibly means, that the secret_key is not persisted
 *   to disk, and/or that it was generated with bad randomness.
 */
gboolean
nm_utils_host_id_get (const guint8 **out_host_id,
                      gsize *out_host_id_len)
{
	const HostIdData *host_id;

	host_id = _host_id_get ();
	*out_host_id = host_id->host_id;
	*out_host_id_len = host_id->host_id_len;
	return host_id->is_good;
}

gint64
nm_utils_host_id_get_timestamp_ns (void)
{
	return _host_id_get ()->timestamp_ns;
}

/*****************************************************************************/

static const UuidData *
_boot_id_get (void)
{
	static const UuidData *volatile p_boot_id;
	const UuidData *d;

again:
	d = g_atomic_pointer_get (&p_boot_id);
	if (G_UNLIKELY (!d)) {
		static gsize lock;
		static UuidData boot_id;
		gs_free char *contents = NULL;
		NMUuid uuid;
		gboolean is_fake = FALSE;

		nm_utils_file_get_contents (-1, "/proc/sys/kernel/random/boot_id", 0,
		                            NM_UTILS_FILE_GET_CONTENTS_FLAG_NONE,
		                            &contents, NULL, NULL);
		if (   !contents
		    || !_nm_utils_uuid_parse (nm_strstrip (contents), &uuid)) {
			/* generate a random UUID instead. */
			is_fake = TRUE;
			_nm_utils_uuid_generate_random (&uuid);
		}

		if (!g_once_init_enter (&lock))
			goto again;

		d = _uuid_data_init (&boot_id, FALSE, is_fake, &uuid);
		g_atomic_pointer_set (&p_boot_id, d);
		g_once_init_leave (&lock, 1);
	}

	return d;
}

const char *
nm_utils_boot_id_str (void)
{
	return _boot_id_get ()->str;
}

const NMUuid *
nm_utils_boot_id_bin (void)
{
	return &_boot_id_get ()->bin;
}

/*****************************************************************************/

/**
 * nm_utils_arp_type_detect_from_hwaddrlen:
 * @hwaddr_len: the length of the hardware address in bytes.
 *
 * Detects the arp-type based on the length of the MAC address.
 * On success, this returns a (positive) value in uint16_t range,
 * like ARPHRD_ETHER or ARPHRD_INFINIBAND.
 *
 * On failure, returns a negative error code.
 *
 * Returns: the arp-type or negative value on error. */
int
nm_utils_arp_type_detect_from_hwaddrlen (gsize hwaddr_len)
{
	switch (hwaddr_len) {
	case ETH_ALEN:
		return ARPHRD_ETHER;
	case INFINIBAND_ALEN:
		return ARPHRD_INFINIBAND;
	default:
		/* Note: if you ever support anything but ethernet and infiniband,
		 * make sure to look at all callers. They assert that it's one of
		 * these two. */
		return -EINVAL;
	}
}

gboolean
nm_utils_arp_type_validate_hwaddr (int arp_type,
                                   const guint8 *hwaddr,
                                   gsize hwaddr_len)
{

	if (!hwaddr)
		return FALSE;

	if (arp_type == ARPHRD_ETHER) {
		G_STATIC_ASSERT (ARPHRD_ETHER >= 0 && ARPHRD_ETHER <= 0xFF);
		if (hwaddr_len != ETH_ALEN)
			return FALSE;
	} else if (arp_type == ARPHRD_INFINIBAND) {
		G_STATIC_ASSERT (ARPHRD_INFINIBAND >= 0 && ARPHRD_INFINIBAND <= 0xFF);
		if (hwaddr_len != INFINIBAND_ALEN)
			return FALSE;
	} else
		return FALSE;

	nm_assert (arp_type == nm_utils_arp_type_detect_from_hwaddrlen (hwaddr_len));
	return TRUE;
}

gboolean
nm_utils_arp_type_get_hwaddr_relevant_part (int arp_type,
                                            const guint8 **hwaddr,
                                            gsize *hwaddr_len)
{
	g_return_val_if_fail (   hwaddr
	                      && hwaddr_len
	                      && nm_utils_arp_type_validate_hwaddr (arp_type, *hwaddr, *hwaddr_len),
	                      FALSE);

	/* for infiniband, we only consider the last 8 bytes. */
	if (arp_type == ARPHRD_INFINIBAND) {
		*hwaddr += (INFINIBAND_ALEN - 8);
		*hwaddr_len = 8;
	}

	return TRUE;
}

/*****************************************************************************/

/* Returns the "u" (universal/local) bit value for a Modified EUI-64 */
static gboolean
get_gre_eui64_u_bit (guint32 addr)
{
	static const struct {
		guint32 mask;
		guint32 result;
	} items[] = {
		{ 0xff000000 }, { 0x7f000000 },  /* IPv4 loopback */
		{ 0xf0000000 }, { 0xe0000000 },  /* IPv4 multicast */
		{ 0xffffff00 }, { 0xe0000000 },  /* IPv4 local multicast */
		{ 0xffffffff }, { INADDR_BROADCAST },  /* limited broadcast */
		{ 0xff000000 }, { 0x00000000 },  /* zero net */
		{ 0xff000000 }, { 0x0a000000 },  /* private 10 (RFC3330) */
		{ 0xfff00000 }, { 0xac100000 },  /* private 172 */
		{ 0xffff0000 }, { 0xc0a80000 },  /* private 192 */
		{ 0xffff0000 }, { 0xa9fe0000 },  /* IPv4 link-local */
		{ 0xffffff00 }, { 0xc0586300 },  /* anycast 6-to-4 */
		{ 0xffffff00 }, { 0xc0000200 },  /* test 192 */
		{ 0xfffe0000 }, { 0xc6120000 },  /* test 198 */
	};
	guint i;

	for (i = 0; i < G_N_ELEMENTS (items); i++) {
		if ((addr & htonl (items[i].mask)) == htonl (items[i].result))
			return 0x00; /* "local" scope */
	}
	return 0x02; /* "universal" scope */
}

/**
 * nm_utils_get_ipv6_interface_identifier:
 * @link_type: the hardware link type
 * @hwaddr: the hardware address of the interface
 * @hwaddr_len: the length (in bytes) of @hwaddr
 * @dev_id: the device identifier, if any
 * @out_iid: on success, filled with the interface identifier; on failure
 * zeroed out
 *
 * Constructs an interface identifier in "Modified EUI-64" format which is
 * suitable for constructing IPv6 addresses.  Note that the identifier is
 * not obscured in any way (eg, RFC3041).
 *
 * Returns: %TRUE if the interface identifier could be constructed, %FALSE if
 * if could not be constructed.
 */
gboolean
nm_utils_get_ipv6_interface_identifier (NMLinkType link_type,
                                        const guint8 *hwaddr,
                                        guint hwaddr_len,
                                        guint dev_id,
                                        NMUtilsIPv6IfaceId *out_iid)
{
	guint32 addr;

	g_return_val_if_fail (hwaddr != NULL, FALSE);
	g_return_val_if_fail (hwaddr_len > 0, FALSE);
	g_return_val_if_fail (out_iid != NULL, FALSE);

	out_iid->id = 0;

	switch (link_type) {
	case NM_LINK_TYPE_INFINIBAND:
		/* Use the port GUID per http://tools.ietf.org/html/rfc4391#section-8,
		 * making sure to set the 'u' bit to 1.  The GUID is the lower 64 bits
		 * of the IPoIB interface's hardware address.
		 */
		g_return_val_if_fail (hwaddr_len == INFINIBAND_ALEN, FALSE);
		memcpy (out_iid->id_u8, hwaddr + INFINIBAND_ALEN - 8, 8);
		out_iid->id_u8[0] |= 0x02;
		return TRUE;
	case NM_LINK_TYPE_GRE:
		/* Hardware address is the network-endian IPv4 address */
		g_return_val_if_fail (hwaddr_len == 4, FALSE);
		addr = * (guint32 *) hwaddr;
		out_iid->id_u8[0] = get_gre_eui64_u_bit (addr);
		out_iid->id_u8[1] = 0x00;
		out_iid->id_u8[2] = 0x5E;
		out_iid->id_u8[3] = 0xFE;
		memcpy (out_iid->id_u8 + 4, &addr, 4);
		return TRUE;
	case NM_LINK_TYPE_6LOWPAN:
		/* The hardware address is already 64-bit. This is the case for
		* IEEE 802.15.4 networks. */
		memcpy (out_iid->id_u8, hwaddr, sizeof (out_iid->id_u8));
		return TRUE;
	default:
		if (hwaddr_len == ETH_ALEN) {
			/* Translate 48-bit MAC address to a 64-bit Modified EUI-64.  See
			 * http://tools.ietf.org/html/rfc4291#appendix-A and the Linux
			 * kernel's net/ipv6/addrconf.c::ipv6_generate_eui64() function.
			 */
			out_iid->id_u8[0] = hwaddr[0];
			out_iid->id_u8[1] = hwaddr[1];
			out_iid->id_u8[2] = hwaddr[2];
			if (dev_id) {
				out_iid->id_u8[3] = (dev_id >> 8) & 0xff;
				out_iid->id_u8[4] = dev_id & 0xff;
			} else {
				out_iid->id_u8[0] ^= 0x02;
				out_iid->id_u8[3] = 0xff;
				out_iid->id_u8[4] = 0xfe;
			}
			out_iid->id_u8[5] = hwaddr[3];
			out_iid->id_u8[6] = hwaddr[4];
			out_iid->id_u8[7] = hwaddr[5];
			return TRUE;
		}
		break;
	}
	return FALSE;
}

/*****************************************************************************/

/**
 * nm_utils_ipv6_addr_set_interface_identifier:
 * @addr: output token encoded as %in6_addr
 * @iid: %NMUtilsIPv6IfaceId interface identifier
 *
 * Converts the %NMUtilsIPv6IfaceId to an %in6_addr (suitable for use
 * with Linux platform). This only copies the lower 8 bytes, ignoring
 * the /64 network prefix which is expected to be all-zero for a valid
 * token.
 */
void
nm_utils_ipv6_addr_set_interface_identifier (struct in6_addr *addr,
                                            const NMUtilsIPv6IfaceId iid)
{
	memcpy (addr->s6_addr + 8, &iid.id_u8, 8);
}

/**
 * nm_utils_ipv6_interface_identifier_get_from_addr:
 * @iid: output %NMUtilsIPv6IfaceId interface identifier set from the token
 * @addr: token encoded as %in6_addr
 *
 * Converts the %in6_addr encoded token (as used by Linux platform) to
 * the interface identifier.
 */
void
nm_utils_ipv6_interface_identifier_get_from_addr (NMUtilsIPv6IfaceId *iid,
                                                 const struct in6_addr *addr)
{
	memcpy (iid, addr->s6_addr + 8, 8);
}

/**
 * nm_utils_ipv6_interface_identifier_get_from_token:
 * @iid: output %NMUtilsIPv6IfaceId interface identifier set from the token
 * @token: token encoded as string
 *
 * Converts the %in6_addr encoded token (as used in ip6 settings) to
 * the interface identifier.
 *
 * Returns: %TRUE if the @token is a valid token, %FALSE otherwise
 */
gboolean
nm_utils_ipv6_interface_identifier_get_from_token (NMUtilsIPv6IfaceId *iid,
                                                   const char *token)
{
	struct in6_addr i6_token;

	g_return_val_if_fail (token, FALSE);

	if (!inet_pton (AF_INET6, token, &i6_token))
		return FALSE;

	if (!_nm_utils_inet6_is_token (&i6_token))
		return FALSE;

	nm_utils_ipv6_interface_identifier_get_from_addr (iid, &i6_token);
	return TRUE;
}

/**
 * nm_utils_inet6_interface_identifier_to_token:
 * @iid: %NMUtilsIPv6IfaceId interface identifier
 * @buf: the destination buffer of at least %NM_UTILS_INET_ADDRSTRLEN
 *   bytes.
 *
 * Converts the interface identifier to a string token.
 *
 * Returns: the input buffer filled with the id as string.
 */
const char *
nm_utils_inet6_interface_identifier_to_token (NMUtilsIPv6IfaceId iid, char *buf)
{
	struct in6_addr i6_token = { .s6_addr = { 0, } };

	nm_utils_ipv6_addr_set_interface_identifier (&i6_token, iid);
	return nm_utils_inet6_ntop (&i6_token, buf);
}

/*****************************************************************************/

char *
nm_utils_stable_id_random (void)
{
	char buf[15];

	nm_utils_random_bytes (buf, sizeof (buf));
	return g_base64_encode ((guchar *) buf, sizeof (buf));
}

char *
nm_utils_stable_id_generated_complete (const char *stable_id_generated)
{
	nm_auto_free_checksum GChecksum *sum = NULL;
	guint8 buf[NM_UTILS_CHECKSUM_LENGTH_SHA1];
	char *base64;

	/* for NM_UTILS_STABLE_TYPE_GENERATED we generate a possibly long string
	 * by doing text-substitutions in nm_utils_stable_id_parse().
	 *
	 * Let's shorten the (possibly) long stable_id to something more compact. */

	g_return_val_if_fail (stable_id_generated, NULL);

	sum = g_checksum_new (G_CHECKSUM_SHA1);
	g_checksum_update (sum, (guchar *) stable_id_generated, strlen (stable_id_generated));
	nm_utils_checksum_get_digest (sum, buf);

	/* we don't care to use the sha1 sum in common hex representation.
	 * Use instead base64, it's 27 chars (stripping the padding) vs.
	 * 40. */

	base64 = g_base64_encode ((guchar *) buf, sizeof (buf));
	nm_assert (strlen (base64) == 28);
	nm_assert (base64[27] == '=');

	base64[27] = '\0';
	return base64;
}

static void
_stable_id_append (GString *str,
                   const char *substitution)
{
	if (!substitution)
		substitution = "";
	g_string_append_printf (str, "=%zu{%s}", strlen (substitution), substitution);
}

NMUtilsStableType
nm_utils_stable_id_parse (const char *stable_id,
                          const char *deviceid,
                          const char *hwaddr,
                          const char *bootid,
                          const char *uuid,
                          char **out_generated)
{
	gsize i, idx_start;
	GString *str = NULL;

	g_return_val_if_fail (out_generated, NM_UTILS_STABLE_TYPE_RANDOM);

	if (!stable_id) {
		*out_generated = NULL;
		return NM_UTILS_STABLE_TYPE_UUID;
	}

	/* the stable-id allows for some dynamic by performing text-substitutions
	 * of ${...} patterns.
	 *
	 * At first, it looks a bit like bash parameter substitution.
	 * In contrast however, the process is unambiguous so that the resulting
	 * effective id differs if:
	 *  - the original, untranslated stable-id differs
	 *  - or any of the subsitutions differs.
	 *
	 * The reason for that is, for example if you specify "${CONNECTION}" in the
	 * stable-id, then the resulting ID should be always(!) unique for this connection.
	 * There should be no way another connection could specify any stable-id that results
	 * in the same addresses to be generated (aside hash collisions).
	 *
	 *
	 * For example: say you have a connection with UUID
	 * "123e4567-e89b-12d3-a456-426655440000" which happens also to be
	 * the current boot-id.
	 * Then:
	 *   (1) connection.stable-id = <NULL>
	 *   (2) connection.stable-id = "123e4567-e89b-12d3-a456-426655440000"
	 *   (3) connection.stable-id = "${CONNECTION}"
	 *   (3) connection.stable-id = "${BOOT}"
	 * will all generate different addresses, although in one way or the
	 * other, they all mangle the uuid "123e4567-e89b-12d3-a456-426655440000".
	 *
	 * For example, with stable-id="${FOO}${BAR}" the substitutions
	 *   - FOO="ab", BAR="c"
	 *   - FOO="a",  BAR="bc"
	 * should give a different effective id.
	 *
	 * For example, with FOO="x" and BAR="x", the stable-ids
	 *   - "${FOO}${BAR}"
	 *   - "${BAR}${FOO}"
	 * should give a different effective id.
	 */

	idx_start = 0;
	for (i = 0; stable_id[i]; ) {
		if (stable_id[i] != '$') {
			i++;
			continue;
		}

#define CHECK_PREFIX(prefix) \
		({ \
			gboolean _match = FALSE; \
			\
			if (g_str_has_prefix (&stable_id[i], ""prefix"")) { \
				_match = TRUE; \
				if (!str) \
					str = g_string_sized_new (256); \
				i += NM_STRLEN (prefix); \
				g_string_append_len (str, &(stable_id)[idx_start], i - idx_start); \
				idx_start = i; \
			} \
			_match; \
		})
		if (CHECK_PREFIX ("${CONNECTION}"))
			_stable_id_append (str, uuid);
		else if (CHECK_PREFIX ("${BOOT}"))
			_stable_id_append (str, bootid);
		else if (CHECK_PREFIX ("${DEVICE}"))
			_stable_id_append (str, deviceid);
		else if (CHECK_PREFIX ("${MAC}"))
			_stable_id_append (str, hwaddr);
		else if (g_str_has_prefix (&stable_id[i], "${RANDOM}")) {
			/* RANDOM makes not so much sense for cloned-mac-address
			 * as the result is similar to specyifing "cloned-mac-address=random".
			 * It makes however sense for RFC 7217 Stable Privacy IPv6 addresses
			 * where this is effectively the only way to generate a different
			 * (random) host identifier for each connect.
			 *
			 * With RANDOM, the user can switch the lifetime of the
			 * generated cloned-mac-address and IPv6 host identifier
			 * by toggeling only the stable-id property of the connection.
			 * With RANDOM being the most short-lived, ~non-stable~ variant.
			 */
			if (str)
				g_string_free (str, TRUE);
			*out_generated = NULL;
			return NM_UTILS_STABLE_TYPE_RANDOM;
		} else {
			/* The text following the '$' is not recognized as valid
			 * substitution pattern. Treat it verbatim. */
			i++;

			/* Note that using unrecognized substitution patterns might
			 * yield different results with future versions. Avoid that,
			 * by not using '$' (except for actual substitutions) or escape
			 * it as "$$" (which is guaranteed to be treated verbatim
			 * in future). */
			if (stable_id[i] == '$')
				i++;
		}
	}
#undef CHECK_PREFIX

	if (!str) {
		*out_generated = NULL;
		return NM_UTILS_STABLE_TYPE_STABLE_ID;
	}

	if (idx_start < i)
		g_string_append_len (str, &stable_id[idx_start], i - idx_start);
	*out_generated = g_string_free (str, FALSE);
	return NM_UTILS_STABLE_TYPE_GENERATED;
}

/*****************************************************************************/

static gboolean
_is_reserved_ipv6_iid (const guint8 *iid)
{
	/* https://tools.ietf.org/html/rfc5453 */
	/* https://www.iana.org/assignments/ipv6-interface-ids/ipv6-interface-ids.xml */

	/* 0000:0000:0000:0000 (Subnet-Router Anycast [RFC4291]) */
	if (memcmp (iid, &nm_ip_addr_zero.addr6.s6_addr[8], 8) == 0)
		return TRUE;

	/* 0200:5EFF:FE00:0000 - 0200:5EFF:FE00:5212 (Reserved IPv6 Interface Identifiers corresponding to the IANA Ethernet Block [RFC4291])
	 * 0200:5EFF:FE00:5213                       (Proxy Mobile IPv6 [RFC6543])
	 * 0200:5EFF:FE00:5214 - 0200:5EFF:FEFF:FFFF (Reserved IPv6 Interface Identifiers corresponding to the IANA Ethernet Block [RFC4291]) */
	if (memcmp (iid, (const guint8[]) { 0x02, 0x00, 0x5E, 0xFF, 0xFE }, 5) == 0)
		return TRUE;

	/* FDFF:FFFF:FFFF:FF80 - FDFF:FFFF:FFFF:FFFF (Reserved Subnet Anycast Addresses [RFC2526]) */
	if (memcmp (iid, (const guint8[]) { 0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, 7) == 0) {
		if (iid[7] & 0x80)
			return TRUE;
	}

	return FALSE;
}

static gboolean
_set_stable_privacy (NMUtilsStableType stable_type,
                     struct in6_addr *addr,
                     const char *ifname,
                     const char *network_id,
                     guint32 dad_counter,
                     const guint8 *host_id,
                     gsize host_id_len,
                     GError **error)
{
	nm_auto_free_checksum GChecksum *sum = NULL;
	guint8 digest[NM_UTILS_CHECKSUM_LENGTH_SHA256];
	guint32 tmp[2];

	nm_assert (host_id_len);
	nm_assert (network_id);

	sum = g_checksum_new (G_CHECKSUM_SHA256);

	host_id_len = MIN (host_id_len, G_MAXUINT32);

	if (stable_type != NM_UTILS_STABLE_TYPE_UUID) {
		guint8 stable_type_uint8;

		nm_assert (stable_type < (NMUtilsStableType) 255);
		stable_type_uint8 = (guint8) stable_type;

		/* Preferably, we would always like to include the stable-type,
		 * but for backward compatibility reasons, we cannot for UUID.
		 *
		 * That is no real problem and it is still impossible to
		 * force a collision here, because of how the remaining
		 * fields are hashed. That is, as we also hash @host_id_len
		 * and the terminating '\0' of @network_id, it is unambigiously
		 * possible to revert the process and deduce the @stable_type.
		 */
		g_checksum_update (sum, &stable_type_uint8, sizeof (stable_type_uint8));
	}

	g_checksum_update (sum, addr->s6_addr, 8);
	g_checksum_update (sum, (const guchar *) ifname, strlen (ifname) + 1);
	g_checksum_update (sum, (const guchar *) network_id, strlen (network_id) + 1);
	tmp[0] = htonl (dad_counter);
	tmp[1] = htonl (host_id_len);
	g_checksum_update (sum, (const guchar *) tmp, sizeof (tmp));
	g_checksum_update (sum, (const guchar *) host_id, host_id_len);
	nm_utils_checksum_get_digest (sum, digest);

	while (_is_reserved_ipv6_iid (digest)) {
		g_checksum_reset (sum);
		tmp[0] = htonl (++dad_counter);
		g_checksum_update (sum, digest, sizeof (digest));
		g_checksum_update (sum, (const guchar *) &tmp[0], sizeof (tmp[0]));
		nm_utils_checksum_get_digest (sum, digest);
	}

	memcpy (addr->s6_addr + 8, &digest[0], 8);
	return TRUE;
}

gboolean
nm_utils_ipv6_addr_set_stable_privacy_impl (NMUtilsStableType stable_type,
                                            struct in6_addr *addr,
                                            const char *ifname,
                                            const char *network_id,
                                            guint32 dad_counter,
                                            guint8 *host_id,
                                            gsize host_id_len,
                                            GError **error)
{
	return _set_stable_privacy (stable_type, addr, ifname, network_id, dad_counter, host_id, host_id_len, error);
}

#define RFC7217_IDGEN_RETRIES 3
/**
 * nm_utils_ipv6_addr_set_stable_privacy:
 *
 * Extend the address prefix with an interface identifier using the
 * RFC 7217 Stable Privacy mechanism.
 *
 * Returns: %TRUE on success, %FALSE if the address could not be generated.
 */
gboolean
nm_utils_ipv6_addr_set_stable_privacy (NMUtilsStableType stable_type,
                                       struct in6_addr *addr,
                                       const char *ifname,
                                       const char *network_id,
                                       guint32 dad_counter,
                                       GError **error)
{
	const guint8 *host_id;
	gsize host_id_len;

	g_return_val_if_fail (network_id, FALSE);

	if (dad_counter >= RFC7217_IDGEN_RETRIES) {
		g_set_error_literal (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		                     "Too many DAD collisions");
		return FALSE;
	}

	nm_utils_host_id_get (&host_id, &host_id_len);

	return _set_stable_privacy (stable_type, addr, ifname, network_id, dad_counter,
	                            host_id, host_id_len, error);
}

/*****************************************************************************/

static void
_hw_addr_eth_complete (struct ether_addr *addr,
                       const char *current_mac_address,
                       const char *generate_mac_address_mask)
{
	struct ether_addr mask;
	struct ether_addr oui;
	struct ether_addr *ouis;
	gsize ouis_len;
	guint i;

	/* the second LSB of the first octet means
	 * "globally unique, OUI enforced, BIA (burned-in-address)"
	 * vs. "locally-administered". By default, set it to
	 * generate locally-administered addresses.
	 *
	 * Maybe be overwritten by a mask below. */
	addr->ether_addr_octet[0] |= 2;

	if (!generate_mac_address_mask || !*generate_mac_address_mask)
		goto out;
	if (!_nm_utils_generate_mac_address_mask_parse (generate_mac_address_mask,
	                                                &mask,
	                                                &ouis,
	                                                &ouis_len,
	                                                NULL))
		goto out;

	nm_assert ((ouis == NULL) ^ (ouis_len != 0));
	if (ouis) {
		/* g_random_int() is good enough here. It uses a static GRand instance
		 * that is seeded from /dev/urandom. */
		oui = ouis[g_random_int () % ouis_len];
		g_free (ouis);
	} else {
		if (!nm_utils_hwaddr_aton (current_mac_address, &oui, ETH_ALEN))
			goto out;
	}

	for (i = 0; i < ETH_ALEN; i++) {
		const guint8 a = addr->ether_addr_octet[i];
		const guint8 o = oui.ether_addr_octet[i];
		const guint8 m = mask.ether_addr_octet[i];

		addr->ether_addr_octet[i] = (a & ~m) | (o & m);
	}

out:
	/* The LSB of the first octet must always be cleared,
	 * it means Unicast vs. Multicast */
	addr->ether_addr_octet[0] &= ~1;
}

char *
nm_utils_hw_addr_gen_random_eth (const char *current_mac_address,
                                 const char *generate_mac_address_mask)
{
	struct ether_addr bin_addr;

	nm_utils_random_bytes (&bin_addr, ETH_ALEN);
	_hw_addr_eth_complete (&bin_addr, current_mac_address, generate_mac_address_mask);
	return nm_utils_hwaddr_ntoa (&bin_addr, ETH_ALEN);
}

static char *
_hw_addr_gen_stable_eth (NMUtilsStableType stable_type,
                         const char *stable_id,
                         const guint8 *host_id,
                         gsize host_id_len,
                         const char *ifname,
                         const char *current_mac_address,
                         const char *generate_mac_address_mask)
{
	nm_auto_free_checksum GChecksum *sum = NULL;
	guint32 tmp;
	guint8 digest[NM_UTILS_CHECKSUM_LENGTH_SHA256];
	struct ether_addr bin_addr;
	guint8 stable_type_uint8;

	nm_assert (stable_id);
	nm_assert (host_id);

	sum = g_checksum_new (G_CHECKSUM_SHA256);

	host_id_len = MIN (host_id_len, G_MAXUINT32);

	nm_assert (stable_type < (NMUtilsStableType) 255);
	stable_type_uint8 = stable_type;
	g_checksum_update (sum, (const guchar *) &stable_type_uint8, sizeof (stable_type_uint8));

	tmp = htonl ((guint32) host_id_len);
	g_checksum_update (sum, (const guchar *) &tmp, sizeof (tmp));
	g_checksum_update (sum, (const guchar *) host_id, host_id_len);
	g_checksum_update (sum, (const guchar *) (ifname ?: ""), ifname ? (strlen (ifname) + 1) : 1);
	g_checksum_update (sum, (const guchar *) stable_id, strlen (stable_id) + 1);

	nm_utils_checksum_get_digest (sum, digest);

	memcpy (&bin_addr, digest, ETH_ALEN);
	_hw_addr_eth_complete (&bin_addr, current_mac_address, generate_mac_address_mask);
	return nm_utils_hwaddr_ntoa (&bin_addr, ETH_ALEN);
}

char *
nm_utils_hw_addr_gen_stable_eth_impl (NMUtilsStableType stable_type,
                                      const char *stable_id,
                                      const guint8 *host_id,
                                      gsize host_id_len,
                                      const char *ifname,
                                      const char *current_mac_address,
                                      const char *generate_mac_address_mask)
{
	return _hw_addr_gen_stable_eth (stable_type, stable_id, host_id, host_id_len, ifname, current_mac_address, generate_mac_address_mask);
}

char *
nm_utils_hw_addr_gen_stable_eth (NMUtilsStableType stable_type,
                                 const char *stable_id,
                                 const char *ifname,
                                 const char *current_mac_address,
                                 const char *generate_mac_address_mask)
{
	const guint8 *host_id;
	gsize host_id_len;

	g_return_val_if_fail (stable_id, NULL);

	nm_utils_host_id_get (&host_id, &host_id_len);

	return _hw_addr_gen_stable_eth (stable_type,
	                                stable_id,
	                                host_id,
	                                host_id_len,
	                                ifname,
	                                current_mac_address,
	                                generate_mac_address_mask);
}

/*****************************************************************************/

GBytes *
nm_utils_dhcp_client_id_mac (int arp_type,
                             const guint8 *hwaddr,
                             gsize hwaddr_len)
{
	guint8 *client_id_buf;
	const guint8 hwaddr_type = arp_type;

	if (!nm_utils_arp_type_get_hwaddr_relevant_part (arp_type, &hwaddr, &hwaddr_len))
		g_return_val_if_reached (NULL);

	client_id_buf = g_malloc (hwaddr_len + 1);
	client_id_buf[0] = hwaddr_type;
	memcpy (&client_id_buf[1], hwaddr, hwaddr_len);
	return g_bytes_new_take (client_id_buf, hwaddr_len + 1);
}

#define HASH_KEY ((const guint8[16]) { 0x80, 0x11, 0x8c, 0xc2, 0xfe, 0x4a, 0x03, 0xee, 0x3e, 0xd6, 0x0c, 0x6f, 0x36, 0x39, 0x14, 0x09 })

/**
 * nm_utils_create_dhcp_iaid:
 * @legacy_unstable_byteorder: legacy behavior is to generate a u32 iaid which
 *   is endianness dependent. This is to preserve backward compatibility.
 *   For non-legacy behavior, the returned integer is in stable endianness,
 *   and corresponds to legacy behavior on little endian systems.
 * @interface_id: the seed for hashing when generating the ID. Usually,
 *   this is the interface name.
 * @interface_id_len: length of @interface_id
 *
 * This corresponds to systemd's dhcp_identifier_set_iaid() for generating
 * a IAID for the interface.
 *
 * Returns: the IAID in host byte order. */
guint32
nm_utils_create_dhcp_iaid (gboolean legacy_unstable_byteorder,
                           const guint8 *interface_id,
                           gsize interface_id_len)
{
	guint64 u64;
	guint32 u32;

	u64 = c_siphash_hash (HASH_KEY, interface_id, interface_id_len);
	u32 = (u64 & 0xffffffffu) ^ (u64 >> 32);
	if (legacy_unstable_byteorder) {
		/* legacy systemd code dhcp_identifier_set_iaid() generates the iaid
		 * dependent on the host endianness. Since this function returns the IAID
		 * in native-byte order, we need to account for that.
		 *
		 * On little endian systems, we want the legacy-behavior is identical to
		 * the endianness-agnostic behavior. So, we need to swap the bytes on
		 * big-endian systems.
		 *
		 * (https://github.com/systemd/systemd/pull/10614). */
		return htole32 (u32);
	} else {
		/* we return the value as-is, in native byte order. */
		return u32;
	}
}

/**
 * nm_utils_dhcp_client_id_systemd_node_specific_full:
 * @legacy_unstable_byteorder: historically, the code would generate a iaid
 *   dependent on host endianness. This is undesirable, if backward compatibility
 *   are not a concern, generate stable endianness.
 * @interface_id: a binary identifier that is hashed into the DUID.
 *   Comonly this is the interface-name, but it may be the MAC address.
 * @interface_id_len: the length of @interface_id.
 * @machine_id: the binary identifier for the machine. It is hashed
 *   into the DUID. It commonly is /etc/machine-id (parsed in binary as NMUuid).
 * @machine_id_len: the length of the @machine_id.
 *
 * Systemd's sd_dhcp_client generates a default client ID (type 255, node-specific,
 * RFC 4361) if no explicit client-id is set. This function duplicates that
 * implementation and exposes it as (internal) API.
 *
 * Returns: a %GBytes of generated client-id. This function cannot fail.
 */
GBytes *
nm_utils_dhcp_client_id_systemd_node_specific_full (gboolean legacy_unstable_byteorder,
                                                    const guint8 *interface_id,
                                                    gsize interface_id_len,
                                                    const guint8 *machine_id,
                                                    gsize machine_id_len)
{
	const guint16 DUID_TYPE_EN = 2;
	const guint32 SYSTEMD_PEN = 43793;
	struct _nm_packed {
		guint8 type;
		guint32 iaid;
		struct _nm_packed {
			guint16 type;
			union {
				struct _nm_packed {
						/* DUID_TYPE_EN */
						guint32 pen;
						uint8_t id[8];
				} en;
			};
		} duid;
	} *client_id;
	guint64 u64;
	guint32 u32;

	g_return_val_if_fail (interface_id, NULL);
	g_return_val_if_fail (interface_id_len > 0, NULL);
	g_return_val_if_fail (machine_id, NULL);
	g_return_val_if_fail (machine_id_len > 0, NULL);

	client_id = g_malloc (sizeof (*client_id));

	client_id->type = 255;

	u32 = nm_utils_create_dhcp_iaid (legacy_unstable_byteorder,
	                                 interface_id,
	                                 interface_id_len);
	unaligned_write_be32 (&client_id->iaid, u32);

	unaligned_write_be16 (&client_id->duid.type, DUID_TYPE_EN);

	unaligned_write_be32 (&client_id->duid.en.pen, SYSTEMD_PEN);

	u64 = htole64 (c_siphash_hash (HASH_KEY, machine_id, machine_id_len));
	memcpy(client_id->duid.en.id, &u64, sizeof (client_id->duid.en.id));

	G_STATIC_ASSERT_EXPR (sizeof (*client_id) == 19);
	return g_bytes_new_take (client_id, 19);
}

GBytes *
nm_utils_dhcp_client_id_systemd_node_specific (gboolean legacy_unstable_byteorder,
                                               const char *ifname)
{
	g_return_val_if_fail (ifname && ifname[0], NULL);

	return nm_utils_dhcp_client_id_systemd_node_specific_full (legacy_unstable_byteorder,
	                                                           (const guint8 *) ifname,
	                                                           strlen (ifname),
	                                                           (const guint8 *) nm_utils_machine_id_bin (),
	                                                           sizeof (NMUuid));
}

/*****************************************************************************/

/**
 * nm_utils_setpgid:
 * @unused: unused
 *
 * This can be passed as a child setup function to the g_spawn*() family
 * of functions, to ensure that the child is in its own process group
 * (and thus, in some situations, will not be killed when NetworkManager
 * is killed).
 */
void
nm_utils_setpgid (gpointer unused G_GNUC_UNUSED)
{
	pid_t pid;

	pid = getpid ();
	setpgid (pid, pid);
}

/**
 * nm_utils_g_value_set_strv:
 * @value: a #GValue, initialized to store a #G_TYPE_STRV
 * @strings: a #GPtrArray of strings. %NULL values are not
 *   allowed.
 *
 * Converts @strings to a #GStrv and stores it in @value.
 */
void
nm_utils_g_value_set_strv (GValue *value, GPtrArray *strings)
{
	char **strv;
	guint i;

	strv = g_new (char *, strings->len + 1);
	for (i = 0; i < strings->len; i++) {
		nm_assert (strings->pdata[i]);
		strv[i] = g_strdup (strings->pdata[i]);
	}
	strv[i] = NULL;

	g_value_take_boxed (value, strv);
}

/*****************************************************************************/

static gboolean
debug_key_matches (const char *key,
                   const char *token,
                   guint        length)
{
	/* may not call GLib functions: see note in g_parse_debug_string() */
	for (; length; length--, key++, token++) {
		char k = (*key   == '_') ? '-' : g_ascii_tolower (*key  );
		char t = (*token == '_') ? '-' : g_ascii_tolower (*token);

		if (k != t)
			return FALSE;
	}

	return *key == '\0';
}

/**
 * nm_utils_parse_debug_string:
 * @string: the string to parse
 * @keys: the debug keys
 * @nkeys: number of entries in @keys
 *
 * Similar to g_parse_debug_string(), but does not special
 * case "help" or "all".
 *
 * Returns: the flags
 */
guint
nm_utils_parse_debug_string (const char *string,
                             const GDebugKey *keys,
                             guint nkeys)
{
	guint i;
	guint result = 0;
	const char *q;

	if (string == NULL)
		return 0;

	while (*string) {
		q = strpbrk (string, ":;, \t");
		if (!q)
			q = string + strlen (string);

		for (i = 0; i < nkeys; i++) {
			if (debug_key_matches (keys[i].key, string, q - string))
				result |= keys[i].value;
		}

		string = q;
		if (*string)
			string++;
	}

	return result;
}

/*****************************************************************************/

void
nm_utils_ifname_cpy (char *dst, const char *name)
{
	g_return_if_fail (dst);
	g_return_if_fail (name && name[0]);

	nm_assert (nm_utils_is_valid_iface_name (name, NULL));

	if (g_strlcpy (dst, name, IFNAMSIZ) >= IFNAMSIZ)
		g_return_if_reached ();
}

/*****************************************************************************/

#define IPV4LL_NETWORK (htonl (0xA9FE0000L))
#define IPV4LL_NETMASK (htonl (0xFFFF0000L))

gboolean
nm_utils_ip4_address_is_link_local (in_addr_t addr)
{
	return (addr & IPV4LL_NETMASK) == IPV4LL_NETWORK;
}

/*****************************************************************************/

/**
 * Takes a pair @timestamp and @duration, and returns the remaining duration based
 * on the new timestamp @now.
 */
guint32
nm_utils_lifetime_rebase_relative_time_on_now (guint32 timestamp,
                                               guint32 duration,
                                               gint32 now)
{
	gint64 t;

	nm_assert (now >= 0);

	if (duration == NM_PLATFORM_LIFETIME_PERMANENT)
		return NM_PLATFORM_LIFETIME_PERMANENT;

	if (timestamp == 0) {
		/* if the @timestamp is zero, assume it was just left unset and that the relative
		 * @duration starts counting from @now. This is convenient to construct an address
		 * and print it in nm_platform_ip4_address_to_string().
		 *
		 * In general it does not make sense to set the @duration without anchoring at
		 * @timestamp because you don't know the absolute expiration time when looking
		 * at the address at a later moment. */
		timestamp = now;
	}

	/* For timestamp > now, just accept it and calculate the expected(?) result. */
	t = (gint64) timestamp + (gint64) duration - (gint64) now;

	if (t <= 0)
		return 0;
	if (t >= NM_PLATFORM_LIFETIME_PERMANENT)
		return NM_PLATFORM_LIFETIME_PERMANENT - 1;
	return t;
}

guint32
nm_utils_lifetime_get (guint32 timestamp,
                       guint32 lifetime,
                       guint32 preferred,
                       gint32 now,
                       guint32 *out_preferred)
{
	guint32 t_lifetime, t_preferred;

	nm_assert (now >= 0);

	if (timestamp == 0 && lifetime == 0) {
		/* We treat lifetime==0 && timestamp==0 addresses as permanent addresses to allow easy
		 * creation of such addresses (without requiring to set the lifetime fields to
		 * NM_PLATFORM_LIFETIME_PERMANENT). The real lifetime==0 addresses (E.g. DHCP6 telling us
		 * to drop an address will have timestamp set.
		 */
		NM_SET_OUT (out_preferred, NM_PLATFORM_LIFETIME_PERMANENT);
		g_return_val_if_fail (preferred == 0, NM_PLATFORM_LIFETIME_PERMANENT);
		return NM_PLATFORM_LIFETIME_PERMANENT;
	}

	if (now <= 0)
		now = nm_utils_get_monotonic_timestamp_s ();

	t_lifetime = nm_utils_lifetime_rebase_relative_time_on_now (timestamp, lifetime, now);
	if (!t_lifetime) {
		NM_SET_OUT (out_preferred, 0);
		return 0;
	}

	t_preferred = nm_utils_lifetime_rebase_relative_time_on_now (timestamp, preferred, now);

	NM_SET_OUT (out_preferred, MIN (t_preferred, t_lifetime));

	/* Assert that non-permanent addresses have a (positive) @timestamp. nm_utils_lifetime_rebase_relative_time_on_now()
	 * treats addresses with timestamp 0 as *now*. Addresses passed to _address_get_lifetime() always
	 * should have a valid @timestamp, otherwise on every re-sync, their lifetime will be extended anew.
	 */
	g_return_val_if_fail (   timestamp != 0
	                      || (   lifetime  == NM_PLATFORM_LIFETIME_PERMANENT
	                          && preferred == NM_PLATFORM_LIFETIME_PERMANENT), t_lifetime);
	g_return_val_if_fail (t_preferred <= t_lifetime, t_lifetime);

	return t_lifetime;
}

const char *
nm_utils_dnsmasq_status_to_string (int status, char *dest, gsize size)
{
	const char *msg;

	nm_utils_to_string_buffer_init (&dest, &size);

	if (status == 0)
		msg = "Success";
	else if (status == 1)
		msg = "Configuration problem";
	else if (status == 2)
		msg = "Network access problem (address in use, permissions)";
	else if (status == 3)
		msg = "Filesystem problem (missing file/directory, permissions)";
	else if (status == 4)
		msg = "Memory allocation failure";
	else if (status == 5)
		msg = "Other problem";
	else if (status >= 11) {
		g_snprintf (dest, size, "Lease script failed with error %d", status - 10);
		return dest;
	}
	else
		msg = "Unknown problem";

	g_snprintf (dest, size, "%s (%d)", msg, status);
	return dest;
}

/**
 * nm_utils_get_reverse_dns_domains_ip4:
 * @addr: IP address in network order
 * @plen: prefix length
 * @domains: array for results
 *
 * Creates reverse DNS domains for the given address and prefix length, and
 * append them to @domains.
 */
void
nm_utils_get_reverse_dns_domains_ip4 (guint32 addr, guint8 plen, GPtrArray *domains)
{
	guint32 ip, ip2, mask;
	guchar *p;
	guint octets;
	guint i;
	gsize len0, len;
	char *str, *s;

	g_return_if_fail (domains);
	g_return_if_fail (plen <= 32);

	if (!plen)
		return;

	octets = (plen - 1) / 8 + 1;
	ip = ntohl (addr);
	mask = 0xFFFFFFFF << (32 - plen);
	ip &= mask;
	ip2 = ip;

	len0 = NM_STRLEN ("in-addr.arpa") + (4 * octets) + 1;
	while ((ip2 & mask) == ip) {
		addr = htonl (ip2);
		p = (guchar *) &addr;

		len = len0;
		str = s = g_malloc (len);
		for (i = octets; i > 0; i--)
			nm_utils_strbuf_append (&s, &len, "%u.", p[i - 1] & 0xff);
		nm_utils_strbuf_append_str (&s, &len, "in-addr.arpa");

		g_ptr_array_add (domains, str);

		ip2 += 1 << ((32 - plen) & ~7);
	}
}

/**
 * nm_utils_get_reverse_dns_domains_ip6:
 * @addr: IPv6 address
 * @plen: prefix length
 * @domains: array for results
 *
 * Creates reverse DNS domains for the given address and prefix length, and
 * append them to @domains.
 */
void
nm_utils_get_reverse_dns_domains_ip6 (const struct in6_addr *ip, guint8 plen, GPtrArray *domains)
{
	struct in6_addr addr;
	guint nibbles, bits, entries;
	int i, j;
	gsize len0, len;
	char *str, *s;

	g_return_if_fail (domains);
	g_return_if_fail (plen <= 128);

	if (!plen)
		return;

	memcpy (&addr, ip, sizeof (struct in6_addr));
	nm_utils_ip6_address_clear_host_address (&addr, NULL, plen);

	/* Number of nibbles to include in domains */
	nibbles = (plen - 1) / 4 + 1;
	/* Prefix length in nibble */
	bits = plen - ((plen - 1) / 4 * 4);
	/* Number of domains */
	entries = 1 << (4 - bits);

	len0 = NM_STRLEN ("ip6.arpa") + (2 * nibbles) + 1;

#define N_SHIFT(x) ((x) % 2 ? 0 : 4)

	for (i = 0; i < entries; i++) {
		len = len0;
		str = s = g_malloc (len);

		for (j = nibbles - 1; j >= 0; j--)
			nm_utils_strbuf_append (&s,
			                        &len,
			                        "%x.",
			                        (addr.s6_addr[j / 2] >> N_SHIFT (j)) & 0xf);
		nm_utils_strbuf_append_str (&s, &len, "ip6.arpa");

		g_ptr_array_add (domains, str);

		addr.s6_addr[(nibbles - 1) / 2] += 1 << N_SHIFT (nibbles - 1);
	}

#undef N_SHIFT
}

struct plugin_info {
	char *path;
	struct stat st;
};

static int
read_device_factory_paths_sort_fcn (gconstpointer a, gconstpointer b)
{
	const struct plugin_info *da = a;
	const struct plugin_info *db = b;
	time_t ta, tb;

	ta = MAX (da->st.st_mtime, da->st.st_ctime);
	tb = MAX (db->st.st_mtime, db->st.st_ctime);

	if (ta < tb)
		return 1;
	if (ta > tb)
		return -1;
	return 0;
}

gboolean
nm_utils_validate_plugin (const char *path, struct stat *st, GError **error)
{
	g_return_val_if_fail (path, FALSE);
	g_return_val_if_fail (st, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	if (!S_ISREG (st->st_mode)) {
		g_set_error_literal (error,
		                     NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		                     "not a regular file");
		return FALSE;
	}

	if (st->st_uid != 0) {
		g_set_error_literal (error,
		                     NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		                     "file has invalid owner (should be root)");
		return FALSE;
	}

	if (st->st_mode & (S_IWGRP | S_IWOTH | S_ISUID)) {
		g_set_error_literal (error,
		                     NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		                     "file has invalid permissions");
		return FALSE;
	}

	return TRUE;
}

char **
nm_utils_read_plugin_paths (const char *dirname, const char *prefix)
{
	GDir *dir;
	GError *error = NULL;
	const char *item;
	GArray *paths;
	char **result;
	guint i;

	g_return_val_if_fail (dirname, NULL);
	g_return_val_if_fail (prefix, NULL);

	dir = g_dir_open (dirname, 0, &error);
	if (!dir) {
		nm_log_warn (LOGD_CORE, "device plugin: failed to open directory %s: %s",
		             dirname,
		             error->message);
		g_clear_error (&error);
		return NULL;
	}

	paths = g_array_new (FALSE, FALSE, sizeof (struct plugin_info));

	while ((item = g_dir_read_name (dir))) {
		int errsv;
		struct plugin_info data;

		if (!g_str_has_prefix (item, prefix))
			continue;
		if (!g_str_has_suffix (item, ".so"))
			continue;

		data.path = g_build_filename (dirname, item, NULL);

		if (stat (data.path, &data.st) != 0) {
			errsv = errno;
			nm_log_warn (LOGD_CORE,
			             "plugin: skip invalid file %s (error during stat: %s)",
			             data.path, nm_strerror_native (errsv));
			goto skip;
		}

		if (!nm_utils_validate_plugin (data.path, &data.st, &error)) {
			nm_log_warn (LOGD_CORE,
			             "plugin: skip invalid file %s: %s",
			             data.path, error->message);
			g_clear_error (&error);
			goto skip;
		}

		g_array_append_val (paths, data);
		continue;
skip:
		g_free (data.path);
	}
	g_dir_close (dir);

	/* sort filenames by modification time. */
	g_array_sort (paths, read_device_factory_paths_sort_fcn);

	result = g_new (char *, paths->len + 1);
	for (i = 0; i < paths->len; i++)
		result[i] = g_array_index (paths, struct plugin_info, i).path;
	result[i] = NULL;

	g_array_free (paths, TRUE);
	return result;
}

char *
nm_utils_format_con_diff_for_audit (GHashTable *diff)
{
	GHashTable *setting_diff;
	char *setting_name, *prop_name;
	GHashTableIter iter, iter2;
	GString *str;

	str = g_string_sized_new (32);
	g_hash_table_iter_init (&iter, diff);

	while (g_hash_table_iter_next (&iter,
	                               (gpointer *) &setting_name,
	                               (gpointer *) &setting_diff)) {
		if (!setting_diff)
			continue;

		g_hash_table_iter_init (&iter2, setting_diff);

		while (g_hash_table_iter_next (&iter2, (gpointer *) &prop_name, NULL))
			g_string_append_printf (str, "%s.%s,", setting_name, prop_name);
	}

	if (str->len)
		str->str[str->len - 1] = '\0';

	return g_string_free (str, FALSE);
}

const char *
nm_utils_parse_dns_domain (const char *domain, gboolean *is_routing)
{
	g_return_val_if_fail (domain, NULL);
	g_return_val_if_fail (domain[0], NULL);

	if (domain[0] == '~') {
		domain++;
		NM_SET_OUT (is_routing, TRUE);
	} else
		NM_SET_OUT (is_routing, FALSE);

	return domain;
}

/*****************************************************************************/

GVariant *
nm_utils_strdict_to_variant (GHashTable *options)
{
	GVariantBuilder builder;
	gs_free const char **keys = NULL;
	guint i;
	guint nkeys;

	keys = nm_utils_strdict_get_keys (options, TRUE, &nkeys);

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));
	for (i = 0; i < nkeys; i++) {
		g_variant_builder_add (&builder,
		                       "{sv}",
		                       keys[i],
		                       g_variant_new_string (g_hash_table_lookup (options, keys[i])));
	}
	return g_variant_builder_end (&builder);
}

/*****************************************************************************/

NM_UTILS_ENUM2STR_DEFINE (nm_icmpv6_router_pref_to_string, NMIcmpv6RouterPref,
	NM_UTILS_ENUM2STR (NM_ICMPV6_ROUTER_PREF_LOW,     "low"),
	NM_UTILS_ENUM2STR (NM_ICMPV6_ROUTER_PREF_MEDIUM,  "medium"),
	NM_UTILS_ENUM2STR (NM_ICMPV6_ROUTER_PREF_HIGH,    "high"),
	NM_UTILS_ENUM2STR (NM_ICMPV6_ROUTER_PREF_INVALID, "invalid"),
);

NM_UTILS_LOOKUP_STR_DEFINE (nm_activation_type_to_string, NMActivationType,
	NM_UTILS_LOOKUP_DEFAULT_WARN ("(unknown)"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_ACTIVATION_TYPE_MANAGED,  "managed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_ACTIVATION_TYPE_ASSUME,   "assume"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_ACTIVATION_TYPE_EXTERNAL, "external"),
)
