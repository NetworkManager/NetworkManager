/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright (C) 2005 - 2010 Red Hat, Inc.
 *
 */

#include "nm-default.h"

#include "nm-dhcp-client.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/rtnetlink.h>

#include "nm-glib-aux/nm-dedup-multi.h"
#include "nm-glib-aux/nm-random-utils.h"

#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-dhcp-utils.h"
#include "platform/nm-platform.h"

#include "nm-dhcp-client-logging.h"

/*****************************************************************************/

enum {
	SIGNAL_STATE_CHANGED,
	SIGNAL_PREFIX_DELEGATED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

NM_GOBJECT_PROPERTIES_DEFINE (NMDhcpClient,
	PROP_ADDR_FAMILY,
	PROP_FLAGS,
	PROP_HWADDR,
	PROP_BROADCAST_HWADDR,
	PROP_IFACE,
	PROP_IFINDEX,
	PROP_MULTI_IDX,
	PROP_ROUTE_METRIC,
	PROP_ROUTE_TABLE,
	PROP_TIMEOUT,
	PROP_UUID,
	PROP_HOSTNAME,
);

typedef struct _NMDhcpClientPrivate {
	NMDedupMultiIndex *multi_idx;
	char *       iface;
	GBytes *     hwaddr;
	GBytes *     bcast_hwaddr;
	char *       uuid;
	GBytes *     client_id;
	char *       hostname;
	pid_t        pid;
	guint        timeout_id;
	guint        watch_id;
	int          addr_family;
	int          ifindex;
	guint32      route_table;
	guint32      route_metric;
	guint32      timeout;
	NMDhcpState  state;
	bool         info_only:1;
	bool         use_fqdn:1;
} NMDhcpClientPrivate;

G_DEFINE_TYPE_EXTENDED (NMDhcpClient, nm_dhcp_client, G_TYPE_OBJECT, G_TYPE_FLAG_ABSTRACT, {})

#define NM_DHCP_CLIENT_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR (self, NMDhcpClient, NM_IS_DHCP_CLIENT)

/*****************************************************************************/

pid_t
nm_dhcp_client_get_pid (NMDhcpClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), -1);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->pid;
}

NMDedupMultiIndex *
nm_dhcp_client_get_multi_idx (NMDhcpClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), NULL);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->multi_idx;
}

const char *
nm_dhcp_client_get_iface (NMDhcpClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), NULL);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->iface;
}

int
nm_dhcp_client_get_ifindex (NMDhcpClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), -1);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->ifindex;
}

int
nm_dhcp_client_get_addr_family (NMDhcpClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), AF_UNSPEC);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->addr_family;
}

const char *
nm_dhcp_client_get_uuid (NMDhcpClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), NULL);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->uuid;
}

GBytes *
nm_dhcp_client_get_hw_addr (NMDhcpClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), NULL);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->hwaddr;
}

GBytes *
nm_dhcp_client_get_broadcast_hw_addr (NMDhcpClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), NULL);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->bcast_hwaddr;
}

guint32
nm_dhcp_client_get_route_table (NMDhcpClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), RT_TABLE_MAIN);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->route_table;
}

void
nm_dhcp_client_set_route_table (NMDhcpClient *self, guint32 route_table)
{
	NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	if (route_table != priv->route_table) {
		priv->route_table = route_table;
		_notify (self, PROP_ROUTE_TABLE);
	}
}

guint32
nm_dhcp_client_get_route_metric (NMDhcpClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), G_MAXUINT32);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->route_metric;
}

void
nm_dhcp_client_set_route_metric (NMDhcpClient *self, guint32 route_metric)
{
	NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	if (route_metric != priv->route_metric) {
		priv->route_metric = route_metric;
		_notify (self, PROP_ROUTE_METRIC);
	}
}

guint32
nm_dhcp_client_get_timeout (NMDhcpClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), 0);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->timeout;
}

GBytes *
nm_dhcp_client_get_client_id (NMDhcpClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), NULL);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->client_id;
}

static void
_set_client_id (NMDhcpClient *self, GBytes *client_id, gboolean take)
{
	NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	nm_assert (!client_id || g_bytes_get_size (client_id) >= 2);

	if (   priv->client_id == client_id
	    || (   priv->client_id
	        && client_id
	        && g_bytes_equal (priv->client_id, client_id))) {
		if (take && client_id)
			g_bytes_unref (client_id);
		return;
	}

	if (priv->client_id)
		g_bytes_unref (priv->client_id);
	priv->client_id = client_id;
	if (!take && client_id)
		g_bytes_ref (client_id);

	{
		gs_free char *s = NULL;

		_LOGT ("%s: set %s",
		       nm_dhcp_client_get_addr_family (self) == AF_INET6
		         ? "duid"
		         : "client-id",
		       priv->client_id
		         ? (s = nm_dhcp_utils_duid_to_string (priv->client_id))
		         : "default");
	}
}

void
nm_dhcp_client_set_client_id (NMDhcpClient *self, GBytes *client_id)
{
	g_return_if_fail (NM_IS_DHCP_CLIENT (self));
	g_return_if_fail (!client_id || g_bytes_get_size (client_id) >= 2);

	_set_client_id (self, client_id, FALSE);
}

void
nm_dhcp_client_set_client_id_bin (NMDhcpClient *self,
                                  guint8 type,
                                  const guint8 *client_id,
                                  gsize len)
{
	guint8 *buf;
	GBytes *b;

	g_return_if_fail (NM_IS_DHCP_CLIENT (self));
	g_return_if_fail (client_id);
	g_return_if_fail (len > 0);

	buf = g_malloc (len + 1);
	buf[0] = type;
	memcpy (buf + 1, client_id, len);
	b = g_bytes_new_take (buf, len + 1);
	_set_client_id (self, b, TRUE);
}

const char *
nm_dhcp_client_get_hostname (NMDhcpClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), NULL);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->hostname;
}

gboolean
nm_dhcp_client_get_info_only (NMDhcpClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), FALSE);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->info_only;
}

gboolean
nm_dhcp_client_get_use_fqdn (NMDhcpClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), FALSE);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->use_fqdn;
}

/*****************************************************************************/

static const char *state_table[NM_DHCP_STATE_MAX + 1] = {
	[NM_DHCP_STATE_UNKNOWN]    = "unknown",
	[NM_DHCP_STATE_BOUND]      = "bound",
	[NM_DHCP_STATE_TIMEOUT]    = "timeout",
	[NM_DHCP_STATE_EXPIRE]     = "expire",
	[NM_DHCP_STATE_DONE]       = "done",
	[NM_DHCP_STATE_FAIL]       = "fail",
	[NM_DHCP_STATE_TERMINATED] = "terminated",
};

static const char *
state_to_string (NMDhcpState state)
{
	if ((gsize) state < G_N_ELEMENTS (state_table))
		return state_table[state];
	return NULL;
}

static NMDhcpState
reason_to_state (NMDhcpClient *self, const char *iface, const char *reason)
{
	if (g_ascii_strcasecmp (reason, "bound") == 0 ||
	    g_ascii_strcasecmp (reason, "bound6") == 0 ||
	    g_ascii_strcasecmp (reason, "renew") == 0 ||
	    g_ascii_strcasecmp (reason, "renew6") == 0 ||
	    g_ascii_strcasecmp (reason, "reboot") == 0 ||
	    g_ascii_strcasecmp (reason, "rebind") == 0 ||
	    g_ascii_strcasecmp (reason, "rebind6") == 0)
		return NM_DHCP_STATE_BOUND;
	else if (g_ascii_strcasecmp (reason, "timeout") == 0)
		return NM_DHCP_STATE_TIMEOUT;
	else if (g_ascii_strcasecmp (reason, "nak") == 0 ||
	         g_ascii_strcasecmp (reason, "expire") == 0 ||
	         g_ascii_strcasecmp (reason, "expire6") == 0)
		return NM_DHCP_STATE_EXPIRE;
	else if (g_ascii_strcasecmp (reason, "end") == 0)
		return NM_DHCP_STATE_DONE;
	else if (g_ascii_strcasecmp (reason, "fail") == 0 ||
	         g_ascii_strcasecmp (reason, "abend") == 0)
		return NM_DHCP_STATE_FAIL;

	_LOGD ("unmapped DHCP state '%s'", reason);
	return NM_DHCP_STATE_UNKNOWN;
}

/*****************************************************************************/

static void
timeout_cleanup (NMDhcpClient *self)
{
	NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	nm_clear_g_source (&priv->timeout_id);
}

static void
watch_cleanup (NMDhcpClient *self)
{
	NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	nm_clear_g_source (&priv->watch_id);
}

void
nm_dhcp_client_stop_pid (pid_t pid, const char *iface)
{
	char *name = iface ? g_strdup_printf ("dhcp-client-%s", iface) : NULL;

	g_return_if_fail (pid > 1);

	nm_utils_kill_child_sync (pid, SIGTERM, LOGD_DHCP, name ?: "dhcp-client", NULL,
	                          1000 / 2, 1000 / 20);
	g_free (name);
}

static void
stop (NMDhcpClient *self, gboolean release)
{
	NMDhcpClientPrivate *priv;

	g_return_if_fail (NM_IS_DHCP_CLIENT (self));

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	if (priv->pid > 0) {
		/* Clean up the watch handler since we're explicitly killing the daemon */
		watch_cleanup (self);
		nm_dhcp_client_stop_pid (priv->pid, priv->iface);
	}
	priv->pid = -1;
}

void
nm_dhcp_client_set_state (NMDhcpClient *self,
                          NMDhcpState new_state,
                          NMIPConfig *ip_config,
                          GHashTable *options)
{
	NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);
	gs_free char *event_id = NULL;

	if (new_state == NM_DHCP_STATE_BOUND) {
		g_return_if_fail (NM_IS_IP_CONFIG (ip_config, priv->addr_family));
		g_return_if_fail (options);
	} else {
		g_return_if_fail (!ip_config);
		g_return_if_fail (!options);
	}

	if (new_state >= NM_DHCP_STATE_BOUND)
		timeout_cleanup (self);
	if (new_state >= NM_DHCP_STATE_TIMEOUT)
		watch_cleanup (self);

	/* The client may send same-state transitions for RENEW/REBIND events and
	 * the lease may have changed, so handle same-state transitions for the
	 * BOUND state.  Ignore same-state transitions for other events since
	 * the lease won't have changed and the state was already handled.
	 */
	if ((priv->state == new_state) && (new_state != NM_DHCP_STATE_BOUND))
		return;

	if (   priv->addr_family == AF_INET6
	    && new_state == NM_DHCP_STATE_BOUND) {
		char *start, *iaid;

		iaid = g_hash_table_lookup (options, "iaid");
		start = g_hash_table_lookup (options, "life_starts");
		if (iaid && start)
			event_id = g_strdup_printf ("%s|%s", iaid, start);
	}

	_LOGI ("state changed %s -> %s%s%s%s",
	       state_to_string (priv->state),
	       state_to_string (new_state),
	       NM_PRINT_FMT_QUOTED (event_id, ", event ID=\"", event_id, "\"", ""));

	priv->state = new_state;
	g_signal_emit (G_OBJECT (self),
	               signals[SIGNAL_STATE_CHANGED], 0,
	               new_state,
	               ip_config,
	               options,
	               event_id);
}

static gboolean
transaction_timeout (gpointer user_data)
{
	NMDhcpClient *self = NM_DHCP_CLIENT (user_data);
	NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	priv->timeout_id = 0;
	_LOGW ("request timed out");
	nm_dhcp_client_set_state (self, NM_DHCP_STATE_TIMEOUT, NULL, NULL);
	return G_SOURCE_REMOVE;
}

static void
daemon_watch_cb (GPid pid, int status, gpointer user_data)
{
	NMDhcpClient *self = NM_DHCP_CLIENT (user_data);
	NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	g_return_if_fail (priv->watch_id);
	priv->watch_id = 0;

	if (WIFEXITED (status))
		_LOGI ("client pid %d exited with status %d", pid, WEXITSTATUS (status));
	else if (WIFSIGNALED (status))
		_LOGI ("client pid %d killed by signal %d", pid, WTERMSIG (status));
	else if (WIFSTOPPED(status))
		_LOGI ("client pid %d stopped by signal %d", pid, WSTOPSIG (status));
	else if (WIFCONTINUED (status))
		_LOGI ("client pid %d resumed (by SIGCONT)", pid);
	else
		_LOGW ("client died abnormally");

	priv->pid = -1;

	nm_dhcp_client_set_state (self, NM_DHCP_STATE_TERMINATED, NULL, NULL);
}

void
nm_dhcp_client_start_timeout (NMDhcpClient *self)
{
	NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	g_return_if_fail (priv->timeout_id == 0);

	/* Set up a timeout on the transaction to kill it after the timeout */

	if (priv->timeout == NM_DHCP_TIMEOUT_INFINITY)
		return;

	priv->timeout_id = g_timeout_add_seconds (priv->timeout,
	                                          transaction_timeout,
	                                          self);
}

void
nm_dhcp_client_watch_child (NMDhcpClient *self, pid_t pid)
{
	NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	g_return_if_fail (priv->pid == -1);
	priv->pid = pid;

	nm_dhcp_client_start_timeout (self);

	g_return_if_fail (priv->watch_id == 0);
	priv->watch_id = g_child_watch_add (pid, daemon_watch_cb, self);
}

gboolean
nm_dhcp_client_start_ip4 (NMDhcpClient *self,
                          GBytes *client_id,
                          const char *dhcp_anycast_addr,
                          const char *last_ip4_address,
                          GError **error)
{
	NMDhcpClientPrivate *priv;

	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), FALSE);

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);
	g_return_val_if_fail (priv->pid == -1, FALSE);
	g_return_val_if_fail (priv->addr_family == AF_INET, FALSE);
	g_return_val_if_fail (priv->uuid != NULL, FALSE);

	if (priv->timeout == NM_DHCP_TIMEOUT_INFINITY)
		_LOGI ("activation: beginning transaction (no timeout)");
	else
		_LOGI ("activation: beginning transaction (timeout in %u seconds)", (guint) priv->timeout);

	nm_dhcp_client_set_client_id (self, client_id);

	return NM_DHCP_CLIENT_GET_CLASS (self)->ip4_start (self,
	                                                   dhcp_anycast_addr,
	                                                   last_ip4_address,
	                                                   error);
}

gboolean
nm_dhcp_client_accept (NMDhcpClient *self,
                       GError **error)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), FALSE);

	if (NM_DHCP_CLIENT_GET_CLASS (self)->accept) {
		return NM_DHCP_CLIENT_GET_CLASS (self)->accept (self,
		                                                error);
	}

	return TRUE;
}

gboolean
nm_dhcp_client_decline (NMDhcpClient *self,
                        const char *error_message,
                        GError **error)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), FALSE);

	if (NM_DHCP_CLIENT_GET_CLASS (self)->decline) {
		return NM_DHCP_CLIENT_GET_CLASS (self)->decline (self,
		                                                 error_message,
		                                                 error);
	}

	return TRUE;
}

static GBytes *
get_duid (NMDhcpClient *self)
{
	return NULL;
}

gboolean
nm_dhcp_client_start_ip6 (NMDhcpClient *self,
                          GBytes *client_id,
                          gboolean enforce_duid,
                          const char *dhcp_anycast_addr,
                          const struct in6_addr *ll_addr,
                          NMSettingIP6ConfigPrivacy privacy,
                          guint needed_prefixes,
                          GError **error)
{
	NMDhcpClientPrivate *priv;
	gs_unref_bytes GBytes *own_client_id = NULL;

	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), FALSE);
	g_return_val_if_fail (client_id, FALSE);

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	g_return_val_if_fail (priv->pid == -1, FALSE);
	g_return_val_if_fail (priv->addr_family == AF_INET6, FALSE);
	g_return_val_if_fail (priv->uuid != NULL, FALSE);
	g_return_val_if_fail (!priv->client_id, FALSE);

	if (!enforce_duid)
		own_client_id = NM_DHCP_CLIENT_GET_CLASS (self)->get_duid (self);

	_set_client_id (self,
	                own_client_id ?: client_id,
	                FALSE);

	if (priv->timeout == NM_DHCP_TIMEOUT_INFINITY)
		_LOGI ("activation: beginning transaction (no timeout)");
	else
		_LOGI ("activation: beginning transaction (timeout in %u seconds)", (guint) priv->timeout);

	return NM_DHCP_CLIENT_GET_CLASS (self)->ip6_start (self,
	                                                   dhcp_anycast_addr,
	                                                   ll_addr,
	                                                   privacy,
	                                                   needed_prefixes,
	                                                   error);
}

void
nm_dhcp_client_stop_existing (const char *pid_file, const char *binary_name)
{
	guint64 start_time;
	pid_t pid, ppid;
	const char *exe;
	char proc_path[NM_STRLEN ("/proc/%lu/cmdline") + 100];
	gs_free char *pid_contents = NULL, *proc_contents = NULL;

	/* Check for an existing instance and stop it */
	if (!g_file_get_contents (pid_file, &pid_contents, NULL, NULL))
		return;

	pid = _nm_utils_ascii_str_to_int64 (pid_contents, 10, 1, G_MAXINT64, 0);
	if (pid <= 0)
		goto out;

	start_time = nm_utils_get_start_time_for_pid (pid, NULL, &ppid);
	if (start_time == 0)
		goto out;

	nm_sprintf_buf (proc_path, "/proc/%lu/cmdline", (unsigned long) pid);
	if (!g_file_get_contents (proc_path, &proc_contents, NULL, NULL))
		goto out;

	exe = strrchr (proc_contents, '/');
	if (exe)
		exe++;
	else
		exe = proc_contents;
	if (!nm_streq0 (exe, binary_name))
		goto out;

	if (ppid == getpid ()) {
		/* the process is our own child. */
		nm_utils_kill_child_sync (pid, SIGTERM, LOGD_DHCP, "dhcp-client", NULL, 1000 / 2, 1000 / 20);
	} else {
		nm_utils_kill_process_sync (pid, start_time, SIGTERM, LOGD_DHCP,
		                            "dhcp-client", 1000 / 2, 1000 / 20, 2000);
	}

out:
	if (remove (pid_file) == -1) {
		int errsv = errno;

		nm_log_dbg (LOGD_DHCP, "dhcp: could not remove pid file \"%s\": %s (%d)",
		            pid_file, nm_strerror_native (errsv), errsv);
	}
}

void
nm_dhcp_client_stop (NMDhcpClient *self, gboolean release)
{
	NMDhcpClientPrivate *priv;
	pid_t old_pid = 0;

	g_return_if_fail (NM_IS_DHCP_CLIENT (self));

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	/* Kill the DHCP client */
	old_pid = priv->pid;
	NM_DHCP_CLIENT_GET_CLASS (self)->stop (self, release);
	if (old_pid > 0)
		_LOGI ("canceled DHCP transaction, DHCP client pid %d", old_pid);
	else
		_LOGI ("canceled DHCP transaction");
	g_assert (priv->pid == -1);

	nm_dhcp_client_set_state (self, NM_DHCP_STATE_DONE, NULL, NULL);
}

/*****************************************************************************/

static char *
bytearray_variant_to_string (NMDhcpClient *self, GVariant *value, const char *key)
{
	const guint8 *array;
	gsize length;
	GString *str;
	int i;
	unsigned char c;
	char *converted = NULL;

	g_return_val_if_fail (value != NULL, NULL);

	array = g_variant_get_fixed_array (value, &length, 1);

	/* Since the DHCP options come through environment variables, they should
	 * already be UTF-8 safe, but just make sure.
	 */
	str = g_string_sized_new (length);
	for (i = 0; i < length; i++) {
		c = array[i];

		/* Convert NULLs to spaces and non-ASCII characters to ? */
		if (c == '\0')
			c = ' ';
		else if (c > 127)
			c = '?';
		str = g_string_append_c (str, c);
	}
	str = g_string_append_c (str, '\0');

	converted = str->str;
	if (!g_utf8_validate (converted, -1, NULL))
		_LOGW ("option '%s' couldn't be converted to UTF-8", key);
	g_string_free (str, FALSE);
	return converted;
}

static int
label_is_unknown_xyz (const char *label)
{
	if (!NM_STR_HAS_PREFIX (label, "unknown_"))
		return -EINVAL;

	label += NM_STRLEN  ("unknown_");
	if (   label[0] != '2'
	    || !g_ascii_isdigit (label[1])
	    || !g_ascii_isdigit (label[2])
	    || label[3] != '\0')
		return -EINVAL;

	return _nm_utils_ascii_str_to_int64 (label, 10, 224, 254, -EINVAL);
}


#define OLD_TAG "old_"
#define NEW_TAG "new_"

static void
maybe_add_option (NMDhcpClient *self,
                  GHashTable *hash,
                  const char *key,
                  GVariant *value)
{
	char *str_value = NULL;

	g_return_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE_BYTESTRING));

	if (g_str_has_prefix (key, OLD_TAG))
		return;

	/* Filter out stuff that's not actually new DHCP options */
	if (NM_IN_STRSET (key, "interface",
	                       "pid",
	                       "reason",
	                       "dhcp_message_type"))
		return;

	if (NM_STR_HAS_PREFIX (key, NEW_TAG))
		key += NM_STRLEN (NEW_TAG);
	if (NM_STR_HAS_PREFIX (key, "private_") || !key[0])
		return;

	str_value = bytearray_variant_to_string (self, value, key);
	if (str_value) {
		int priv_opt_num;

		g_hash_table_insert (hash, g_strdup (key), str_value);

		/* dhclient has no special labels for private dhcp options: it uses "unknown_xyz"
		 * labels for that. We need to identify those to alias them to our "private_xyz"
		 * format unsed in the internal dchp plugins.
		 */
		if ((priv_opt_num = label_is_unknown_xyz (key)) > 0) {
			gs_free guint8 *check_val = NULL;
			char *hex_str = NULL;
			gsize len;

			/* dhclient passes values from dhcp private options in its own "string" format:
			 * if the raw values are printable as ascii strings, it will pass the string
			 * representation; if the values are not printable as an ascii string, it will
			 * pass a string displaying the hex values (hex string). Try to enforce passing
			 * always an hex string, converting string representation if needed.
			 */
			check_val = nm_utils_hexstr2bin_alloc (str_value, FALSE, TRUE, ":", 0, &len);
			hex_str = nm_utils_bin2hexstr_full (check_val ?: (guint8 *) str_value,
			                                    check_val ? len : strlen (str_value),
			                                    ':', FALSE, NULL);
			g_hash_table_insert (hash,
			                     g_strdup_printf ("private_%d", priv_opt_num),
			                     hex_str);
		}
	}
}

gboolean
nm_dhcp_client_handle_event (gpointer unused,
                             const char *iface,
                             int pid,
                             GVariant *options,
                             const char *reason,
                             NMDhcpClient *self)
{
	NMDhcpClientPrivate *priv;
	guint32 old_state;
	guint32 new_state;
	gs_unref_hashtable GHashTable *str_options = NULL;
	gs_unref_object NMIPConfig *ip_config = NULL;
	NMPlatformIP6Address prefix = { 0, };

	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), FALSE);
	g_return_val_if_fail (iface != NULL, FALSE);
	g_return_val_if_fail (pid > 0, FALSE);
	g_return_val_if_fail (g_variant_is_of_type (options, G_VARIANT_TYPE_VARDICT), FALSE);
	g_return_val_if_fail (reason != NULL, FALSE);

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	if (g_strcmp0 (priv->iface, iface) != 0)
		return FALSE;
	if (priv->pid != pid)
		return FALSE;

	old_state = priv->state;
	new_state = reason_to_state (self, priv->iface, reason);
	_LOGD ("DHCP state '%s' -> '%s' (reason: '%s')",
	       state_to_string (old_state), state_to_string (new_state), reason);

	if (new_state == NM_DHCP_STATE_BOUND) {
		GVariantIter iter;
		const char *name;
		GVariant *value;

		/* Copy options */
		str_options = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, g_free);
		g_variant_iter_init (&iter, options);
		while (g_variant_iter_next (&iter, "{&sv}", &name, &value)) {
			maybe_add_option (self, str_options, name, value);
			g_variant_unref (value);
		}

		if (nm_logging_enabled (LOGL_DEBUG, LOGD_DHCP6)) {
			GHashTableIter hash_iter;
			gpointer key, val;

			g_hash_table_iter_init (&hash_iter, str_options);
			while (g_hash_table_iter_next (&hash_iter, &key, &val))
				_LOGD ("option '%s'=>'%s'", (const char *) key, (const char *) val);
		}

		/* Create the IP config */
		if (g_hash_table_size (str_options) > 0) {
			if (priv->addr_family == AF_INET) {
				ip_config = NM_IP_CONFIG_CAST (nm_dhcp_utils_ip4_config_from_options (nm_dhcp_client_get_multi_idx (self),
				                                                                      priv->ifindex,
				                                                                      priv->iface,
				                                                                      str_options,
				                                                                      priv->route_table,
				                                                                      priv->route_metric));
			} else {
				prefix = nm_dhcp_utils_ip6_prefix_from_options (str_options);
				ip_config = NM_IP_CONFIG_CAST (nm_dhcp_utils_ip6_config_from_options (nm_dhcp_client_get_multi_idx (self),
				                                                                      priv->ifindex,
				                                                                      priv->iface,
				                                                                      str_options,
				                                                                      priv->info_only));
			}
		} else
			g_warn_if_reached ();
	}

	if (!IN6_IS_ADDR_UNSPECIFIED (&prefix.address)) {
		/* If we got an IPv6 prefix to delegate, we don't change the state
		 * of the DHCP client instance. Instead, we just signal the prefix
		 * to the device. */
		g_signal_emit (G_OBJECT (self),
		               signals[SIGNAL_PREFIX_DELEGATED], 0,
		               &prefix);
	} else {
		/* Fail if no valid IP config was received */
		if (   new_state == NM_DHCP_STATE_BOUND
		    && !ip_config) {
			_LOGW ("client bound but IP config not received");
			new_state = NM_DHCP_STATE_FAIL;
			g_clear_pointer (&str_options, g_hash_table_unref);
		}

		nm_dhcp_client_set_state (self, new_state, ip_config, str_options);
	}

	return TRUE;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE ((NMDhcpClient *) object);

	switch (prop_id) {
	case PROP_IFACE:
		g_value_set_string (value, priv->iface);
		break;
	case PROP_IFINDEX:
		g_value_set_int (value, priv->ifindex);
		break;
	case PROP_HWADDR:
		g_value_set_boxed (value, priv->hwaddr);
		break;
	case PROP_BROADCAST_HWADDR:
		g_value_set_boxed (value, priv->bcast_hwaddr);
		break;
	case PROP_ADDR_FAMILY:
		g_value_set_int (value, priv->addr_family);
		break;
	case PROP_UUID:
		g_value_set_string (value, priv->uuid);
		break;
	case PROP_HOSTNAME:
		g_value_set_string (value, priv->hostname);
		break;
	case PROP_ROUTE_METRIC:
		g_value_set_uint (value, priv->route_metric);
		break;
	case PROP_ROUTE_TABLE:
		g_value_set_uint (value, priv->route_table);
		break;
	case PROP_TIMEOUT:
		g_value_set_uint (value, priv->timeout);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE ((NMDhcpClient *) object);
	guint flags;

	switch (prop_id) {
	case PROP_FLAGS:
		/* construct-only */
		flags = g_value_get_uint (value);
		nm_assert ((flags & ~((guint) (NM_DHCP_CLIENT_FLAGS_INFO_ONLY | NM_DHCP_CLIENT_FLAGS_USE_FQDN))) == 0);
		priv->info_only = NM_FLAGS_HAS (flags, NM_DHCP_CLIENT_FLAGS_INFO_ONLY);
		priv->use_fqdn = NM_FLAGS_HAS (flags, NM_DHCP_CLIENT_FLAGS_USE_FQDN);
		break;
	case PROP_MULTI_IDX:
		/* construct-only */
		priv->multi_idx = g_value_get_pointer (value);
		if (!priv->multi_idx)
			g_return_if_reached ();
		nm_dedup_multi_index_ref (priv->multi_idx);
		break;
	case PROP_IFACE:
		/* construct-only */
		priv->iface = g_value_dup_string (value);
		g_return_if_fail (   priv->iface
		                  && nm_utils_is_valid_iface_name (priv->iface, NULL));
		break;
	case PROP_IFINDEX:
		/* construct-only */
		priv->ifindex = g_value_get_int (value);
		g_return_if_fail (priv->ifindex > 0);
		break;
	case PROP_HWADDR:
		/* construct-only */
		priv->hwaddr = g_value_dup_boxed (value);
		break;
	case PROP_BROADCAST_HWADDR:
		/* construct-only */
		priv->bcast_hwaddr = g_value_dup_boxed (value);
		break;
	case PROP_ADDR_FAMILY:
		/* construct-only */
		priv->addr_family = g_value_get_int (value);
		if (!NM_IN_SET (priv->addr_family, AF_INET, AF_INET6))
			g_return_if_reached ();
		break;
	case PROP_UUID:
		/* construct-only */
		priv->uuid = g_value_dup_string (value);
		break;
	case PROP_HOSTNAME:
		/* construct-only */
		priv->hostname = g_value_dup_string (value);
		break;
	case PROP_ROUTE_TABLE:
		priv->route_table = g_value_get_uint (value);
		break;
	case PROP_ROUTE_METRIC:
		priv->route_metric = g_value_get_uint (value);
		break;
	case PROP_TIMEOUT:
		/* construct-only */
		priv->timeout = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_dhcp_client_init (NMDhcpClient *self)
{
	NMDhcpClientPrivate *priv;

	priv = G_TYPE_INSTANCE_GET_PRIVATE (self, NM_TYPE_DHCP_CLIENT, NMDhcpClientPrivate);
	self->_priv = priv;

	c_list_init (&self->dhcp_client_lst);

	priv->pid = -1;
}

static void
dispose (GObject *object)
{
	NMDhcpClient *self = NM_DHCP_CLIENT (object);
	NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	/* Stopping the client is left up to the controlling device
	 * explicitly since we may want to quit NetworkManager but not terminate
	 * the DHCP client.
	 */

	nm_assert (c_list_is_empty (&self->dhcp_client_lst));

	watch_cleanup (self);
	timeout_cleanup (self);

	g_clear_pointer (&priv->iface, g_free);
	g_clear_pointer (&priv->hostname, g_free);
	g_clear_pointer (&priv->uuid, g_free);
	g_clear_pointer (&priv->client_id, g_bytes_unref);
	g_clear_pointer (&priv->hwaddr, g_bytes_unref);
	g_clear_pointer (&priv->bcast_hwaddr, g_bytes_unref);

	G_OBJECT_CLASS (nm_dhcp_client_parent_class)->dispose (object);

	priv->multi_idx = nm_dedup_multi_index_unref (priv->multi_idx);
}

static void
nm_dhcp_client_class_init (NMDhcpClientClass *client_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (client_class);

	g_type_class_add_private (client_class, sizeof (NMDhcpClientPrivate));

	object_class->dispose = dispose;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	client_class->stop = stop;
	client_class->get_duid = get_duid;

	obj_properties[PROP_MULTI_IDX] =
	    g_param_spec_pointer (NM_DHCP_CLIENT_MULTI_IDX, "", "",
	                            G_PARAM_WRITABLE
	                          | G_PARAM_CONSTRUCT_ONLY
	                          | G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_IFACE] =
	    g_param_spec_string (NM_DHCP_CLIENT_INTERFACE, "", "",
	                         NULL,
	                         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_IFINDEX] =
	    g_param_spec_int (NM_DHCP_CLIENT_IFINDEX, "", "",
	                      -1, G_MAXINT, -1,
	                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                      G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_HWADDR] =
	    g_param_spec_boxed (NM_DHCP_CLIENT_HWADDR, "", "",
	                        G_TYPE_BYTES,
	                        G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                        G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_BROADCAST_HWADDR] =
	    g_param_spec_boxed (NM_DHCP_CLIENT_BROADCAST_HWADDR, "", "",
	                        G_TYPE_BYTES,
	                        G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                        G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_ADDR_FAMILY] =
	    g_param_spec_int (NM_DHCP_CLIENT_ADDR_FAMILY, "", "",
	                      0, G_MAXINT, AF_UNSPEC,
	                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                      G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_UUID] =
	    g_param_spec_string (NM_DHCP_CLIENT_UUID, "", "",
	                         NULL,
	                         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_HOSTNAME] =
	    g_param_spec_string (NM_DHCP_CLIENT_HOSTNAME, "", "",
	                         NULL,
	                         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_ROUTE_TABLE] =
	    g_param_spec_uint (NM_DHCP_CLIENT_ROUTE_TABLE, "", "",
	                       0, G_MAXUINT32, RT_TABLE_MAIN,
	                       G_PARAM_READWRITE |
	                       G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_ROUTE_METRIC] =
	    g_param_spec_uint (NM_DHCP_CLIENT_ROUTE_METRIC, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READWRITE |
	                       G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_TIMEOUT] =
	    g_param_spec_uint (NM_DHCP_CLIENT_TIMEOUT, "", "",
	                       1, G_MAXINT32, NM_DHCP_TIMEOUT_DEFAULT,
	                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                       G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_FLAGS] =
	    g_param_spec_uint (NM_DHCP_CLIENT_FLAGS, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY |
	                       G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	signals[SIGNAL_STATE_CHANGED] =
	    g_signal_new (NM_DHCP_CLIENT_SIGNAL_STATE_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 4, G_TYPE_UINT, G_TYPE_OBJECT, G_TYPE_HASH_TABLE, G_TYPE_STRING);

	signals[SIGNAL_PREFIX_DELEGATED] =
	    g_signal_new (NM_DHCP_CLIENT_SIGNAL_PREFIX_DELEGATED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 1, G_TYPE_POINTER);
}
