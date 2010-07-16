/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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

#include <glib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include "nm-utils.h"
#include "nm-logging.h"
#include "nm-dbus-glib-types.h"
#include "nm-dhcp-client.h"

typedef struct {
	char *       iface;
	gboolean     ipv6;
	char *       uuid;
	guint32      timeout;

	guchar       state;
	GPid         pid;
	gboolean     dead;
	guint        timeout_id;
	guint        watch_id;
	guint32      remove_id;
	GHashTable * options;
	gboolean     info_only;

} NMDHCPClientPrivate;

#define NM_DHCP_CLIENT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DHCP_CLIENT, NMDHCPClientPrivate))

G_DEFINE_TYPE_EXTENDED (NMDHCPClient, nm_dhcp_client, G_TYPE_OBJECT, G_TYPE_FLAG_ABSTRACT, {})

enum {
	STATE_CHANGED,
	TIMEOUT,
	REMOVE,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_IFACE,
	PROP_IPV6,
	PROP_UUID,
	PROP_TIMEOUT,
	LAST_PROP
};

/********************************************/

GPid
nm_dhcp_client_get_pid (NMDHCPClient *self)
{
	g_return_val_if_fail (self != NULL, -1);
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), -1);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->pid;
}

const char *
nm_dhcp_client_get_iface (NMDHCPClient *self)
{
	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), NULL);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->iface;
}

gboolean
nm_dhcp_client_get_ipv6 (NMDHCPClient *self)
{
	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), FALSE);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->ipv6;
}

const char *
nm_dhcp_client_get_uuid (NMDHCPClient *self)
{
	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), NULL);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->uuid;
}

/********************************************/

static void
timeout_cleanup (NMDHCPClient *self)
{
	NMDHCPClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	if (priv->timeout_id) {
		g_source_remove (priv->timeout_id);
		priv->timeout_id = 0;
	}
}

static void
watch_cleanup (NMDHCPClient *self)
{
	NMDHCPClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	if (priv->watch_id) {
		g_source_remove (priv->watch_id);
		priv->watch_id = 0;
	}
}

static void
stop_process (GPid pid, const char *iface)
{
	int i = 15; /* 3 seconds */

	g_return_if_fail (pid > 0);

	/* Tell it to quit; maybe it wants to send out a RELEASE message */
	kill (pid, SIGTERM);

	while (i-- > 0) {
		gint child_status;
		int ret;

		ret = waitpid (pid, &child_status, WNOHANG);
		if (ret > 0)
			break;

		if (ret == -1) {
			/* Child already exited */
			if (errno == ECHILD)
				break;
			/* Took too long; shoot it in the head */
			i = 0;
			break;
		}
		g_usleep (G_USEC_PER_SEC / 5);
	}

	if (i <= 0) {
		if (iface) {
			nm_log_warn (LOGD_DHCP, "(%s): DHCP client pid %d didn't exit, will kill it.",
			             iface, pid);
		}
		kill (pid, SIGKILL);

		nm_log_dbg (LOGD_DHCP, "waiting for DHCP client pid %d to exit", pid);
		waitpid (pid, NULL, 0);
		nm_log_dbg (LOGD_DHCP, "DHCP client pid %d cleaned up", pid);
	}
}

static void
real_stop (NMDHCPClient *self)
{
	NMDHCPClientPrivate *priv;

	g_return_if_fail (self != NULL);
	g_return_if_fail (NM_IS_DHCP_CLIENT (self));

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);
	g_return_if_fail (priv->pid > 0);

	/* Clean up the watch handler since we're explicitly killing the daemon */
	watch_cleanup (self);

	stop_process (priv->pid, priv->iface);

	priv->info_only = FALSE;
}

static gboolean
daemon_timeout (gpointer user_data)
{
	NMDHCPClient *self = NM_DHCP_CLIENT (user_data);
	NMDHCPClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	if (priv->ipv6) {
		nm_log_warn (LOGD_DHCP6, "(%s): DHCPv6 request timed out.", priv->iface);
	} else {
		nm_log_warn (LOGD_DHCP4, "(%s): DHCPv4 request timed out.", priv->iface);
	}
	g_signal_emit (G_OBJECT (self), signals[TIMEOUT], 0);
	return FALSE;
}

static gboolean
signal_remove (gpointer user_data)
{
	NMDHCPClient *self = NM_DHCP_CLIENT (user_data);

	NM_DHCP_CLIENT_GET_PRIVATE (self)->remove_id = 0;
	g_signal_emit (G_OBJECT (self), signals[REMOVE], 0);
	return FALSE;
}

static void
dhcp_client_set_state (NMDHCPClient *self,
                       NMDHCPState state,
                       gboolean emit_state,
                       gboolean remove_now)
{
	NMDHCPClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	priv->state = state;

	if (emit_state)
		g_signal_emit (G_OBJECT (self), signals[STATE_CHANGED], 0, priv->state);

	if (state == DHC_END || state == DHC_ABEND) {
		/* Start the remove signal timer */
		if (remove_now) {
			g_signal_emit (G_OBJECT (self), signals[REMOVE], 0);
		} else {
			if (!priv->remove_id)
				priv->remove_id = g_timeout_add_seconds (5, signal_remove, self);
		}
	}
}

static void
daemon_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMDHCPClient *self = NM_DHCP_CLIENT (user_data);
	NMDHCPClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);
	NMDHCPState new_state;

	if (priv->ipv6) {
		nm_log_info (LOGD_DHCP6, "(%s): DHCPv6 client pid %d exited with status %d",
		             priv->iface, pid,
		             WIFEXITED (status) ? WEXITSTATUS (status) : -1);
	} else {
		nm_log_info (LOGD_DHCP6, "(%s): DHCPv4 client pid %d exited with status %d",
		             priv->iface, pid,
		             WIFEXITED (status) ? WEXITSTATUS (status) : -1);
	}

	if (!WIFEXITED (status)) {
		new_state = DHC_ABEND;
		nm_log_warn (LOGD_DHCP, "DHCP client died abnormally");
	} else
		new_state = DHC_END;

	watch_cleanup (self);
	timeout_cleanup (self);
	priv->dead = TRUE;

	dhcp_client_set_state (self, new_state, TRUE, FALSE);
}

static void
start_monitor (NMDHCPClient *self)
{
	NMDHCPClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	g_return_if_fail (priv->pid > 0);

	/* Set up a timeout on the transaction to kill it after the timeout */
	priv->timeout_id = g_timeout_add_seconds (priv->timeout,
	                                          daemon_timeout,
	                                          self);
	priv->watch_id = g_child_watch_add (priv->pid,
	                                    (GChildWatchFunc) daemon_watch_cb,
	                                    self);
}

gboolean
nm_dhcp_client_start_ip4 (NMDHCPClient *self,
                          NMSettingIP4Config *s_ip4,
                          guint8 *dhcp_anycast_addr,
                          const char *hostname)
{
	NMDHCPClientPrivate *priv;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), FALSE);

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);
	g_return_val_if_fail (priv->pid == -1, FALSE);
	g_return_val_if_fail (priv->ipv6 == FALSE, FALSE);
	g_return_val_if_fail (priv->uuid != NULL, FALSE);

	nm_log_info (LOGD_DHCP, "Activation (%s) Beginning DHCPv4 transaction (timeout in %d seconds)",
	             priv->iface, priv->timeout);

	priv->pid = NM_DHCP_CLIENT_GET_CLASS (self)->ip4_start (self, s_ip4, dhcp_anycast_addr, hostname);
	if (priv->pid)
		start_monitor (self);

	return priv->pid ? TRUE : FALSE;
}

gboolean
nm_dhcp_client_start_ip6 (NMDHCPClient *self,
                          NMSettingIP6Config *s_ip6,
                          guint8 *dhcp_anycast_addr,
                          const char *hostname,
                          gboolean info_only)
{
	NMDHCPClientPrivate *priv;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), FALSE);

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);
	g_return_val_if_fail (priv->pid == -1, FALSE);
	g_return_val_if_fail (priv->ipv6 == TRUE, FALSE);
	g_return_val_if_fail (priv->uuid != NULL, FALSE);

	priv->info_only = info_only;

	nm_log_info (LOGD_DHCP, "Activation (%s) Beginning DHCPv6 transaction (timeout in %d seconds)",
	             priv->iface, priv->timeout);

	priv->pid = NM_DHCP_CLIENT_GET_CLASS (self)->ip6_start (self, s_ip6, dhcp_anycast_addr, hostname, info_only);
	if (priv->pid > 0)
		start_monitor (self);

	return priv->pid ? TRUE : FALSE;
}

void
nm_dhcp_client_stop_existing (const char *pid_file, const char *binary_name)
{
	char *pid_contents = NULL, *proc_contents = NULL, *proc_path = NULL;
	long int tmp;

	/* Check for an existing instance and stop it */
	if (!g_file_get_contents (pid_file, &pid_contents, NULL, NULL))
		return;

	errno = 0;
	tmp = strtol (pid_contents, NULL, 10);
	if ((errno == 0) && (tmp > 1)) {
		const char *exe;

		/* Ensure the process is a DHCP client */
		proc_path = g_strdup_printf ("/proc/%ld/cmdline", tmp);
		if (g_file_get_contents (proc_path, &proc_contents, NULL, NULL)) {
			exe = strrchr (proc_contents, '/');
			if (exe)
				exe++;
			else
				exe = proc_contents;

			if (!strcmp (exe, binary_name))
				stop_process ((GPid) tmp, NULL);
		}
	}

	remove (pid_file);
	g_free (proc_path);
	g_free (pid_contents);
	g_free (proc_contents);
}

void
nm_dhcp_client_stop (NMDHCPClient *self)
{
	NMDHCPClientPrivate *priv;

	g_return_if_fail (self != NULL);
	g_return_if_fail (NM_IS_DHCP_CLIENT (self));

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	/* Kill the DHCP client */
	if (!priv->dead) {
		NM_DHCP_CLIENT_GET_CLASS (self)->stop (self);
		priv->dead = TRUE;

		nm_log_info (LOGD_DHCP, "(%s): canceled DHCP transaction, DHCP client pid %d",
		             priv->iface, priv->pid);
	}

	/* And clean stuff up */

	priv->pid = -1;
	dhcp_client_set_state (self, DHC_END, FALSE, TRUE);

	g_hash_table_remove_all (priv->options);

	timeout_cleanup (self);
	watch_cleanup (self);
}

/********************************************/

static gboolean
state_is_bound (guint32 state)
{
	if (   (state == DHC_BOUND4)
	    || (state == DHC_BOUND6)
	    || (state == DHC_RENEW4)
	    || (state == DHC_RENEW6)
	    || (state == DHC_REBOOT)
	    || (state == DHC_REBIND4)
	    || (state == DHC_REBIND6)
	    || (state == DHC_IPV4LL))
		return TRUE;

	return FALSE;
}

typedef struct {
	NMDHCPState state;
	const char *name;
} DhcState;

#define STATE_TABLE_SIZE (sizeof (state_table) / sizeof (state_table[0]))

static DhcState state_table[] = {
	{ DHC_NBI,     "nbi" },
	{ DHC_PREINIT, "preinit" },
	{ DHC_PREINIT6,"preinit6" },
	{ DHC_BOUND4,  "bound" },
	{ DHC_BOUND6,  "bound6" },
	{ DHC_IPV4LL,  "ipv4ll" },
	{ DHC_RENEW4,  "renew" },
	{ DHC_RENEW6,  "renew6" },
	{ DHC_REBOOT,  "reboot" },
	{ DHC_REBIND4, "rebind" },
	{ DHC_REBIND6, "rebind6" },
	{ DHC_STOP,    "stop" },
	{ DHC_STOP6,   "stop6" },
	{ DHC_MEDIUM,  "medium" },
	{ DHC_TIMEOUT, "timeout" },
	{ DHC_FAIL,    "fail" },
	{ DHC_EXPIRE,  "expire" },
	{ DHC_EXPIRE6, "expire6" },
	{ DHC_RELEASE, "release" },
	{ DHC_RELEASE6,"release6" },
	{ DHC_START,   "start" },
	{ DHC_ABEND,   "abend" },
	{ DHC_END,     "end" },
	{ DHC_DEPREF6, "depref6" },
};

static inline const char *
state_to_string (guint32 state)
{
	int i;

	for (i = 0; i < STATE_TABLE_SIZE; i++) {
		if (state == state_table[i].state)
			return state_table[i].name;
	}

	return NULL;
}

static inline NMDHCPState
string_to_state (const char *name)
{
	int i;

	for (i = 0; i < STATE_TABLE_SIZE; i++) {
		if (!strcasecmp (name, state_table[i].name))
			return state_table[i].state;
	}

	return 255;
}

static char *
garray_to_string (GArray *array, const char *key)
{
	GString *str;
	int i;
	unsigned char c;
	char *converted = NULL;

	g_return_val_if_fail (array != NULL, NULL);

	/* Since the DHCP options come through environment variables, they should
	 * already be UTF-8 safe, but just make sure.
	 */
	str = g_string_sized_new (array->len);
	for (i = 0; i < array->len; i++) {
		c = array->data[i];

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
		nm_log_warn (LOGD_DHCP, "DHCP option '%s' couldn't be converted to UTF-8", key);
	g_string_free (str, FALSE);
	return converted;
}

static void
copy_option (gpointer key,
             gpointer value,
             gpointer user_data)
{
	GHashTable *hash = user_data;
	const char *str_key = (const char *) key;
	char *str_value = NULL;

	if (G_VALUE_TYPE (value) != DBUS_TYPE_G_UCHAR_ARRAY) {
		nm_log_warn (LOGD_DHCP, "unexpected key %s value type was not "
		             "DBUS_TYPE_G_UCHAR_ARRAY",
		             str_key);
		return;
	}

	str_value = garray_to_string ((GArray *) g_value_get_boxed (value), str_key);
	if (str_value)
		g_hash_table_insert (hash, g_strdup (str_key), str_value);
}

void
nm_dhcp_client_new_options (NMDHCPClient *self,
                            GHashTable *options,
                            const char *reason)
{
	NMDHCPClientPrivate *priv;
	guint32 old_state;
	guint32 new_state;

	g_return_if_fail (self != NULL);
	g_return_if_fail (NM_IS_DHCP_CLIENT (self));
	g_return_if_fail (options != NULL);
	g_return_if_fail (reason != NULL);

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);
	old_state = priv->state;
	new_state = string_to_state (reason);

	/* Clear old and save new DHCP options */
	g_hash_table_remove_all (priv->options);
	g_hash_table_foreach (options, copy_option, priv->options);

	if (old_state == new_state)
		return;

	/* Handle changed device state */
	if (state_is_bound (new_state)) {
		/* Cancel the timeout if the DHCP client is now bound */
		timeout_cleanup (self);
	}

	if (priv->ipv6) {
		nm_log_info (LOGD_DHCP6, "(%s): DHCPv6 state changed %s -> %s",
		            priv->iface,
		            state_to_string (old_state),
		            state_to_string (new_state));
	} else {
		nm_log_info (LOGD_DHCP4, "(%s): DHCPv4 state changed %s -> %s",
		            priv->iface,
		            state_to_string (old_state),
		            state_to_string (new_state));
	}

	dhcp_client_set_state (self, new_state, TRUE, FALSE);
}

#define NEW_TAG "new_"
#define OLD_TAG "old_"

gboolean
nm_dhcp_client_foreach_option (NMDHCPClient *self,
                               GHFunc func,
                               gpointer user_data)
{
	NMDHCPClientPrivate *priv;
	GHashTableIter iter;
	gpointer iterkey, itervalue;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), FALSE);
	g_return_val_if_fail (func != NULL, FALSE);

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	if (!state_is_bound (priv->state)) {
		if (priv->ipv6) {
			nm_log_warn (LOGD_DHCP6, "(%s): DHCPv6 client didn't bind to a lease.", priv->iface);
		} else {
			nm_log_warn (LOGD_DHCP4, "(%s): DHCPv4 client didn't bind to a lease.", priv->iface);
		}
	}

	g_hash_table_iter_init (&iter, priv->options);
	while (g_hash_table_iter_next (&iter, &iterkey, &itervalue)) {
		const char *key = iterkey, *value = itervalue;
		const char **p;
		static const char *filter_options[] = {
			"interface", "pid", "reason", "dhcp_message_type", NULL
		};
		gboolean ignore = FALSE;

		/* Filter out stuff that's not actually new DHCP options */
		for (p = filter_options; *p; p++) {
			if (!strcmp (*p, key) || !strncmp (key, OLD_TAG, strlen (OLD_TAG))) {
				ignore = TRUE;
				break;
			}
		}

		if (!ignore) {
			const char *tmp_key = value;

			/* Remove the "new_" prefix that dhclient passes back */
			if (!strncmp (key, NEW_TAG, strlen (NEW_TAG)))
				tmp_key = key + strlen (NEW_TAG);

			func ((gpointer) tmp_key, (gpointer) value, user_data);
		}
	}
	return TRUE;
}

/********************************************/

static void
process_classful_routes (GHashTable *options, NMIP4Config *ip4_config)
{
	const char *str;
	char **searches, **s;

	str = g_hash_table_lookup (options, "new_static_routes");
	if (!str)
		return;

	searches = g_strsplit (str, " ", 0);
	if ((g_strv_length (searches) % 2)) {
		nm_log_info (LOGD_DHCP, "  static routes provided, but invalid");
		goto out;
	}

	for (s = searches; *s; s += 2) {
		NMIP4Route *route;
		struct in_addr rt_addr;
		struct in_addr rt_route;

		if (inet_pton (AF_INET, *s, &rt_addr) <= 0) {
			nm_log_warn (LOGD_DHCP, "DHCP provided invalid static route address: '%s'", *s);
			continue;
		}
		if (inet_pton (AF_INET, *(s + 1), &rt_route) <= 0) {
			nm_log_warn (LOGD_DHCP, "DHCP provided invalid static route gateway: '%s'", *(s + 1));
			continue;
		}

		// FIXME: ensure the IP addresse and route are sane

		route = nm_ip4_route_new ();
		nm_ip4_route_set_dest (route, (guint32) rt_addr.s_addr);
		nm_ip4_route_set_prefix (route, 32); /* 255.255.255.255 */
		nm_ip4_route_set_next_hop (route, (guint32) rt_route.s_addr);

		nm_ip4_config_take_route (ip4_config, route);
		nm_log_info (LOGD_DHCP, "  static route %s gw %s", *s, *(s + 1));
	}

out:
	g_strfreev (searches);
}

static void
process_domain_search (const char *str, GFunc add_func, gpointer user_data)
{
	char **searches, **s;
	char *unescaped, *p;
	int i;

	g_return_if_fail (str != NULL);
	g_return_if_fail (add_func != NULL);

	p = unescaped = g_strdup (str);
	do {
		p = strstr (p, "\\032");
		if (!p)
			break;

		/* Clear the escaped space with real spaces */
		for (i = 0; i < 4; i++)
			*p++ = ' ';
	} while (*p++);

	if (strchr (unescaped, '\\')) {
		nm_log_warn (LOGD_DHCP, "  invalid domain search: '%s'", unescaped);
		goto out;
	}

	searches = g_strsplit (unescaped, " ", 0);
	for (s = searches; *s; s++) {
		if (strlen (*s)) {
			nm_log_info (LOGD_DHCP, "  domain search '%s'", *s);
			add_func (*s, user_data);
		}
	}
	g_strfreev (searches);

out:
	g_free (unescaped);
}

static void
ip4_add_domain_search (gpointer data, gpointer user_data)
{
	nm_ip4_config_add_search (NM_IP4_CONFIG (user_data), (const char *) data);
}

/* Given a table of DHCP options from the client, convert into an IP4Config */
static NMIP4Config *
ip4_options_to_config (NMDHCPClient *self)
{
	NMDHCPClientPrivate *priv;
	NMIP4Config *ip4_config = NULL;
	struct in_addr tmp_addr;
	NMIP4Address *addr = NULL;
	char *str = NULL;
	guint32 gwaddr = 0, prefix = 0;
	gboolean have_classless = FALSE;

	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), NULL);

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);
	g_return_val_if_fail (priv->options != NULL, NULL);

	ip4_config = nm_ip4_config_new ();
	if (!ip4_config) {
		nm_log_warn (LOGD_DHCP4, "(%s): couldn't allocate memory for an IP4Config!", priv->iface);
		return NULL;
	}

	addr = nm_ip4_address_new ();
	if (!addr) {
		nm_log_warn (LOGD_DHCP4, "(%s): couldn't allocate memory for an IP4 Address!", priv->iface);
		goto error;
	}

	str = g_hash_table_lookup (priv->options, "new_ip_address");
	if (str && (inet_pton (AF_INET, str, &tmp_addr) > 0)) {
		nm_ip4_address_set_address (addr, tmp_addr.s_addr);
		nm_log_info (LOGD_DHCP4, "  address %s", str);
	} else
		goto error;

	str = g_hash_table_lookup (priv->options, "new_subnet_mask");
	if (str && (inet_pton (AF_INET, str, &tmp_addr) > 0)) {
		prefix = nm_utils_ip4_netmask_to_prefix (tmp_addr.s_addr);
		nm_log_info (LOGD_DHCP4, "  prefix %d (%s)", prefix, str);
	} else {
		/* Get default netmask for the IP according to appropriate class. */
		prefix = nm_utils_ip4_get_default_prefix (nm_ip4_address_get_address (addr));
		nm_log_info (LOGD_DHCP4, "  prefix %d (default)", prefix);
	}
	nm_ip4_address_set_prefix (addr, prefix);

	/* Routes: if the server returns classless static routes, we MUST ignore
	 * the 'static_routes' option.
	 */
	if (NM_DHCP_CLIENT_GET_CLASS (self)->ip4_process_classless_routes) {
		have_classless = NM_DHCP_CLIENT_GET_CLASS (self)->ip4_process_classless_routes (self,
		                                                                                priv->options,
		                                                                                ip4_config,
		                                                                                &gwaddr);
	}

	if (!have_classless) {
		gwaddr = 0;  /* Ensure client code doesn't lie */
		process_classful_routes (priv->options, ip4_config);
	}

	if (gwaddr) {
		char buf[INET_ADDRSTRLEN + 1];

		inet_ntop (AF_INET, &gwaddr, buf, sizeof (buf));
		nm_log_info (LOGD_DHCP4, "  gateway %s", buf);
		nm_ip4_address_set_gateway (addr, gwaddr);
	} else {
		/* If the gateway wasn't provided as a classless static route with a
		 * subnet length of 0, try to find it using the old-style 'routers' option.
		 */
		str = g_hash_table_lookup (priv->options, "new_routers");
		if (str) {
			char **routers = g_strsplit (str, " ", 0);
			char **s;

			for (s = routers; *s; s++) {
				/* FIXME: how to handle multiple routers? */
				if (inet_pton (AF_INET, *s, &tmp_addr) > 0) {
					nm_ip4_address_set_gateway (addr, tmp_addr.s_addr);
					nm_log_info (LOGD_DHCP4, "  gateway %s", *s);
					break;
				} else
					nm_log_warn (LOGD_DHCP4, "ignoring invalid gateway '%s'", *s);
			}
			g_strfreev (routers);
		}
	}

	nm_ip4_config_take_address (ip4_config, addr);
	addr = NULL;

	str = g_hash_table_lookup (priv->options, "new_host_name");
	if (str)
		nm_log_info (LOGD_DHCP4, "  hostname '%s'", str);

	str = g_hash_table_lookup (priv->options, "new_domain_name_servers");
	if (str) {
		char **searches = g_strsplit (str, " ", 0);
		char **s;

		for (s = searches; *s; s++) {
			if (inet_pton (AF_INET, *s, &tmp_addr) > 0) {
				nm_ip4_config_add_nameserver (ip4_config, tmp_addr.s_addr);
				nm_log_info (LOGD_DHCP4, "  nameserver '%s'", *s);
			} else
				nm_log_warn (LOGD_DHCP4, "ignoring invalid nameserver '%s'", *s);
		}
		g_strfreev (searches);
	}

	str = g_hash_table_lookup (priv->options, "new_domain_name");
	if (str) {
		char **domains = g_strsplit (str, " ", 0);
		char **s;

		for (s = domains; *s; s++) {
			nm_log_info (LOGD_DHCP4, "  domain name '%s'", *s);
			nm_ip4_config_add_domain (ip4_config, *s);
		}
		g_strfreev (domains);
	}

	str = g_hash_table_lookup (priv->options, "new_domain_search");
	if (str)
		process_domain_search (str, ip4_add_domain_search, ip4_config);

	str = g_hash_table_lookup (priv->options, "new_netbios_name_servers");
	if (str) {
		char **searches = g_strsplit (str, " ", 0);
		char **s;

		for (s = searches; *s; s++) {
			if (inet_pton (AF_INET, *s, &tmp_addr) > 0) {
				nm_ip4_config_add_wins (ip4_config, tmp_addr.s_addr);
				nm_log_info (LOGD_DHCP4, "  wins '%s'", *s);
			} else
				nm_log_warn (LOGD_DHCP4, "ignoring invalid WINS server '%s'", *s);
		}
		g_strfreev (searches);
	}

	str = g_hash_table_lookup (priv->options, "new_interface_mtu");
	if (str) {
		int int_mtu;

		errno = 0;
		int_mtu = strtol (str, NULL, 10);
		if ((errno == EINVAL) || (errno == ERANGE))
			goto error;

		if (int_mtu > 576)
			nm_ip4_config_set_mtu (ip4_config, int_mtu);
	}

	str = g_hash_table_lookup (priv->options, "new_nis_domain");
	if (str) {
		nm_log_info (LOGD_DHCP4, "  NIS domain '%s'", str);
		nm_ip4_config_set_nis_domain (ip4_config, str);
	}

	str = g_hash_table_lookup (priv->options, "new_nis_servers");
	if (str) {
		char **searches = g_strsplit (str, " ", 0);
		char **s;

		for (s = searches; *s; s++) {
			if (inet_pton (AF_INET, *s, &tmp_addr) > 0) {
				nm_ip4_config_add_nis_server (ip4_config, tmp_addr.s_addr);
				nm_log_info (LOGD_DHCP4, "  nis '%s'", *s);
			} else
				nm_log_warn (LOGD_DHCP4, "ignoring invalid NIS server '%s'", *s);
		}
		g_strfreev (searches);
	}

	return ip4_config;

error:
	if (addr)
		nm_ip4_address_unref (addr);
	g_object_unref (ip4_config);
	return NULL;
}

NMIP4Config *
nm_dhcp_client_get_ip4_config (NMDHCPClient *self, gboolean test)
{
	NMDHCPClientPrivate *priv;

	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), NULL);

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	if (test && !state_is_bound (priv->state)) {
		nm_log_warn (LOGD_DHCP4, "(%s): DHCPv4 client didn't bind to a lease.", priv->iface);
		return NULL;
	}

	if (!g_hash_table_size (priv->options)) {
		/* We never got a response from the DHCP client */
		return NULL;
	}

	return ip4_options_to_config (self);
}

/********************************************/

static void
ip6_add_domain_search (gpointer data, gpointer user_data)
{
	nm_ip6_config_add_search (NM_IP6_CONFIG (user_data), (const char *) data);
}

/* Given a table of DHCP options from the client, convert into an IP6Config */
static NMIP6Config *
ip6_options_to_config (NMDHCPClient *self)
{
	NMDHCPClientPrivate *priv;
	NMIP6Config *ip6_config = NULL;
	struct in6_addr tmp_addr;
	NMIP6Address *addr = NULL;
	char *str = NULL;
	GHashTableIter iter;
	gpointer key, value;

	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), NULL);

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);
	g_return_val_if_fail (priv->options != NULL, NULL);

	g_hash_table_iter_init (&iter, priv->options);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		nm_log_dbg (LOGD_DHCP6, "(%s): option '%s'=>'%s'",
		            priv->iface, (const char *) key, (const char *) value);
	}

	ip6_config = nm_ip6_config_new ();
	if (!ip6_config) {
		nm_log_warn (LOGD_DHCP6, "(%s): couldn't allocate memory for an IP6Config!", priv->iface);
		return NULL;
	}

	addr = nm_ip6_address_new ();
	if (!addr) {
		nm_log_warn (LOGD_DHCP6, "(%s): couldn't allocate memory for an IP6 Address!", priv->iface);
		goto error;
	}

	str = g_hash_table_lookup (priv->options, "new_ip6_address");
	if (str) {
		if (!inet_pton (AF_INET6, str, &tmp_addr)) {
			nm_log_warn (LOGD_DHCP6, "(%s): DHCP returned invalid address '%s'",
			             priv->iface);
			goto error;
		}

		nm_ip6_address_set_address (addr, &tmp_addr);
		nm_log_info (LOGD_DHCP6, "  address %s", str);
	} else {
		/* No address in managed mode is a hard error */
		if (priv->info_only == FALSE)
			goto error;

		/* But "info-only" setups don't necessarily need an address */
		nm_ip6_address_unref (addr);
		addr = NULL;
	}

	/* Only care about prefix if we got an address */
	if (addr) {
		str = g_hash_table_lookup (priv->options, "new_ip6_prefixlen");
		if (str) {
			long unsigned int prefix;

			errno = 0;
			prefix = strtoul (str, NULL, 10);
			if (errno != 0 || prefix > 128)
				goto error;

			nm_ip6_address_set_prefix (addr, (guint32) prefix);
			nm_log_info (LOGD_DHCP6, "  prefix %lu", prefix);
		}

		nm_ip6_config_take_address (ip6_config, addr);
		addr = NULL;
	}

	str = g_hash_table_lookup (priv->options, "new_host_name");
	if (str)
		nm_log_info (LOGD_DHCP6, "  hostname '%s'", str);

	str = g_hash_table_lookup (priv->options, "new_dhcp6_name_servers");
	if (str) {
		char **searches = g_strsplit (str, " ", 0);
		char **s;

		for (s = searches; *s; s++) {
			if (inet_pton (AF_INET6, *s, &tmp_addr) > 0) {
				nm_ip6_config_add_nameserver (ip6_config, &tmp_addr);
				nm_log_info (LOGD_DHCP6, "  nameserver '%s'", *s);
			} else
				nm_log_warn (LOGD_DHCP6, "ignoring invalid nameserver '%s'", *s);
		}
		g_strfreev (searches);
	}

	str = g_hash_table_lookup (priv->options, "new_dhcp6_domain_search");
	if (str)
		process_domain_search (str, ip6_add_domain_search, ip6_config);

	return ip6_config;

error:
	if (addr)
		nm_ip6_address_unref (addr);
	g_object_unref (ip6_config);
	return NULL;
}

NMIP6Config *
nm_dhcp_client_get_ip6_config (NMDHCPClient *self, gboolean test)
{
	NMDHCPClientPrivate *priv;

	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), NULL);

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	if (test && !state_is_bound (priv->state)) {
		nm_log_warn (LOGD_DHCP6, "(%s): DHCPv6 client didn't bind to a lease.", priv->iface);
		return NULL;
	}

	if (!g_hash_table_size (priv->options)) {
		/* We never got a response from the DHCP client */
		return NULL;
	}

	return ip6_options_to_config (self);
}

/********************************************/

static void
nm_dhcp_client_init (NMDHCPClient *self)
{
	NMDHCPClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	priv->options = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	priv->pid = -1;
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMDHCPClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_IFACE:
		g_value_set_string (value, priv->iface);
		break;
	case PROP_IPV6:
		g_value_set_boolean (value, priv->ipv6);
		break;
	case PROP_UUID:
		g_value_set_string (value, priv->uuid);
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
	NMDHCPClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (object);
 
	switch (prop_id) {
	case PROP_IFACE:
		/* construct-only */
		priv->iface = g_strdup (g_value_get_string (value));
		break;
	case PROP_IPV6:
		/* construct-only */
		priv->ipv6 = g_value_get_boolean (value);
		break;
	case PROP_UUID:
		/* construct-only */
		priv->uuid = g_value_dup_string (value);
		break;
	case PROP_TIMEOUT:
		priv->timeout = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMDHCPClient *self = NM_DHCP_CLIENT (object);
	NMDHCPClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	/* Stopping the client is left up to the controlling device
	 * explicitly since we may want to quit NetworkManager but not terminate
	 * the DHCP client.
	 */

	if (priv->remove_id)
		g_source_remove (priv->remove_id);

	g_hash_table_destroy (priv->options);
	g_free (priv->iface);

	G_OBJECT_CLASS (nm_dhcp_client_parent_class)->dispose (object);
}

static void
nm_dhcp_client_class_init (NMDHCPClientClass *client_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (client_class);

	g_type_class_add_private (client_class, sizeof (NMDHCPClientPrivate));

	/* virtual methods */
	object_class->dispose = dispose;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	client_class->stop = real_stop;

	g_object_class_install_property
		(object_class, PROP_IFACE,
		 g_param_spec_string (NM_DHCP_CLIENT_INTERFACE,
		                      "iface",
		                      "Interface",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_IPV6,
		 g_param_spec_boolean (NM_DHCP_CLIENT_IPV6,
		                       "ipv6",
		                       "IPv6",
		                       FALSE,
		                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_UUID,
		 g_param_spec_string (NM_DHCP_CLIENT_UUID,
		                      "uuid",
		                      "UUID",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_TIMEOUT,
		 g_param_spec_uint (NM_DHCP_CLIENT_TIMEOUT,
		                    "timeout",
		                    "Timeout",
		                    0, G_MAXUINT, 45,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/* signals */
	signals[STATE_CHANGED] =
		g_signal_new ("state-changed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMDHCPClientClass, state_changed),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__UINT,
					  G_TYPE_NONE, 1, G_TYPE_UINT);

	signals[TIMEOUT] =
		g_signal_new ("timeout",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMDHCPClientClass, timeout),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__VOID,
					  G_TYPE_NONE, 0);

	signals[REMOVE] =
		g_signal_new ("remove",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMDHCPClientClass, remove),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__VOID,
					  G_TYPE_NONE, 0);
}

