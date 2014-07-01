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

#include <config.h>
#include <glib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <uuid/uuid.h>

#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-logging.h"
#include "nm-dbus-glib-types.h"
#include "nm-dhcp-client.h"
#include "nm-dhcp-utils.h"

typedef struct {
	char *       iface;
	int          ifindex;
	GByteArray * hwaddr;
	gboolean     ipv6;
	char *       uuid;
	guint        priority;
	guint32      timeout;
	GByteArray * duid;

	NMDhcpState  state;
	pid_t        pid;
	guint        timeout_id;
	guint        watch_id;
	GHashTable * options;
	gboolean     info_only;

} NMDHCPClientPrivate;

#define NM_DHCP_CLIENT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DHCP_CLIENT, NMDHCPClientPrivate))

G_DEFINE_TYPE_EXTENDED (NMDHCPClient, nm_dhcp_client, G_TYPE_OBJECT, G_TYPE_FLAG_ABSTRACT, {})

enum {
	SIGNAL_STATE_CHANGED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_IFACE,
	PROP_IFINDEX,
	PROP_HWADDR,
	PROP_IPV6,
	PROP_UUID,
	PROP_PRIORITY,
	PROP_TIMEOUT,
	LAST_PROP
};

/********************************************/

pid_t
nm_dhcp_client_get_pid (NMDHCPClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), -1);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->pid;
}

const char *
nm_dhcp_client_get_iface (NMDHCPClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), NULL);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->iface;
}

int
nm_dhcp_client_get_ifindex (NMDHCPClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), -1);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->ifindex;
}

gboolean
nm_dhcp_client_get_ipv6 (NMDHCPClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), FALSE);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->ipv6;
}

const char *
nm_dhcp_client_get_uuid (NMDHCPClient *self)
{
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

void
nm_dhcp_client_stop_pid (pid_t pid, const char *iface)
{
	char *name = iface ? g_strdup_printf ("dhcp-client-%s", iface) : NULL;

	nm_utils_kill_child_sync (pid, SIGTERM, LOGD_DHCP, name ? name : "dhcp-client", NULL,
	                          1000 / 2, 1000 / 20);
	g_free (name);
}

static void
stop (NMDHCPClient *self, gboolean release, const GByteArray *duid)
{
	NMDHCPClientPrivate *priv;

	g_return_if_fail (NM_IS_DHCP_CLIENT (self));

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	if (priv->pid > 0) {
		/* Clean up the watch handler since we're explicitly killing the daemon */
		watch_cleanup (self);
		nm_dhcp_client_stop_pid (priv->pid, priv->iface);
		priv->pid = -1;
	}

	priv->info_only = FALSE;
}

void
nm_dhcp_client_set_state (NMDHCPClient *self, NMDhcpState state)
{
	NM_DHCP_CLIENT_GET_PRIVATE (self)->state = state;
	g_signal_emit (G_OBJECT (self), signals[SIGNAL_STATE_CHANGED], 0, state);
}

static gboolean
daemon_timeout (gpointer user_data)
{
	NMDHCPClient *self = NM_DHCP_CLIENT (user_data);
	NMDHCPClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	priv->timeout_id = 0;
	nm_log_warn (priv->ipv6 ? LOGD_DHCP6 : LOGD_DHCP4,
	             "(%s): DHCPv%c request timed out.",
	             priv->iface,
	             priv->ipv6 ? '6' : '4');
	nm_dhcp_client_set_state (self, NM_DHCP_STATE_TIMEOUT);
	return G_SOURCE_REMOVE;
}

static void
daemon_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMDHCPClient *self = NM_DHCP_CLIENT (user_data);
	NMDHCPClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);
	NMDhcpState new_state;

	if (priv->ipv6) {
		nm_log_info (LOGD_DHCP6, "(%s): DHCPv6 client pid %d exited with status %d",
		             priv->iface, pid,
		             WIFEXITED (status) ? WEXITSTATUS (status) : -1);
	} else {
		nm_log_info (LOGD_DHCP4, "(%s): DHCPv4 client pid %d exited with status %d",
		             priv->iface, pid,
		             WIFEXITED (status) ? WEXITSTATUS (status) : -1);
	}

	if (!WIFEXITED (status)) {
		new_state = NM_DHCP_STATE_FAIL;
		nm_log_warn (LOGD_DHCP, "DHCP client died abnormally");
	} else
		new_state = NM_DHCP_STATE_DONE;

	watch_cleanup (self);
	timeout_cleanup (self);
	priv->pid = -1;

	nm_dhcp_client_set_state (self, new_state);
}

void
nm_dhcp_client_watch_child (NMDHCPClient *self, pid_t pid)
{
	NMDHCPClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	g_return_if_fail (priv->pid == -1);
	priv->pid = pid;

	/* Set up a timeout on the transaction to kill it after the timeout */
	g_assert (priv->timeout_id == 0);
	priv->timeout_id = g_timeout_add_seconds (priv->timeout,
	                                          daemon_timeout,
	                                          self);
	g_assert (priv->watch_id == 0);
	priv->watch_id = g_child_watch_add (pid, daemon_watch_cb, self);
}

gboolean
nm_dhcp_client_start_ip4 (NMDHCPClient *self,
                          const char *dhcp_client_id,
                          GByteArray *dhcp_anycast_addr,
                          const char *hostname)
{
	NMDHCPClientPrivate *priv;

	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), FALSE);

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);
	g_return_val_if_fail (priv->pid == -1, FALSE);
	g_return_val_if_fail (priv->ipv6 == FALSE, FALSE);
	g_return_val_if_fail (priv->uuid != NULL, FALSE);

	nm_log_info (LOGD_DHCP, "Activation (%s) Beginning DHCPv4 transaction (timeout in %d seconds)",
	             priv->iface, priv->timeout);

	return NM_DHCP_CLIENT_GET_CLASS (self)->ip4_start (self, dhcp_client_id, dhcp_anycast_addr, hostname);
}

/* uuid_parse does not work for machine-id, so we use our own converter */
static gboolean
machine_id_parse (const char *in, uuid_t uu)
{
	const char *cp;
	int i;
	char buf[3];

	g_return_val_if_fail (in != NULL, FALSE);
	g_return_val_if_fail (strlen (in) == 32, FALSE);

	for (i = 0; i < 32; i++) {
		if (!g_ascii_isxdigit (in[i]))
			return FALSE;
	}

	buf[2] = 0;
	cp = in;
	for (i = 0; i < 16; i++) {
		buf[0] = *cp++;
		buf[1] = *cp++;
		uu[i] = ((unsigned char) strtoul (buf, NULL, 16)) & 0xFF;
	}
	return TRUE;
}

static GByteArray *
generate_duid_from_machine_id (void)
{
	GByteArray *duid;
	char *contents = NULL;
	GChecksum *sum;
	guint8 buffer[32]; /* SHA256 digest size */
	gsize sumlen = sizeof (buffer);
	const guint16 duid_type = g_htons (4);
	uuid_t uuid;
	GRand *generator;
	guint i;
	gboolean success = FALSE;

	/* Get the machine ID from /etc/machine-id; it's always in /etc no matter
	 * where our configured SYSCONFDIR is.  Alternatively, it might be in
	 * LOCALSTATEDIR /lib/dbus/machine-id.
	 */
	if (   g_file_get_contents ("/etc/machine-id", &contents, NULL, NULL)
	    || g_file_get_contents (LOCALSTATEDIR "/lib/dbus/machine-id", &contents, NULL, NULL)) {
		contents = g_strstrip (contents);
		success = machine_id_parse (contents, uuid);
		if (success) {
			/* Hash the machine ID so it's not leaked to the network */
			sum = g_checksum_new (G_CHECKSUM_SHA256);
			g_checksum_update (sum, (const guchar *) &uuid, sizeof (uuid));
			g_checksum_get_digest (sum, buffer, &sumlen);
			g_checksum_free (sum);
		}
		g_free (contents);
	}

	if (!success) {
		nm_log_warn (LOGD_DHCP6, "Failed to read " SYSCONFDIR "/machine-id "
		             "or " LOCALSTATEDIR "/lib/dbus/machine-id to generate "
		             "DHCPv6 DUID; creating non-persistent random DUID.");

		generator = g_rand_new ();
		for (i = 0; i < sizeof (buffer) / sizeof (guint32); i++)
			((guint32 *) buffer)[i] = g_rand_int (generator);
		g_rand_free (generator);
	}

	/* Generate a DHCP Unique Identifier for DHCPv6 using the
	 * DUID-UUID method (see RFC 6355 section 4).  Format is:
	 *
	 * u16: type (DUID-UUID = 4)
	 * u8[16]: UUID bytes
	 */
	duid = g_byte_array_sized_new (18);
	g_byte_array_append (duid, (guint8 *) &duid_type, sizeof (duid_type));

	/* Since SHA256 is 256 bits, but UUID is 128 bits, we just take the first
	 * 128 bits of the SHA256 as the DUID-UUID.
	 */
	g_byte_array_append (duid, buffer, 16);

	return duid;
}

static char *
escape_duid (const GByteArray *duid)
{
	guint32 i = 0;
	GString *s;

	g_return_val_if_fail (duid != NULL, NULL);

	s = g_string_sized_new (40);
	while (i < duid->len) {
		if (s->len)
			g_string_append_c (s, ':');
		g_string_append_printf (s, "%02x", duid->data[i++]);
	}
	return g_string_free (s, FALSE);
}

static GByteArray *
get_duid (NMDHCPClient *self)
{
	static GByteArray *duid = NULL;
	GByteArray *copy = NULL;
	char *escaped;

	if (G_UNLIKELY (duid == NULL)) {
		duid = generate_duid_from_machine_id ();
		g_assert (duid);

		if (nm_logging_enabled (LOGL_DEBUG, LOGD_DHCP6)) {
			escaped = escape_duid (duid);
			nm_log_dbg (LOGD_DHCP6, "Generated DUID %s", escaped);
			g_free (escaped);
		}
	}

	if (G_LIKELY (duid)) {
		copy = g_byte_array_sized_new (duid->len);
		g_byte_array_append (copy, duid->data, duid->len);
	}

	return copy;
}

gboolean
nm_dhcp_client_start_ip6 (NMDHCPClient *self,
                          GByteArray *dhcp_anycast_addr,
                          const char *hostname,
                          gboolean info_only)
{
	NMDHCPClientPrivate *priv;
	char *escaped;

	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), FALSE);

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);
	g_return_val_if_fail (priv->pid == -1, FALSE);
	g_return_val_if_fail (priv->ipv6 == TRUE, FALSE);
	g_return_val_if_fail (priv->uuid != NULL, FALSE);

	/* If we don't have one yet, read the default DUID for this DHCPv6 client
	 * from the client-specific persistent configuration.
	 */
	if (!priv->duid)
		priv->duid = NM_DHCP_CLIENT_GET_CLASS (self)->get_duid (self);

	if (nm_logging_enabled (LOGL_DEBUG, LOGD_DHCP)) {
		escaped = escape_duid (priv->duid);
		nm_log_dbg (LOGD_DHCP, "(%s): DHCPv6 DUID is '%s'", priv->iface, escaped);
		g_free (escaped);
	}

	priv->info_only = info_only;

	nm_log_info (LOGD_DHCP, "Activation (%s) Beginning DHCPv6 transaction (timeout in %d seconds)",
	             priv->iface, priv->timeout);

	return NM_DHCP_CLIENT_GET_CLASS (self)->ip6_start (self,
	                                                   dhcp_anycast_addr,
	                                                   hostname,
	                                                   info_only,
	                                                   priv->duid);
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
				nm_dhcp_client_stop_pid ((pid_t) tmp, NULL);
		}
	}

	if (remove (pid_file) == -1)
		nm_log_dbg (LOGD_DHCP, "Could not remove dhcp pid file \"%s\": %d (%s)", pid_file, errno, g_strerror (errno));

	g_free (proc_path);
	g_free (pid_contents);
	g_free (proc_contents);
}

void
nm_dhcp_client_stop (NMDHCPClient *self, gboolean release)
{
	NMDHCPClientPrivate *priv;
	pid_t old_pid = 0;

	g_return_if_fail (NM_IS_DHCP_CLIENT (self));

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	/* Kill the DHCP client */
	old_pid = priv->pid;
	NM_DHCP_CLIENT_GET_CLASS (self)->stop (self, release, priv->duid);
	if (old_pid > 0) {
		nm_log_info (LOGD_DHCP, "(%s): canceled DHCP transaction, DHCP client pid %d",
		             priv->iface, old_pid);
	} else
		nm_log_info (LOGD_DHCP, "(%s): canceled DHCP transaction", priv->iface);
	g_assert (priv->pid == -1);

	/* And clean stuff up */
	g_hash_table_remove_all (priv->options);
	timeout_cleanup (self);
	watch_cleanup (self);

	nm_dhcp_client_set_state (self, NM_DHCP_STATE_DONE);
}

/********************************************/

static const char *state_table[NM_DHCP_STATE_MAX + 1] = {
	[NM_DHCP_STATE_UNKNOWN]  = "unknown",
	[NM_DHCP_STATE_BOUND]    = "bound",
	[NM_DHCP_STATE_TIMEOUT]  = "timeout",
	[NM_DHCP_STATE_DONE]     = "done",
	[NM_DHCP_STATE_FAIL]     = "fail",
};

static const char *
state_to_string (NMDhcpState state)
{
	if (state >= 0 && state < G_N_ELEMENTS (state_table))
		return state_table[state];
	return NULL;
}

static NMDhcpState
reason_to_state (const char *iface, const char *reason)
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
	else if (g_ascii_strcasecmp (reason, "end") == 0)
		return NM_DHCP_STATE_DONE;
	else if (g_ascii_strcasecmp (reason, "fail") == 0 ||
	         g_ascii_strcasecmp (reason, "abend") == 0 ||
	         g_ascii_strcasecmp (reason, "nak") == 0)
		return NM_DHCP_STATE_FAIL;

	nm_log_dbg (LOGD_DHCP, "(%s): unmapped DHCP state '%s'", iface, reason);
	return NM_DHCP_STATE_UNKNOWN;
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

	g_return_if_fail (NM_IS_DHCP_CLIENT (self));
	g_return_if_fail (options != NULL);
	g_return_if_fail (reason != NULL);

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);
	old_state = priv->state;
	new_state = reason_to_state (priv->iface, reason);

	/* Clear old and save new DHCP options */
	g_hash_table_remove_all (priv->options);
	g_hash_table_foreach (options, copy_option, priv->options);

	/* dhclient sends same-state transitions for RENEW/REBIND events, but
	 * the lease may have changed, so handle same-state transitions for
	 * these events.  Ignore same-state transitions for other events since
	 * the lease won't have changed and the state was already handled.
	 */
	if ((old_state == new_state) && (new_state != NM_DHCP_STATE_BOUND))
		return;

	if (new_state == NM_DHCP_STATE_BOUND) {
		/* Cancel the timeout if the DHCP client is now bound */
		timeout_cleanup (self);
	}

	nm_log_info (priv->ipv6 ? LOGD_DHCP6 : LOGD_DHCP4,
	             "(%s): DHCPv%c state changed %s -> %s",
	             priv->iface,
	             priv->ipv6 ? '6' : '4',
	             state_to_string (old_state),
	             state_to_string (new_state));

	nm_dhcp_client_set_state (self, new_state);
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

	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), FALSE);
	g_return_val_if_fail (func != NULL, FALSE);

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	if (priv->state != NM_DHCP_STATE_BOUND) {
		nm_log_warn (priv->ipv6 ? LOGD_DHCP6 : LOGD_DHCP4,
		             "(%s): DHCPv%c client didn't bind to a lease.",
		             priv->iface,
		             priv->ipv6 ? '6' : '4');
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
			const char *tmp_key = key;

			/* Remove the "new_" prefix that dhclient passes back */
			if (!strncmp (key, NEW_TAG, strlen (NEW_TAG)))
				tmp_key = key + strlen (NEW_TAG);

			func ((gpointer) tmp_key, (gpointer) value, user_data);
		}
	}
	return TRUE;
}

/********************************************/

NMIP4Config *
nm_dhcp_client_get_ip4_config (NMDHCPClient *self, gboolean test)
{
	NMDHCPClientPrivate *priv;

	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), NULL);

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	if (test && (priv->state != NM_DHCP_STATE_BOUND)) {
		nm_log_warn (LOGD_DHCP4, "(%s): DHCPv4 client didn't bind to a lease.", priv->iface);
		return NULL;
	}

	if (!g_hash_table_size (priv->options)) {
		/* We never got a response from the DHCP client */
		return NULL;
	}

	return nm_dhcp_utils_ip4_config_from_options (priv->iface, priv->options, priv->priority);
}

NMIP6Config *
nm_dhcp_client_get_ip6_config (NMDHCPClient *self, gboolean test)
{
	NMDHCPClientPrivate *priv;

	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), NULL);

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	if (test && (priv->state != NM_DHCP_STATE_BOUND)) {
		nm_log_warn (LOGD_DHCP6, "(%s): DHCPv6 client didn't bind to a lease.", priv->iface);
		return NULL;
	}

	if (!g_hash_table_size (priv->options)) {
		/* We never got a response from the DHCP client */
		return NULL;
	}

	return nm_dhcp_utils_ip6_config_from_options (priv->iface,
	                                              priv->options,
	                                              priv->priority,
	                                              priv->info_only);
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
	case PROP_IFINDEX:
		g_value_set_int (value, priv->ifindex);
		break;
	case PROP_HWADDR:
		g_value_set_boxed (value, priv->hwaddr);
		break;
	case PROP_IPV6:
		g_value_set_boolean (value, priv->ipv6);
		break;
	case PROP_UUID:
		g_value_set_string (value, priv->uuid);
		break;
	case PROP_PRIORITY:
		g_value_set_uint (value, priv->priority);
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
	case PROP_IFINDEX:
		/* construct-only */
		priv->ifindex = g_value_get_int (value);
		g_warn_if_fail (priv->ifindex > 0);
		break;
	case PROP_HWADDR:
		/* construct only */
		priv->hwaddr = g_value_dup_boxed (value);
		break;
	case PROP_IPV6:
		/* construct-only */
		priv->ipv6 = g_value_get_boolean (value);
		break;
	case PROP_UUID:
		/* construct-only */
		priv->uuid = g_value_dup_string (value);
		break;
	case PROP_PRIORITY:
		/* construct-only */
		priv->priority = g_value_get_uint (value);
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

	watch_cleanup (self);
	timeout_cleanup (self);

	if (priv->options) {
		g_hash_table_destroy (priv->options);
		priv->options = NULL;
	}
	g_clear_pointer (&priv->iface, g_free);

	if (priv->hwaddr) {
		g_byte_array_free (priv->hwaddr, TRUE);
		priv->hwaddr = NULL;
	}

	if (priv->duid) {
		g_byte_array_free (priv->duid, TRUE);
		priv->duid = NULL;
	}

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

	client_class->stop = stop;
	client_class->get_duid = get_duid;

	g_object_class_install_property
		(object_class, PROP_IFACE,
		 g_param_spec_string (NM_DHCP_CLIENT_INTERFACE, "", "",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_IFINDEX,
		 g_param_spec_int (NM_DHCP_CLIENT_IFINDEX, "", "",
		                   -1, G_MAXINT, -1,
		                   G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_HWADDR,
		 g_param_spec_boxed (NM_DHCP_CLIENT_HWADDR, "", "",
		                     G_TYPE_BYTE_ARRAY,
		                     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                     G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_IPV6,
		 g_param_spec_boolean (NM_DHCP_CLIENT_IPV6, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_UUID,
		 g_param_spec_string (NM_DHCP_CLIENT_UUID, "", "",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_PRIORITY,
		 g_param_spec_uint (NM_DHCP_CLIENT_PRIORITY, "", "",
		                    0, G_MAXUINT, 0,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_TIMEOUT,
		 g_param_spec_uint (NM_DHCP_CLIENT_TIMEOUT, "", "",
		                    0, G_MAXUINT, 45,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                    G_PARAM_STATIC_STRINGS));

	/* signals */
	signals[SIGNAL_STATE_CHANGED] =
		g_signal_new (NM_DHCP_CLIENT_SIGNAL_STATE_CHANGED,
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMDHCPClientClass, state_changed),
					  NULL, NULL, NULL,
					  G_TYPE_NONE, 1, G_TYPE_UINT);
}

