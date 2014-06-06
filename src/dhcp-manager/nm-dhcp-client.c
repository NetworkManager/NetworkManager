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

typedef struct {
	char *       iface;
	GByteArray * hwaddr;
	gboolean     ipv6;
	char *       uuid;
	guint        priority;
	guint32      timeout;
	GByteArray * duid;

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
	SIGNAL_STATE_CHANGED,
	SIGNAL_TIMEOUT,
	SIGNAL_REMOVE,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_IFACE,
	PROP_HWADDR,
	PROP_IPV6,
	PROP_UUID,
	PROP_PRIORITY,
	PROP_TIMEOUT,
	LAST_PROP
};

/********************************************/

GPid
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
nm_dhcp_client_stop_pid (GPid pid, const char *iface)
{
	int i = 5;  /* roughly 0.5 seconds */

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
			if (errno == ECHILD) {
				/* Was it really our child and it exited? */
				if (kill (pid, 0) < 0 && errno == ESRCH)
					break;
			} else {
				/* Took too long; shoot it in the head */
				i = 0;
				break;
			}
		}
		g_usleep (G_USEC_PER_SEC / 10);
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
stop (NMDHCPClient *self, gboolean release, const GByteArray *duid)
{
	NMDHCPClientPrivate *priv;

	g_return_if_fail (NM_IS_DHCP_CLIENT (self));

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);
	g_return_if_fail (priv->pid > 0);

	/* Clean up the watch handler since we're explicitly killing the daemon */
	watch_cleanup (self);

	nm_dhcp_client_stop_pid (priv->pid, priv->iface);

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
	g_signal_emit (G_OBJECT (self), signals[SIGNAL_TIMEOUT], 0);
	return FALSE;
}

static gboolean
signal_remove (gpointer user_data)
{
	NMDHCPClient *self = NM_DHCP_CLIENT (user_data);

	NM_DHCP_CLIENT_GET_PRIVATE (self)->remove_id = 0;
	g_signal_emit (G_OBJECT (self), signals[SIGNAL_REMOVE], 0);
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
		g_signal_emit (G_OBJECT (self), signals[SIGNAL_STATE_CHANGED], 0, priv->state);

	if (state == DHC_END || state == DHC_ABEND) {
		/* Start the remove signal timer */
		if (remove_now) {
			g_signal_emit (G_OBJECT (self), signals[SIGNAL_REMOVE], 0);
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
		nm_log_info (LOGD_DHCP4, "(%s): DHCPv4 client pid %d exited with status %d",
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

	priv->pid = NM_DHCP_CLIENT_GET_CLASS (self)->ip4_start (self, dhcp_client_id, dhcp_anycast_addr, hostname);
	if (priv->pid)
		start_monitor (self);

	return priv->pid ? TRUE : FALSE;
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

	priv->pid = NM_DHCP_CLIENT_GET_CLASS (self)->ip6_start (self,
	                                                        dhcp_anycast_addr,
	                                                        hostname,
	                                                        info_only,
	                                                        priv->duid);
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
				nm_dhcp_client_stop_pid ((GPid) tmp, NULL);
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

	g_return_if_fail (NM_IS_DHCP_CLIENT (self));

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	/* Kill the DHCP client */
	if (!priv->dead) {
		NM_DHCP_CLIENT_GET_CLASS (self)->stop (self, release, priv->duid);
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

static const char *state_table[] = {
	[DHC_NBI]             = "nbi",
	[DHC_PREINIT]         = "preinit",
	[DHC_PREINIT6]        = "preinit6",
	[DHC_BOUND4]          = "bound",
	[DHC_BOUND6]          = "bound6",
	[DHC_IPV4LL]          = "ipv4ll",
	[DHC_RENEW4]          = "renew",
	[DHC_RENEW6]          = "renew6",
	[DHC_REBOOT]          = "reboot",
	[DHC_REBIND4]         = "rebind",
	[DHC_REBIND6]         = "rebind6",
	[DHC_DEPREF6]         = "depref6",
	[DHC_STOP]            = "stop",
	[DHC_STOP6]           = "stop6",
	[DHC_MEDIUM]          = "medium",
	[DHC_TIMEOUT]         = "timeout",
	[DHC_FAIL]            = "fail",
	[DHC_EXPIRE]          = "expire",
	[DHC_EXPIRE6]         = "expire6",
	[DHC_RELEASE]         = "release",
	[DHC_RELEASE6]        = "release6",
	[DHC_START]           = "start",
	[DHC_ABEND]           = "abend",
	[DHC_END]             = "end",
};

static const char *
state_to_string (NMDHCPState state)
{
	if (state >= 0 && state < G_N_ELEMENTS (state_table))
		return state_table[state];
	return NULL;
}

static NMDHCPState
string_to_state (const char *name)
{
	int i;

	if (name) {
		for (i = 0; i < G_N_ELEMENTS (state_table); i++) {
			const char *n = state_table[i];

			if (n && !strcasecmp (name, n))
				return i;
		}
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

	g_return_if_fail (NM_IS_DHCP_CLIENT (self));
	g_return_if_fail (options != NULL);
	g_return_if_fail (reason != NULL);

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);
	old_state = priv->state;
	new_state = string_to_state (reason);

	/* Clear old and save new DHCP options */
	g_hash_table_remove_all (priv->options);
	g_hash_table_foreach (options, copy_option, priv->options);

	if (old_state == new_state) {
		/* dhclient will stay in the same state (or, really, provide the same
		 * reason) for operations like RENEW and REBIND.  We need to ensure
		 * that triggers various DHCP lease change code, so we need to pass
		 * along same-state transitions for these states.
		 */
		if (   new_state != DHC_BOUND4
		    && new_state != DHC_RENEW4
		    && new_state != DHC_REBIND4
		    && new_state != DHC_BOUND6
		    && new_state != DHC_RENEW6
		    && new_state != DHC_REBIND6)
			return;
	}

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

static gboolean
ip4_process_dhcpcd_rfc3442_routes (NMDHCPClient *self,
                                   const char *str,
                                   NMIP4Config *ip4_config,
                                   guint32 *gwaddr)
{
	NMDHCPClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);
	char **routes, **r;
	gboolean have_routes = FALSE;

	routes = g_strsplit (str, " ", 0);
	if (g_strv_length (routes) == 0)
		goto out;

	if ((g_strv_length (routes) % 2) != 0) {
		nm_log_warn (LOGD_DHCP4, "  classless static routes provided, but invalid");
		goto out;
	}

	for (r = routes; *r; r += 2) {
		char *slash;
		NMPlatformIP4Route route;
		int rt_cidr = 32;
		guint32 rt_addr, rt_route;

		slash = strchr(*r, '/');
		if (slash) {
			*slash = '\0';
			errno = 0;
			rt_cidr = strtol (slash + 1, NULL, 10);
			if ((errno == EINVAL) || (errno == ERANGE)) {
				nm_log_warn (LOGD_DHCP4, "DHCP provided invalid classless static route cidr: '%s'", slash + 1);
				continue;
			}
		}
		if (inet_pton (AF_INET, *r, &rt_addr) <= 0) {
			nm_log_warn (LOGD_DHCP4, "DHCP provided invalid classless static route address: '%s'", *r);
			continue;
		}
		if (inet_pton (AF_INET, *(r + 1), &rt_route) <= 0) {
			nm_log_warn (LOGD_DHCP4, "DHCP provided invalid classless static route gateway: '%s'", *(r + 1));
			continue;
		}

		have_routes = TRUE;
		if (rt_cidr == 0 && rt_addr == 0) {
			/* FIXME: how to handle multiple routers? */
			*gwaddr = rt_route;
		} else {
			nm_log_info (LOGD_DHCP4, "  classless static route %s/%d gw %s", *r, rt_cidr, *(r + 1));
			memset (&route, 0, sizeof (route));
			route.network = rt_addr;
			route.plen = rt_cidr;
			route.gateway = rt_route;
			route.source = NM_PLATFORM_SOURCE_DHCP;
			route.metric = priv->priority;
			nm_ip4_config_add_route (ip4_config, &route);
		}
	}

out:
	g_strfreev (routes);
	return have_routes;
}

static const char **
process_dhclient_rfc3442_route (const char **octets, NMPlatformIP4Route *route, gboolean *success)
{
	const char **o = octets;
	int addr_len = 0, i = 0;
	long int tmp;
	char *next_hop;
	guint32 tmp_addr;

	*success = FALSE;

	if (!*o)
		return o; /* no prefix */

	tmp = strtol (*o, NULL, 10);
	if (tmp < 0 || tmp > 32)  /* 32 == max IP4 prefix length */
		return o;

	memset (route, 0, sizeof (*route));
	route->plen = tmp;
	o++;

	if (tmp > 0)
		addr_len = ((tmp - 1) / 8) + 1;

	/* ensure there's at least the address + next hop left */
	if (g_strv_length ((char **) o) < addr_len + 4)
		goto error;

	if (tmp) {
		const char *addr[4] = { "0", "0", "0", "0" };
		char *str_addr;

		for (i = 0; i < addr_len; i++)
			addr[i] = *o++;

		str_addr = g_strjoin (".", addr[0], addr[1], addr[2], addr[3], NULL);
		if (inet_pton (AF_INET, str_addr, &tmp_addr) <= 0) {
			g_free (str_addr);
			goto error;
		}
		tmp_addr &= nm_utils_ip4_prefix_to_netmask ((guint32) tmp);
		route->network = tmp_addr;
	}

	/* Handle next hop */
	next_hop = g_strjoin (".", o[0], o[1], o[2], o[3], NULL);
	if (inet_pton (AF_INET, next_hop, &tmp_addr) <= 0) {
		g_free (next_hop);
		goto error;
	}
	route->gateway = tmp_addr;
	g_free (next_hop);

	*success = TRUE;
	return o + 4; /* advance to past the next hop */

error:
	return o;
}

static gboolean
ip4_process_dhclient_rfc3442_routes (NMDHCPClient *self,
                                     const char *str,
                                     NMIP4Config *ip4_config,
                                     guint32 *gwaddr)
{
	NMDHCPClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);
	char **octets, **o;
	gboolean have_routes = FALSE;
	NMPlatformIP4Route route;
	gboolean success;

	o = octets = g_strsplit_set (str, " .", 0);
	if (g_strv_length (octets) < 5) {
		nm_log_warn (LOGD_DHCP4, "ignoring invalid classless static routes '%s'", str);
		goto out;
	}

	while (*o) {
		memset (&route, 0, sizeof (route));
		o = (char **) process_dhclient_rfc3442_route ((const char **) o, &route, &success);
		if (!success) {
			nm_log_warn (LOGD_DHCP4, "ignoring invalid classless static routes");
			break;
		}

		have_routes = TRUE;
		if (!route.plen) {
			/* gateway passed as classless static route */
			*gwaddr = route.gateway;
		} else {
			char addr[INET_ADDRSTRLEN];

			/* normal route */
			route.source = NM_PLATFORM_SOURCE_DHCP;
			route.metric = priv->priority;
			nm_ip4_config_add_route (ip4_config, &route);

			nm_log_info (LOGD_DHCP4, "  classless static route %s/%d gw %s",
			             nm_utils_inet4_ntop (route.network, addr), route.plen,
			             nm_utils_inet4_ntop (route.gateway, NULL));
		}
	}

out:
	g_strfreev (octets);
	return have_routes;
}

static gboolean
ip4_process_classless_routes (NMDHCPClient *self,
                              GHashTable *options,
                              NMIP4Config *ip4_config,
                              guint32 *gwaddr)
{
	const char *str, *p;

	g_return_val_if_fail (options != NULL, FALSE);
	g_return_val_if_fail (ip4_config != NULL, FALSE);

	*gwaddr = 0;

	/* dhcpd/dhclient in Fedora has support for rfc3442 implemented using a
	 * slightly different format:
	 *
	 * option classless-static-routes = array of (destination-descriptor ip-address);
	 *
	 * which results in:
	 *
	 * 0 192.168.0.113 25.129.210.177.132 192.168.0.113 7.2 10.34.255.6
	 *
	 * dhcpcd supports classless static routes natively and uses this same
	 * option identifier with the following format:
	 *
	 * 192.168.10.0/24 192.168.1.1 10.0.0.0/8 10.17.66.41
	 */
	str = g_hash_table_lookup (options, "new_classless_static_routes");

	/* dhclient doesn't have actual support for rfc3442 classless static routes
	 * upstream.  Thus, people resort to defining the option in dhclient.conf
	 * and using arbitrary formats like so:
	 *
	 * option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;
	 *
	 * See https://lists.isc.org/pipermail/dhcp-users/2008-December/007629.html
	 */
	if (!str)
		str = g_hash_table_lookup (options, "new_rfc3442_classless_static_routes");

	/* Microsoft version; same as rfc3442 but with a different option # (249) */
	if (!str)
		str = g_hash_table_lookup (options, "new_ms_classless_static_routes");

	if (!str || !strlen (str))
		return FALSE;

	p = str;
	while (*p) {
		if (!g_ascii_isdigit (*p) && (*p != ' ') && (*p != '.') && (*p != '/')) {
			nm_log_warn (LOGD_DHCP4, "ignoring invalid classless static routes '%s'", str);
			return FALSE;
		}
		p++;
	};

	if (strchr (str, '/')) {
		/* dhcpcd format */
		return ip4_process_dhcpcd_rfc3442_routes (self, str, ip4_config, gwaddr);
	}

	return ip4_process_dhclient_rfc3442_routes (self, str, ip4_config, gwaddr);
}

static void
process_classful_routes (NMDHCPClient *self, GHashTable *options, NMIP4Config *ip4_config)
{
	NMDHCPClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);
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
		NMPlatformIP4Route route;
		guint32 rt_addr, rt_route;

		if (inet_pton (AF_INET, *s, &rt_addr) <= 0) {
			nm_log_warn (LOGD_DHCP, "DHCP provided invalid static route address: '%s'", *s);
			continue;
		}
		if (inet_pton (AF_INET, *(s + 1), &rt_route) <= 0) {
			nm_log_warn (LOGD_DHCP, "DHCP provided invalid static route gateway: '%s'", *(s + 1));
			continue;
		}

		// FIXME: ensure the IP address and route are sane

		memset (&route, 0, sizeof (route));
		route.network = rt_addr;
		/* RFC 2132, updated by RFC 3442:
		   The Static Routes option (option 33) does not provide a subnet mask
		   for each route - it is assumed that the subnet mask is implicit in
		   whatever network number is specified in each route entry */
		route.plen = nm_utils_ip4_get_default_prefix (rt_addr);
		if (rt_addr & ~nm_utils_ip4_prefix_to_netmask (route.plen)) {
			/* RFC 943: target not "this network"; using host routing */
			route.plen = 32;
		}
		route.gateway = rt_route;
		route.source = NM_PLATFORM_SOURCE_DHCP;
		route.metric = priv->priority;

		nm_ip4_config_add_route (ip4_config, &route);
		nm_log_info (LOGD_DHCP, "  static route %s",
		                        nm_platform_ip4_route_to_string (&route));
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
	guint32 tmp_addr;
	NMPlatformIP4Address address;
	char *str = NULL;
	guint32 gwaddr = 0, plen = 0;

	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), NULL);

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);
	g_return_val_if_fail (priv->options != NULL, NULL);

	ip4_config = nm_ip4_config_new ();
	memset (&address, 0, sizeof (address));
	address.timestamp = nm_utils_get_monotonic_timestamp_s ();

	str = g_hash_table_lookup (priv->options, "new_ip_address");
	if (str && (inet_pton (AF_INET, str, &tmp_addr) > 0)) {
		address.address = tmp_addr;
		nm_log_info (LOGD_DHCP4, "  address %s", str);
	} else
		goto error;

	str = g_hash_table_lookup (priv->options, "new_subnet_mask");
	if (str && (inet_pton (AF_INET, str, &tmp_addr) > 0)) {
		plen = nm_utils_ip4_netmask_to_prefix (tmp_addr);
		nm_log_info (LOGD_DHCP4, "  plen %d (%s)", plen, str);
	} else {
		/* Get default netmask for the IP according to appropriate class. */
		plen = nm_utils_ip4_get_default_prefix (address.address);
		nm_log_info (LOGD_DHCP4, "  plen %d (default)", plen);
	}
	address.plen = plen;

	/* Routes: if the server returns classless static routes, we MUST ignore
	 * the 'static_routes' option.
	 */
	if (!ip4_process_classless_routes (self, priv->options, ip4_config, &gwaddr))
		process_classful_routes (self, priv->options, ip4_config);

	if (gwaddr) {
		nm_log_info (LOGD_DHCP4, "  gateway %s", nm_utils_inet4_ntop (gwaddr, NULL));
		nm_ip4_config_set_gateway (ip4_config, gwaddr);
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
				if (inet_pton (AF_INET, *s, &gwaddr) > 0) {
					nm_ip4_config_set_gateway (ip4_config, gwaddr);
					nm_log_info (LOGD_DHCP4, "  gateway %s", *s);
					break;
				} else
					nm_log_warn (LOGD_DHCP4, "ignoring invalid gateway '%s'", *s);
			}
			g_strfreev (routers);
		}
	}

	/*
	 * RFC 2132, section 9.7
	 *   DHCP clients use the contents of the 'server identifier' field
	 *   as the destination address for any DHCP messages unicast to
	 *   the DHCP server.
	 *
	 * Some ISP's provide leases from central servers that are on
	 * different subnets that the address offered.  If the host
	 * does not configure the interface as the default route, the
	 * dhcp server may not be reachable via unicast, and a host
	 * specific route is needed.
	 **/
	str = g_hash_table_lookup (priv->options, "new_dhcp_server_identifier");
	if (str) {
		if (inet_pton (AF_INET, str, &tmp_addr) > 0) {
			NMPlatformIP4Route route;
			guint32 mask = nm_utils_ip4_prefix_to_netmask (address.plen);

			nm_log_info (LOGD_DHCP4, "  server identifier %s", str);
			if ((tmp_addr & mask) != (address.address & mask)) {
				/* DHCP server not on assigned subnet, route needed */
				memset (&route, 0, sizeof (route));
				route.network = tmp_addr;
				route.plen = 32;
				/* this will be a device route if gwaddr is 0 */
				route.gateway = gwaddr;
				route.source = NM_PLATFORM_SOURCE_DHCP;
				route.metric = priv->priority;
				nm_ip4_config_add_route (ip4_config, &route);
				nm_log_dbg (LOGD_IP, "adding route for server identifier: %s",
				                      nm_platform_ip4_route_to_string (&route));
			}
		}
		else
			nm_log_warn (LOGD_DHCP4, "ignoring invalid server identifier '%s'", str);
	}

	str = g_hash_table_lookup (priv->options, "new_dhcp_lease_time");
	if (str) {
		address.lifetime = address.preferred = strtoul (str, NULL, 10);
		nm_log_info (LOGD_DHCP4, "  lease time %d", address.lifetime);
	}

	address.source = NM_PLATFORM_SOURCE_DHCP;
	nm_ip4_config_add_address (ip4_config, &address);

	str = g_hash_table_lookup (priv->options, "new_host_name");
	if (str)
		nm_log_info (LOGD_DHCP4, "  hostname '%s'", str);

	str = g_hash_table_lookup (priv->options, "new_domain_name_servers");
	if (str) {
		char **searches = g_strsplit (str, " ", 0);
		char **s;

		for (s = searches; *s; s++) {
			if (inet_pton (AF_INET, *s, &tmp_addr) > 0) {
				nm_ip4_config_add_nameserver (ip4_config, tmp_addr);
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
				nm_ip4_config_add_wins (ip4_config, tmp_addr);
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
				nm_ip4_config_add_nis_server (ip4_config, tmp_addr);
				nm_log_info (LOGD_DHCP4, "  nis '%s'", *s);
			} else
				nm_log_warn (LOGD_DHCP4, "ignoring invalid NIS server '%s'", *s);
		}
		g_strfreev (searches);
	}

	return ip4_config;

error:
	g_object_unref (ip4_config);
	return NULL;
}

NMIP4Config *
nm_dhcp_client_get_ip4_config (NMDHCPClient *self, gboolean test)
{
	NMDHCPClientPrivate *priv;

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
	NMPlatformIP6Address address;
	char *str = NULL;
	GHashTableIter iter;
	gpointer key, value;

	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), NULL);

	memset (&address, 0, sizeof (address));
	address.plen = 128;
	address.timestamp = nm_utils_get_monotonic_timestamp_s ();

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);
	g_return_val_if_fail (priv->options != NULL, NULL);

	g_hash_table_iter_init (&iter, priv->options);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		nm_log_dbg (LOGD_DHCP6, "(%s): option '%s'=>'%s'",
		            priv->iface, (const char *) key, (const char *) value);
	}

	ip6_config = nm_ip6_config_new ();

	str = g_hash_table_lookup (priv->options, "new_max_life");
	if (str) {
		address.lifetime = strtoul (str, NULL, 10);
		nm_log_info (LOGD_DHCP6, "  valid_lft %d", address.lifetime);
	}

	str = g_hash_table_lookup (priv->options, "new_preferred_life");
	if (str) {
		address.preferred = strtoul (str, NULL, 10);
		nm_log_info (LOGD_DHCP6, "  preferred_lft %d", address.preferred);
	}

	str = g_hash_table_lookup (priv->options, "new_ip6_address");
	if (str) {
		if (!inet_pton (AF_INET6, str, &tmp_addr)) {
			nm_log_warn (LOGD_DHCP6, "(%s): DHCP returned invalid address '%s'",
			             priv->iface, str);
			goto error;
		}

		address.address = tmp_addr;
		address.source = NM_PLATFORM_SOURCE_DHCP;
		nm_ip6_config_add_address (ip6_config, &address);
		nm_log_info (LOGD_DHCP6, "  address %s", str);
	} else if (priv->info_only == FALSE) {
		/* No address in Managed mode is a hard error */
		goto error;
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
	g_object_unref (ip6_config);
	return NULL;
}

NMIP6Config *
nm_dhcp_client_get_ip6_config (NMDHCPClient *self, gboolean test)
{
	NMDHCPClientPrivate *priv;

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

	if (priv->remove_id) {
		g_source_remove (priv->remove_id);
		priv->remove_id = 0;
	}

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
		 g_param_spec_string (NM_DHCP_CLIENT_INTERFACE,
		                      "iface",
		                      "Interface",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_HWADDR,
		 g_param_spec_boxed (NM_DHCP_CLIENT_HWADDR,
		                     "hwaddr",
		                     "hardware address",
		                     G_TYPE_BYTE_ARRAY,
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
		(object_class, PROP_PRIORITY,
		 g_param_spec_uint (NM_DHCP_CLIENT_PRIORITY,
		                    "priority",
		                    "Priority",
		                    0, G_MAXUINT, 0,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_TIMEOUT,
		 g_param_spec_uint (NM_DHCP_CLIENT_TIMEOUT,
		                    "timeout",
		                    "Timeout",
		                    0, G_MAXUINT, 45,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/* signals */
	signals[SIGNAL_STATE_CHANGED] =
		g_signal_new (NM_DHCP_CLIENT_SIGNAL_STATE_CHANGED,
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMDHCPClientClass, state_changed),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__UINT,
					  G_TYPE_NONE, 1, G_TYPE_UINT);

	signals[SIGNAL_TIMEOUT] =
		g_signal_new (NM_DHCP_CLIENT_SIGNAL_TIMEOUT,
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMDHCPClientClass, timeout),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__VOID,
					  G_TYPE_NONE, 0);

	signals[SIGNAL_REMOVE] =
		g_signal_new (NM_DHCP_CLIENT_SIGNAL_REMOVE,
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMDHCPClientClass, remove),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__VOID,
					  G_TYPE_NONE, 0);
}

