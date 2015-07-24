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

#include "config.h"

#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <uuid/uuid.h>

#include "nm-glib.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-logging.h"
#include "nm-dbus-glib-types.h"
#include "nm-dhcp-client.h"
#include "nm-dhcp-utils.h"
#include "nm-platform.h"

typedef struct {
	char *       iface;
	int          ifindex;
	GByteArray * hwaddr;
	gboolean     ipv6;
	char *       uuid;
	guint32      priority;
	guint32      timeout;
	GByteArray * duid;
	GBytes *     client_id;
	char *       hostname;

	NMDhcpState  state;
	pid_t        pid;
	guint        timeout_id;
	guint        watch_id;
	gboolean     info_only;

} NMDhcpClientPrivate;

#define NM_DHCP_CLIENT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DHCP_CLIENT, NMDhcpClientPrivate))

G_DEFINE_TYPE_EXTENDED (NMDhcpClient, nm_dhcp_client, G_TYPE_OBJECT, G_TYPE_FLAG_ABSTRACT, {})

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
nm_dhcp_client_get_pid (NMDhcpClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), -1);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->pid;
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

gboolean
nm_dhcp_client_get_ipv6 (NMDhcpClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), FALSE);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->ipv6;
}

const char *
nm_dhcp_client_get_uuid (NMDhcpClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), NULL);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->uuid;
}

const GByteArray *
nm_dhcp_client_get_duid (NMDhcpClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), NULL);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->duid;
}

const GByteArray *
nm_dhcp_client_get_hw_addr (NMDhcpClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), NULL);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->hwaddr;
}

guint32
nm_dhcp_client_get_priority (NMDhcpClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), G_MAXUINT32);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->priority;
}

GBytes *
nm_dhcp_client_get_client_id (NMDhcpClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), NULL);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->client_id;
}

void
nm_dhcp_client_set_client_id (NMDhcpClient *self, GBytes *client_id)
{
	NMDhcpClientPrivate *priv;

	g_return_if_fail (NM_IS_DHCP_CLIENT (self));

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	if (priv->client_id && client_id && g_bytes_equal (priv->client_id, client_id))
		return;
	g_clear_pointer (&priv->client_id, g_bytes_unref);
	priv->client_id = client_id ? g_bytes_ref (client_id) : NULL;
}

const char *
nm_dhcp_client_get_hostname (NMDhcpClient *self)
{
	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), NULL);

	return NM_DHCP_CLIENT_GET_PRIVATE (self)->hostname;
}

/********************************************/

static const char *state_table[NM_DHCP_STATE_MAX + 1] = {
	[NM_DHCP_STATE_UNKNOWN]  = "unknown",
	[NM_DHCP_STATE_BOUND]    = "bound",
	[NM_DHCP_STATE_TIMEOUT]  = "timeout",
	[NM_DHCP_STATE_EXPIRE]   = "expire",
	[NM_DHCP_STATE_DONE]     = "done",
	[NM_DHCP_STATE_FAIL]     = "fail",
};

static const char *
state_to_string (NMDhcpState state)
{
	if ((gsize) state < G_N_ELEMENTS (state_table))
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
	else if (g_ascii_strcasecmp (reason, "nak") == 0 ||
	         g_ascii_strcasecmp (reason, "expire") == 0 ||
	         g_ascii_strcasecmp (reason, "expire6") == 0)
		return NM_DHCP_STATE_EXPIRE;
	else if (g_ascii_strcasecmp (reason, "end") == 0)
		return NM_DHCP_STATE_DONE;
	else if (g_ascii_strcasecmp (reason, "fail") == 0 ||
	         g_ascii_strcasecmp (reason, "abend") == 0)
		return NM_DHCP_STATE_FAIL;

	nm_log_dbg (LOGD_DHCP, "(%s): unmapped DHCP state '%s'", iface, reason);
	return NM_DHCP_STATE_UNKNOWN;
}

/********************************************/

static void
timeout_cleanup (NMDhcpClient *self)
{
	NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	if (priv->timeout_id) {
		g_source_remove (priv->timeout_id);
		priv->timeout_id = 0;
	}
}

static void
watch_cleanup (NMDhcpClient *self)
{
	NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	if (priv->watch_id) {
		g_source_remove (priv->watch_id);
		priv->watch_id = 0;
	}
}

void
nm_dhcp_client_stop_pid (pid_t pid, const char *iface)
{
	char *name = iface ? g_strdup_printf ("dhcp-client-%s", iface) : NULL;

	g_return_if_fail (pid > 1);

	nm_utils_kill_child_sync (pid, SIGTERM, LOGD_DHCP, name ? name : "dhcp-client", NULL,
	                          1000 / 2, 1000 / 20);
	g_free (name);
}

static void
stop (NMDhcpClient *self, gboolean release, const GByteArray *duid)
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
	priv->info_only = FALSE;
}

void
nm_dhcp_client_set_state (NMDhcpClient *self,
                          NMDhcpState new_state,
                          GObject *ip_config,
                          GHashTable *options)
{
	NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	if (new_state >= NM_DHCP_STATE_BOUND)
		timeout_cleanup (self);
	if (new_state >= NM_DHCP_STATE_TIMEOUT)
		watch_cleanup (self);

	if (new_state == NM_DHCP_STATE_BOUND) {
		g_assert (   (priv->ipv6 && NM_IS_IP6_CONFIG (ip_config))
		          || (!priv->ipv6 && NM_IS_IP4_CONFIG (ip_config)));
		g_assert (options);
		g_assert_cmpint (g_hash_table_size (options), >, 0);
	} else {
		g_assert (ip_config == NULL);
		g_assert (options == NULL);
	}

	/* The client may send same-state transitions for RENEW/REBIND events and
	 * the lease may have changed, so handle same-state transitions for the
	 * BOUND state.  Ignore same-state transitions for other events since
	 * the lease won't have changed and the state was already handled.
	 */
	if ((priv->state == new_state) && (new_state != NM_DHCP_STATE_BOUND))
		return;

	nm_log_info (priv->ipv6 ? LOGD_DHCP6 : LOGD_DHCP4,
	             "(%s): DHCPv%c state changed %s -> %s",
	             priv->iface,
	             priv->ipv6 ? '6' : '4',
	             state_to_string (priv->state),
	             state_to_string (new_state));

	priv->state = new_state;
	g_signal_emit (G_OBJECT (self),
	               signals[SIGNAL_STATE_CHANGED], 0,
	               new_state,
	               ip_config,
	               options);
}

static gboolean
daemon_timeout (gpointer user_data)
{
	NMDhcpClient *self = NM_DHCP_CLIENT (user_data);
	NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	priv->timeout_id = 0;
	nm_log_warn (priv->ipv6 ? LOGD_DHCP6 : LOGD_DHCP4,
	             "(%s): DHCPv%c request timed out.",
	             priv->iface,
	             priv->ipv6 ? '6' : '4');
	nm_dhcp_client_set_state (self, NM_DHCP_STATE_TIMEOUT, NULL, NULL);
	return G_SOURCE_REMOVE;
}

static void
daemon_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMDhcpClient *self = NM_DHCP_CLIENT (user_data);
	NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);
	NMDhcpState new_state;
	guint64 log_domain;
	guint ip_ver;

	log_domain = priv->ipv6 ? LOGD_DHCP6 : LOGD_DHCP4;
	ip_ver = priv->ipv6 ? 6 : 4;

	if (WIFEXITED (status))
		nm_log_info (log_domain, "(%s): DHCPv%d client pid %d exited with status %d",
		             priv->iface, ip_ver, pid, WEXITSTATUS (status));
	else if (WIFSIGNALED (status))
		nm_log_info (log_domain, "(%s): DHCPv%d client pid %d killed by signal %d",
		             priv->iface, ip_ver, pid, WTERMSIG (status));
	else if (WIFSTOPPED(status))
		nm_log_info (log_domain, "(%s): DHCPv%d client pid %d stopped by signal %d",
		             priv->iface, ip_ver, pid, WSTOPSIG (status));
	else if (WIFCONTINUED (status))
		nm_log_info (log_domain, "(%s): DHCPv%d client pid %d resumed (by SIGCONT)",
		             priv->iface, ip_ver, pid);
	else
		nm_log_warn (LOGD_DHCP, "DHCP client died abnormally");

	if (!WIFEXITED (status))
		new_state = NM_DHCP_STATE_FAIL;
	else
		new_state = NM_DHCP_STATE_DONE;

	priv->pid = -1;

	nm_dhcp_client_set_state (self, new_state, NULL, NULL);
}

void
nm_dhcp_client_watch_child (NMDhcpClient *self, pid_t pid)
{
	NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

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
nm_dhcp_client_start_ip4 (NMDhcpClient *self,
                          const char *dhcp_client_id,
                          const char *dhcp_anycast_addr,
                          const char *hostname,
                          const char *last_ip4_address)
{
	NMDhcpClientPrivate *priv;

	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), FALSE);

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);
	g_return_val_if_fail (priv->pid == -1, FALSE);
	g_return_val_if_fail (priv->ipv6 == FALSE, FALSE);
	g_return_val_if_fail (priv->uuid != NULL, FALSE);

	nm_log_info (LOGD_DHCP, "Activation (%s) Beginning DHCPv4 transaction (timeout in %d seconds)",
	             priv->iface, priv->timeout);

	nm_dhcp_client_set_client_id (self, dhcp_client_id ? nm_dhcp_utils_client_id_string_to_bytes (dhcp_client_id) : NULL);

	g_clear_pointer (&priv->hostname, g_free);
	priv->hostname = g_strdup (hostname);

	return NM_DHCP_CLIENT_GET_CLASS (self)->ip4_start (self, dhcp_anycast_addr, last_ip4_address);
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

static GByteArray *
get_duid (NMDhcpClient *self)
{
	static GByteArray *duid = NULL;
	GByteArray *copy = NULL;
	char *str;

	if (G_UNLIKELY (duid == NULL)) {
		duid = generate_duid_from_machine_id ();
		g_assert (duid);

		if (nm_logging_enabled (LOGL_DEBUG, LOGD_DHCP6)) {
			str = nm_dhcp_utils_duid_to_string (duid);
			nm_log_dbg (LOGD_DHCP6, "Generated DUID %s", str);
			g_free (str);
		}
	}

	if (G_LIKELY (duid)) {
		copy = g_byte_array_sized_new (duid->len);
		g_byte_array_append (copy, duid->data, duid->len);
	}

	return copy;
}

gboolean
nm_dhcp_client_start_ip6 (NMDhcpClient *self,
                          const char *dhcp_anycast_addr,
                          const char *hostname,
                          gboolean info_only,
                          NMSettingIP6ConfigPrivacy privacy)
{
	NMDhcpClientPrivate *priv;
	char *str;

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
		str = nm_dhcp_utils_duid_to_string (priv->duid);
		nm_log_dbg (LOGD_DHCP, "(%s): DHCPv6 DUID is '%s'", priv->iface, str);
		g_free (str);
	}

	g_clear_pointer (&priv->hostname, g_free);
	priv->hostname = g_strdup (hostname);

	priv->info_only = info_only;

	nm_log_info (LOGD_DHCP, "Activation (%s) Beginning DHCPv6 transaction (timeout in %d seconds)",
	             priv->iface, priv->timeout);

	return NM_DHCP_CLIENT_GET_CLASS (self)->ip6_start (self,
	                                                   dhcp_anycast_addr,
	                                                   info_only,
	                                                   privacy,
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
		guint64 start_time;
		const char *exe;
		pid_t ppid;

		/* Ensure the process is a DHCP client */
		start_time = nm_utils_get_start_time_for_pid (tmp, NULL, &ppid);
		proc_path = g_strdup_printf ("/proc/%ld/cmdline", tmp);
		if (   start_time
		    && g_file_get_contents (proc_path, &proc_contents, NULL, NULL)) {
			exe = strrchr (proc_contents, '/');
			if (exe)
				exe++;
			else
				exe = proc_contents;

			if (!strcmp (exe, binary_name)) {
				if (ppid == getpid ()) {
					/* the process is our own child. */
					nm_utils_kill_child_sync (tmp, SIGTERM, LOGD_DHCP, "dhcp-client", NULL, 1000 / 2, 1000 / 20);
				} else {
					nm_utils_kill_process_sync (tmp, start_time, SIGTERM, LOGD_DHCP,
					                            "dhcp-client", 1000 / 2, 1000 / 20, 2000);
				}
			}
		}
	}

	if (remove (pid_file) == -1)
		nm_log_dbg (LOGD_DHCP, "Could not remove dhcp pid file \"%s\": %d (%s)", pid_file, errno, g_strerror (errno));

	g_free (proc_path);
	g_free (pid_contents);
	g_free (proc_contents);
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
	NM_DHCP_CLIENT_GET_CLASS (self)->stop (self, release, priv->duid);
	if (old_pid > 0) {
		nm_log_info (LOGD_DHCP, "(%s): canceled DHCP transaction, DHCP client pid %d",
		             priv->iface, old_pid);
	} else
		nm_log_info (LOGD_DHCP, "(%s): canceled DHCP transaction", priv->iface);
	g_assert (priv->pid == -1);

	nm_dhcp_client_set_state (self, NM_DHCP_STATE_DONE, NULL, NULL);
}

/********************************************/

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

#define OLD_TAG "old_"
#define NEW_TAG "new_"

static void
copy_option (const char * key,
             GValue *value,
             gpointer user_data)
{
	GHashTable *hash = user_data;
	char *str_value = NULL;
	const char **p;
	static const char *ignored_keys[] = {
		"interface",
		"pid",
		"reason",
		"dhcp_message_type",
		NULL
	};

	if (!G_VALUE_HOLDS (value, DBUS_TYPE_G_UCHAR_ARRAY)) {
		nm_log_warn (LOGD_DHCP, "key %s value type was not DBUS_TYPE_G_UCHAR_ARRAY", key);
		return;
	}

	if (g_str_has_prefix (key, OLD_TAG))
		return;

	/* Filter out stuff that's not actually new DHCP options */
	for (p = ignored_keys; *p; p++) {
		if (!strcmp (*p, key))
			return;
	}

	if (g_str_has_prefix (key, NEW_TAG))
		key += STRLEN (NEW_TAG);
	if (!key[0])
		return;

	str_value = garray_to_string ((GArray *) g_value_get_boxed (value), key);
	if (str_value)
		g_hash_table_insert (hash, g_strdup (key), str_value);
}

gboolean
nm_dhcp_client_handle_event (gpointer unused,
                             const char *iface,
                             gint pid,
                             GHashTable *options,
                             const char *reason,
                             NMDhcpClient *self)
{
	NMDhcpClientPrivate *priv;
	guint32 old_state;
	guint32 new_state;
	GHashTable *str_options = NULL;
	GObject *ip_config = NULL;

	g_return_val_if_fail (NM_IS_DHCP_CLIENT (self), FALSE);
	g_return_val_if_fail (iface != NULL, FALSE);
	g_return_val_if_fail (pid > 0, FALSE);
	g_return_val_if_fail (options != NULL, FALSE);
	g_return_val_if_fail (reason != NULL, FALSE);

	priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	if (g_strcmp0 (priv->iface, iface) != 0)
		return FALSE;
	if (priv->pid != pid)
		return FALSE;

	old_state = priv->state;
	new_state = reason_to_state (priv->iface, reason);
	nm_log_dbg (LOGD_DHCP, "(%s): DHCP reason '%s' -> state '%s'",
	            iface, reason, state_to_string (new_state));

	if (new_state == NM_DHCP_STATE_BOUND) {
		/* Copy options */
		str_options = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
		g_hash_table_foreach (options, (GHFunc) copy_option, str_options);

		/* Create the IP config */
		g_warn_if_fail (g_hash_table_size (str_options));
		if (g_hash_table_size (str_options)) {
			if (priv->ipv6) {
				ip_config = (GObject *) nm_dhcp_utils_ip6_config_from_options (priv->ifindex,
				                                                               priv->iface,
				                                                               str_options,
				                                                               priv->priority,
				                                                               priv->info_only);
			} else {
				ip_config = (GObject *) nm_dhcp_utils_ip4_config_from_options (priv->ifindex,
				                                                               priv->iface,
				                                                               str_options,
				                                                               priv->priority);
			}

			/* Fail if no valid IP config was received */
			if (ip_config == NULL) {
				nm_log_warn (LOGD_DHCP, "(%s): DHCP client bound but IP config not received", iface);
				new_state = NM_DHCP_STATE_FAIL;
				g_clear_pointer (&str_options, g_hash_table_unref);
			}
		}
	}

	nm_dhcp_client_set_state (self, new_state, ip_config, str_options);

	if (str_options)
		g_hash_table_destroy (str_options);
	g_clear_object (&ip_config);

	return TRUE;
}

/********************************************/

static void
nm_dhcp_client_init (NMDhcpClient *self)
{
	NM_DHCP_CLIENT_GET_PRIVATE (self)->pid = -1;
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (object);

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
	NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (object);
 
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
	NMDhcpClient *self = NM_DHCP_CLIENT (object);
	NMDhcpClientPrivate *priv = NM_DHCP_CLIENT_GET_PRIVATE (self);

	/* Stopping the client is left up to the controlling device
	 * explicitly since we may want to quit NetworkManager but not terminate
	 * the DHCP client.
	 */

	watch_cleanup (self);
	timeout_cleanup (self);

	g_clear_pointer (&priv->iface, g_free);
	g_clear_pointer (&priv->hostname, g_free);
	g_clear_pointer (&priv->uuid, g_free);

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
nm_dhcp_client_class_init (NMDhcpClientClass *client_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (client_class);

	g_type_class_add_private (client_class, sizeof (NMDhcpClientPrivate));

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
		                    0, G_MAXUINT32, 0,
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
					  G_STRUCT_OFFSET (NMDhcpClientClass, state_changed),
					  NULL, NULL, NULL,
					  G_TYPE_NONE, 3, G_TYPE_UINT, G_TYPE_OBJECT, G_TYPE_HASH_TABLE);
}

