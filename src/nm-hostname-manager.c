/* NetworkManager
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
 * (C) Copyright 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-hostname-manager.h"

#include <sys/stat.h>

#if HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#include "nm-libnm-core-intern/nm-common-macros.h"
#include "nm-dbus-interface.h"
#include "nm-connection.h"
#include "nm-utils.h"
#include "nm-core-internal.h"

#include "NetworkManagerUtils.h"

/*****************************************************************************/

#define HOSTNAMED_SERVICE_NAME      "org.freedesktop.hostname1"
#define HOSTNAMED_SERVICE_PATH      "/org/freedesktop/hostname1"
#define HOSTNAMED_SERVICE_INTERFACE "org.freedesktop.hostname1"

#define HOSTNAME_FILE_DEFAULT        "/etc/hostname"
#define HOSTNAME_FILE_UCASE_HOSTNAME "/etc/HOSTNAME"
#define HOSTNAME_FILE_GENTOO         "/etc/conf.d/hostname"

#define CONF_DHCP                    SYSCONFDIR "/sysconfig/network/dhcp"

#if (defined(HOSTNAME_PERSIST_SUSE) + defined(HOSTNAME_PERSIST_SLACKWARE) + defined(HOSTNAME_PERSIST_GENTOO)) > 1
#error "Can only define one of HOSTNAME_PERSIST_*"
#endif

#if defined(HOSTNAME_PERSIST_SUSE)
#define HOSTNAME_FILE           HOSTNAME_FILE_UCASE_HOSTNAME
#elif defined(HOSTNAME_PERSIST_SLACKWARE)
#define HOSTNAME_FILE           HOSTNAME_FILE_UCASE_HOSTNAME
#elif defined(HOSTNAME_PERSIST_GENTOO)
#define HOSTNAME_FILE           HOSTNAME_FILE_GENTOO
#else
#define HOSTNAME_FILE           HOSTNAME_FILE_DEFAULT
#endif

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMHostnameManager,
	PROP_HOSTNAME,
);

typedef struct {
	char *current_hostname;
	GFileMonitor *monitor;
	GFileMonitor *dhcp_monitor;
	gulong monitor_id;
	gulong dhcp_monitor_id;
	GDBusProxy *hostnamed_proxy;
} NMHostnameManagerPrivate;

struct _NMHostnameManager {
	GObject parent;
	NMHostnameManagerPrivate _priv;
};

struct _NMHostnameManagerClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMHostnameManager, nm_hostname_manager, G_TYPE_OBJECT);

#define NM_HOSTNAME_MANAGER_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMHostnameManager, NM_IS_HOSTNAME_MANAGER)

NM_DEFINE_SINGLETON_GETTER (NMHostnameManager, nm_hostname_manager_get, NM_TYPE_HOSTNAME_MANAGER);

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_CORE
#define _NMLOG(level, ...) __NMLOG_DEFAULT (level, _NMLOG_DOMAIN, "hostname", __VA_ARGS__)

/*****************************************************************************/

#if defined(HOSTNAME_PERSIST_GENTOO)
static char *
read_hostname_gentoo (const char *path)
{
	gs_free char *contents = NULL;
	gs_strfreev char **all_lines = NULL;
	const char *tmp;
	guint i;

	if (!g_file_get_contents (path, &contents, NULL, NULL))
		return NULL;

	all_lines = g_strsplit (contents, "\n", 0);
	for (i = 0; all_lines[i]; i++) {
		g_strstrip (all_lines[i]);
		if (all_lines[i][0] == '#' || all_lines[i][0] == '\0')
			continue;
		if (g_str_has_prefix (all_lines[i], "hostname=")) {
			tmp = &all_lines[i][NM_STRLEN ("hostname=")];
			return g_shell_unquote (tmp, NULL);
		}
	}
	return NULL;
}
#endif

#if defined(HOSTNAME_PERSIST_SLACKWARE)
static char *
read_hostname_slackware (const char *path)
{
	gs_free char *contents = NULL;
	gs_strfreev char **all_lines = NULL;
	guint i = 0;

	if (!g_file_get_contents (path, &contents, NULL, NULL))
		return NULL;

	all_lines = g_strsplit (contents, "\n", 0);
	for (i = 0; all_lines[i]; i++) {
		g_strstrip (all_lines[i]);
		if (all_lines[i][0] == '#' || all_lines[i][0] == '\0')
			continue;
		return g_shell_unquote (&all_lines[i][0], NULL);
	}
	return NULL;
}
#endif

#if defined(HOSTNAME_PERSIST_SUSE)
static gboolean
hostname_is_dynamic (void)
{
	GIOChannel *channel;
	char *str = NULL;
	gboolean dynamic = FALSE;

	channel = g_io_channel_new_file (CONF_DHCP, "r", NULL);
	if (!channel)
		return dynamic;

	while (g_io_channel_read_line (channel, &str, NULL, NULL, NULL) != G_IO_STATUS_EOF) {
		if (str) {
			g_strstrip (str);
			if (g_str_has_prefix (str, "DHCLIENT_SET_HOSTNAME="))
				dynamic = strcmp (&str[NM_STRLEN ("DHCLIENT_SET_HOSTNAME=")], "\"yes\"") == 0;
			g_free (str);
		}
	}

	g_io_channel_shutdown (channel, FALSE, NULL);
	g_io_channel_unref (channel);

	return dynamic;
}
#endif

/* Returns an allocated string which the caller owns and must eventually free */
char *
nm_hostname_manager_read_hostname (NMHostnameManager *self)
{
	NMHostnameManagerPrivate *priv = NM_HOSTNAME_MANAGER_GET_PRIVATE (self);
	char *hostname = NULL;

	if (priv->hostnamed_proxy) {
		hostname = g_strdup (priv->current_hostname);
		goto out;
	}

#if defined(HOSTNAME_PERSIST_SUSE)
	if (priv->dhcp_monitor_id && hostname_is_dynamic ())
		return NULL;
#endif

#if defined(HOSTNAME_PERSIST_GENTOO)
	hostname = read_hostname_gentoo (HOSTNAME_FILE);
#elif defined(HOSTNAME_PERSIST_SLACKWARE)
	hostname = read_hostname_slackware (HOSTNAME_FILE);
#else
	if (g_file_get_contents (HOSTNAME_FILE, &hostname, NULL, NULL))
		g_strchomp (hostname);
#endif

out:
	if (hostname && !hostname[0]) {
		g_free (hostname);
		return NULL;
	}

	return hostname;
}

/*****************************************************************************/

const char *
nm_hostname_manager_get_hostname (NMHostnameManager *self)
{
	g_return_val_if_fail (NM_IS_HOSTNAME_MANAGER (self), NULL);
	return NM_HOSTNAME_MANAGER_GET_PRIVATE (self)->current_hostname;
}

static void
_set_hostname_take (NMHostnameManager *self, char *hostname)
{
	NMHostnameManagerPrivate *priv = NM_HOSTNAME_MANAGER_GET_PRIVATE (self);

	_LOGI ("hostname changed from %s%s%s to %s%s%s",
	       NM_PRINT_FMT_QUOTED (priv->current_hostname, "\"", priv->current_hostname, "\"", "(none)"),
	       NM_PRINT_FMT_QUOTED (hostname, "\"", hostname, "\"", "(none)"));

	g_free (priv->current_hostname);
	priv->current_hostname = hostname;
	_notify (self, PROP_HOSTNAME);
}

static void
_set_hostname (NMHostnameManager *self, const char *hostname)
{
	NMHostnameManagerPrivate *priv = NM_HOSTNAME_MANAGER_GET_PRIVATE (self);

	hostname = nm_str_not_empty (hostname);
	if (!nm_streq0 (hostname, priv->current_hostname))
		_set_hostname_take (self, g_strdup (hostname));
}

static void
_set_hostname_read (NMHostnameManager *self)
{
	NMHostnameManagerPrivate *priv = NM_HOSTNAME_MANAGER_GET_PRIVATE (self);
	char *hostname;

	if (priv->hostnamed_proxy) {
		/* read-hostname returns the current hostname with hostnamed. */
		return;
	}

	hostname = nm_hostname_manager_read_hostname (self);

	if (nm_streq0 (hostname, priv->current_hostname)) {
		g_free (hostname);
		return;
	}

	_set_hostname_take (self, hostname);
}

/*****************************************************************************/

typedef struct {
	char *hostname;
	NMHostnameManagerSetHostnameCb cb;
	gpointer user_data;
} SetHostnameInfo;

static void
set_transient_hostname_done (GObject *object,
                             GAsyncResult *res,
                             gpointer user_data)
{
	GDBusProxy *proxy = G_DBUS_PROXY (object);
	gs_free SetHostnameInfo *info = user_data;
	gs_unref_variant GVariant *result = NULL;
	gs_free_error GError *error = NULL;

	result = g_dbus_proxy_call_finish (proxy, res, &error);

	if (error) {
		_LOGW ("couldn't set the system hostname to '%s' using hostnamed: %s",
		       info->hostname, error->message);
	}

	info->cb (info->hostname, !error, info->user_data);
	g_free (info->hostname);
}

void
nm_hostname_manager_set_transient_hostname (NMHostnameManager *self,
                                            const char *hostname,
                                            NMHostnameManagerSetHostnameCb cb,
                                            gpointer user_data)
{
	NMHostnameManagerPrivate *priv;
	SetHostnameInfo *info;

	g_return_if_fail (NM_IS_HOSTNAME_MANAGER (self));

	priv = NM_HOSTNAME_MANAGER_GET_PRIVATE (self);

	if (!priv->hostnamed_proxy) {
		cb (hostname, FALSE, user_data);
		return;
	}

	info = g_new0 (SetHostnameInfo, 1);
	info->hostname = g_strdup (hostname);
	info->cb = cb;
	info->user_data = user_data;

	g_dbus_proxy_call (priv->hostnamed_proxy,
	                   "SetHostname",
	                   g_variant_new ("(sb)", hostname, FALSE),
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1,
	                   NULL,
	                   set_transient_hostname_done,
	                   info);
}

gboolean
nm_hostname_manager_get_transient_hostname (NMHostnameManager *self, char **hostname)
{
	NMHostnameManagerPrivate *priv = NM_HOSTNAME_MANAGER_GET_PRIVATE (self);
	GVariant *v_hostname;

	if (!priv->hostnamed_proxy)
		return FALSE;

	v_hostname = g_dbus_proxy_get_cached_property (priv->hostnamed_proxy,
	                                               "Hostname");
	if (!v_hostname) {
		_LOGT ("transient hostname retrieval failed");
		return FALSE;
	}

	*hostname = g_variant_dup_string (v_hostname, NULL);
	g_variant_unref (v_hostname);

	return TRUE;
}

gboolean
nm_hostname_manager_write_hostname (NMHostnameManager *self, const char *hostname)
{
	NMHostnameManagerPrivate *priv;
	char *hostname_eol;
	gboolean ret;
	gs_free_error GError *error = NULL;
	const char *file = HOSTNAME_FILE;
	gs_free char *link_path = NULL;
	gs_unref_variant GVariant *var = NULL;
	struct stat file_stat;
#if HAVE_SELINUX
	security_context_t se_ctx_prev = NULL, se_ctx = NULL;
	mode_t st_mode = 0;
#endif

	g_return_val_if_fail (NM_IS_HOSTNAME_MANAGER (self), FALSE);

	priv = NM_HOSTNAME_MANAGER_GET_PRIVATE (self);

	if (priv->hostnamed_proxy) {
		var = g_dbus_proxy_call_sync (priv->hostnamed_proxy,
		                              "SetStaticHostname",
		                              g_variant_new ("(sb)", hostname, FALSE),
		                              G_DBUS_CALL_FLAGS_NONE,
		                              -1,
		                              NULL,
		                              &error);
		if (error)
			_LOGW ("could not set hostname: %s", error->message);

		return !error;
	}

	/* If the hostname file is a symbolic link, follow it to find where the
	 * real file is located, otherwise g_file_set_contents will attempt to
	 * replace the link with a plain file.
	 */
	if (   lstat (file, &file_stat) == 0
	    && S_ISLNK (file_stat.st_mode)
	    && (link_path = nm_utils_read_link_absolute (file, NULL)))
		file = link_path;

#if HAVE_SELINUX
	/* Get default context for hostname file and set it for fscreate */
	if (stat (file, &file_stat) == 0)
		st_mode = file_stat.st_mode;
	matchpathcon (file, st_mode, &se_ctx);
	matchpathcon_fini ();
	getfscreatecon (&se_ctx_prev);
	setfscreatecon (se_ctx);
#endif

#if defined (HOSTNAME_PERSIST_GENTOO)
	hostname_eol = g_strdup_printf ("#Generated by NetworkManager\n"
	                                "hostname=\"%s\"\n", hostname);
#else
	hostname_eol = g_strdup_printf ("%s\n", hostname);
#endif

	ret = g_file_set_contents (file, hostname_eol, -1, &error);

#if HAVE_SELINUX
	/* Restore previous context and cleanup */
	setfscreatecon (se_ctx_prev);
	freecon (se_ctx);
	freecon (se_ctx_prev);
#endif

	g_free (hostname_eol);

	if (!ret) {
		_LOGW ("could not save hostname to %s: %s", file, error->message);
		return FALSE;
	}

	return TRUE;
}

gboolean
nm_hostname_manager_validate_hostname (const char *hostname)
{
	const char *p;
	gboolean dot = TRUE;

	if (!hostname || !hostname[0])
		return FALSE;

	for (p = hostname; *p; p++) {
		if (*p == '.') {
			if (dot)
				return FALSE;
			dot = TRUE;
		} else {
			if (!g_ascii_isalnum (*p) && (*p != '-') && (*p != '_'))
				return FALSE;
			dot = FALSE;
		}
	}

	if (dot)
		return FALSE;

	return (p - hostname <= HOST_NAME_MAX);
}

static void
hostname_file_changed_cb (GFileMonitor *monitor,
                          GFile *file,
                          GFile *other_file,
                          GFileMonitorEvent event_type,
                          gpointer user_data)
{
	_set_hostname_read (user_data);
}

/*****************************************************************************/

static void
hostnamed_properties_changed (GDBusProxy *proxy,
                              GVariant *changed_properties,
                              char **invalidated_properties,
                              gpointer user_data)
{
	NMHostnameManager *self = user_data;
	NMHostnameManagerPrivate *priv = NM_HOSTNAME_MANAGER_GET_PRIVATE (self);
	GVariant *v_hostname;

	v_hostname = g_dbus_proxy_get_cached_property (priv->hostnamed_proxy,
	                                               "StaticHostname");
	if (v_hostname) {
		_set_hostname (self, g_variant_get_string (v_hostname, NULL));
		g_variant_unref (v_hostname);
	}
}

static void
setup_hostname_file_monitors (NMHostnameManager *self)
{
	NMHostnameManagerPrivate *priv = NM_HOSTNAME_MANAGER_GET_PRIVATE (self);
	GFileMonitor *monitor;
	const char *path = HOSTNAME_FILE;
	char *link_path = NULL;
	struct stat file_stat;
	GFile *file;

	/* resolve the path to the hostname file if it is a symbolic link */
	if (   lstat(path, &file_stat) == 0
	    && S_ISLNK (file_stat.st_mode)
	    && (link_path = nm_utils_read_link_absolute (path, NULL))) {
		path = link_path;
		if (   lstat(link_path, &file_stat) == 0
		    && S_ISLNK (file_stat.st_mode)) {
			_LOGW ("only one level of symbolic link indirection is allowed when monitoring "
			       HOSTNAME_FILE);
		}
	}

	/* monitor changes to hostname file */
	file = g_file_new_for_path (path);
	monitor = g_file_monitor_file (file, G_FILE_MONITOR_NONE, NULL, NULL);
	g_object_unref (file);
	g_free(link_path);
	if (monitor) {
		priv->monitor_id = g_signal_connect (monitor, "changed",
		                                              G_CALLBACK (hostname_file_changed_cb),
		                                              self);
		priv->monitor = monitor;
	}

#if defined (HOSTNAME_PERSIST_SUSE)
	/* monitor changes to dhcp file to know whether the hostname is valid */
	file = g_file_new_for_path (CONF_DHCP);
	monitor = g_file_monitor_file (file, G_FILE_MONITOR_NONE, NULL, NULL);
	g_object_unref (file);
	if (monitor) {
		priv->dhcp_monitor_id = g_signal_connect (monitor, "changed",
		                                                   G_CALLBACK (hostname_file_changed_cb),
		                                                   self);
		priv->dhcp_monitor = monitor;
	}
#endif

	_set_hostname_read (self);
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMHostnameManager *self = NM_HOSTNAME_MANAGER (object);

	switch (prop_id) {
	case PROP_HOSTNAME:
		g_value_set_string (value, nm_hostname_manager_get_hostname (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_hostname_manager_init (NMHostnameManager *self)
{
}

static void
constructed (GObject *object)
{
	NMHostnameManager *self = NM_HOSTNAME_MANAGER (object);
	NMHostnameManagerPrivate *priv = NM_HOSTNAME_MANAGER_GET_PRIVATE (self);
	GDBusProxy *proxy;
	GVariant *variant;
	gs_free_error GError *error = NULL;

	proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM, 0, NULL,
	                                       HOSTNAMED_SERVICE_NAME, HOSTNAMED_SERVICE_PATH,
	                                       HOSTNAMED_SERVICE_INTERFACE, NULL, &error);
	if (proxy) {
		variant = g_dbus_proxy_get_cached_property (proxy, "StaticHostname");
		if (variant) {
			_LOGI ("hostname: using hostnamed");
			priv->hostnamed_proxy = proxy;
			g_signal_connect (proxy, "g-properties-changed",
			                  G_CALLBACK (hostnamed_properties_changed), self);
			hostnamed_properties_changed (proxy, NULL, NULL, self);
			g_variant_unref (variant);
		} else {
			_LOGI ("hostname: couldn't get property from hostnamed");
			g_object_unref (proxy);
		}
	} else {
		_LOGI ("hostname: hostnamed not used as proxy creation failed with: %s",
		       error->message);
		g_clear_error (&error);
	}

	if (!priv->hostnamed_proxy)
		setup_hostname_file_monitors (self);

	G_OBJECT_CLASS (nm_hostname_manager_parent_class)->constructed (object);
}

static void
dispose (GObject *object)
{
	NMHostnameManager *self = NM_HOSTNAME_MANAGER (object);
	NMHostnameManagerPrivate *priv = NM_HOSTNAME_MANAGER_GET_PRIVATE (self);

	if (priv->hostnamed_proxy) {
		g_signal_handlers_disconnect_by_func (priv->hostnamed_proxy,
		                                      G_CALLBACK (hostnamed_properties_changed),
		                                      self);
		g_clear_object (&priv->hostnamed_proxy);
	}

	if (priv->monitor) {
		if (priv->monitor_id)
			g_signal_handler_disconnect (priv->monitor, priv->monitor_id);

		g_file_monitor_cancel (priv->monitor);
		g_clear_object (&priv->monitor);
	}

	if (priv->dhcp_monitor) {
		if (priv->dhcp_monitor_id)
			g_signal_handler_disconnect (priv->dhcp_monitor,
			                             priv->dhcp_monitor_id);

		g_file_monitor_cancel (priv->dhcp_monitor);
		g_clear_object (&priv->dhcp_monitor);
	}

	nm_clear_g_free (&priv->current_hostname);

	G_OBJECT_CLASS (nm_hostname_manager_parent_class)->dispose (object);
}

static void
nm_hostname_manager_class_init (NMHostnameManagerClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);

	object_class->constructed = constructed;
	object_class->get_property = get_property;
	object_class->dispose = dispose;

	obj_properties[PROP_HOSTNAME] =
	    g_param_spec_string (NM_HOSTNAME_MANAGER_HOSTNAME, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
