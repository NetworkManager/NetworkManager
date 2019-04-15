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
 * Copyright (C) 2017 Intel Corporation
 */

#include "nm-default.h"

#include "nm-iwd-manager.h"

#include <net/if.h>

#include "nm-logging.h"
#include "nm-core-internal.h"
#include "nm-manager.h"
#include "nm-device-iwd.h"
#include "nm-wifi-utils.h"
#include "nm-glib-aux/nm-random-utils.h"
#include "settings/nm-settings.h"

/*****************************************************************************/

typedef struct {
	const char *name;
	NMIwdNetworkSecurity security;
	char buf[0];
} KnownNetworkId;

typedef struct {
	GDBusProxy *known_network;
	NMSettingsConnection *mirror_connection;
} KnownNetworkData;

typedef struct {
	NMManager *manager;
	NMSettings *settings;
	GCancellable *cancellable;
	gboolean running;
	GDBusObjectManager *object_manager;
	guint agent_id;
	char *agent_path;
	GHashTable *known_networks;
} NMIwdManagerPrivate;

struct _NMIwdManager {
	GObject parent;
	NMIwdManagerPrivate _priv;
};

struct _NMIwdManagerClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMIwdManager, nm_iwd_manager, G_TYPE_OBJECT)

#define NM_IWD_MANAGER_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMIwdManager, NM_IS_IWD_MANAGER)

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME                "iwd-manager"
#define _NMLOG_DOMAIN                     LOGD_WIFI

#define _NMLOG(level, ...) \
	G_STMT_START { \
		if (nm_logging_enabled (level, _NMLOG_DOMAIN)) { \
			char __prefix[32]; \
			\
			if (self) \
				g_snprintf (__prefix, sizeof (__prefix), "%s[%p]", ""_NMLOG_PREFIX_NAME"", (self)); \
			else \
				g_strlcpy (__prefix, _NMLOG_PREFIX_NAME, sizeof (__prefix)); \
			_nm_log ((level), (_NMLOG_DOMAIN), 0, NULL, NULL, \
			          "%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
			          __prefix _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
		} \
	} G_STMT_END

/*****************************************************************************/

static void mirror_8021x_connection_take_and_delete (NMSettingsConnection *sett_conn);

/*****************************************************************************/

static const char *
get_variant_string_or_null (GVariant *v)
{
	if (!v)
		return NULL;

	if (   !g_variant_is_of_type (v, G_VARIANT_TYPE_STRING)
	    && !g_variant_is_of_type (v, G_VARIANT_TYPE_OBJECT_PATH))
		return NULL;

	return g_variant_get_string (v, NULL);
}

static const char *
get_property_string_or_null (GDBusProxy *proxy, const char *property)
{
	gs_unref_variant GVariant *value = NULL;

	if (!proxy || !property)
		return NULL;

	value = g_dbus_proxy_get_cached_property (proxy, property);

	return get_variant_string_or_null (value);
}

static void
agent_dbus_method_cb (GDBusConnection *connection,
                      const char *sender, const char *object_path,
                      const char *interface_name, const char *method_name,
                      GVariant *parameters,
                      GDBusMethodInvocation *invocation,
                      gpointer user_data)
{
	NMIwdManager *self = user_data;
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);
	const char *network_path, *device_path, *ifname;
	gs_unref_object GDBusInterface *network = NULL, *device_obj = NULL;
	int ifindex;
	NMDevice *device;
	gs_free char *name_owner = NULL;
	int errsv;

	/* Be paranoid and check the sender address */
	name_owner = g_dbus_object_manager_client_get_name_owner (G_DBUS_OBJECT_MANAGER_CLIENT (priv->object_manager));
	if (!nm_streq0 (name_owner, sender))
		goto return_error;

	if (!strcmp (method_name, "RequestUserPassword"))
		g_variant_get (parameters, "(&os)", &network_path, NULL);
	else
		g_variant_get (parameters, "(&o)", &network_path);

	network = g_dbus_object_manager_get_interface (priv->object_manager,
	                                               network_path,
	                                               NM_IWD_NETWORK_INTERFACE);

	device_path = get_property_string_or_null (G_DBUS_PROXY (network), "Device");
	if (!device_path) {
		_LOGD ("agent-request: device not cached for network %s in IWD Agent request",
		       network_path);
		goto return_error;
	}

	device_obj = g_dbus_object_manager_get_interface (priv->object_manager,
	                                                  device_path,
	                                                  NM_IWD_DEVICE_INTERFACE);

	ifname = get_property_string_or_null (G_DBUS_PROXY (device_obj), "Name");
	if (!ifname) {
		_LOGD ("agent-request: name not cached for device %s in IWD Agent request",
		       device_path);
		goto return_error;
	}

	ifindex = if_nametoindex (ifname);
	if (!ifindex) {
		errsv = errno;
		_LOGD ("agent-request: if_nametoindex failed for Name %s for Device at %s: %i",
		       ifname, device_path, errsv);
		goto return_error;
	}

	device = nm_manager_get_device_by_ifindex (priv->manager, ifindex);
	if (!NM_IS_DEVICE_IWD (device)) {
		_LOGD ("agent-request: IWD device named %s is not a Wifi device in IWD Agent request",
		       ifname);
		goto return_error;
	}

	if (nm_device_iwd_agent_query (NM_DEVICE_IWD (device), invocation))
		return;

	_LOGD ("agent-request: device %s did not handle the IWD Agent request", ifname);

return_error:
	/* IWD doesn't look at the specific error */
	g_dbus_method_invocation_return_error_literal (invocation, NM_DEVICE_ERROR,
	                                               NM_DEVICE_ERROR_INVALID_CONNECTION,
	                                               "Secrets not available for this connection");
}

static const GDBusInterfaceInfo iwd_agent_iface_info = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
	"net.connman.iwd.Agent",
	.methods = NM_DEFINE_GDBUS_METHOD_INFOS (
		NM_DEFINE_GDBUS_METHOD_INFO (
			"RequestPassphrase",
			.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
				NM_DEFINE_GDBUS_ARG_INFO ("network", "o"),
			),
			.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
				NM_DEFINE_GDBUS_ARG_INFO ("passphrase", "s"),
			),
		),
		NM_DEFINE_GDBUS_METHOD_INFO (
			"RequestPrivateKeyPassphrase",
			.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
				NM_DEFINE_GDBUS_ARG_INFO ("network", "o"),
			),
			.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
				NM_DEFINE_GDBUS_ARG_INFO ("passphrase", "s"),
			),
		),
		NM_DEFINE_GDBUS_METHOD_INFO (
			"RequestUserNameAndPassword",
			.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
				NM_DEFINE_GDBUS_ARG_INFO ("network", "o"),
			),
			.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
				NM_DEFINE_GDBUS_ARG_INFO ("user", "s"),
				NM_DEFINE_GDBUS_ARG_INFO ("password", "s"),
			),
		),
		NM_DEFINE_GDBUS_METHOD_INFO (
			"RequestUserPassword",
			.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
				NM_DEFINE_GDBUS_ARG_INFO ("network", "o"),
				NM_DEFINE_GDBUS_ARG_INFO ("user", "s"),
			),
			.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
				NM_DEFINE_GDBUS_ARG_INFO ("password", "s"),
			),
		),
	),
);

static guint
iwd_agent_export (GDBusConnection *connection, gpointer user_data,
                  char **agent_path, GError **error)
{
	static const GDBusInterfaceVTable vtable = {
		.method_call = agent_dbus_method_cb,
	};
	char path[50];
	unsigned int rnd;
	guint id;

	nm_utils_random_bytes (&rnd, sizeof (rnd));

	nm_sprintf_buf (path, "/agent/%u", rnd);

	id = g_dbus_connection_register_object (connection, path,
	                                        NM_UNCONST_PTR (GDBusInterfaceInfo, &iwd_agent_iface_info),
	                                        &vtable, user_data, NULL, error);

	if (id)
		*agent_path = g_strdup (path);
	return id;
}

static void
register_agent (NMIwdManager *self)
{
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);
	GDBusInterface *agent_manager;

	agent_manager = g_dbus_object_manager_get_interface (priv->object_manager,
	                                                     "/",
	                                                     NM_IWD_AGENT_MANAGER_INTERFACE);

	/* Register our agent */
	g_dbus_proxy_call (G_DBUS_PROXY (agent_manager),
	                   "RegisterAgent",
	                   g_variant_new ("(o)", priv->agent_path),
	                   G_DBUS_CALL_FLAGS_NONE, -1,
	                   NULL, NULL, NULL);

	g_object_unref (agent_manager);
}

/*****************************************************************************/

static KnownNetworkId *
known_network_id_new (const char *name, NMIwdNetworkSecurity security)
{
	KnownNetworkId *id;
	gsize strsize = strlen (name) + 1;

	id = g_malloc (sizeof (KnownNetworkId) + strsize);
	id->name = id->buf;
	id->security = security;
	memcpy (id->buf, name, strsize);

	return id;
}

static guint
known_network_id_hash (KnownNetworkId *id)
{
	NMHashState h;

	nm_hash_init (&h, 1947951703u);
	nm_hash_update_val (&h, id->security);
	nm_hash_update_str (&h, id->name);
	return nm_hash_complete (&h);
}

static gboolean
known_network_id_equal (KnownNetworkId *a, KnownNetworkId *b)
{
	return    a->security == b->security
	       && nm_streq (a->name, b->name);
}

static void
known_network_data_free (KnownNetworkData *network)
{
	if (!network)
		return;

	g_object_unref (network->known_network);
	mirror_8021x_connection_take_and_delete (network->mirror_connection);
	g_slice_free (KnownNetworkData, network);
}

/*****************************************************************************/

static void
set_device_dbus_object (NMIwdManager *self, GDBusProxy *proxy,
                        GDBusObject *object)
{
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);
	const char *ifname;
	int ifindex;
	NMDevice *device;
	int errsv;

	ifname = get_property_string_or_null (proxy, "Name");
	if (!ifname) {
		_LOGE ("Name not cached for Device at %s",
		       g_dbus_proxy_get_object_path (proxy));
		return;
	}

	ifindex = if_nametoindex (ifname);

	if (!ifindex) {
		errsv = errno;
		_LOGE ("if_nametoindex failed for Name %s for Device at %s: %i",
		       ifname, g_dbus_proxy_get_object_path (proxy), errsv);
		return;
	}

	device = nm_manager_get_device_by_ifindex (priv->manager, ifindex);
	if (!NM_IS_DEVICE_IWD (device)) {
		_LOGE ("IWD device named %s is not a Wifi device", ifname);
		return;
	}

	nm_device_iwd_set_dbus_object (NM_DEVICE_IWD (device), object);
}

/* Look up an existing NMSettingsConnection for a WPA2-Enterprise network
 * that has been preprovisioned with an IWD config file, or create a new
 * in-memory connection object so that NM autoconnect mechanism and the
 * clients know this networks needs no additional EAP configuration from
 * the user.
 */
static NMSettingsConnection *
mirror_8021x_connection (NMIwdManager *self,
                         const char *name,
                         gboolean create_new)
{
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);
	NMSettingsConnection *const*iter;
	gs_unref_object NMConnection *connection = NULL;
	NMSettingsConnection *settings_connection = NULL;
	char uuid[37];
	NMSetting *setting;
	GError *error = NULL;
	gs_unref_bytes GBytes *new_ssid = NULL;

	for (iter = nm_settings_get_connections (priv->settings, NULL); *iter; iter++) {
		NMSettingsConnection *sett_conn = *iter;
		NMConnection *conn = nm_settings_connection_get_connection (sett_conn);
		NMIwdNetworkSecurity security;
		gs_free char *ssid_name = NULL;
		NMSettingWireless *s_wifi;
		NMSetting8021x *s_8021x;
		gboolean external = FALSE;
		guint i;

		security = nm_wifi_connection_get_iwd_security (conn, NULL);
		if (security != NM_IWD_NETWORK_SECURITY_8021X)
			continue;

		s_wifi = nm_connection_get_setting_wireless (conn);
		if (!s_wifi)
			continue;

		ssid_name = _nm_utils_ssid_to_utf8 (nm_setting_wireless_get_ssid (s_wifi));

		if (!nm_streq (ssid_name, name))
			continue;

		s_8021x = nm_connection_get_setting_802_1x (conn);
		for (i = 0; i < nm_setting_802_1x_get_num_eap_methods (s_8021x); i++) {
			if (nm_streq (nm_setting_802_1x_get_eap_method (s_8021x, i), "external")) {
				external = TRUE;
				break;
			}
		}

		/* Prefer returning connections for EAP method "external" */
		if (!settings_connection || external)
			settings_connection = sett_conn;
	}

	/* If we already have an NMSettingsConnection matching this
	 * KnownNetwork, whether it's saved or an in-memory connection
	 * potentially created by ourselves then we have nothing left to
	 * do here.
	 */
	if (settings_connection || !create_new)
		return settings_connection;

	connection = nm_simple_connection_new ();

	setting = NM_SETTING (g_object_new (NM_TYPE_SETTING_CONNECTION,
	                                    NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRELESS_SETTING_NAME,
	                                    NM_SETTING_CONNECTION_ID, name,
	                                    NM_SETTING_CONNECTION_UUID, nm_utils_uuid_generate_buf (uuid),
	                                    NM_SETTING_CONNECTION_READ_ONLY, TRUE,
	                                    NULL));
	nm_connection_add_setting (connection, setting);

	new_ssid = g_bytes_new (name, strlen (name));
	setting = NM_SETTING (g_object_new (NM_TYPE_SETTING_WIRELESS,
	                                    NM_SETTING_WIRELESS_SSID, new_ssid,
	                                    NM_SETTING_WIRELESS_MODE, NM_SETTING_WIRELESS_MODE_INFRA,
	                                    NULL));
	nm_connection_add_setting (connection, setting);

	setting = NM_SETTING (g_object_new (NM_TYPE_SETTING_WIRELESS_SECURITY,
	                                    NM_SETTING_WIRELESS_SECURITY_AUTH_ALG, "open",
	                                    NM_SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-eap",
	                                    NULL));
	nm_connection_add_setting (connection, setting);

	/* "password" and "private-key-password" may be requested by the IWD agent
	 * from NM and IWD will implement a specific secret cache policy so by
	 * default respect that policy and don't save copies of those secrets in
	 * NM settings.  The saved values can not be used anyway because of our
	 * use of NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW.
	 */
	setting = NM_SETTING (g_object_new (NM_TYPE_SETTING_802_1X,
	                                    NM_SETTING_802_1X_PASSWORD_FLAGS, NM_SETTING_SECRET_FLAG_NOT_SAVED,
	                                    NM_SETTING_802_1X_PRIVATE_KEY_PASSWORD_FLAGS, NM_SETTING_SECRET_FLAG_NOT_SAVED,
	                                    NULL));
	nm_setting_802_1x_add_eap_method (NM_SETTING_802_1X (setting), "external");
	nm_connection_add_setting (connection, setting);

	if (!nm_connection_normalize (connection, NULL, NULL, NULL))
		return NULL;

	settings_connection = nm_settings_add_connection (priv->settings, connection,
	                                                  FALSE, &error);
	if (!settings_connection) {
		_LOGW ("failed to add a mirror NMConnection for IWD's Known Network '%s': %s",
		       name, error->message);
		g_error_free (error);
		return NULL;
	}

	nm_settings_connection_set_flags (settings_connection,
	                                  NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED |
	                                  NM_SETTINGS_CONNECTION_INT_FLAGS_UNSAVED,
	                                  TRUE);
	return settings_connection;
}

static void
mirror_8021x_connection_take_and_delete (NMSettingsConnection *sett_conn)
{
	NMSettingsConnectionIntFlags flags;

	if (!sett_conn)
		return;

	flags = nm_settings_connection_get_flags (sett_conn);

	/* If connection has not been saved since we created it
	 * in interface_added it too can be removed now. */
	if (NM_FLAGS_HAS (flags, NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED))
		nm_settings_connection_delete (sett_conn, NULL);

	g_object_unref (sett_conn);
}

static void
interface_added (GDBusObjectManager *object_manager, GDBusObject *object,
                 GDBusInterface *interface, gpointer user_data)
{
	NMIwdManager *self = user_data;
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);
	GDBusProxy *proxy;
	const char *iface_name;

	if (!priv->running)
		return;

	g_return_if_fail (G_IS_DBUS_PROXY (interface));

	proxy = G_DBUS_PROXY (interface);
	iface_name = g_dbus_proxy_get_interface_name (proxy);

	if (nm_streq (iface_name, NM_IWD_DEVICE_INTERFACE)) {
		set_device_dbus_object (self, proxy, object);
		return;
	}

	if (nm_streq (iface_name, NM_IWD_KNOWN_NETWORK_INTERFACE)) {
		KnownNetworkId *id;
		KnownNetworkData *data;
		NMIwdNetworkSecurity security;
		const char *type_str, *name;
		NMSettingsConnection *sett_conn = NULL;

		type_str = get_property_string_or_null (proxy, "Type");
		name = get_property_string_or_null (proxy, "Name");
		if (!type_str || !name)
			return;

		if (nm_streq (type_str, "open"))
			security = NM_IWD_NETWORK_SECURITY_NONE;
		else if (nm_streq (type_str, "psk"))
			security = NM_IWD_NETWORK_SECURITY_PSK;
		else if (nm_streq (type_str, "8021x"))
			security = NM_IWD_NETWORK_SECURITY_8021X;
		else
			return;

		id = known_network_id_new (name, security);

		data = g_hash_table_lookup (priv->known_networks, id);
		if (data) {
			_LOGW ("DBus error: KnownNetwork already exists ('%s', %s)",
			       name, type_str);
			g_free (id);
			nm_g_object_ref_set (&data->known_network, proxy);
		} else {
			data = g_slice_new0 (KnownNetworkData);
			data->known_network = g_object_ref (proxy);
			g_hash_table_insert (priv->known_networks, id, data);
		}

		if (security == NM_IWD_NETWORK_SECURITY_8021X) {
			sett_conn = mirror_8021x_connection (self, name, TRUE);

			if (   sett_conn
			    && sett_conn != data->mirror_connection) {
				NMSettingsConnection *sett_conn_old = data->mirror_connection;

				data->mirror_connection = nm_g_object_ref (sett_conn);
				mirror_8021x_connection_take_and_delete (sett_conn_old);
			}
		} else
			mirror_8021x_connection_take_and_delete (g_steal_pointer (&data->mirror_connection));

		return;
	}
}

static void
interface_removed (GDBusObjectManager *object_manager, GDBusObject *object,
                   GDBusInterface *interface, gpointer user_data)
{
	NMIwdManager *self = user_data;
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);
	GDBusProxy *proxy;
	const char *iface_name;

	g_return_if_fail (G_IS_DBUS_PROXY (interface));

	proxy = G_DBUS_PROXY (interface);
	iface_name = g_dbus_proxy_get_interface_name (proxy);

	if (nm_streq (iface_name, NM_IWD_DEVICE_INTERFACE)) {
		set_device_dbus_object (self, proxy, NULL);
		return;
	}

	if (nm_streq (iface_name, NM_IWD_KNOWN_NETWORK_INTERFACE)) {
		KnownNetworkId id;
		const char *type_str;

		type_str = get_property_string_or_null (proxy, "Type");
		id.name = get_property_string_or_null (proxy, "Name");
		if (!type_str || !id.name)
			return;

		if (nm_streq (type_str, "open"))
			id.security = NM_IWD_NETWORK_SECURITY_NONE;
		else if (nm_streq (type_str, "psk"))
			id.security = NM_IWD_NETWORK_SECURITY_PSK;
		else if (nm_streq (type_str, "8021x"))
			id.security = NM_IWD_NETWORK_SECURITY_8021X;
		else
			return;

		g_hash_table_remove (priv->known_networks, &id);
		return;
	}
}

static void
connection_removed (NMSettings *settings,
                    NMSettingsConnection *sett_conn,
                    gpointer user_data)
{
	NMIwdManager *self = user_data;
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);
	NMConnection *conn = nm_settings_connection_get_connection (sett_conn);
	NMSettingWireless *s_wireless;
	gboolean mapped;
	KnownNetworkData *data;
	KnownNetworkId id;

	id.security = nm_wifi_connection_get_iwd_security (conn, &mapped);
	if (!mapped)
		return;

	s_wireless = nm_connection_get_setting_wireless (conn);
	id.name = _nm_utils_ssid_to_utf8 (nm_setting_wireless_get_ssid (s_wireless));
	data = g_hash_table_lookup (priv->known_networks, &id);
	g_free ((char *) id.name);
	if (!data)
		return;

	if (id.security == NM_IWD_NETWORK_SECURITY_8021X) {
		NMSettingsConnection *new_mirror_conn;

		if (data->mirror_connection != sett_conn)
			return;

		g_clear_object (&data->mirror_connection);

		/* Don't call Forget for an 8021x network until there's no
		 * longer *any* matching NMSettingsConnection (debatable)
		 */
		new_mirror_conn = mirror_8021x_connection (self, id.name, FALSE);
		if (new_mirror_conn) {
			data->mirror_connection = g_object_ref (new_mirror_conn);
			return;
		}
	}

	if (!priv->running)
		return;

	g_dbus_proxy_call (data->known_network, "Forget",
	                   NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL, NULL);
}

static gboolean
_om_has_name_owner (GDBusObjectManager *object_manager)
{
	gs_free char *name_owner = NULL;

	nm_assert (G_IS_DBUS_OBJECT_MANAGER_CLIENT (object_manager));

	name_owner = g_dbus_object_manager_client_get_name_owner (G_DBUS_OBJECT_MANAGER_CLIENT (object_manager));
	return !!name_owner;
}

static void
object_added (NMIwdManager *self, GDBusObject *object)
{
	GList *interfaces, *iter;

	interfaces = g_dbus_object_get_interfaces (object);

	for (iter = interfaces; iter; iter = iter->next) {
		GDBusInterface *interface = G_DBUS_INTERFACE (iter->data);

		interface_added (NULL, object, interface, self);
	}

	g_list_free_full (interfaces, g_object_unref);
}

static void
release_object_manager (NMIwdManager *self)
{
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);

	if (!priv->object_manager)
		return;

	g_signal_handlers_disconnect_by_data (priv->object_manager, self);

	if (priv->agent_id) {
		GDBusConnection *agent_connection;
		GDBusObjectManagerClient *omc = G_DBUS_OBJECT_MANAGER_CLIENT (priv->object_manager);

		agent_connection = g_dbus_object_manager_client_get_connection (omc);

		/* We're is called when we're shutting down (i.e. our DBus connection
		 * is being closed, and IWD will detect this) or IWD was stopped so
		 * in either case calling UnregisterAgent will not do anything.
		 */
		g_dbus_connection_unregister_object (agent_connection, priv->agent_id);
		priv->agent_id = 0;
		nm_clear_g_free (&priv->agent_path);
	}

	g_clear_object (&priv->object_manager);
}

static void prepare_object_manager (NMIwdManager *self);

static void
name_owner_changed (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	NMIwdManager *self = user_data;
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);
	GDBusObjectManager *object_manager = G_DBUS_OBJECT_MANAGER (object);

	nm_assert (object_manager == priv->object_manager);

	if (_om_has_name_owner (object_manager)) {
		release_object_manager (self);
		prepare_object_manager (self);
	} else {
		const CList *tmp_lst;
		NMDevice *device;

		if (!priv->running)
			return;

		priv->running = false;

		nm_manager_for_each_device (priv->manager, device, tmp_lst) {
			if (NM_IS_DEVICE_IWD (device)) {
				nm_device_iwd_set_dbus_object (NM_DEVICE_IWD (device),
				                               NULL);
			}
		}
	}
}

static void
device_added (NMManager *manager, NMDevice *device, gpointer user_data)
{
	NMIwdManager *self = user_data;
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);
	GList *objects, *iter;

	if (!NM_IS_DEVICE_IWD (device))
		return;

	if (!priv->running)
		return;

	objects = g_dbus_object_manager_get_objects (priv->object_manager);
	for (iter = objects; iter; iter = iter->next) {
		GDBusObject *object = G_DBUS_OBJECT (iter->data);
		gs_unref_object GDBusInterface *interface = NULL;
		const char *obj_ifname;

		interface = g_dbus_object_get_interface (object,
		                                         NM_IWD_DEVICE_INTERFACE);
		obj_ifname = get_property_string_or_null ((GDBusProxy *) interface, "Name");

		if (!obj_ifname || strcmp (nm_device_get_iface (device), obj_ifname))
			continue;

		nm_device_iwd_set_dbus_object (NM_DEVICE_IWD (device), object);
		break;
	}

	g_list_free_full (objects, g_object_unref);
}

static void
got_object_manager (GObject *object, GAsyncResult *result, gpointer user_data)
{
	NMIwdManager *self = user_data;
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);
	GError *error = NULL;
	GDBusObjectManager *object_manager;
	GDBusConnection *connection;

	object_manager = g_dbus_object_manager_client_new_for_bus_finish (result, &error);
	if (object_manager == NULL) {
		_LOGE ("failed to acquire IWD Object Manager: Wi-Fi will not be available (%s)",
		       error->message);
		g_clear_error (&error);
		return;
	}

	priv->object_manager = object_manager;

	g_signal_connect (priv->object_manager, "notify::name-owner",
	                  G_CALLBACK (name_owner_changed), self);

	nm_assert (G_IS_DBUS_OBJECT_MANAGER_CLIENT (object_manager));

	connection = g_dbus_object_manager_client_get_connection (G_DBUS_OBJECT_MANAGER_CLIENT (object_manager));

	priv->agent_id = iwd_agent_export (connection,
	                                   self,
	                                   &priv->agent_path,
	                                   &error);
	if (!priv->agent_id) {
		_LOGE ("failed to export the IWD Agent: PSK/8021x Wi-Fi networks may not work: %s",
		       error->message);
		g_clear_error (&error);
	}

	if (_om_has_name_owner (object_manager)) {
		GList *objects, *iter;

		priv->running = true;

		g_signal_connect (priv->object_manager, "interface-added",
		                  G_CALLBACK (interface_added), self);
		g_signal_connect (priv->object_manager, "interface-removed",
		                  G_CALLBACK (interface_removed), self);

		g_hash_table_remove_all (priv->known_networks);

		objects = g_dbus_object_manager_get_objects (object_manager);
		for (iter = objects; iter; iter = iter->next)
			object_added (self, G_DBUS_OBJECT (iter->data));

		g_list_free_full (objects, g_object_unref);

		if (priv->agent_id)
			register_agent (self);
	}
}

static void
prepare_object_manager (NMIwdManager *self)
{
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);

	g_dbus_object_manager_client_new_for_bus (NM_IWD_BUS_TYPE,
	                                          G_DBUS_OBJECT_MANAGER_CLIENT_FLAGS_NONE,
	                                          NM_IWD_SERVICE, "/",
	                                          NULL, NULL, NULL,
	                                          priv->cancellable,
	                                          got_object_manager, self);
}

gboolean
nm_iwd_manager_is_known_network (NMIwdManager *self, const char *name,
                                 NMIwdNetworkSecurity security)
{
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);
	KnownNetworkId kn_id = { name, security };

	return g_hash_table_contains (priv->known_networks, &kn_id);
}

GDBusProxy *
nm_iwd_manager_get_dbus_interface (NMIwdManager *self, const char *path,
                                   const char *name)
{
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);
	GDBusInterface *interface;

	if (!priv->object_manager)
		return NULL;

	interface = g_dbus_object_manager_get_interface (priv->object_manager, path, name);

	return interface ? G_DBUS_PROXY (interface) : NULL;
}

/*****************************************************************************/

NM_DEFINE_SINGLETON_GETTER (NMIwdManager, nm_iwd_manager_get,
                            NM_TYPE_IWD_MANAGER);

static void
nm_iwd_manager_init (NMIwdManager *self)
{
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);

	priv->manager = g_object_ref (nm_manager_get ());
	g_signal_connect (priv->manager, NM_MANAGER_DEVICE_ADDED,
	                  G_CALLBACK (device_added), self);

	priv->settings = g_object_ref (nm_settings_get ());
	g_signal_connect (priv->settings, NM_SETTINGS_SIGNAL_CONNECTION_REMOVED,
	                  G_CALLBACK (connection_removed), self);

	priv->cancellable = g_cancellable_new ();

	priv->known_networks = g_hash_table_new_full ((GHashFunc) known_network_id_hash,
	                                              (GEqualFunc) known_network_id_equal,
	                                              g_free,
	                                              (GDestroyNotify) known_network_data_free);

	prepare_object_manager (self);
}

static void
dispose (GObject *object)
{
	NMIwdManager *self = (NMIwdManager *) object;
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);

	release_object_manager (self);

	nm_clear_g_cancellable (&priv->cancellable);

	if (priv->settings) {
		g_signal_handlers_disconnect_by_data (priv->settings, self);
		g_clear_object (&priv->settings);
	}

	/* This may trigger mirror connection removals so it happens
	 * after the g_signal_handlers_disconnect_by_data above.
	 */
	nm_clear_pointer (&priv->known_networks, g_hash_table_destroy);

	if (priv->manager) {
		g_signal_handlers_disconnect_by_data (priv->manager, self);
		g_clear_object (&priv->manager);
	}

	G_OBJECT_CLASS (nm_iwd_manager_parent_class)->dispose (object);
}

static void
nm_iwd_manager_class_init (NMIwdManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = dispose;
}
