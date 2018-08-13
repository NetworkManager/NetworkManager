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

#include <string.h>
#include <net/if.h>

#include "nm-logging.h"
#include "nm-core-internal.h"
#include "nm-manager.h"
#include "nm-device-iwd.h"
#include "nm-utils/nm-random-utils.h"

/*****************************************************************************/

typedef struct {
	char *name;
	NMIwdNetworkSecurity security;
} KnownNetworkData;

typedef struct {
	NMManager *manager;
	GCancellable *cancellable;
	gboolean running;
	GDBusObjectManager *object_manager;
	guint agent_id;
	char *agent_path;
	GSList *known_networks;
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
		_LOGD ("agent-request: if_nametoindex failed for Name %s for Device at %s: %i",
		       ifname, device_path, errno);
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

static void
set_device_dbus_object (NMIwdManager *self, GDBusInterface *interface,
                        GDBusObject *object)
{
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);
	GDBusProxy *proxy;
	const char *ifname;
	int ifindex;
	NMDevice *device;

	if (!priv->running)
		return;

	g_return_if_fail (G_IS_DBUS_PROXY (interface));

	proxy = G_DBUS_PROXY (interface);

	if (strcmp (g_dbus_proxy_get_interface_name (proxy),
	            NM_IWD_DEVICE_INTERFACE))
		return;

	ifname = get_property_string_or_null (proxy, "Name");
	if (!ifname) {
		_LOGE ("Name not cached for Device at %s",
		       g_dbus_proxy_get_object_path (proxy));
		return;
	}

	ifindex = if_nametoindex (ifname);

	if (!ifindex) {
		_LOGE ("if_nametoindex failed for Name %s for Device at %s: %i",
		       ifname, g_dbus_proxy_get_object_path (proxy), errno);
		return;
	}

	device = nm_manager_get_device_by_ifindex (priv->manager, ifindex);
	if (!NM_IS_DEVICE_IWD (device)) {
		_LOGE ("IWD device named %s is not a Wifi device", ifname);
		return;
	}

	nm_device_iwd_set_dbus_object (NM_DEVICE_IWD (device), object);
}

static void
interface_added (GDBusObjectManager *object_manager, GDBusObject *object,
                 GDBusInterface *interface, gpointer user_data)
{
	NMIwdManager *self = user_data;

	set_device_dbus_object (self, interface, object);
}

static void
interface_removed (GDBusObjectManager *object_manager, GDBusObject *object,
                   GDBusInterface *interface, gpointer user_data)
{
	NMIwdManager *self = user_data;

	/*
	 * TODO: we may need to save the GDBusInterface or GDBusObject
	 * pointer in the hash table because we may be no longer able to
	 * access the Name property or map the name to ifindex with
	 * if_nametoindex at this point.
	 */

	set_device_dbus_object (self, interface, NULL);
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

		set_device_dbus_object (self, interface, object);
	}

	g_list_free_full (interfaces, g_object_unref);
}

static void
known_network_free (KnownNetworkData *network)
{
	g_free (network->name);
	g_free (network);
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
		g_signal_handlers_disconnect_by_data (object_manager, self);
		g_clear_object (&priv->object_manager);
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
		gs_unref_object GDBusInterface *interface;
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
		       NM_G_ERROR_MSG (error));
		g_clear_error (&error);
		return;
	}

	priv->object_manager = object_manager;

	g_signal_connect (priv->object_manager, "notify::name-owner",
	                  G_CALLBACK (name_owner_changed), self);

	nm_assert (G_IS_DBUS_OBJECT_MANAGER_CLIENT (object_manager));

	connection = g_dbus_object_manager_client_get_connection (G_DBUS_OBJECT_MANAGER_CLIENT (object_manager));

	priv->agent_id = iwd_agent_export (connection, self,
	                                   &priv->agent_path, &error);
	if (!priv->agent_id) {
		_LOGE ("failed to export the IWD Agent: PSK/8021x WiFi networks will not work: %s",
		       NM_G_ERROR_MSG (error));
		g_clear_error (&error);
	}

	if (_om_has_name_owner (object_manager)) {
		GList *objects, *iter;

		priv->running = true;

		g_signal_connect (priv->object_manager, "interface-added",
		                  G_CALLBACK (interface_added), self);
		g_signal_connect (priv->object_manager, "interface-removed",
		                  G_CALLBACK (interface_removed), self);

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
	const GSList *iter;

	for (iter = priv->known_networks; iter; iter = g_slist_next (iter)) {
		const KnownNetworkData *network = iter->data;

		if (!strcmp (network->name, name) && network->security == security)
			return true;
	}

	return false;
}

void
nm_iwd_manager_network_connected (NMIwdManager *self, const char *name,
                                  NMIwdNetworkSecurity security)
{
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);
	KnownNetworkData *network_data;

	if (nm_iwd_manager_is_known_network (self, name, security))
		return;

	network_data = g_new (KnownNetworkData, 1);
	network_data->name = g_strdup (name);
	network_data->security = security;
	priv->known_networks = g_slist_append (priv->known_networks, network_data);
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

	priv->cancellable = g_cancellable_new ();

	prepare_object_manager (self);
}

static void
dispose (GObject *object)
{
	NMIwdManager *self = (NMIwdManager *) object;
	NMIwdManagerPrivate *priv = NM_IWD_MANAGER_GET_PRIVATE (self);

	if (priv->object_manager) {
		if (priv->agent_id) {
			GDBusConnection *connection;
			GDBusObjectManagerClient *omc = G_DBUS_OBJECT_MANAGER_CLIENT (priv->object_manager);

			/* No need to unregister the agent as IWD will detect
			 * our DBus connection being closed.
			 */

			connection = g_dbus_object_manager_client_get_connection (omc);

			g_dbus_connection_unregister_object (connection, priv->agent_id);
			priv->agent_id = 0;
		}

		g_clear_object (&priv->object_manager);
	}

	nm_clear_g_free (&priv->agent_path);

	nm_clear_g_cancellable (&priv->cancellable);

	g_slist_free_full (priv->known_networks, (GDestroyNotify) known_network_free);
	priv->known_networks = NULL;

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
