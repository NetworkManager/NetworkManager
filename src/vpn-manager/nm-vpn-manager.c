/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <string.h>

#include "nm-vpn-manager.h"
#include "nm-vpn-service.h"
#include "nm-vpn-connection.h"
#include "nm-dbus-manager.h"
#include "NetworkManagerVPN.h"
#include "nm-utils.h"

static gboolean impl_vpn_manager_connect (NMVPNManager *manager,
								  const char *type,
								  const char *name,
								  GHashTable *properties,
								  const char *device_path,
								  char **routes,
								  char **connection,
								  GError **err);

static gboolean impl_vpn_manager_get_connections (NMVPNManager *manager,
										GPtrArray **connections,
										GError **err);

#include "nm-vpn-manager-glue.h"

G_DEFINE_TYPE (NMVPNManager, nm_vpn_manager, G_TYPE_OBJECT)

typedef struct {
	NMManager *nm_mgr;
	NMDBusManager *dbus_mgr;
	GSList *services;
} NMVPNManagerPrivate;

#define NM_VPN_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_VPN_MANAGER, NMVPNManagerPrivate))

static NMVPNService *
nm_vpn_manager_get_service (NMVPNManager *manager, const char *service_name)
{
	GSList *iter;

	for (iter = NM_VPN_MANAGER_GET_PRIVATE (manager)->services; iter; iter = iter->next) {
		NMVPNService *service = NM_VPN_SERVICE (iter->data);

		if (!strcmp (service_name, nm_vpn_service_get_name (service)))
			return service;
	}

	return NULL;
}

static void
remove_service (gpointer data, GObject *service)
{
	NMVPNManagerPrivate *priv = NM_VPN_MANAGER_GET_PRIVATE (data);

	priv->services = g_slist_remove (priv->services, service);
}

static void
nm_vpn_manager_add_service (NMVPNManager *manager, NMVPNService *service)
{
	NMVPNManagerPrivate *priv = NM_VPN_MANAGER_GET_PRIVATE (manager);

	priv->services = g_slist_prepend (priv->services, service);
	g_object_weak_ref (G_OBJECT (service), remove_service, manager);
}

NMVPNConnection *
nm_vpn_manager_connect (NMVPNManager *manager,
				    const char *type,
				    const char *name,
				    NMDevice *device,
				    GHashTable *properties,
				    char **routes)
{
	NMVPNService *service;

	g_return_val_if_fail (NM_IS_VPN_MANAGER (manager), NULL);
	g_return_val_if_fail (type != NULL, NULL);
	g_return_val_if_fail (name != NULL, NULL);
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);
	g_return_val_if_fail (properties != NULL, NULL);

	if (nm_device_get_state (device) != NM_DEVICE_STATE_ACTIVATED)
		return NULL;

	service = nm_vpn_manager_get_service (manager, type);
	if (!service) {
		service = nm_vpn_service_new (type);
		if (service)
			nm_vpn_manager_add_service (manager, service);
	}

	if (service)
		return nm_vpn_service_activate (service, name, device, properties, routes);

	return NULL;
}

static NMDevice *
find_device (NMVPNManager *manager, const char *device_path)
{
	GSList *devices;
	GSList *iter;

	devices = nm_manager_get_devices (NM_VPN_MANAGER_GET_PRIVATE (manager)->nm_mgr);
	for (iter = devices; iter; iter = iter->next) {
		NMDevice *device = NM_DEVICE (iter->data);

		if (!strcmp (device_path, nm_device_get_dbus_path	(device)))
			return device;
	}

	return NULL;
}

static gboolean
impl_vpn_manager_connect (NMVPNManager *manager,
					 const char *type,
					 const char *name,
					 GHashTable *properties,
					 const char *device_path,
					 char **routes,
					 char **connection_path,
					 GError **err)
{
	NMDevice *device;
	NMVPNConnection *connection;
	GHashTable *properties_dup;
	char **routes_dup;

	device = find_device (manager, device_path);
	if (!device)
		return FALSE;

	properties_dup = nm_utils_gvalue_hash_dup (properties);
	routes_dup = g_strdupv (routes);

	connection = nm_vpn_manager_connect (manager,
								  type, name,
								  device,
								  properties_dup,
								  routes_dup);
	if (connection)
		*connection_path = g_strdup (nm_vpn_connection_get_object_path (connection));
	else {
		g_hash_table_destroy (properties_dup);
		g_strfreev (routes_dup);
	}

	return *connection_path != NULL;
}

static void
get_connections (gpointer data, gpointer user_data)
{
	NMVPNService *service = NM_VPN_SERVICE (data);
	GSList **list = (GSList **) user_data;

	*list = g_slist_concat (*list, nm_vpn_service_get_connections (service));
}

GSList *
nm_vpn_manager_get_connections (NMVPNManager *manager)
{
	GSList *list = NULL;

	g_return_val_if_fail (NM_IS_VPN_MANAGER (manager), NULL);

	g_slist_foreach (NM_VPN_MANAGER_GET_PRIVATE (manager)->services, get_connections, &list);

	return list;
}

static gboolean
impl_vpn_manager_get_connections (NMVPNManager *manager, GPtrArray **connections, GError **err)
{
	GSList *list;
	GSList *iter;

	list = nm_vpn_manager_get_connections (manager);
	*connections = g_ptr_array_sized_new (g_slist_length (list));

	for (iter = list; iter; iter = iter->next)
		g_ptr_array_add (*connections,
					  g_strdup (nm_vpn_connection_get_object_path (NM_VPN_CONNECTION (iter->data))));

	g_slist_free (list);

	return TRUE;
}

NMVPNManager *
nm_vpn_manager_new (NMManager *nm_manager)
{
	NMVPNManager *manager;

	g_return_val_if_fail (NM_IS_MANAGER (nm_manager), NULL);

	manager = (NMVPNManager *) g_object_new (NM_TYPE_VPN_MANAGER, NULL);
	if (manager)
		NM_VPN_MANAGER_GET_PRIVATE (manager)->nm_mgr = g_object_ref (nm_manager);

	return manager;
}

/******************************************************************************/

static void
nm_vpn_manager_init (NMVPNManager *manager)
{
	NMVPNManagerPrivate *priv = NM_VPN_MANAGER_GET_PRIVATE (manager);

	priv->dbus_mgr = nm_dbus_manager_get ();
	dbus_g_connection_register_g_object (nm_dbus_manager_get_connection (priv->dbus_mgr),
								  NM_DBUS_PATH_VPN,
								  G_OBJECT (manager));
}

static void
finalize (GObject *object)
{
	NMVPNManagerPrivate *priv = NM_VPN_MANAGER_GET_PRIVATE (object);

	g_slist_foreach (priv->services, (GFunc) g_object_unref, NULL);
	g_object_unref (priv->dbus_mgr);
	g_object_unref (priv->nm_mgr);

	G_OBJECT_CLASS (nm_vpn_manager_parent_class)->finalize (object);
}

static void
nm_vpn_manager_class_init (NMVPNManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);

	g_type_class_add_private (manager_class, sizeof (NMVPNManagerPrivate));

	/* virtual methods */
	object_class->finalize = finalize;

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (manager_class),
							   &dbus_glib_nm_vpn_manager_object_info);
}
