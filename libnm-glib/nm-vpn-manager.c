/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <dbus/dbus-glib.h>
#include <string.h>
#include "nm-vpn-manager.h"
#include "nm-marshal.h"

#include "nm-vpn-manager-bindings.h"

G_DEFINE_TYPE (NMVPNManager, nm_vpn_manager, NM_TYPE_OBJECT)

#define NM_VPN_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_VPN_MANAGER, NMVPNManagerPrivate))

typedef struct {
	DBusGProxy *manager_proxy;
} NMVPNManagerPrivate;

NMVPNManager *
nm_vpn_manager_new (void)
{
	DBusGConnection *connection;
	GError *err = NULL;

	connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
	if (!connection) {
		g_warning ("Couldn't connect to system bus: %s", err->message);
		g_error_free (err);
		return NULL;
	}

	return (NMVPNManager *) g_object_new (NM_TYPE_VPN_MANAGER,
								   NM_OBJECT_CONNECTION, connection,
								   NM_OBJECT_PATH, NM_DBUS_PATH_VPN,
								   NULL);

}

NMVPNConnection *
nm_vpn_manager_connect (NMVPNManager *manager,
				    const char   *type,
				    const char   *name,
				    GHashTable   *properties,
				    NMDevice     *device,
				    char        **routes)
{
	char *connection_path = NULL;
	GError *err = NULL;

	g_return_val_if_fail (NM_IS_VPN_MANAGER (manager), NULL);
	g_return_val_if_fail (type != NULL, NULL);
	g_return_val_if_fail (name != NULL, NULL);
	g_return_val_if_fail (properties != NULL, NULL);
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	if (!org_freedesktop_NetworkManager_VPN_Manager_connect (NM_VPN_MANAGER_GET_PRIVATE (manager)->manager_proxy,
												  type, name,
												  properties,
												  nm_object_get_path (NM_OBJECT (device)),
												  routes,
												  &connection_path,
												  &err)) {
		g_warning ("Error in VPN Connect: %s", err->message);
		g_error_free (err);
		return NULL;
	}

	return nm_vpn_connection_new (nm_object_get_connection (NM_OBJECT (manager)), connection_path);
}

GSList *
nm_vpn_manager_get_connections (NMVPNManager *manager)
{
	GPtrArray *array = NULL;
	GSList *list = NULL;
	DBusGConnection *dbus_connection;
	int i;
	GError *err = NULL;

	g_return_val_if_fail (NM_IS_VPN_MANAGER (manager), NULL);

	if (!org_freedesktop_NetworkManager_VPN_Manager_list_connections (NM_VPN_MANAGER_GET_PRIVATE (manager)->manager_proxy,
														 &array, &err)) {
		g_warning ("Error in getting VPN connections: %s", err->message);
		g_error_free (err);
		return NULL;
	}

	dbus_connection = nm_object_get_connection (NM_OBJECT (manager));

	for (i = 0; i < array->len; i++)
		list = g_slist_prepend (list, nm_vpn_connection_new (dbus_connection, (char *) g_ptr_array_index (array, i)));

	return list;
}

/*****************************************************************************/

static void
nm_vpn_manager_init (NMVPNManager *manager)
{
}

static GObject*
constructor (GType type,
		   guint n_construct_params,
		   GObjectConstructParam *construct_params)
{
	NMObject *object;

	object = (NMObject *) G_OBJECT_CLASS (nm_vpn_manager_parent_class)->constructor (type,
																	 n_construct_params,
																	 construct_params);
	if (!object)
		return NULL;

	NM_VPN_MANAGER_GET_PRIVATE (object)->manager_proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (object),
																	NM_DBUS_SERVICE,
																	nm_object_get_path (object),
																	NM_DBUS_INTERFACE_VPN);
	return G_OBJECT (object);
}

static void
finalize (GObject *object)
{
	g_object_unref (NM_VPN_MANAGER_GET_PRIVATE (object)->manager_proxy);
}

static void
nm_vpn_manager_class_init (NMVPNManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);

	g_type_class_add_private (manager_class, sizeof (NMVPNManagerPrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->finalize = finalize;
}
