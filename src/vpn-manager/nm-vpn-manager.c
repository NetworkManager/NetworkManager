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
 * Copyright (C) 2005 - 2008 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include <string.h>

#include "nm-vpn-manager.h"
#include "nm-vpn-service.h"
#include "nm-vpn-connection.h"
#include "nm-setting-vpn.h"
#include "nm-dbus-manager.h"
#include "NetworkManagerVPN.h"
#include "nm-marshal.h"

G_DEFINE_TYPE (NMVPNManager, nm_vpn_manager, G_TYPE_OBJECT)

#define NM_VPN_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_VPN_MANAGER, NMVPNManagerPrivate))

typedef struct {
	GSList *services;
} NMVPNManagerPrivate;

enum {
	CONNECTION_ACTIVATED,
	CONNECTION_DEACTIVATED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

GQuark
nm_vpn_manager_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-vpn-manager-error");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_vpn_manager_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* The base device for the VPN connection is not active. */
			ENUM_ENTRY (NM_VPN_MANAGER_ERROR_DEVICE_NOT_ACTIVE, "BaseDeviceNotActive"),
			/* The requested VPN connection was invalid. */
			ENUM_ENTRY (NM_VPN_MANAGER_ERROR_CONNECTION_INVALID, "ConnectionInvalid"),
			/* The VPN service required by this VPN connection did not exist or was invalid. */
			ENUM_ENTRY (NM_VPN_MANAGER_ERROR_SERVICE_INVALID, "ServiceInvalid"),
			/* The VPN service required by this VPN connection could not be started. */
			ENUM_ENTRY (NM_VPN_MANAGER_ERROR_SERVICE_START_FAILED, "ServiceStartFailed"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMVPNManagerError", values);
	}
	return etype;
}



static NMVPNService *
nm_vpn_manager_get_service (NMVPNManager *manager, const char *service_name)
{
	GSList *iter;

	for (iter = NM_VPN_MANAGER_GET_PRIVATE (manager)->services; iter; iter = iter->next) {
		NMVPNService *service = NM_VPN_SERVICE (iter->data);

		if (!strcmp (service_name, nm_vpn_service_get_name (service)))
			return g_object_ref (service);
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

static NMVPNConnection *
find_active_vpn_connection_by_connection (NMVPNManager *manager, NMConnection *connection)
{
	NMVPNManagerPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_VPN_MANAGER (manager), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	priv = NM_VPN_MANAGER_GET_PRIVATE (manager);
	for (iter = priv->services; iter; iter = g_slist_next (iter)) {
		GSList *connections, *elt;

		connections = nm_vpn_service_get_active_connections (NM_VPN_SERVICE (iter->data));
		for (elt = connections; elt; elt = g_slist_next (elt)) {
			NMVPNConnection *vpn = NM_VPN_CONNECTION (elt->data);

			if (nm_vpn_connection_get_connection (vpn) == connection)
				return vpn;
		}
	}
	return NULL;
}

static void
connection_vpn_state_changed (NMVPNConnection *connection,
                              NMVPNConnectionState state,
                              NMVPNConnectionStateReason reason,
                              gpointer user_data)
{
	NMVPNManager *manager = NM_VPN_MANAGER (user_data);

	switch (state) {
	case NM_VPN_CONNECTION_STATE_ACTIVATED:
		g_signal_emit (manager, signals[CONNECTION_ACTIVATED], 0, connection);
		break;
	case NM_VPN_CONNECTION_STATE_FAILED:
	case NM_VPN_CONNECTION_STATE_DISCONNECTED:
		g_signal_emit (manager, signals[CONNECTION_DEACTIVATED], 0, connection, state, reason);
		break;
	default:
		break;
	}
}

NMVPNConnection *
nm_vpn_manager_activate_connection (NMVPNManager *manager,
                                    NMConnection *connection,
                                    NMActRequest *act_request,
                                    NMDevice *device,
                                    GError **error)
{
	NMSettingVPN *vpn_setting;
	NMVPNService *service;
	NMVPNConnection *vpn = NULL;
	const char *service_type;

	g_return_val_if_fail (NM_IS_VPN_MANAGER (manager), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (NM_IS_ACT_REQUEST (act_request), NULL);
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);
	g_return_val_if_fail (error != NULL, NULL);
	g_return_val_if_fail (*error == NULL, NULL);

	if (nm_device_get_state (device) != NM_DEVICE_STATE_ACTIVATED) {
		g_set_error (error,
		             NM_VPN_MANAGER_ERROR, NM_VPN_MANAGER_ERROR_DEVICE_NOT_ACTIVE,
		             "%s", "The base device for the VPN connection was not active.");
		return NULL;
	}

	vpn_setting = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	if (!vpn_setting) {
		g_set_error (error,
		             NM_VPN_MANAGER_ERROR, NM_VPN_MANAGER_ERROR_CONNECTION_INVALID,
		             "%s", "The connection was not a VPN connection.");
		return NULL;
	}

	vpn = find_active_vpn_connection_by_connection (manager, connection);
	if (vpn) {
		nm_vpn_connection_disconnect (vpn, NM_VPN_CONNECTION_STATE_REASON_USER_DISCONNECTED);
		vpn = NULL;
	}

	service_type = nm_setting_vpn_get_service_type (vpn_setting);
	service = nm_vpn_manager_get_service (manager, service_type);
	if (!service) {
		service = nm_vpn_service_new (service_type);
		if (service)
			nm_vpn_manager_add_service (manager, service);
	}

	if (service) {
		vpn = nm_vpn_service_activate (service, connection, act_request, device, error);
		if (vpn) {
			g_signal_connect (vpn, "vpn-state-changed",
			                  G_CALLBACK (connection_vpn_state_changed),
			                  manager);
		}
	} else {
		g_set_error (error,
		             NM_VPN_MANAGER_ERROR, NM_VPN_MANAGER_ERROR_SERVICE_INVALID,
		             "%s", "The VPN service was invalid.");
	}

	return vpn;
}

gboolean
nm_vpn_manager_deactivate_connection (NMVPNManager *manager,
                                      const char *path,
                                      NMVPNConnectionStateReason reason)
{
	NMVPNManagerPrivate *priv;
	GSList *iter;
	gboolean found = FALSE;

	g_return_val_if_fail (NM_IS_VPN_MANAGER (manager), FALSE);
	g_return_val_if_fail (path != NULL, FALSE);

	priv = NM_VPN_MANAGER_GET_PRIVATE (manager);
	for (iter = priv->services; iter; iter = g_slist_next (iter)) {
		GSList *connections, *elt;

		connections = nm_vpn_service_get_active_connections (NM_VPN_SERVICE (iter->data));
		for (elt = connections; elt; elt = g_slist_next (elt)) {
			NMVPNConnection *vpn = NM_VPN_CONNECTION (elt->data);
			const char *vpn_path;

			vpn_path = nm_vpn_connection_get_active_connection_path (vpn);
			if (!strcmp (path, vpn_path)) {
				nm_vpn_connection_disconnect (vpn, reason);
				found = TRUE;
			}
		}
	}

	return found ? TRUE : FALSE;
}

void
nm_vpn_manager_add_active_connections (NMVPNManager *manager,
                                       NMConnection *filter,
                                       GPtrArray *array)
{
	NMVPNManagerPrivate *priv;
	GSList *iter;

	g_return_if_fail (NM_IS_VPN_MANAGER (manager));
	g_return_if_fail (array != NULL);

	priv = NM_VPN_MANAGER_GET_PRIVATE (manager);
	for (iter = priv->services; iter; iter = g_slist_next (iter)) {
		GSList *active, *elt;

		active = nm_vpn_service_get_active_connections (NM_VPN_SERVICE (iter->data));
		for (elt = active; elt; elt = g_slist_next (elt)) {
			NMVPNConnection *vpn = NM_VPN_CONNECTION (elt->data);
			const char *path;

			if (!filter || (nm_vpn_connection_get_connection (vpn) == filter)) {
				path = nm_vpn_connection_get_active_connection_path (vpn);
				g_ptr_array_add (array, g_strdup (path));
			}
		}
	}
}

GSList *
nm_vpn_manager_get_active_connections (NMVPNManager *manager)
{
	NMVPNManagerPrivate *priv;
	GSList *iter;
	GSList *list = NULL;

	g_return_val_if_fail (NM_IS_VPN_MANAGER (manager), NULL);

	priv = NM_VPN_MANAGER_GET_PRIVATE (manager);
	for (iter = priv->services; iter; iter = g_slist_next (iter)) {
		GSList *active, *elt;

		active = nm_vpn_service_get_active_connections (NM_VPN_SERVICE (iter->data));
		for (elt = active; elt; elt = g_slist_next (elt))
			list = g_slist_append (list, g_object_ref (NM_VPN_CONNECTION (elt->data)));
	}

	return list;
}

NMConnection *
nm_vpn_manager_get_connection_for_active (NMVPNManager *manager,
                                          const char *active_path)
{
	NMVPNManagerPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_VPN_MANAGER (manager), NULL);

	priv = NM_VPN_MANAGER_GET_PRIVATE (manager);
	for (iter = priv->services; iter; iter = g_slist_next (iter)) {
		GSList *active, *elt;

		active = nm_vpn_service_get_active_connections (NM_VPN_SERVICE (iter->data));
		for (elt = active; elt; elt = g_slist_next (elt)) {
			NMVPNConnection *candidate = NM_VPN_CONNECTION (elt->data);
			const char *ac_path;

			ac_path = nm_vpn_connection_get_active_connection_path (candidate);
			if (ac_path && !strcmp (ac_path, active_path))
				return nm_vpn_connection_get_connection (candidate);
		}
	}

	return NULL;
}

NMVPNManager *
nm_vpn_manager_get (void)
{
	static NMVPNManager *singleton = NULL;

	if (!singleton)
		singleton = NM_VPN_MANAGER (g_object_new (NM_TYPE_VPN_MANAGER, NULL));
	else
		g_object_ref (singleton);

	g_assert (singleton);
	return singleton;
}

/******************************************************************************/

static void
nm_vpn_manager_init (NMVPNManager *manager)
{
}

static void
finalize (GObject *object)
{
	NMVPNManagerPrivate *priv = NM_VPN_MANAGER_GET_PRIVATE (object);

	g_slist_foreach (priv->services, (GFunc) g_object_unref, NULL);

	G_OBJECT_CLASS (nm_vpn_manager_parent_class)->finalize (object);
}

static void
nm_vpn_manager_class_init (NMVPNManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);

	g_type_class_add_private (manager_class, sizeof (NMVPNManagerPrivate));

	/* virtual methods */
	object_class->finalize = finalize;

	/* signals */
	signals[CONNECTION_ACTIVATED] =
		g_signal_new ("connection-activated",
				    G_OBJECT_CLASS_TYPE (object_class),
				    G_SIGNAL_RUN_FIRST,
				    0, NULL, NULL,
				    g_cclosure_marshal_VOID__OBJECT,
				    G_TYPE_NONE, 1, G_TYPE_OBJECT);

	signals[CONNECTION_DEACTIVATED] =
		g_signal_new ("connection-deactivated",
				    G_OBJECT_CLASS_TYPE (object_class),
				    G_SIGNAL_RUN_FIRST,
				    G_STRUCT_OFFSET (NMVPNManagerClass, connection_deactivated),
				    NULL, NULL,
				    _nm_marshal_VOID__OBJECT_UINT_UINT,
				    G_TYPE_NONE, 3,
				    G_TYPE_OBJECT, G_TYPE_UINT, G_TYPE_UINT);

	dbus_g_error_domain_register (NM_VPN_MANAGER_ERROR, NULL, NM_TYPE_VPN_MANAGER_ERROR);
}

