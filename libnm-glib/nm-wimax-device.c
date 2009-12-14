/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2009 Novell, Inc.
 */

#include <string.h>

#include "nm-wimax-device.h"
#include "nm-object-private.h"
#include "nm-object-cache.h"
#include "nm-dbus-glib-types.h"
#include "nm-types-private.h"

#include "nm-wimax-device-bindings.h"

G_DEFINE_TYPE (NMWimaxDevice, nm_wimax_device, NM_TYPE_DEVICE)

#define NM_WIMAX_DEVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_WIMAX_DEVICE, NMWimaxDevicePrivate))

static gboolean demarshal_active_nsp (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field);

void _nm_wimax_device_set_wireless_enabled (NMWimaxDevice *wimax, gboolean enabled);

typedef struct {
	gboolean disposed;
	DBusGProxy *proxy;

	char *hw_address;
	NMWimaxNsp *active_nsp;
	gboolean null_active_nsp;
	GPtrArray *nsps;
} NMWimaxDevicePrivate;

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_ACTIVE_NSP,

	LAST_PROP
};

#define DBUS_PROP_HW_ADDRESS "HwAddress"
#define DBUS_PROP_ACTIVE_NSP "ActiveNsp"

enum {
	NSP_ADDED,
	NSP_REMOVED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

/**
 * nm_wimax_device_new:
 * @connection: the #DBusGConnection
 * @path: the DBus object path of the wimax
 *
 * Creates a new #NMWimaxDevice.
 *
 * Returns: a new wimax
 **/
GObject *
nm_wimax_device_new (DBusGConnection *connection, const char *path)
{
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return g_object_new (NM_TYPE_WIMAX_DEVICE,
	                     NM_OBJECT_DBUS_CONNECTION, connection,
	                     NM_OBJECT_DBUS_PATH, path,
	                     NULL);
}

/**
 * nm_wimax_device_get_hw_address:
 * @device: a #NMWimaxDevice
 *
 * Gets the hardware (MAC) address of the #NMWimaxDevice
 *
 * Returns: the hardware address. This is the internal string used by the
 * device, and must not be modified.
 **/
const char *
nm_wimax_device_get_hw_address (NMWimaxDevice *wimax)
{
	NMWimaxDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_WIMAX_DEVICE (wimax), NULL);

	priv = NM_WIMAX_DEVICE_GET_PRIVATE (wimax);
	if (!priv->hw_address) {
		priv->hw_address = _nm_object_get_string_property (NM_OBJECT (wimax),
														   NM_DBUS_INTERFACE_WIMAX_DEVICE,
														   DBUS_PROP_HW_ADDRESS);
	}

	return priv->hw_address;
}

/**
 * nm_wimax_device_get_active_nsp:
 * @wimax: a #NMWimaxDevice
 *
 * Gets the active #NMWimaxNsp.
 *
 * Returns: the access point or %NULL if none is active
 **/
NMWimaxNsp *
nm_wimax_device_get_active_nsp (NMWimaxDevice *wimax)
{
	NMWimaxDevicePrivate *priv;
	NMDeviceState state;
	char *path;
	GValue value = { 0, };

	g_return_val_if_fail (NM_IS_WIMAX_DEVICE (wimax), NULL);

	state = nm_device_get_state (NM_DEVICE (wimax));
	switch (state) {
	case NM_DEVICE_STATE_PREPARE:
	case NM_DEVICE_STATE_CONFIG:
	case NM_DEVICE_STATE_NEED_AUTH:
	case NM_DEVICE_STATE_IP_CONFIG:
	case NM_DEVICE_STATE_ACTIVATED:
		break;
	default:
		return NULL;
		break;
	}

	priv = NM_WIMAX_DEVICE_GET_PRIVATE (wimax);
	if (priv->active_nsp)
		return priv->active_nsp;
	if (priv->null_active_nsp)
		return NULL;

	path = _nm_object_get_object_path_property (NM_OBJECT (wimax),
												NM_DBUS_INTERFACE_WIMAX_DEVICE,
												DBUS_PROP_ACTIVE_NSP);
	if (path) {
		g_value_init (&value, DBUS_TYPE_G_OBJECT_PATH);
		g_value_take_boxed (&value, path);
		demarshal_active_nsp (NM_OBJECT (wimax), NULL, &value, &priv->active_nsp);
		g_value_unset (&value);
	}

	return priv->active_nsp;
}

/**
 * nm_wimax_device_get_nsps:
 * @wimax: a #NMWimaxDevice
 *
 * Gets all the scanned NSPs of the #NMWimaxDevice.
 *
 * Returns: a #GPtrArray containing all the scanned #NMWimaxNsp<!-- -->s.
 * The returned array is owned by the client and should not be modified.
 **/
const GPtrArray *
nm_wimax_device_get_nsps (NMWimaxDevice *wimax)
{
	NMWimaxDevicePrivate *priv;
	DBusGConnection *connection;
	GValue value = { 0, };
	GError *error = NULL;
	GPtrArray *temp;

	g_return_val_if_fail (NM_IS_WIMAX_DEVICE (wimax), NULL);

	priv = NM_WIMAX_DEVICE_GET_PRIVATE (wimax);
	if (priv->nsps)
		return handle_ptr_array_return (priv->nsps);

	if (!org_freedesktop_NetworkManager_Device_WiMax_get_nsp_list (priv->proxy, &temp, &error)) {
		g_warning ("%s: error getting NSPs: %s", __func__, error->message);
		g_error_free (error);
		return NULL;
	}

	g_value_init (&value, DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH);
	g_value_take_boxed (&value, temp);
	connection = nm_object_get_connection (NM_OBJECT (wimax));
	_nm_object_array_demarshal (&value, &priv->nsps, connection, nm_wimax_nsp_new);
	g_value_unset (&value);

	return handle_ptr_array_return (priv->nsps);
}

/**
 * nm_wimax_device_get_nsp_by_path:
 * @wimax: a #NMWimaxDevice
 * @path: the object path of the NSP
 *
 * Gets a #NMWimaxNsp by path.
 *
 * Returns: the access point or %NULL if none is found.
 **/
NMWimaxNsp *
nm_wimax_device_get_nsp_by_path (NMWimaxDevice *wimax,
								 const char *path)
{
	const GPtrArray *nsps;
	int i;
	NMWimaxNsp *nsp = NULL;

	g_return_val_if_fail (NM_IS_WIMAX_DEVICE (wimax), NULL);
	g_return_val_if_fail (path != NULL, NULL);

	nsps = nm_wimax_device_get_nsps (wimax);
	if (!nsps)
		return NULL;

	for (i = 0; i < nsps->len; i++) {
		NMWimaxNsp *candidate = g_ptr_array_index (nsps, i);
		if (!strcmp (nm_object_get_path (NM_OBJECT (candidate)), path)) {
			nsp = candidate;
			break;
		}
	}

	return nsp;
}

static void
nsp_added_proxy (DBusGProxy *proxy, char *path, gpointer user_data)
{
	NMWimaxDevice *self = NM_WIMAX_DEVICE (user_data);
	NMWimaxDevicePrivate *priv;
	GObject *nsp;

	g_return_if_fail (self != NULL);

	nsp = G_OBJECT (nm_wimax_device_get_nsp_by_path (self, path));
	if (!nsp) {
		DBusGConnection *connection = nm_object_get_connection (NM_OBJECT (self));

		priv = NM_WIMAX_DEVICE_GET_PRIVATE (self);
		nsp = G_OBJECT (_nm_object_cache_get (path));
		if (nsp) {
			g_ptr_array_add (priv->nsps, g_object_ref (nsp));
		} else {
			nsp = G_OBJECT (nm_wimax_nsp_new (connection, path));
			if (nsp)
				g_ptr_array_add (priv->nsps, nsp);
		}
	}

	if (nsp)
		g_signal_emit (self, signals[NSP_ADDED], 0, nsp);
}

static void
nsp_removed_proxy (DBusGProxy *proxy, char *path, gpointer user_data)
{
	NMWimaxDevice *self = NM_WIMAX_DEVICE (user_data);
	NMWimaxDevicePrivate *priv = NM_WIMAX_DEVICE_GET_PRIVATE (self);
	NMWimaxNsp *nsp;

	g_return_if_fail (self != NULL);

	nsp = nm_wimax_device_get_nsp_by_path (self, path);
	if (nsp) {
		if (nsp == priv->active_nsp) {
			g_object_unref (priv->active_nsp);
			priv->active_nsp = NULL;
			priv->null_active_nsp = FALSE;

			_nm_object_queue_notify (NM_OBJECT (self), NM_WIMAX_DEVICE_ACTIVE_NSP);
		}

		g_signal_emit (self, signals[NSP_REMOVED], 0, nsp);
		g_ptr_array_remove (priv->nsps, nsp);
		g_object_unref (G_OBJECT (nsp));
	}
}

static void
clean_up_nsps (NMWimaxDevice *self, gboolean notify)
{
	NMWimaxDevicePrivate *priv;

	g_return_if_fail (NM_IS_WIMAX_DEVICE (self));

	priv = NM_WIMAX_DEVICE_GET_PRIVATE (self);

	if (priv->active_nsp) {
		g_object_unref (priv->active_nsp);
		priv->active_nsp = NULL;
	}

	if (priv->nsps) {
		while (priv->nsps->len) {
			NMWimaxNsp *nsp = NM_WIMAX_NSP (g_ptr_array_index (priv->nsps, 0));

			if (notify)
				g_signal_emit (self, signals[NSP_REMOVED], 0, nsp);
			g_ptr_array_remove (priv->nsps, nsp);
			g_object_unref (nsp);
		}
		g_ptr_array_free (priv->nsps, TRUE);
		priv->nsps = NULL;
	}
}

/**************************************************************/

static void
nm_wimax_device_init (NMWimaxDevice *wimax)
{
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMWimaxDevice *self = NM_WIMAX_DEVICE (object);

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_set_string (value, nm_wimax_device_get_hw_address (self));
		break;
	case PROP_ACTIVE_NSP:
		g_value_set_object (value, nm_wimax_device_get_active_nsp (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
state_changed_cb (NMDevice *device, GParamSpec *pspec, gpointer user_data)
{
	NMWimaxDevice *self = NM_WIMAX_DEVICE (device);
	NMWimaxDevicePrivate *priv = NM_WIMAX_DEVICE_GET_PRIVATE (self);

	switch (nm_device_get_state (device)) {
	case NM_DEVICE_STATE_UNKNOWN:
	case NM_DEVICE_STATE_UNMANAGED:
	case NM_DEVICE_STATE_UNAVAILABLE:
	case NM_DEVICE_STATE_DISCONNECTED:
	case NM_DEVICE_STATE_FAILED:
		if (priv->active_nsp) {
			g_object_unref (priv->active_nsp);
			priv->active_nsp = NULL;
			priv->null_active_nsp = FALSE;
		}
		_nm_object_queue_notify (NM_OBJECT (device), NM_WIMAX_DEVICE_ACTIVE_NSP);
		break;
	default:
		break;
	}
}

static gboolean
demarshal_active_nsp (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	NMWimaxDevicePrivate *priv = NM_WIMAX_DEVICE_GET_PRIVATE (object);
	const char *path;
	NMWimaxNsp *nsp = NULL;
	DBusGConnection *connection;

	if (!G_VALUE_HOLDS (value, DBUS_TYPE_G_OBJECT_PATH))
		return FALSE;

	priv->null_active_nsp = FALSE;

	path = g_value_get_boxed (value);
	if (path) {
		if (!strcmp (path, "/"))
			priv->null_active_nsp = TRUE;
		else {
			nsp = NM_WIMAX_NSP (_nm_object_cache_get (path));
			if (nsp)
				nsp = g_object_ref (nsp);
			else {
				connection = nm_object_get_connection (object);
				nsp = NM_WIMAX_NSP (nm_wimax_nsp_new (connection, path));
			}
		}
	}

	if (priv->active_nsp) {
		g_object_unref (priv->active_nsp);
		priv->active_nsp = NULL;
	}

	if (nsp)
		priv->active_nsp = nsp;

	_nm_object_queue_notify (object, NM_WIMAX_DEVICE_ACTIVE_NSP);
	return TRUE;
}

static void
register_for_property_changed (NMWimaxDevice *wimax)
{
	NMWimaxDevicePrivate *priv = NM_WIMAX_DEVICE_GET_PRIVATE (wimax);
	const NMPropertiesChangedInfo property_changed_info[] = {
		{ NM_WIMAX_DEVICE_HW_ADDRESS, _nm_object_demarshal_generic, &priv->hw_address },
		{ NM_WIMAX_DEVICE_ACTIVE_NSP, demarshal_active_nsp, &priv->active_nsp },
		{ NULL },
	};

	_nm_object_handle_properties_changed (NM_OBJECT (wimax),
										  priv->proxy,
										  property_changed_info);
}

static GObject*
constructor (GType type,
		   guint n_construct_params,
		   GObjectConstructParam *construct_params)
{
	GObject *object;
	NMWimaxDevicePrivate *priv;

	object = G_OBJECT_CLASS (nm_wimax_device_parent_class)->constructor (type,
																		 n_construct_params,
																		 construct_params);
	if (!object)
		return NULL;

	priv = NM_WIMAX_DEVICE_GET_PRIVATE (object);

	priv->proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (NM_OBJECT (object)),
											 NM_DBUS_SERVICE,
											 nm_object_get_path (NM_OBJECT (object)),
											 NM_DBUS_INTERFACE_WIMAX_DEVICE);

	dbus_g_proxy_add_signal (priv->proxy, "NspAdded",
	                         DBUS_TYPE_G_OBJECT_PATH,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "NspAdded",
								 G_CALLBACK (nsp_added_proxy),
								 object, NULL);

	dbus_g_proxy_add_signal (priv->proxy, "NspRemoved",
	                         DBUS_TYPE_G_OBJECT_PATH,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "NspRemoved",
								 G_CALLBACK (nsp_removed_proxy),
								 object, NULL);

	register_for_property_changed (NM_WIMAX_DEVICE (object));

	g_signal_connect (object,
	                  "notify::" NM_DEVICE_STATE,
	                  G_CALLBACK (state_changed_cb),
	                  NULL);

	return object;
}

static void
dispose (GObject *object)
{
	NMWimaxDevicePrivate *priv = NM_WIMAX_DEVICE_GET_PRIVATE (object);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_wimax_device_parent_class)->dispose (object);
		return;
	}

	priv->disposed = TRUE;

	clean_up_nsps (NM_WIMAX_DEVICE (object), FALSE);
	g_object_unref (priv->proxy);

	G_OBJECT_CLASS (nm_wimax_device_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMWimaxDevicePrivate *priv = NM_WIMAX_DEVICE_GET_PRIVATE (object);

	if (priv->hw_address)
		g_free (priv->hw_address);

	G_OBJECT_CLASS (nm_wimax_device_parent_class)->finalize (object);
}

static void
nm_wimax_device_class_init (NMWimaxDeviceClass *wimax_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (wimax_class);

	g_type_class_add_private (wimax_class, sizeof (NMWimaxDevicePrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* properties */

	/**
	 * NMWimaxDevice:active-nsp:
	 *
	 * The active #NMWimaxNsp of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_ACTIVE_NSP,
		 g_param_spec_object (NM_WIMAX_DEVICE_ACTIVE_NSP,
							  "Active NSP",
							  "Active NSP",
							  NM_TYPE_WIMAX_NSP,
							  G_PARAM_READABLE));

	/* signals */

	/**
	 * NMWimaxDevice::nsp-added:
	 * @self: the wimax device that received the signal
	 * @nsp: the new NSP
	 *
	 * Notifies that a #NMWimaxNsp is added to the wimax device.
	 **/
	signals[NSP_ADDED] =
		g_signal_new ("nsp-added",
				    G_OBJECT_CLASS_TYPE (object_class),
				    G_SIGNAL_RUN_FIRST,
				    G_STRUCT_OFFSET (NMWimaxDeviceClass, nsp_added),
				    NULL, NULL,
				    g_cclosure_marshal_VOID__OBJECT,
				    G_TYPE_NONE, 1,
				    G_TYPE_OBJECT);

	/**
	 * NMWimaxDevice::nsp-removed:
	 * @self: the wimax device that received the signal
	 * @nsp: the removed NSP
	 *
	 * Notifies that a #NMWimaxNsp is removed from the wimax device.
	 **/
	signals[NSP_REMOVED] =
		g_signal_new ("nsp-removed",
				    G_OBJECT_CLASS_TYPE (object_class),
				    G_SIGNAL_RUN_FIRST,
				    G_STRUCT_OFFSET (NMWimaxDeviceClass, nsp_removed),
				    NULL, NULL,
				    g_cclosure_marshal_VOID__OBJECT,
				    G_TYPE_NONE, 1,
				    G_TYPE_OBJECT);
}
