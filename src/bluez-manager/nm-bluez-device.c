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
 * Copyright (C) 2009 - 2012 Red Hat, Inc.
 * Copyright (C) 2013 Intel Corporation.
 */

#include <glib.h>
#include <glib/gi18n.h>
#include <gio/gio.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

#include "NetworkManager.h"
#include "nm-setting-bluetooth.h"

#include "nm-bluez-common.h"
#if ! WITH_BLUEZ5
#include "nm-dbus-manager.h"
#include "nm-dbus-glib-types.h"
#endif
#include "nm-bluez-device.h"
#include "nm-logging.h"
#include "nm-utils.h"


G_DEFINE_TYPE (NMBluezDevice, nm_bluez_device, G_TYPE_OBJECT)

#define NM_BLUEZ_DEVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_BLUEZ_DEVICE, NMBluezDevicePrivate))

typedef struct {
	char *path;
#if WITH_BLUEZ5
	GDBusProxy *proxy5;
	GDBusProxy *adapter;
	GDBusConnection *dbus_connection;
#else
	DBusGProxy *proxy4;
	DBusGProxy *connection_proxy;
#endif

	gboolean initialized;
	gboolean usable;
	NMBluetoothCapabilities connection_bt_type;

	char *address;
	guint8 bin_address[ETH_ALEN];
	char *name;
	guint32 capabilities;
	gint rssi;
	gboolean connected;

	char *bt_iface;

	NMConnectionProvider *provider;
	GSList *connections;

	NMConnection *pan_connection;
	gboolean pan_connection_no_autocreate;
} NMBluezDevicePrivate;


enum {
	PROP_0,
	PROP_PATH,
	PROP_ADDRESS,
	PROP_NAME,
	PROP_CAPABILITIES,
	PROP_RSSI,
	PROP_USABLE,
	PROP_CONNECTED,

	LAST_PROP
};

/* Signals */
enum {
	INITIALIZED,
	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };


static void cp_connection_added (NMConnectionProvider *provider,
                                 NMConnection *connection, NMBluezDevice *self);


/***********************************************************/

const char *
nm_bluez_device_get_path (NMBluezDevice *self)
{
	g_return_val_if_fail (NM_IS_BLUEZ_DEVICE (self), NULL);

	return NM_BLUEZ_DEVICE_GET_PRIVATE (self)->path;
}

const char *
nm_bluez_device_get_address (NMBluezDevice *self)
{
	g_return_val_if_fail (NM_IS_BLUEZ_DEVICE (self), NULL);

	return NM_BLUEZ_DEVICE_GET_PRIVATE (self)->address;
}

gboolean
nm_bluez_device_get_initialized (NMBluezDevice *self)
{
	g_return_val_if_fail (NM_IS_BLUEZ_DEVICE (self), FALSE);

	return NM_BLUEZ_DEVICE_GET_PRIVATE (self)->initialized;
}

gboolean
nm_bluez_device_get_usable (NMBluezDevice *self)
{
	g_return_val_if_fail (NM_IS_BLUEZ_DEVICE (self), FALSE);

	return NM_BLUEZ_DEVICE_GET_PRIVATE (self)->usable;
}

const char *
nm_bluez_device_get_name (NMBluezDevice *self)
{
	g_return_val_if_fail (NM_IS_BLUEZ_DEVICE (self), NULL);

	return NM_BLUEZ_DEVICE_GET_PRIVATE (self)->name;
}

guint32
nm_bluez_device_get_capabilities (NMBluezDevice *self)
{
	g_return_val_if_fail (NM_IS_BLUEZ_DEVICE (self), 0);

	return NM_BLUEZ_DEVICE_GET_PRIVATE (self)->capabilities;
}

gint
nm_bluez_device_get_rssi (NMBluezDevice *self)
{
	g_return_val_if_fail (NM_IS_BLUEZ_DEVICE (self), 0);

	return NM_BLUEZ_DEVICE_GET_PRIVATE (self)->rssi;
}

gboolean
nm_bluez_device_get_connected (NMBluezDevice *self)
{
	g_return_val_if_fail (NM_IS_BLUEZ_DEVICE (self), FALSE);

	return NM_BLUEZ_DEVICE_GET_PRIVATE (self)->connected;
}

static void
pan_connection_check_create (NMBluezDevice *self)
{
	NMConnection *connection;
	NMConnection *added;
	NMSetting *setting;
	char *uuid, *id;
	GByteArray *bdaddr_array;
	GError *error = NULL;
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);

	g_return_if_fail (priv->capabilities & NM_BT_CAPABILITY_NAP);
	g_return_if_fail (priv->connections == NULL);
	g_return_if_fail (priv->name);

	if (priv->pan_connection || priv->pan_connection_no_autocreate) {
		/* already have a connection or we don't want to create one, nothing to do. */
		return;
	}

	if (!nm_connection_provider_has_connections_loaded (priv->provider)) {
		/* do not try to create any connections until the connection provider is ready. */
		return;
	}

	/* Only try once to create a connection. If it does not succeed, we do not try again. Also,
	 * if the connection gets deleted later, do not create another one for this device. */
	priv->pan_connection_no_autocreate = TRUE;

	/* create a new connection */

	connection = nm_connection_new ();

	/* Setting: Connection */
	uuid = nm_utils_uuid_generate ();
	id = g_strdup_printf (_("%s Network"), priv->name);
	setting = nm_setting_connection_new ();
	g_object_set (setting,
	              NM_SETTING_CONNECTION_ID, id,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_BLUETOOTH_SETTING_NAME,
	              NULL);
	nm_connection_add_setting (connection, setting);

	/* Setting: Bluetooth */
	bdaddr_array = g_byte_array_sized_new (sizeof (priv->bin_address));
	g_byte_array_append (bdaddr_array, priv->bin_address, sizeof (priv->bin_address));
	setting = nm_setting_bluetooth_new ();
	g_object_set (G_OBJECT (setting),
	              NM_SETTING_BLUETOOTH_BDADDR, bdaddr_array,
	              NM_SETTING_BLUETOOTH_TYPE, NM_SETTING_BLUETOOTH_TYPE_PANU,
	              NULL);
	nm_connection_add_setting (connection, setting);
	g_byte_array_free (bdaddr_array, TRUE);

	/* Setting: IPv4 */
	setting = nm_setting_ip4_config_new ();
	g_object_set (G_OBJECT (setting),
	              NM_SETTING_IP4_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP4_CONFIG_MAY_FAIL, FALSE,
	              NULL);
	nm_connection_add_setting (connection, setting);

	/* Setting: IPv6 */
	setting = nm_setting_ip6_config_new ();
	g_object_set (G_OBJECT (setting),
	              NM_SETTING_IP6_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP6_CONFIG_MAY_FAIL, TRUE,
	              NULL);
	nm_connection_add_setting (connection, setting);

	/* Adding a new connection raises a signal which eventually calls check_emit_usable (again)
	 * which then already finds the suitable connection in priv->connections. This is confusing,
	 * so block the signal. check_emit_usable will succeed after this function call returns. */
	g_signal_handlers_block_by_func (priv->provider, cp_connection_added, self);
	added = nm_connection_provider_add_connection (priv->provider, connection, FALSE, &error);
	g_signal_handlers_unblock_by_func (priv->provider, cp_connection_added, self);

	if (added) {
		g_assert (g_slist_find (priv->connections, added));

		priv->pan_connection = added;
		nm_log_dbg (LOGD_SETTINGS, "added new Bluetooth connection for NAP device '%s': '%s' (%s)", priv->path, id, uuid);
	} else {
		nm_log_warn (LOGD_SETTINGS, "couldn't add new Bluetooth connection for NAP device '%s': '%s' (%s): %d / %s",
		             priv->path, id, uuid, error ? error->code : -1,
		             (error && error->message) ? error->message : "(unknown)");
		g_clear_error (&error);
	}

	g_object_unref (connection);
	g_free (id);
	g_free (uuid);
}

static void
check_emit_usable (NMBluezDevice *self)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	gboolean new_usable;

	new_usable = (priv->initialized && priv->capabilities && priv->name &&
#if WITH_BLUEZ5
	              priv->adapter && priv->dbus_connection &&
	              (priv->capabilities & NM_BT_CAPABILITY_NAP) && /* BlueZ5 is only usable with NAP devices */
#endif
	              priv->address);

	if (!new_usable)
		goto END;

	if (priv->connections)
		goto END;

	if (!(priv->capabilities & NM_BT_CAPABILITY_NAP)) {
		/* non NAP devices are only usable, if they already have a connection. */
		new_usable = FALSE;
		goto END;
	}

	pan_connection_check_create (self);
	new_usable = !!priv->pan_connection;

END:
	if (new_usable != priv->usable) {
		priv->usable = new_usable;
		g_object_notify (G_OBJECT (self), NM_BLUEZ_DEVICE_USABLE);
	}
}

/********************************************************************/

static gboolean
connection_compatible (NMBluezDevice *self, NMConnection *connection)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	NMSettingBluetooth *s_bt;
	const char *bt_type;
	const GByteArray *bdaddr;

	if (!nm_connection_is_type (connection, NM_SETTING_BLUETOOTH_SETTING_NAME))
		return FALSE;

	s_bt = nm_connection_get_setting_bluetooth (connection);
	if (!s_bt)
		return FALSE;

	bdaddr = nm_setting_bluetooth_get_bdaddr (s_bt);
	if (!bdaddr || bdaddr->len != ETH_ALEN)
		return FALSE;
	if (memcmp (bdaddr->data, priv->bin_address, ETH_ALEN) != 0)
		return FALSE;

	bt_type = nm_setting_bluetooth_get_connection_type (s_bt);
	if (   g_str_equal (bt_type, NM_SETTING_BLUETOOTH_TYPE_DUN)
	    && !(priv->capabilities & NM_BT_CAPABILITY_DUN))
		return FALSE;

	if (   g_str_equal (bt_type, NM_SETTING_BLUETOOTH_TYPE_PANU)
	    && !(priv->capabilities & NM_BT_CAPABILITY_NAP))
		return FALSE;

	return TRUE;
}

static void
_internal_add_connection (NMBluezDevice *self, NMConnection *connection)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);

	if (!g_slist_find (priv->connections, connection)) {
		priv->connections = g_slist_prepend (priv->connections, g_object_ref (connection));
		check_emit_usable (self);
	}
}

static void
cp_connection_added (NMConnectionProvider *provider,
                     NMConnection *connection,
                     NMBluezDevice *self)
{
	if (connection_compatible (self, connection))
		_internal_add_connection (self, connection);
}

static void
cp_connection_removed (NMConnectionProvider *provider,
                       NMConnection *connection,
                       NMBluezDevice *self)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);

	if (g_slist_find (priv->connections, connection)) {
		priv->connections = g_slist_remove (priv->connections, connection);
		if (priv->pan_connection == connection) {
			priv->pan_connection = NULL;
		}
		g_object_unref (connection);
		check_emit_usable (self);
	}
}

static void
cp_connection_updated (NMConnectionProvider *provider,
                       NMConnection *connection,
                       NMBluezDevice *self)
{
	if (connection_compatible (self, connection))
		_internal_add_connection (self, connection);
	else
		cp_connection_removed (provider, connection, self);
}

static void
cp_connections_loaded (NMConnectionProvider *provider, NMBluezDevice *self)
{
	const GSList *connections, *iter;

	connections = nm_connection_provider_get_connections (provider);
	for (iter = connections; iter; iter = g_slist_next (iter))
		cp_connection_added (provider, NM_CONNECTION (iter->data), self);
}

/***********************************************************/

void
nm_bluez_device_disconnect (NMBluezDevice *self)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);

#if WITH_BLUEZ5
	g_return_if_fail (priv->dbus_connection);
	g_return_if_fail (priv->connection_bt_type == NM_BT_CAPABILITY_NAP);

	g_dbus_connection_call (priv->dbus_connection,
	                        BLUEZ_SERVICE,
	                        priv->path,
	                        BLUEZ_NETWORK_INTERFACE,
	                        "Disconnect",
	                        g_variant_new ("()"),
	                        NULL,
	                        G_DBUS_CALL_FLAGS_NONE,
	                        -1,
	                        NULL, NULL, NULL);
#else
	g_return_if_fail (priv->connection_bt_type == NM_BT_CAPABILITY_NAP || priv->connection_bt_type == NM_BT_CAPABILITY_DUN);

	if (!priv->connection_proxy)
		return;

	if (priv->connection_bt_type == NM_BT_CAPABILITY_DUN) {
		/* Don't ever pass NULL through dbus; bt_iface
		 * might happen to be NULL for some reason.
		 */
		if (priv->bt_iface)
			dbus_g_proxy_call_no_reply (priv->connection_proxy, "Disconnect",
			                            G_TYPE_STRING, priv->bt_iface,
			                            G_TYPE_INVALID);
	} else {
		dbus_g_proxy_call_no_reply (priv->connection_proxy, "Disconnect",
		                            G_TYPE_INVALID);
	}

	g_clear_object (&priv->connection_proxy);
#endif
	priv->connection_bt_type = NM_BT_CAPABILITY_NONE;
}

static void
#if WITH_BLUEZ5
bluez_connect_pan_cb (GDBusConnection *dbus_connection,
                      GAsyncResult *res,
                      gpointer user_data)
#else
bluez_connect_cb (DBusGProxy *proxy4,
                  DBusGProxyCall *call_id,
                  gpointer user_data)
#endif
{
	GSimpleAsyncResult *result = G_SIMPLE_ASYNC_RESULT (user_data);
	NMBluezDevice *self = NM_BLUEZ_DEVICE (g_async_result_get_source_object (G_ASYNC_RESULT (result)));
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	GError *error = NULL;
	char *device;

#if WITH_BLUEZ5
	GVariant *variant;

	variant = g_dbus_connection_call_finish (dbus_connection, res, &error);

	if (!variant) {
		g_simple_async_result_take_error (result, error);
	} else {
		g_variant_get (variant, "(s)", &device);

		g_simple_async_result_set_op_res_gpointer (result,
		                                           g_strdup (device),
		                                           g_free);
		priv->bt_iface = device;
		g_variant_unref (variant);
	}
#else
	if (dbus_g_proxy_end_call (proxy4, call_id, &error,
	                           G_TYPE_STRING, &device,
	                           G_TYPE_INVALID) == FALSE)
		g_simple_async_result_take_error (result, error);
	else if (!device || !strlen (device)) {
		g_simple_async_result_set_error (result, G_IO_ERROR, G_IO_ERROR_FAILED,
		                                 "Invalid argument received");
		g_free (device);
	} else {
		g_simple_async_result_set_op_res_gpointer (result,
		                                           g_strdup (device),
		                                           g_free);
		priv->bt_iface = device;
	}
#endif

	g_simple_async_result_complete (result);
	g_object_unref (result);
}

void
nm_bluez_device_connect_async (NMBluezDevice *self,
                               NMBluetoothCapabilities connection_bt_type,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
	GSimpleAsyncResult *simple;
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
#if ! WITH_BLUEZ5
	DBusGConnection *connection;

	connection = nm_dbus_manager_get_connection (nm_dbus_manager_get ());
#endif

#if WITH_BLUEZ5
	g_return_if_fail (connection_bt_type == NM_BT_CAPABILITY_NAP);

	simple = g_simple_async_result_new (G_OBJECT (self),
	                                    callback,
	                                    user_data,
	                                    nm_bluez_device_connect_async);

	/* For PAN we call Connect() on org.bluez.Network1 */
	g_dbus_connection_call (priv->dbus_connection,
	                        BLUEZ_SERVICE,
	                        priv->path,
	                        BLUEZ_NETWORK_INTERFACE,
	                        "Connect",
	                        g_variant_new ("(s)", BLUETOOTH_CONNECT_NAP),
	                        NULL,
	                        G_DBUS_CALL_FLAGS_NONE,
	                        20000,
	                        NULL,
	                        (GAsyncReadyCallback) bluez_connect_pan_cb,
	                        simple);

	priv->connection_bt_type = connection_bt_type;
#else
	g_return_if_fail (connection_bt_type == NM_BT_CAPABILITY_NAP || connection_bt_type == NM_BT_CAPABILITY_DUN);

	if (priv->connection_proxy) {
		g_simple_async_report_error_in_idle (G_OBJECT (self),
		                                     callback,
		                                     user_data,
		                                     G_IO_ERROR,
		                                     G_IO_ERROR_FAILED,
		                                     "Already connected to bluez service");
		return;
	}
	priv->connection_proxy = dbus_g_proxy_new_for_name (connection,
	                                                    BLUEZ_SERVICE,
	                                                    priv->path,
	                                                    connection_bt_type == NM_BT_CAPABILITY_DUN ? BLUEZ_SERIAL_INTERFACE : BLUEZ_NETWORK_INTERFACE);
	if (!priv->connection_proxy) {
		g_simple_async_report_error_in_idle (G_OBJECT (self),
		                                     callback,
		                                     user_data,
		                                     G_IO_ERROR,
		                                     G_IO_ERROR_FAILED,
		                                     "Unable to create proxy");
	} else {
		simple = g_simple_async_result_new (G_OBJECT (self),
		                                    callback,
		                                    user_data,
		                                    nm_bluez_device_connect_async);
		dbus_g_proxy_begin_call_with_timeout (priv->connection_proxy, "Connect",
		                                      bluez_connect_cb,
		                                      simple,
		                                      NULL,
		                                      20000,
		                                      G_TYPE_STRING,
		                                      connection_bt_type == NM_BT_CAPABILITY_DUN ? BLUETOOTH_CONNECT_DUN : BLUETOOTH_CONNECT_NAP,
		                                      G_TYPE_INVALID);
		priv->connection_bt_type = connection_bt_type;
	}
#endif
}

const char *
nm_bluez_device_connect_finish (NMBluezDevice *self,
                                GAsyncResult *result,
                                GError **error)
{
	GSimpleAsyncResult *simple;
	const char *device;

	g_return_val_if_fail (g_simple_async_result_is_valid (result,
	                                                      G_OBJECT (self),
	                                                      nm_bluez_device_connect_async),
	                      NULL);

	simple = (GSimpleAsyncResult *) result;

	if (g_simple_async_result_propagate_error (simple, error))
		return NULL;

	device = (const char *) g_simple_async_result_get_op_res_gpointer (simple);
	return device;
}

/***********************************************************/

static guint32
convert_uuids_to_capabilities (const char **strings)
{
	const char **iter;
	guint32 capabilities = 0;

	for (iter = strings; iter && *iter; iter++) {
		char **parts;

		parts = g_strsplit (*iter, "-", -1);
		if (parts && parts[0]) {
			switch (g_ascii_strtoull (parts[0], NULL, 16)) {
#if ! WITH_BLUEZ5
			case 0x1103:
				capabilities |= NM_BT_CAPABILITY_DUN;
				break;
#endif
			case 0x1116:
				capabilities |= NM_BT_CAPABILITY_NAP;
				break;
			default:
				break;
			}
		}
		g_strfreev (parts);
	}

	return capabilities;
}

#if WITH_BLUEZ5
static void
on_adapter_acquired (GObject *object, GAsyncResult *res, NMBluezDevice *self)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	GError *error;

	priv->adapter = g_dbus_proxy_new_for_bus_finish (res, &error);

	if (!priv->adapter) {
		nm_log_warn (LOGD_BT, "failed to acquire adapter proxy: %s.", error->message);
		g_clear_error (&error);
	} else
		check_emit_usable (self);

	g_object_unref (self);
}

static void
properties_changed (GDBusProxy *proxy5,
                    GVariant *changed_properties,
                    GStrv invalidated_properties,
                    gpointer user_data)
{
	NMBluezDevice *self = NM_BLUEZ_DEVICE (user_data);
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	GVariantIter i;
	const char *property;
	const char *str;
	GVariant *v;
	guint32 uint_val;
	gint int_val;
	const char **strv;

	g_variant_iter_init (&i, changed_properties);
	while (g_variant_iter_next (&i, "{&sv}", &property, &v)) {
		if (!strcmp (property, "Name")) {
			str = g_variant_get_string (v, NULL);
			if (g_strcmp0 (priv->name, str)) {
				g_free (priv->name);
				priv->name = g_strdup (str);
				g_object_notify (G_OBJECT (self), NM_BLUEZ_DEVICE_NAME);
			}
		} else if (!strcmp (property, "RSSI")) {
			int_val = g_variant_get_int16 (v);
			if (priv->rssi != int_val) {
				priv->rssi = int_val;
				g_object_notify (G_OBJECT (self), NM_BLUEZ_DEVICE_RSSI);
			}
		} else if (!strcmp (property, "UUIDs")) {
			strv = g_variant_get_strv (v, NULL);
			uint_val = convert_uuids_to_capabilities (strv);
			g_free (strv);
			if (priv->capabilities != uint_val) {
				priv->capabilities = uint_val;
				g_object_notify (G_OBJECT (self), NM_BLUEZ_DEVICE_CAPABILITIES);
			}
		} else if (!strcmp (property, "Connected")) {
			gboolean connected = g_variant_get_boolean (v);
			if (priv->connected != connected) {
				priv->connected = connected;
				g_object_notify (G_OBJECT (self), NM_BLUEZ_DEVICE_CONNECTED);
			}
		}
		g_variant_unref (v);
	}

	check_emit_usable (self);
}
#else
static void
property_changed (DBusGProxy *proxy4,
                  const char *property,
                  GValue *value,
                  gpointer user_data)
{
	NMBluezDevice *self = NM_BLUEZ_DEVICE (user_data);
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	const char *str;
	guint32 uint_val;
	gint int_val;

	{
		if (!strcmp (property, "Name")) {
			str = g_value_get_string (value);
			if (   (!priv->name && str)
			    || (priv->name && !str)
			    || (priv->name && str && strcmp (priv->name, str))) {
				g_free (priv->name);
				priv->name = g_strdup (str);
				g_object_notify (G_OBJECT (self), NM_BLUEZ_DEVICE_NAME);
			}
		} else if (!strcmp (property, "RSSI")) {
			int_val = g_value_get_int (value);
			if (priv->rssi != int_val) {
				priv->rssi = int_val;
				g_object_notify (G_OBJECT (self), NM_BLUEZ_DEVICE_RSSI);
			}
		} else if (!strcmp (property, "UUIDs")) {
			uint_val = convert_uuids_to_capabilities ((const char **) g_value_get_boxed (value));
			if (priv->capabilities != uint_val) {
				priv->capabilities = uint_val;
				g_object_notify (G_OBJECT (self), NM_BLUEZ_DEVICE_CAPABILITIES);
			}
		} else if (!strcmp (property, "Connected")) {
			gboolean connected = g_value_get_boolean (value);
			if (priv->connected != connected) {
				priv->connected = connected;
				g_object_notify (G_OBJECT (self), NM_BLUEZ_DEVICE_CONNECTED);
			}
		}
	}

	check_emit_usable (self);
}
#endif

#if WITH_BLUEZ5
static void
query_properties (NMBluezDevice *self)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	GVariant *v;
	const char **uuids;
	struct ether_addr *tmp;

	v = g_dbus_proxy_get_cached_property (priv->proxy5, "Address");
	priv->address = v ? g_variant_dup_string (v, NULL) : NULL;
	if (v)
		g_variant_unref (v);
	if (priv->address) {
		tmp = ether_aton (priv->address);
		g_assert (tmp);
		memcpy (priv->bin_address, tmp->ether_addr_octet, ETH_ALEN);
	}

	v = g_dbus_proxy_get_cached_property (priv->proxy5, "Name");
	priv->name = v ? g_variant_dup_string (v, NULL) : NULL;
	if (v)
		g_variant_unref (v);

	v = g_dbus_proxy_get_cached_property (priv->proxy5, "RSSI");
	priv->rssi = v ? g_variant_get_int16 (v) : 0;
	if (v)
		g_variant_unref (v);

	v = g_dbus_proxy_get_cached_property (priv->proxy5, "UUIDs");
	if (v) {
		uuids = g_variant_get_strv (v, NULL);
		priv->capabilities = convert_uuids_to_capabilities (uuids);
		g_variant_unref (v);
	} else
		priv->capabilities = NM_BT_CAPABILITY_NONE;

	v = g_dbus_proxy_get_cached_property (priv->proxy5, "Adapter");
	if (v) {
		g_object_ref (self);
		g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
		                          G_DBUS_PROXY_FLAGS_NONE,
		                          NULL,
		                          BLUEZ_SERVICE,
		                          g_variant_get_string (v, NULL),
		                          BLUEZ_ADAPTER_INTERFACE,
		                          NULL,
		                          (GAsyncReadyCallback) on_adapter_acquired,
		                          self);
		g_variant_unref (v);
	}

	/* Check if any connections match this device */
	cp_connections_loaded (priv->provider, self);

	priv->initialized = TRUE;
	g_signal_emit (self, signals[INITIALIZED], 0, TRUE);

	check_emit_usable (self);
}
#else
static void
get_properties_cb (DBusGProxy *proxy4, DBusGProxyCall *call, gpointer user_data)
{
	NMBluezDevice *self = NM_BLUEZ_DEVICE (user_data);
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	GHashTable *properties = NULL;
	GError *err = NULL;
	GValue *value;
	const char **uuids;
	struct ether_addr *tmp;

	if (!dbus_g_proxy_end_call (proxy4, call, &err,
	                            DBUS_TYPE_G_MAP_OF_VARIANT, &properties,
	                            G_TYPE_INVALID)) {
		nm_log_warn (LOGD_BT, "bluez error getting device properties: %s",
		             err && err->message ? err->message : "(unknown)");
		g_error_free (err);
		g_signal_emit (self, signals[INITIALIZED], 0, FALSE);
		return;
	}

	value = g_hash_table_lookup (properties, "Address");
	priv->address = value ? g_value_dup_string (value) : NULL;
	if (priv->address) {
		tmp = ether_aton (priv->address);
		g_assert (tmp);
		memcpy (priv->bin_address, tmp->ether_addr_octet, ETH_ALEN);
	}

	value = g_hash_table_lookup (properties, "Name");
	priv->name = value ? g_value_dup_string (value) : NULL;

	value = g_hash_table_lookup (properties, "RSSI");
	priv->rssi = value ? g_value_get_int (value) : 0;

	value = g_hash_table_lookup (properties, "UUIDs");
	if (value) {
		uuids = (const char **) g_value_get_boxed (value);
		priv->capabilities = convert_uuids_to_capabilities (uuids);
	} else
		priv->capabilities = NM_BT_CAPABILITY_NONE;

	g_hash_table_unref (properties);

	/* Check if any connections match this device */
	cp_connections_loaded (priv->provider, self);

	priv->initialized = TRUE;
	g_signal_emit (self, signals[INITIALIZED], 0, TRUE);

	check_emit_usable (self);
}

static void
query_properties (NMBluezDevice *self)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	DBusGProxyCall *call;

	call = dbus_g_proxy_begin_call (priv->proxy4, "GetProperties",
	                                get_properties_cb,
	                                self,
	                                NULL, G_TYPE_INVALID);
	if (!call) {
		nm_log_warn (LOGD_BT, "failed to request Bluetooth device properties for %s.",
		             priv->path);
	}
}
#endif


#if WITH_BLUEZ5
static void
on_proxy_acquired (GObject *object, GAsyncResult *res, NMBluezDevice *self)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	GError *error;

	priv->proxy5 = g_dbus_proxy_new_for_bus_finish (res, &error);

	if (!priv->proxy5) {
		nm_log_warn (LOGD_BT, "failed to acquire device proxy: %s.", error->message);
		g_clear_error (&error);
		g_signal_emit (self, signals[INITIALIZED], 0, FALSE);
	} else {
		g_signal_connect (priv->proxy5, "g-properties-changed",
		                  G_CALLBACK (properties_changed), self);

		query_properties (self);
	}
	g_object_unref (self);
}

static void
on_bus_acquired (GObject *object, GAsyncResult *res, NMBluezDevice *self)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	GError *error = NULL;

	priv->dbus_connection = g_bus_get_finish (res, &error);

	if (!priv->dbus_connection) {
		nm_log_warn (LOGD_BT, "failed to acquire bus connection: %s.", error->message);
		g_clear_error (&error);
		g_signal_emit (self, signals[INITIALIZED], 0, FALSE);
		return;
	}

	check_emit_usable (self);
}
#endif

/********************************************************************/

NMBluezDevice *
nm_bluez_device_new (const char *path, NMConnectionProvider *provider)
{
	NMBluezDevice *self;
	NMBluezDevicePrivate *priv;
#if ! WITH_BLUEZ5
	DBusGConnection *connection;
#endif

	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (provider != NULL, NULL);

	self = (NMBluezDevice *) g_object_new (NM_TYPE_BLUEZ_DEVICE,
	                                       NM_BLUEZ_DEVICE_PATH, path,
	                                       NULL);
	if (!self)
		return NULL;

	priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);

	priv->provider = provider;

	g_signal_connect (priv->provider,
	                  NM_CP_SIGNAL_CONNECTION_ADDED,
	                  G_CALLBACK (cp_connection_added),
	                  self);

	g_signal_connect (priv->provider,
	                  NM_CP_SIGNAL_CONNECTION_REMOVED,
	                  G_CALLBACK (cp_connection_removed),
	                  self);

	g_signal_connect (priv->provider,
	                  NM_CP_SIGNAL_CONNECTION_UPDATED,
	                  G_CALLBACK (cp_connection_updated),
	                  self);

	g_signal_connect (priv->provider,
	                  NM_CP_SIGNAL_CONNECTIONS_LOADED,
	                  G_CALLBACK (cp_connections_loaded),
	                  self);

#if WITH_BLUEZ5
	g_bus_get (G_BUS_TYPE_SYSTEM,
	           NULL,
	           (GAsyncReadyCallback) on_bus_acquired,
	           self);

	g_object_ref (self);
	g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
	                          G_DBUS_PROXY_FLAGS_NONE,
	                          NULL,
	                          BLUEZ_SERVICE,
	                          priv->path,
	                          BLUEZ_DEVICE_INTERFACE,
	                          NULL,
	                          (GAsyncReadyCallback) on_proxy_acquired,
	                          self);
#else
	connection = nm_dbus_manager_get_connection (nm_dbus_manager_get ());

	priv->proxy4 = dbus_g_proxy_new_for_name (connection,
	                                          BLUEZ_SERVICE,
	                                          priv->path,
	                                          BLUEZ_DEVICE_INTERFACE);

	dbus_g_object_register_marshaller (g_cclosure_marshal_generic,
	                                   G_TYPE_NONE,
	                                   G_TYPE_STRING, G_TYPE_VALUE,
	                                   G_TYPE_INVALID);
	dbus_g_proxy_add_signal (priv->proxy4, "PropertyChanged",
	                         G_TYPE_STRING, G_TYPE_VALUE, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy4, "PropertyChanged",
	                             G_CALLBACK (property_changed), self, NULL);

	query_properties (self);
#endif
	return self;
}

static void
nm_bluez_device_init (NMBluezDevice *self)
{
}

static void
dispose (GObject *object)
{
	NMBluezDevice *self = NM_BLUEZ_DEVICE (object);
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);

	g_slist_foreach (priv->connections, (GFunc) g_object_unref, NULL);
	g_slist_free (priv->connections);
	priv->connections = NULL;

	g_signal_handlers_disconnect_by_func (priv->provider, cp_connection_added, self);
	g_signal_handlers_disconnect_by_func (priv->provider, cp_connection_removed, self);
	g_signal_handlers_disconnect_by_func (priv->provider, cp_connection_updated, self);
	g_signal_handlers_disconnect_by_func (priv->provider, cp_connections_loaded, self);

#if WITH_BLUEZ5
	g_clear_object (&priv->adapter);
	g_clear_object (&priv->dbus_connection);
#else
	g_clear_object (&priv->connection_proxy);
#endif

	G_OBJECT_CLASS (nm_bluez_device_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (object);

	g_free (priv->path);
	g_free (priv->address);
	g_free (priv->name);
	g_free (priv->bt_iface);
#if WITH_BLUEZ5
	g_object_unref (priv->proxy5);
#else
	g_object_unref (priv->proxy4);
#endif

	G_OBJECT_CLASS (nm_bluez_device_parent_class)->finalize (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PATH:
		g_value_set_string (value, priv->path);
		break;
	case PROP_ADDRESS:
		g_value_set_string (value, priv->address);
		break;
	case PROP_NAME:
		g_value_set_string (value, priv->name);
		break;
	case PROP_CAPABILITIES:
		g_value_set_uint (value, priv->capabilities);
		break;
	case PROP_RSSI:
		g_value_set_int (value, priv->rssi);
		break;
	case PROP_USABLE:
		g_value_set_boolean (value, priv->usable);
		break;
	case PROP_CONNECTED:
		g_value_set_boolean (value, priv->connected);
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
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PATH:
		/* construct only */
		priv->path = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_bluez_device_class_init (NMBluezDeviceClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMBluezDevicePrivate));

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_PATH,
		 g_param_spec_string (NM_BLUEZ_DEVICE_PATH,
		                      "DBus Path",
		                      "DBus Path",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_ADDRESS,
		 g_param_spec_string (NM_BLUEZ_DEVICE_ADDRESS,
		                      "Address",
		                      "Address",
		                      NULL,
		                      G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_NAME,
		 g_param_spec_string (NM_BLUEZ_DEVICE_NAME,
		                      "Name",
		                      "Name",
		                      NULL,
		                      G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_CAPABILITIES,
		 g_param_spec_uint (NM_BLUEZ_DEVICE_CAPABILITIES,
		                      "Capabilities",
		                      "Capabilities",
		                      0, G_MAXUINT, 0,
		                      G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_RSSI,
		 g_param_spec_int (NM_BLUEZ_DEVICE_RSSI,
		                      "RSSI",
		                      "RSSI",
		                      G_MININT, G_MAXINT, 0,
		                      G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_USABLE,
		 g_param_spec_boolean (NM_BLUEZ_DEVICE_USABLE,
		                       "Usable",
		                       "Usable",
		                       FALSE,
		                       G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_CONNECTED,
		 g_param_spec_boolean (NM_BLUEZ_DEVICE_CONNECTED,
		                       "Connected",
		                       "Connected",
		                       FALSE,
		                       G_PARAM_READABLE));

	/* Signals */
	signals[INITIALIZED] = g_signal_new ("initialized",
	                                     G_OBJECT_CLASS_TYPE (object_class),
	                                     G_SIGNAL_RUN_LAST,
	                                     G_STRUCT_OFFSET (NMBluezDeviceClass, initialized),
	                                     NULL, NULL, NULL,
	                                     G_TYPE_NONE, 1, G_TYPE_BOOLEAN);
}

