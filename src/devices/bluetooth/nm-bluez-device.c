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

#include "config.h"

#include <string.h>

#include "nm-default.h"
#include "nm-core-internal.h"

#include "nm-bt-error.h"
#include "nm-bluez-common.h"
#include "nm-bluez-device.h"
#include "nm-settings-connection.h"
#include "NetworkManagerUtils.h"

#if WITH_BLUEZ5_DUN
#include "nm-bluez5-dun.h"
#endif

G_DEFINE_TYPE (NMBluezDevice, nm_bluez_device, G_TYPE_OBJECT)

#define NM_BLUEZ_DEVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_BLUEZ_DEVICE, NMBluezDevicePrivate))

typedef struct {
	char *path;
	GDBusConnection *dbus_connection;

	GDBusProxy *proxy;

	GDBusProxy *adapter5;
	gboolean adapter_powered;

	int bluez_version;

	gboolean initialized;
	gboolean usable;
	NMBluetoothCapabilities connection_bt_type;

	char *adapter_address;
	char *address;
	char *name;
	guint32 capabilities;
	gboolean connected;

	char *b4_iface;
#if WITH_BLUEZ5_DUN
	NMBluez5DunContext *b5_dun_context;
#endif

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
	PROP_USABLE,
	PROP_CONNECTED,

	LAST_PROP
};

/* Signals */
enum {
	INITIALIZED,
	REMOVED,
	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };


static void cp_connection_added (NMConnectionProvider *provider,
                                 NMConnection *connection, NMBluezDevice *self);
static gboolean connection_compatible (NMBluezDevice *self, NMConnection *connection);


#define VARIANT_IS_OF_TYPE_BOOLEAN(v)      ((v) != NULL && ( g_variant_is_of_type ((v), G_VARIANT_TYPE_BOOLEAN) ))
#define VARIANT_IS_OF_TYPE_STRING(v)       ((v) != NULL && ( g_variant_is_of_type ((v), G_VARIANT_TYPE_STRING) ))
#define VARIANT_IS_OF_TYPE_OBJECT_PATH(v)  ((v) != NULL && ( g_variant_is_of_type ((v), G_VARIANT_TYPE_OBJECT_PATH) ))
#define VARIANT_IS_OF_TYPE_STRING_ARRAY(v) ((v) != NULL && ( g_variant_is_of_type ((v), G_VARIANT_TYPE_STRING_ARRAY) ))

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

gboolean
nm_bluez_device_get_connected (NMBluezDevice *self)
{
	NMBluezDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_BLUEZ_DEVICE (self), FALSE);

	priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	return priv->connected;
}

static void
pan_connection_check_create (NMBluezDevice *self)
{
	NMConnection *connection;
	NMConnection *added;
	NMSetting *setting;
	char *uuid, *id;
	GError *error = NULL;
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);

	g_return_if_fail (priv->capabilities & NM_BT_CAPABILITY_NAP);
	g_return_if_fail (priv->connections == NULL);
	g_return_if_fail (priv->name);

	if (priv->pan_connection || priv->pan_connection_no_autocreate) {
		/* already have a connection or we don't want to create one, nothing to do. */
		return;
	}

	/* Only try once to create a connection. If it does not succeed, we do not try again. Also,
	 * if the connection gets deleted later, do not create another one for this device. */
	priv->pan_connection_no_autocreate = TRUE;

	/* create a new connection */

	connection = nm_simple_connection_new ();

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
	setting = nm_setting_bluetooth_new ();
	g_object_set (G_OBJECT (setting),
	              NM_SETTING_BLUETOOTH_BDADDR, priv->address,
	              NM_SETTING_BLUETOOTH_TYPE, NM_SETTING_BLUETOOTH_TYPE_PANU,
	              NULL);
	nm_connection_add_setting (connection, setting);

	/* Setting: IPv4 */
	setting = nm_setting_ip4_config_new ();
	g_object_set (G_OBJECT (setting),
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, FALSE,
	              NULL);
	nm_connection_add_setting (connection, setting);

	/* Setting: IPv6 */
	setting = nm_setting_ip6_config_new ();
	g_object_set (G_OBJECT (setting),
	              NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP6_CONFIG_METHOD_AUTO,
	              NM_SETTING_IP_CONFIG_MAY_FAIL, TRUE,
	              NULL);
	nm_connection_add_setting (connection, setting);

	/* Adding a new connection raises a signal which eventually calls check_emit_usable (again)
	 * which then already finds the suitable connection in priv->connections. This is confusing,
	 * so block the signal. check_emit_usable will succeed after this function call returns. */
	g_signal_handlers_block_by_func (priv->provider, cp_connection_added, self);
	added = nm_connection_provider_add_connection (priv->provider, connection, FALSE, &error);
	g_signal_handlers_unblock_by_func (priv->provider, cp_connection_added, self);

	if (added) {
		g_assert (!g_slist_find (priv->connections, added));
		g_assert (connection_compatible (self, added));
		g_assert (nm_connection_compare (added, connection, NM_SETTING_COMPARE_FLAG_EXACT));

		nm_settings_connection_set_flags (NM_SETTINGS_CONNECTION (added), NM_SETTINGS_CONNECTION_FLAGS_NM_GENERATED, TRUE);

		priv->connections = g_slist_prepend (priv->connections, g_object_ref (added));
		priv->pan_connection = added;
		nm_log_dbg (LOGD_BT, "bluez[%s] added new Bluetooth connection for NAP device: '%s' (%s)", priv->path, id, uuid);
	} else {
		nm_log_warn (LOGD_BT, "bluez[%s] couldn't add new Bluetooth connection for NAP device: '%s' (%s): %d / %s",
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

	/* only expect the supported capabilities set. */
	g_assert ((priv->capabilities & ~(NM_BT_CAPABILITY_NAP | NM_BT_CAPABILITY_DUN)) == NM_BT_CAPABILITY_NONE );

	new_usable = (priv->initialized && priv->capabilities && priv->name &&
	              ((priv->bluez_version == 4) ||
	               (priv->bluez_version == 5 && priv->adapter5 && priv->adapter_powered) ) &&
	              priv->dbus_connection && priv->address && priv->adapter_address);

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
	const char *bdaddr;

	if (!nm_connection_is_type (connection, NM_SETTING_BLUETOOTH_SETTING_NAME))
		return FALSE;

	s_bt = nm_connection_get_setting_bluetooth (connection);
	if (!s_bt)
		return FALSE;

	if (!priv->address)
		return FALSE;

	bdaddr = nm_setting_bluetooth_get_bdaddr (s_bt);
	if (!bdaddr)
		return FALSE;
	if (!nm_utils_hwaddr_matches (bdaddr, -1, priv->address, -1))
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
		if (priv->pan_connection == connection)
			priv->pan_connection = NULL;
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
load_connections (NMBluezDevice *self)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	const GSList *connections, *iter;

	connections = nm_connection_provider_get_connections (priv->provider);
	for (iter = connections; iter; iter = g_slist_next (iter))
		cp_connection_added (priv->provider, NM_CONNECTION (iter->data), self);
}

/***********************************************************/

static void
bluez_disconnect_cb (GDBusConnection *dbus_connection,
                     GAsyncResult *res,
                     gpointer user_data)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (user_data);
	GError *error = NULL;
	GVariant *variant;

	variant = g_dbus_connection_call_finish (dbus_connection, res, &error);
	if (!variant) {
		if (!strstr (error->message, "org.bluez.Error.NotConnected"))
			nm_log_warn (LOGD_BT, "bluez[%s]: failed to disconnect: %s", priv->path, error->message);
		g_error_free (error);
	} else
		g_variant_unref (variant);

	g_object_unref (NM_BLUEZ_DEVICE (user_data));
}

void
nm_bluez_device_disconnect (NMBluezDevice *self)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	GVariant *args = NULL;
	const char *dbus_iface = NULL;

	g_return_if_fail (priv->dbus_connection);

	if (priv->connection_bt_type == NM_BT_CAPABILITY_DUN) {
		if (priv->bluez_version == 4) {
			/* Can't pass a NULL interface name through dbus to bluez, so just
			 * ignore the disconnect if the interface isn't known.
			 */
			if (!priv->b4_iface)
				goto out;
			args = g_variant_new ("(s)", priv->b4_iface),
			dbus_iface = BLUEZ4_SERIAL_INTERFACE;
		} else if (priv->bluez_version == 5) {
#if WITH_BLUEZ5_DUN
			nm_bluez5_dun_cleanup (priv->b5_dun_context);
#endif
			priv->connected = FALSE;
			goto out;
		}
	} else if (priv->connection_bt_type == NM_BT_CAPABILITY_NAP) {
		if (priv->bluez_version == 4)
			dbus_iface = BLUEZ4_NETWORK_INTERFACE;
		else if (priv->bluez_version == 5)
			dbus_iface = BLUEZ5_NETWORK_INTERFACE;
		else
			g_assert_not_reached ();
	} else
		g_assert_not_reached ();

	g_dbus_connection_call (priv->dbus_connection,
	                        BLUEZ_SERVICE,
	                        priv->path,
	                        dbus_iface,
	                        "Disconnect",
	                        args ? args : g_variant_new ("()"),
	                        NULL,
	                        G_DBUS_CALL_FLAGS_NONE,
	                        10000,
	                        NULL,
	                        (GAsyncReadyCallback) bluez_disconnect_cb,
	                        g_object_ref (self));

out:
	g_clear_pointer (&priv->b4_iface, g_free);
	priv->connection_bt_type = NM_BT_CAPABILITY_NONE;
}

static void
bluez_connect_cb (GDBusConnection *dbus_connection,
                  GAsyncResult *res,
                  gpointer user_data)
{
	GSimpleAsyncResult *result = G_SIMPLE_ASYNC_RESULT (user_data);
	GObject *result_object = g_async_result_get_source_object (G_ASYNC_RESULT (result));
	NMBluezDevice *self = NM_BLUEZ_DEVICE (result_object);
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	GError *error = NULL;
	char *device;
	GVariant *variant;

	variant = g_dbus_connection_call_finish (dbus_connection, res, &error);

	if (!variant) {
		g_simple_async_result_take_error (result, error);
	} else {
		g_variant_get (variant, "(s)", &device);

		g_simple_async_result_set_op_res_gpointer (result,
		                                           g_strdup (device),
		                                           g_free);
		priv->b4_iface = device;
		g_variant_unref (variant);
	}

	g_simple_async_result_complete (result);
	g_object_unref (result);
	g_object_unref (result_object);
}

#if WITH_BLUEZ5_DUN
static void
bluez5_dun_connect_cb (NMBluez5DunContext *context,
                   const char *device,
                   GError *error,
                   gpointer user_data)
{
	GSimpleAsyncResult *result = G_SIMPLE_ASYNC_RESULT (user_data);

	if (error) {
		g_simple_async_result_take_error (result, error);
	} else {
		g_simple_async_result_set_op_res_gpointer (result,
		                                           g_strdup (device),
		                                           g_free);
	}

	g_simple_async_result_complete (result);
	g_object_unref (result);
}
#endif

void
nm_bluez_device_connect_async (NMBluezDevice *self,
                               NMBluetoothCapabilities connection_bt_type,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
	GSimpleAsyncResult *simple;
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	const char *dbus_iface = NULL;
	const char *connect_type = NULL;

	g_return_if_fail (priv->capabilities & connection_bt_type & (NM_BT_CAPABILITY_DUN | NM_BT_CAPABILITY_NAP));

	simple = g_simple_async_result_new (G_OBJECT (self),
	                                    callback,
	                                    user_data,
	                                    nm_bluez_device_connect_async);
	priv->connection_bt_type = connection_bt_type;

	if (connection_bt_type == NM_BT_CAPABILITY_NAP) {
		connect_type = BLUETOOTH_CONNECT_NAP;
		if (priv->bluez_version == 4)
			dbus_iface = BLUEZ4_NETWORK_INTERFACE;
		else if (priv->bluez_version == 5)
			dbus_iface = BLUEZ5_NETWORK_INTERFACE;
	} else if (connection_bt_type == NM_BT_CAPABILITY_DUN) {
		connect_type = BLUETOOTH_CONNECT_DUN;
		if (priv->bluez_version == 4)
			dbus_iface = BLUEZ4_SERIAL_INTERFACE;
		else if (priv->bluez_version == 5) {
#if WITH_BLUEZ5_DUN
			if (priv->b5_dun_context == NULL)
				priv->b5_dun_context = nm_bluez5_dun_new (priv->adapter_address, priv->address);
			nm_bluez5_dun_connect (priv->b5_dun_context, bluez5_dun_connect_cb, simple);
#else
			g_simple_async_result_set_error (simple,
							 NM_BT_ERROR,
							 NM_BT_ERROR_DUN_CONNECT_FAILED,
							 "NetworkManager built without support for Bluez 5");
			g_simple_async_result_complete (simple);
#endif
			return;
		}
	} else
		g_assert_not_reached ();

	g_dbus_connection_call (priv->dbus_connection,
	                        BLUEZ_SERVICE,
	                        priv->path,
	                        dbus_iface,
	                        "Connect",
	                        g_variant_new ("(s)", connect_type),
	                        NULL,
	                        G_DBUS_CALL_FLAGS_NONE,
	                        20000,
	                        NULL,
	                        (GAsyncReadyCallback) bluez_connect_cb,
	                        simple);
}

const char *
nm_bluez_device_connect_finish (NMBluezDevice *self,
                                GAsyncResult *result,
                                GError **error)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
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
	if (device && priv->bluez_version == 5)
		priv->connected = TRUE;

	return device;
}

/***********************************************************/

static void
set_adapter_address (NMBluezDevice *self, const char *address)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);

	g_return_if_fail (address);

	if (priv->adapter_address)
		g_free (priv->adapter_address);
	priv->adapter_address = g_strdup (address);
}

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
			case 0x1103:
				capabilities |= NM_BT_CAPABILITY_DUN;
				break;
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

static void
_set_property_capabilities (NMBluezDevice *self, const char **uuids)
{
	guint32 uint_val;
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);

	uint_val = convert_uuids_to_capabilities (uuids);
	if (priv->capabilities != uint_val) {
		if (priv->capabilities) {
			/* changing (relevant) capabilities is not supported and ignored -- except setting initially */
			nm_log_warn (LOGD_BT, "bluez[%s] ignore change of capabilities for Bluetooth device from %u to %u",
			             priv->path, priv->capabilities, uint_val);
			return;
		}
		nm_log_dbg (LOGD_BT, "bluez[%s] set capabilities for Bluetooth device: %s%s%s", priv->path,
		            uint_val & NM_BT_CAPABILITY_NAP ? "NAP" : "",
		            ((uint_val & NM_BT_CAPABILITY_DUN) && (uint_val &NM_BT_CAPABILITY_NAP)) ? " | " : "",
		            uint_val & NM_BT_CAPABILITY_DUN ? "DUN" : "");
		priv->capabilities = uint_val;
		g_object_notify (G_OBJECT (self), NM_BLUEZ_DEVICE_CAPABILITIES);
	}
}

/**
 * priv->address can only be set one to a certain (non NULL) value. Every later attempt
 * to reset it to another value will be ignored and a warning will be logged.
 **/
static void
_set_property_address (NMBluezDevice *self, const char *addr)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);

	if (g_strcmp0 (priv->address, addr) == 0)
		return;

	if (!addr) {
		nm_log_warn (LOGD_BT, "bluez[%s] cannot reset address from '%s' to NULL", priv->path, priv->address);
		return;
	}

	if (priv->address != NULL) {
		nm_log_warn (LOGD_BT, "bluez[%s] cannot reset address from '%s' to '%s'", priv->path, priv->address, addr);
		return;
	}

	if (!nm_utils_hwaddr_valid (addr, ETH_ALEN)) {
		nm_log_warn (LOGD_BT, "bluez[%s] cannot set address to '%s' (invalid value)", priv->path, addr);
		return;
	}

	priv->address = g_strdup (addr);
	g_object_notify (G_OBJECT (self), NM_BLUEZ_DEVICE_ADDRESS);
}

static void
_take_variant_property_address (NMBluezDevice *self, GVariant *v)
{
	_set_property_address (self, VARIANT_IS_OF_TYPE_STRING (v) ? g_variant_get_string (v, NULL) : NULL);
	if (v)
		g_variant_unref (v);
}

static void
_take_variant_property_name (NMBluezDevice *self, GVariant *v)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	const char *str;

	if (VARIANT_IS_OF_TYPE_STRING (v)) {
		str = g_variant_get_string (v, NULL);
		if (g_strcmp0 (priv->name, str)) {
			g_free (priv->name);
			priv->name = g_strdup (str);
			g_object_notify (G_OBJECT (self), NM_BLUEZ_DEVICE_NAME);
		}
	}
	if (v)
		g_variant_unref (v);
}

static void
_take_variant_property_uuids (NMBluezDevice *self, GVariant *v)
{
	if (VARIANT_IS_OF_TYPE_STRING_ARRAY (v)) {
		const char **uuids = g_variant_get_strv (v, NULL);

		_set_property_capabilities (self, uuids);
		g_free (uuids);
	}
	if (v)
		g_variant_unref (v);
}

static void
_take_variant_property_connected (NMBluezDevice *self, GVariant *v)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);

	if (VARIANT_IS_OF_TYPE_BOOLEAN (v)) {
		gboolean connected = g_variant_get_boolean (v);

		if (priv->connected != connected) {
			priv->connected = connected;
			g_object_notify (G_OBJECT (self), NM_BLUEZ_DEVICE_CONNECTED);
		}
	}
	if (v)
		g_variant_unref (v);
}


static void
adapter5_on_properties_changed (GDBusProxy *proxy,
                                GVariant *changed_properties,
                                GStrv invalidated_properties,
                                gpointer user_data)
{
	NMBluezDevice *self = NM_BLUEZ_DEVICE (user_data);
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	GVariantIter i;
	const char *property;
	GVariant *v;

	g_variant_iter_init (&i, changed_properties);
	while (g_variant_iter_next (&i, "{&sv}", &property, &v)) {
		if (!strcmp (property, "Powered") && VARIANT_IS_OF_TYPE_BOOLEAN (v)) {
			gboolean powered = g_variant_get_boolean (v);
			if (priv->adapter_powered != powered)
				priv->adapter_powered = powered;
		}
		g_variant_unref (v);
	}

	check_emit_usable (self);
}

static void
adapter5_on_acquired (GObject *object, GAsyncResult *res, NMBluezDevice *self)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	GError *error;
	GVariant *v;

	priv->adapter5 = g_dbus_proxy_new_for_bus_finish (res, &error);
	if (!priv->adapter5) {
		nm_log_warn (LOGD_BT, "bluez[%s] failed to acquire adapter proxy: %s.", priv->path, error->message);
		g_clear_error (&error);
		g_signal_emit (self, signals[INITIALIZED], 0, FALSE);
	} else {
		g_signal_connect (priv->adapter5, "g-properties-changed",
		                  G_CALLBACK (adapter5_on_properties_changed), self);

		/* Check adapter's powered state */
		v = g_dbus_proxy_get_cached_property (priv->adapter5, "Powered");
		priv->adapter_powered = VARIANT_IS_OF_TYPE_BOOLEAN (v) ? g_variant_get_boolean (v) : FALSE;
		if (v)
			g_variant_unref (v);

		v = g_dbus_proxy_get_cached_property (priv->adapter5, "Address");
		if (VARIANT_IS_OF_TYPE_STRING (v))
			set_adapter_address (self, g_variant_get_string (v, NULL));

		priv->initialized = TRUE;
		g_signal_emit (self, signals[INITIALIZED], 0, TRUE);

		check_emit_usable (self);
	}

	g_object_unref (self);
}

static void
_take_one_variant_property (NMBluezDevice *self, const char *property, GVariant *v)
{
	if (v) {
		if (!g_strcmp0 (property, "Address"))
			_take_variant_property_address (self, v);
		else if (!g_strcmp0 (property, "Connected"))
			_take_variant_property_connected (self, v);
		else if (!g_strcmp0 (property, "Name"))
			_take_variant_property_name (self, v);
		else if (!g_strcmp0 (property, "UUIDs"))
			_take_variant_property_uuids (self, v);
		else
			g_variant_unref (v);
	}
}

static void
_set_properties (NMBluezDevice *self, GVariant *properties)
{
	GVariantIter i;
	const char *property;
	GVariant *v;

	g_object_freeze_notify (G_OBJECT (self));
	g_variant_iter_init (&i, properties);
	while (g_variant_iter_next (&i, "{&sv}", &property, &v))
		_take_one_variant_property (self, property, v);
	g_object_thaw_notify (G_OBJECT (self));
}

static void
properties_changed (GDBusProxy *proxy,
                    GVariant *changed_properties,
                    GStrv invalidated_properties,
                    gpointer user_data)
{
	NMBluezDevice *self = NM_BLUEZ_DEVICE (user_data);

	_set_properties (self, changed_properties);
	check_emit_usable (self);
}

static void
bluez4_property_changed (GDBusProxy *proxy,
                         const char *property,
                         GVariant   *v,
                         gpointer    user_data)
{
	NMBluezDevice *self = NM_BLUEZ_DEVICE (user_data);

	_take_one_variant_property (self, property, v);
	check_emit_usable (self);
}

static void
get_properties_cb_4 (GObject *source_object, GAsyncResult *res, gpointer user_data)
{
	NMBluezDevice *self = NM_BLUEZ_DEVICE (user_data);
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	GError *err = NULL;
	GVariant *v_properties, *v_dict;

	v_properties = _nm_dbus_proxy_call_finish (priv->proxy, res,
	                                           G_VARIANT_TYPE ("(a{sv})"),
	                                           &err);
	if (!v_properties) {
		g_dbus_error_strip_remote_error (err);
		nm_log_warn (LOGD_BT, "bluez[%s] error getting device properties: %s",
		             priv->path, err->message);
		g_error_free (err);
		g_signal_emit (self, signals[INITIALIZED], 0, FALSE);
		goto END;
	}

	v_dict = g_variant_get_child_value (v_properties, 0);
	_set_properties (self, v_dict);
	g_variant_unref (v_dict);
	g_variant_unref (v_properties);

	/* Check if any connections match this device */
	load_connections (self);

	priv->initialized = TRUE;
	g_signal_emit (self, signals[INITIALIZED], 0, TRUE);

	check_emit_usable (self);

END:
	g_object_unref (self);
}

static void
query_properties (NMBluezDevice *self)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	GVariant *v;

	switch (priv->bluez_version) {
	case 4:
		g_dbus_proxy_call (priv->proxy, "GetProperties", NULL, G_DBUS_CALL_FLAGS_NO_AUTO_START, 3000,
		                   NULL, get_properties_cb_4, g_object_ref (self));
		break;
	case 5:
		g_object_freeze_notify (G_OBJECT (self));
		_take_variant_property_address   (self, g_dbus_proxy_get_cached_property (priv->proxy, "Address"));
		_take_variant_property_connected (self, g_dbus_proxy_get_cached_property (priv->proxy, "Connected"));
		_take_variant_property_name      (self, g_dbus_proxy_get_cached_property (priv->proxy, "Name"));
		_take_variant_property_uuids     (self, g_dbus_proxy_get_cached_property (priv->proxy, "UUIDs"));
		g_object_thaw_notify (G_OBJECT (self));

		v = g_dbus_proxy_get_cached_property (priv->proxy, "Adapter");
		if (VARIANT_IS_OF_TYPE_OBJECT_PATH (v)) {
			g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
			                          G_DBUS_PROXY_FLAGS_NONE,
			                          NULL,
			                          BLUEZ_SERVICE,
			                          g_variant_get_string (v, NULL),
			                          BLUEZ5_ADAPTER_INTERFACE,
			                          NULL,
			                          (GAsyncReadyCallback) adapter5_on_acquired,
			                          g_object_ref (self));
			g_variant_unref (v);
		} else {
			/* If the Adapter property is unset at this point, we won't try to acquire the adapter later on
			 * and the device stays unusable. This should not happen, but if it does, log a debug message. */
			nm_log_dbg (LOGD_BT, "bluez[%s] device has no adapter property and cannot be used.", priv->path);
		}

		/* Check if any connections match this device */
		load_connections (self);

		break;
	}
}

static void
on_proxy_acquired (GObject *object, GAsyncResult *res, NMBluezDevice *self)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);
	GError *error = NULL;

	priv->proxy = g_dbus_proxy_new_for_bus_finish (res, &error);

	if (!priv->proxy) {
		nm_log_warn (LOGD_BT, "bluez[%s] failed to acquire device proxy: %s.", priv->path, error->message);
		g_clear_error (&error);
		g_signal_emit (self, signals[INITIALIZED], 0, FALSE);
	} else {
		g_signal_connect (priv->proxy, "g-properties-changed",
		                  G_CALLBACK (properties_changed), self);
		if (priv->bluez_version == 4) {
			/* Watch for custom Bluez4 PropertyChanged signals */
			_nm_dbus_signal_connect (priv->proxy, "PropertyChanged", G_VARIANT_TYPE ("(sv)"),
			                         G_CALLBACK (bluez4_property_changed), self);
		}

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
		nm_log_warn (LOGD_BT, "bluez[%s] failed to acquire bus connection: %s.", priv->path, error->message);
		g_clear_error (&error);
		g_signal_emit (self, signals[INITIALIZED], 0, FALSE);
	} else
		check_emit_usable (self);

	g_object_unref (self);
}

/********************************************************************/

NMBluezDevice *
nm_bluez_device_new (const char *path,
                     const char *adapter_address,
                     NMConnectionProvider *provider,
                     int bluez_version)
{
	NMBluezDevice *self;
	NMBluezDevicePrivate *priv;
	const char *interface_name = NULL;

	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (provider != NULL, NULL);
	g_return_val_if_fail (bluez_version == 4 || bluez_version == 5, NULL);

	self = (NMBluezDevice *) g_object_new (NM_TYPE_BLUEZ_DEVICE,
	                                       NM_BLUEZ_DEVICE_PATH, path,
	                                       NULL);
	if (!self)
		return NULL;

	nm_log_dbg (LOGD_BT, "bluez[%s] create NMBluezDevice", path);

	priv = NM_BLUEZ_DEVICE_GET_PRIVATE (self);

	priv->bluez_version = bluez_version;
	priv->provider = provider;
	g_return_val_if_fail (bluez_version == 5 || (bluez_version == 4 && adapter_address), NULL);
	if (adapter_address)
		set_adapter_address (self, adapter_address);

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

	g_bus_get (G_BUS_TYPE_SYSTEM,
	           NULL,
	           (GAsyncReadyCallback) on_bus_acquired,
	           g_object_ref (self));

	switch (priv->bluez_version) {
	case 4:
		interface_name = BLUEZ4_DEVICE_INTERFACE;
		break;
	case 5:
		interface_name = BLUEZ5_DEVICE_INTERFACE;
		break;
	}

	g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
	                          G_DBUS_PROXY_FLAGS_NONE,
	                          NULL,
	                          BLUEZ_SERVICE,
	                          priv->path,
	                          interface_name,
	                          NULL,
	                          (GAsyncReadyCallback) on_proxy_acquired,
	                          g_object_ref (self));
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
	NMConnection *to_delete = NULL;

	if (priv->pan_connection) {
		/* Check whether we want to remove the created connection. If so, we take a reference
		 * and delete it at the end of dispose(). */
		if (nm_settings_connection_get_nm_generated (NM_SETTINGS_CONNECTION (priv->pan_connection)))
			to_delete = g_object_ref (priv->pan_connection);

		priv->pan_connection = NULL;
	}

#if WITH_BLUEZ5_DUN
	if (priv->b5_dun_context) {
		nm_bluez5_dun_free (priv->b5_dun_context);
		priv->b5_dun_context = NULL;
	}
#endif

	g_signal_handlers_disconnect_by_func (priv->provider, cp_connection_added, self);
	g_signal_handlers_disconnect_by_func (priv->provider, cp_connection_removed, self);
	g_signal_handlers_disconnect_by_func (priv->provider, cp_connection_updated, self);

	g_slist_free_full (priv->connections, g_object_unref);
	priv->connections = NULL;

	g_clear_object (&priv->adapter5);
	g_clear_object (&priv->dbus_connection);

	G_OBJECT_CLASS (nm_bluez_device_parent_class)->dispose (object);

	if (to_delete) {
		nm_log_dbg (LOGD_BT, "bluez[%s] removing Bluetooth connection for NAP device: '%s' (%s)", priv->path,
		            nm_connection_get_id (to_delete), nm_connection_get_uuid (to_delete));
		nm_settings_connection_delete (NM_SETTINGS_CONNECTION (to_delete), NULL, NULL);
		g_object_unref (to_delete);
	}
}

static void
finalize (GObject *object)
{
	NMBluezDevicePrivate *priv = NM_BLUEZ_DEVICE_GET_PRIVATE (object);

	nm_log_dbg (LOGD_BT, "bluez[%s]: finalize NMBluezDevice", priv->path);

	g_free (priv->path);
	g_free (priv->adapter_address);
	g_free (priv->address);
	g_free (priv->name);
	g_free (priv->b4_iface);

	if (priv->proxy)
		g_signal_handlers_disconnect_by_data (priv->proxy, object);
	g_clear_object (&priv->proxy);

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
		 g_param_spec_string (NM_BLUEZ_DEVICE_PATH, "", "",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_ADDRESS,
		 g_param_spec_string (NM_BLUEZ_DEVICE_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_NAME,
		 g_param_spec_string (NM_BLUEZ_DEVICE_NAME, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_CAPABILITIES,
		 g_param_spec_uint (NM_BLUEZ_DEVICE_CAPABILITIES, "", "",
		                    0, G_MAXUINT, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_USABLE,
		 g_param_spec_boolean (NM_BLUEZ_DEVICE_USABLE, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_CONNECTED,
		 g_param_spec_boolean (NM_BLUEZ_DEVICE_CONNECTED, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/* Signals */
	signals[INITIALIZED] = g_signal_new ("initialized",
	                                     G_OBJECT_CLASS_TYPE (object_class),
	                                     G_SIGNAL_RUN_LAST,
	                                     G_STRUCT_OFFSET (NMBluezDeviceClass, initialized),
	                                     NULL, NULL, NULL,
	                                     G_TYPE_NONE, 1, G_TYPE_BOOLEAN);

	signals[REMOVED] =     g_signal_new (NM_BLUEZ_DEVICE_REMOVED,
	                                     G_OBJECT_CLASS_TYPE (object_class),
	                                     G_SIGNAL_RUN_LAST,
	                                     G_STRUCT_OFFSET (NMBluezDeviceClass, removed),
	                                     NULL, NULL, NULL,
	                                     G_TYPE_NONE, 0);
}

