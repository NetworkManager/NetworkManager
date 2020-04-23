// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 - 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-bluez-manager.h"

#include <signal.h>
#include <stdlib.h>
#include <gmodule.h>

#include "nm-glib-aux/nm-dbus-aux.h"
#include "nm-glib-aux/nm-c-list.h"
#include "nm-dbus-manager.h"
#include "devices/nm-device-factory.h"
#include "devices/nm-device-bridge.h"
#include "nm-setting-bluetooth.h"
#include "settings/nm-settings.h"
#include "nm-bluez-common.h"
#include "nm-device-bt.h"
#include "nm-manager.h"
#include "nm-bluez5-dun.h"
#include "nm-core-internal.h"
#include "platform/nm-platform.h"
#include "nm-std-aux/nm-dbus-compat.h"

/*****************************************************************************/

#if WITH_BLUEZ5_DUN
#define _NM_BT_CAPABILITY_SUPPORTED_DUN NM_BT_CAPABILITY_DUN
#else
#define _NM_BT_CAPABILITY_SUPPORTED_DUN NM_BT_CAPABILITY_NONE
#endif
#define _NM_BT_CAPABILITY_SUPPORTED (NM_BT_CAPABILITY_NAP | _NM_BT_CAPABILITY_SUPPORTED_DUN)

typedef struct {
	const char *bdaddr;
	CList lst_head;
	NMBluetoothCapabilities bt_type:8;
	char bdaddr_data[];
} ConnDataHead;

typedef struct {
	NMSettingsConnection *sett_conn;
	ConnDataHead *cdata_hd;
	CList lst;
} ConnDataElem;

typedef struct {
	GCancellable *ext_cancellable;
	GCancellable *int_cancellable;
	NMBtVTableRegisterCallback callback;
	gpointer callback_user_data;
	gulong ext_cancelled_id;
} NetworkServerRegisterReqData;

typedef struct {
	GCancellable *ext_cancellable;
	GCancellable *int_cancellable;
	NMBluezManagerConnectCb callback;
	gpointer callback_user_data;
	char *device_name;
	gulong ext_cancelled_id;
	guint timeout_id;
	guint timeout_wait_connect_id;
} DeviceConnectReqData;

typedef struct {
	const char *object_path;

	NMBluezManager *self;

	/* Fields name with "d_" prefix are purely cached values from BlueZ's
	 * ObjectManager D-Bus interface. There is no logic whatsoever about
	 * them.
	 */

	CList process_change_lst;

	struct {
		char *address;
	} d_adapter;

	struct {
		char *address;
		char *name;
		char *adapter;
	} d_device;

	struct {
		char *interface;
	} d_network;

	struct {
		CList lst;
		char *adapter_address;
		NMDevice *device_br;
		NetworkServerRegisterReqData *r_req_data;
	} x_network_server;

	struct {
		NMSettingsConnection *panu_connection;
		NMDeviceBt *device_bt;
		DeviceConnectReqData *c_req_data;
		NMBluez5DunContext *connect_dun_context;
		gulong device_bt_signal_id;
	} x_device;

	/* indicate whether the D-Bus object has the particular D-Bus interface. */
	bool d_has_adapter_iface:1;
	bool d_has_device_iface:1;
	bool d_has_network_iface:1;
	bool d_has_network_server_iface:1;

	/* cached D-Bus properties for Device1 ("d_device*"). */
	NMBluetoothCapabilities d_device_capabilities:6;
	bool d_device_connected:1;
	bool d_device_paired:1;

	/* cached D-Bus properties for Network1 ("d_network*"). */
	bool d_network_connected:1;

	/* cached D-Bus properties for Adapter1 ("d_adapter*"). */
	bool d_adapter_powered:1;

	/* properties related to device ("x_device*"). */
	NMBluetoothCapabilities x_device_connect_bt_type:6;
	bool x_device_is_usable:1;
	bool x_device_is_connected:1;

	bool x_device_panu_connection_allow_create:1;

	/* flag to remember last time when we checked wether the object
	 * was  a suitable adapter that is usable to a device. */
	bool was_usable_adapter_for_device_before:1;

	char _object_path_intern[];
} BzDBusObj;

typedef struct {
	NMManager *manager;
	NMSettings *settings;

	GDBusConnection *dbus_connection;

	NMBtVTableNetworkServer vtable_network_server;

	GCancellable *name_owner_get_cancellable;
	GCancellable *get_managed_objects_cancellable;

	GHashTable *bzobjs;

	char *name_owner;

	GHashTable *conn_data_heads;
	GHashTable *conn_data_elems;

	CList network_server_lst_head;

	CList process_change_lst_head;

	guint name_owner_changed_id;

	guint managed_objects_changed_id;

	guint properties_changed_id;

	guint process_change_idle_id;

	bool settings_registered:1;
} NMBluezManagerPrivate;

struct _NMBluezManager {
	NMDeviceFactory parent;
	NMBluezManagerPrivate _priv;
};

struct _NMBluezManagerClass {
	NMDeviceFactoryClass parent;
};

G_DEFINE_TYPE (NMBluezManager, nm_bluez_manager, NM_TYPE_DEVICE_FACTORY);

#define NM_BLUEZ_MANAGER_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMBluezManager, NM_IS_BLUEZ_MANAGER)

/*****************************************************************************/

NM_DEVICE_FACTORY_DECLARE_TYPES (
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES    (NM_LINK_TYPE_BNEP)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_BLUETOOTH_SETTING_NAME)
)

G_MODULE_EXPORT NMDeviceFactory *
nm_device_factory_create (GError **error)
{
	return (NMDeviceFactory *) g_object_new (NM_TYPE_BLUEZ_MANAGER, NULL);
}

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_BT
#define _NMLOG(level, ...) __NMLOG_DEFAULT (level, _NMLOG_DOMAIN, "bluez", __VA_ARGS__)

/*****************************************************************************/

static NMBluetoothCapabilities
convert_uuids_to_capabilities (const char *const*strv)
{
	NMBluetoothCapabilities capabilities = NM_BT_CAPABILITY_NONE;

	if (strv) {
		for (; strv[0]; strv++) {
			gs_free char *s_part1 = NULL;
			const char *str = strv[0];
			const char *s;

			s = strchr (str, '-');
			if (!s)
				continue;

			s_part1 = g_strndup (str, s - str);
			switch (_nm_utils_ascii_str_to_int64 (s_part1, 16, 0, G_MAXINT, -1)) {
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
	}

	return capabilities;
}

/*****************************************************************************/

static void _cleanup_for_name_owner (NMBluezManager *self);
static void _connect_disconnect (NMBluezManager *self,
                                 BzDBusObj *bzobj,
                                 const char *reason);
static gboolean _bzobjs_network_server_is_usable (const BzDBusObj *bzobj,
                                                  gboolean require_powered);
static gboolean _bzobjs_is_dead (const BzDBusObj *bzobj);
static gboolean _bzobjs_device_is_usable (const BzDBusObj *bzobj,
                                          BzDBusObj **out_adapter_bzobj,
                                          gboolean *out_create_panu_connection);
static gboolean _bzobjs_adapter_is_usable_for_device (const BzDBusObj *bzobj);
static ConnDataHead *_conn_track_find_head (NMBluezManager *self,
                                            NMBluetoothCapabilities bt_type,
                                            const char *bdaddr);
static void _process_change_idle_schedule (NMBluezManager *self,
                                           BzDBusObj *bzobj);
static void _network_server_unregister_bridge (NMBluezManager *self,
                                               BzDBusObj *bzobj,
                                               const char *reason);
static gboolean _connect_timeout_wait_connected_cb (gpointer user_data);

/*****************************************************************************/

static void
_dbus_call_complete_cb_nop (GObject *source_object,
                            GAsyncResult *res,
                            gpointer user_data)
{
	/* we don't do anything at all. The only reason to register this
	 * callback is so that GDBusConnection keeps the cancellable alive
	 * long enough until the call completes.
	 *
	 * Note that this cancellable in turn is registered via
	 * nm_shutdown_wait_obj_register_*(), to block shutdown until
	 * we are done. */
}

/*****************************************************************************/

static void
_network_server_register_req_data_complete (NetworkServerRegisterReqData *r_req_data,
                                            GError *error)
{
	nm_clear_g_signal_handler (r_req_data->ext_cancellable, &r_req_data->ext_cancelled_id);

	nm_clear_g_cancellable (&r_req_data->int_cancellable);

	if (r_req_data->callback) {
		gs_free_error GError *error_cancelled = NULL;

		if (g_cancellable_set_error_if_cancelled (r_req_data->ext_cancellable, &error_cancelled))
			error = error_cancelled;

		r_req_data->callback (error, r_req_data->callback_user_data);
	}

	g_object_unref (r_req_data->ext_cancellable);
	nm_g_slice_free (r_req_data);
}

static void
_device_connect_req_data_complete (DeviceConnectReqData *c_req_data,
                                   NMBluezManager *self,
                                   const char *device_name,
                                   GError *error)
{
	nm_assert ((!!device_name) != (!!error));

	nm_clear_g_signal_handler (c_req_data->ext_cancellable, &c_req_data->ext_cancelled_id);

	nm_clear_g_cancellable (&c_req_data->int_cancellable);
	nm_clear_g_source (&c_req_data->timeout_id);
	nm_clear_g_source (&c_req_data->timeout_wait_connect_id);

	if (c_req_data->callback) {
		gs_free_error GError *error_cancelled = NULL;

		if (g_cancellable_set_error_if_cancelled (c_req_data->ext_cancellable, &error_cancelled)) {
			error = error_cancelled;
			device_name = NULL;
		}

		c_req_data->callback (self, TRUE, device_name, error, c_req_data->callback_user_data);
	}

	g_object_unref (c_req_data->ext_cancellable);
	nm_clear_g_free (&c_req_data->device_name);
	nm_g_slice_free (c_req_data);
}

/*****************************************************************************/

static BzDBusObj *
_bz_dbus_obj_new (NMBluezManager *self,
                  const char *object_path)
{
	BzDBusObj *bzobj;
	gsize l;

	nm_assert (NM_IS_BLUEZ_MANAGER (self));

	l = strlen (object_path) + 1;

	bzobj = g_malloc (sizeof (BzDBusObj) + l);
	*bzobj = (BzDBusObj) {
		.object_path                           = bzobj->_object_path_intern,
		.self                                  = self,
		.x_network_server.lst                  = C_LIST_INIT (bzobj->x_network_server.lst),
		.process_change_lst                    = C_LIST_INIT (bzobj->process_change_lst),
		.x_device_panu_connection_allow_create = TRUE,
	};
	memcpy (bzobj->_object_path_intern, object_path, l);

	return bzobj;
}

static void
_bz_dbus_obj_free (BzDBusObj *bzobj)
{
	nm_assert (bzobj);
	nm_assert (NM_IS_BLUEZ_MANAGER (bzobj->self));
	nm_assert (!bzobj->x_network_server.device_br);
	nm_assert (!bzobj->x_network_server.r_req_data);
	nm_assert (!bzobj->x_device.c_req_data);

	c_list_unlink_stale (&bzobj->process_change_lst);
	c_list_unlink_stale (&bzobj->x_network_server.lst);
	g_free (bzobj->x_network_server.adapter_address);
	g_free (bzobj->d_adapter.address);
	g_free (bzobj->d_network.interface);
	g_free (bzobj->d_device.address);
	g_free (bzobj->d_device.name);
	g_free (bzobj->d_device.adapter);
	g_free (bzobj);
}

/*****************************************************************************/

static const char *
_bzobj_to_string (const BzDBusObj *bzobj, char *buf, gsize len)
{
	char *buf0 = buf;
	const char *prefix = "";
	gboolean device_is_usable;
	gboolean create_panu_connection = FALSE;
	gboolean network_server_is_usable;
	char sbuf_cap[100];

	if (len > 0)
		buf[0] = '\0';

	if (bzobj->d_has_adapter_iface) {
		nm_utils_strbuf_append_str (&buf, &len, prefix);
		prefix = ", ";
		nm_utils_strbuf_append_str (&buf, &len, "Adapter1 {");
		if (bzobj->d_adapter.address) {
			nm_utils_strbuf_append (&buf, &len, " d.address: \"%s\"", bzobj->d_adapter.address);
			if (bzobj->d_adapter_powered)
				nm_utils_strbuf_append_str (&buf, &len, ",");
		}
		if (bzobj->d_adapter_powered)
			nm_utils_strbuf_append (&buf, &len, " d.powered: 1");
		nm_utils_strbuf_append_str (&buf, &len, " }");
	}

	if (bzobj->d_has_device_iface) {
		const char *prefix1 = "";

		nm_utils_strbuf_append_str (&buf, &len, prefix);
		prefix = ", ";
		nm_utils_strbuf_append_str (&buf, &len, "Device1 {");
		if (bzobj->d_device.address) {
			nm_utils_strbuf_append (&buf, &len, "%s d.address: \"%s\"", prefix1, bzobj->d_device.address);
			prefix1 = ",";
		}
		if (bzobj->d_device.name) {
			nm_utils_strbuf_append (&buf, &len, "%s d.name: \"%s\"", prefix1, bzobj->d_device.name);
			prefix1 = ",";
		}
		if (bzobj->d_device.adapter) {
			nm_utils_strbuf_append (&buf, &len, "%s d.adapter: \"%s\"", prefix1, bzobj->d_device.adapter);
			prefix1 = ",";
		}
		if (bzobj->d_device_capabilities != NM_BT_CAPABILITY_NONE) {
			nm_utils_strbuf_append (&buf, &len, "%s d.capabilities: \"%s\"",
			                        prefix1,
			                        nm_bluetooth_capability_to_string (bzobj->d_device_capabilities, sbuf_cap, sizeof (sbuf_cap)));
			prefix1 = ",";
		}
		if (bzobj->d_device_connected) {
			nm_utils_strbuf_append (&buf, &len, "%s d.connected: 1", prefix1);
			prefix1 = ",";
		}
		if (bzobj->d_device_paired) {
			nm_utils_strbuf_append (&buf, &len, "%s d.paired: 1", prefix1);
			prefix1 = ",";
		}
		nm_utils_strbuf_append_str (&buf, &len, " }");
	}

	network_server_is_usable = _bzobjs_network_server_is_usable (bzobj, TRUE);

	if (   bzobj->d_has_network_server_iface
	    || network_server_is_usable != (!c_list_is_empty (&bzobj->x_network_server.lst))
	    || !c_list_is_empty (&bzobj->x_network_server.lst)
	    || !nm_streq0 (bzobj->d_has_adapter_iface ? bzobj->d_adapter.address : NULL, bzobj->x_network_server.adapter_address)
	    || bzobj->x_network_server.device_br
	    || bzobj->x_network_server.r_req_data) {

		nm_utils_strbuf_append_str (&buf, &len, prefix);
		prefix = ", ";

		nm_utils_strbuf_append (&buf, &len, "NetworkServer1 { ");

		if (!bzobj->d_has_network_server_iface)
			nm_utils_strbuf_append (&buf, &len, " has-d-iface: 0, ");

		if (network_server_is_usable != (!c_list_is_empty (&bzobj->x_network_server.lst)))
			nm_utils_strbuf_append (&buf, &len, "usable: %d, used: %d", !!network_server_is_usable, !network_server_is_usable);
		else if (network_server_is_usable)
			nm_utils_strbuf_append (&buf, &len, "used: 1");
		else
			nm_utils_strbuf_append (&buf, &len, "usable: 0");

		if (!nm_streq0 (bzobj->d_has_adapter_iface ? bzobj->d_adapter.address : NULL, bzobj->x_network_server.adapter_address)) {
			if (bzobj->x_network_server.adapter_address)
				nm_utils_strbuf_append (&buf, &len, ", adapter-address: \"%s\"", bzobj->x_network_server.adapter_address);
			else
				nm_utils_strbuf_append (&buf, &len, ", adapter-address: <NULL>");
		}

		if (bzobj->x_network_server.device_br)
			nm_utils_strbuf_append (&buf, &len, ", bridge-device: 1");

		if (bzobj->x_network_server.r_req_data)
			nm_utils_strbuf_append (&buf, &len, ", register-in-progress: 1");

		nm_utils_strbuf_append_str (&buf, &len, " }");
	}

	device_is_usable = _bzobjs_device_is_usable (bzobj, NULL, &create_panu_connection);

	if (   bzobj->d_has_network_iface
	    || bzobj->d_network.interface
	    || bzobj->d_network_connected
	    || create_panu_connection
	    || bzobj->x_device.panu_connection
	    || device_is_usable != bzobj->x_device_is_usable
	    || bzobj->x_device.device_bt
	    || bzobj->x_device_connect_bt_type != NM_BT_CAPABILITY_NONE
	    || bzobj->x_device.connect_dun_context
	    || bzobj->x_device.c_req_data
	    || bzobj->x_device_is_connected != bzobj->d_network_connected) {

		nm_utils_strbuf_append_str (&buf, &len, prefix);
		prefix = ", ";
		nm_utils_strbuf_append_str (&buf, &len, "Network1 {");
		if (bzobj->d_network.interface)
			nm_utils_strbuf_append (&buf, &len, " d.interface: \"%s\", ", bzobj->d_network.interface);
		if (bzobj->d_network_connected)
			nm_utils_strbuf_append (&buf, &len, " d.connected: %d, ", !!bzobj->d_network_connected);
		if (!bzobj->d_has_network_iface)
			nm_utils_strbuf_append (&buf, &len, " has-d-iface: 0, ");
		if (device_is_usable != bzobj->x_device_is_usable)
			nm_utils_strbuf_append (&buf, &len, " usable: %d, used: %d", !!device_is_usable, !device_is_usable);
		else if (device_is_usable)
			nm_utils_strbuf_append (&buf, &len, " used: 1");
		else
			nm_utils_strbuf_append (&buf, &len, " usable: 0");

		if (create_panu_connection)
			nm_utils_strbuf_append (&buf, &len, ", create-panu-connection: 1");

		if (bzobj->x_device.panu_connection)
			nm_utils_strbuf_append (&buf, &len, ", has-panu-connection: 1");

		if (bzobj->x_device.device_bt)
			nm_utils_strbuf_append (&buf, &len, ", has-device: 1");

		if (   bzobj->x_device_connect_bt_type != NM_BT_CAPABILITY_NONE
		    || bzobj->x_device.connect_dun_context) {
			nm_utils_strbuf_append (&buf, &len, ", connect: %s%s",
			                        nm_bluetooth_capability_to_string (bzobj->x_device_connect_bt_type, sbuf_cap, sizeof (sbuf_cap)),
			                        bzobj->x_device.connect_dun_context ? ",with-dun-context" : "");
		}

		if (bzobj->x_device.c_req_data)
			nm_utils_strbuf_append (&buf, &len, ", connecting: 1");

		if (bzobj->x_device_is_connected != bzobj->d_network_connected)
			nm_utils_strbuf_append (&buf, &len, ", connected: %d", !!bzobj->x_device_is_connected);

		nm_utils_strbuf_append_str (&buf, &len, " }");
	}

	if (_bzobjs_is_dead (bzobj)) {
		nm_utils_strbuf_append_str (&buf, &len, prefix);
		prefix = ", ";
		nm_utils_strbuf_append_str (&buf, &len, "dead: 1");
	}

	if (!c_list_is_empty (&bzobj->process_change_lst)) {
		nm_utils_strbuf_append_str (&buf, &len, prefix);
		prefix = ", ";
		nm_utils_strbuf_append (&buf, &len, "change-pending-on-idle: 1");
	}

	if (_bzobjs_adapter_is_usable_for_device (bzobj) != bzobj->was_usable_adapter_for_device_before) {
		nm_utils_strbuf_append_str (&buf, &len, prefix);
		prefix = ", ";
		nm_utils_strbuf_append (&buf, &len, "change-usable-adapter-for-device: 1");
	}

	return buf0;
}

#define _LOG_bzobj(bzobj, context) \
	G_STMT_START { \
		const BzDBusObj *const _bzobj = (bzobj); \
		char _buf[500]; \
		\
		_LOGT ("change %-21s %s : { %s }", \
		       (context), \
		       _bzobj->object_path, \
		       _bzobj_to_string (_bzobj, _buf, sizeof (_buf))); \
	} G_STMT_END

static gboolean
_bzobjs_is_dead (const BzDBusObj *bzobj)
{
	return    !bzobj->d_has_adapter_iface
	       && !bzobj->d_has_device_iface
	       && !bzobj->d_has_network_iface
	       && !bzobj->d_has_network_server_iface
	       && c_list_is_empty (&bzobj->process_change_lst);
}

static BzDBusObj *
_bzobjs_get (NMBluezManager *self, const char *object_path)
{
	return g_hash_table_lookup (NM_BLUEZ_MANAGER_GET_PRIVATE (self)->bzobjs, &object_path);
}

static BzDBusObj *
_bzobjs_add (NMBluezManager *self,
             const char *object_path)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);
	BzDBusObj *bzobj;

	bzobj = _bz_dbus_obj_new (self, object_path);
	if (!g_hash_table_add (priv->bzobjs, bzobj))
		nm_assert_not_reached ();
	return bzobj;
}

static void
_bzobjs_del (BzDBusObj *bzobj)
{
	nm_assert (bzobj);
	nm_assert (bzobj == _bzobjs_get (bzobj->self, bzobj->object_path));

	if (!g_hash_table_remove (NM_BLUEZ_MANAGER_GET_PRIVATE (bzobj->self)->bzobjs, bzobj))
		nm_assert_not_reached ();
}

static void
_bzobjs_del_if_dead (BzDBusObj *bzobj)
{
	if (_bzobjs_is_dead (bzobj))
		_bzobjs_del (bzobj);
}

static BzDBusObj *
_bzobjs_init (NMBluezManager *self, BzDBusObj **inout, const char *object_path)
{
	nm_assert (NM_IS_BLUEZ_MANAGER (self));
	nm_assert (object_path);
	nm_assert (inout);

	if (!*inout) {
		*inout = _bzobjs_get (self, object_path);
		if (!*inout)
			*inout = _bzobjs_add (self, object_path);
	}

	nm_assert (nm_streq ((*inout)->object_path, object_path));
	nm_assert (*inout == _bzobjs_get (self, object_path));
	return *inout;
}

static gboolean
_bzobjs_adapter_is_usable_for_device (const BzDBusObj *bzobj)
{
	return    bzobj->d_has_adapter_iface
	       && bzobj->d_adapter.address
	       && bzobj->d_adapter_powered;
}

static gboolean
_bzobjs_device_is_usable (const BzDBusObj *bzobj,
                          BzDBusObj **out_adapter_bzobj,
                          gboolean *out_create_panu_connection)
{
	NMBluezManager *self;
	NMBluezManagerPrivate *priv;
	gboolean usable_dun = FALSE;
	gboolean usable_nap = FALSE;
	BzDBusObj *bzobj_adapter;
	gboolean create_panu_connection = FALSE;

	if (   !bzobj->d_has_device_iface
	    || !NM_FLAGS_ANY ((NMBluetoothCapabilities) bzobj->d_device_capabilities, _NM_BT_CAPABILITY_SUPPORTED)
	    || !bzobj->d_device.name
	    || !bzobj->d_device.address
	    || !bzobj->d_device_paired
	    || !bzobj->d_device.adapter)
		goto out_unusable;

	self = bzobj->self;

	priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	if (!priv->settings_registered)
		goto out_unusable;

	bzobj_adapter = _bzobjs_get (self, bzobj->d_device.adapter);
	if (   !bzobj_adapter
	    || !_bzobjs_adapter_is_usable_for_device (bzobj_adapter))
		goto out_unusable;

#if WITH_BLUEZ5_DUN
	if (NM_FLAGS_HAS (bzobj->d_device_capabilities, NM_BT_CAPABILITY_DUN)) {
		if (_conn_track_find_head (self, NM_BT_CAPABILITY_DUN, bzobj->d_device.address))
			usable_dun = TRUE;
	}
#endif

	if (NM_FLAGS_HAS (bzobj->d_device_capabilities, NM_BT_CAPABILITY_NAP)) {
		if (!bzobj->d_has_network_iface)
			usable_nap = FALSE;
		else if (_conn_track_find_head (self, NM_BT_CAPABILITY_NAP, bzobj->d_device.address))
			usable_nap = TRUE;
		else if (bzobj->x_device_panu_connection_allow_create) {
			/* We didn't yet try to create a connection. Presume we are going to create
			 * it when the time comes... */
			usable_nap = TRUE;
			create_panu_connection = TRUE;
		}
	}

	if (   !usable_dun
	    && !usable_nap) {
		if (   bzobj->x_device.device_bt
		    && nm_device_get_state (NM_DEVICE (bzobj->x_device.device_bt)) > NM_DEVICE_STATE_DISCONNECTED) {
			/* The device is still activated... the absence of a profile does not
			 * render it unusable (yet). But since there is no more profile, the
			 * device is probably about to disconnect. */
		} else
			goto out_unusable;
	}

	NM_SET_OUT (out_create_panu_connection, create_panu_connection);
	NM_SET_OUT (out_adapter_bzobj, bzobj_adapter);
	return TRUE;

out_unusable:
	NM_SET_OUT (out_create_panu_connection, FALSE);
	NM_SET_OUT (out_adapter_bzobj, NULL);
	return FALSE;
}

static gboolean
_bzobjs_device_is_connected (const BzDBusObj *bzobj)
{
	nm_assert (_bzobjs_device_is_usable (bzobj, NULL, NULL));

	if (   !bzobj->d_has_device_iface
	    || !bzobj->d_device_connected)
		return FALSE;

	if (   bzobj->d_has_network_iface
	    && bzobj->d_network_connected)
		return TRUE;
	if (bzobj->x_device.connect_dun_context) {
		/* As long as we have a dun-context, we consider it connected.
		 *
		 * We require NMDeviceBt to try to connect to the modem, and if that fails,
		 * it will disconnect. */
		return TRUE;
	}
	return FALSE;
}

static gboolean
_bzobjs_network_server_is_usable (const BzDBusObj *bzobj,
                                  gboolean require_powered)
{
	return    bzobj->d_has_network_server_iface
	       && bzobj->d_has_adapter_iface
	       && bzobj->d_adapter.address
	       && (   !require_powered
	           || bzobj->d_adapter_powered);
}

/*****************************************************************************/

static ConnDataHead *
_conn_data_head_new (NMBluetoothCapabilities bt_type,
                     const char *bdaddr)
{
	ConnDataHead *cdata_hd;
	gsize l;

	nm_assert (NM_IN_SET (bt_type, NM_BT_CAPABILITY_DUN,
	                               NM_BT_CAPABILITY_NAP));
	nm_assert (bdaddr);

	l = strlen (bdaddr) + 1;
	cdata_hd = g_malloc (sizeof (ConnDataHead) + l);
	*cdata_hd = (ConnDataHead) {
		.bdaddr   = cdata_hd->bdaddr_data,
		.lst_head = C_LIST_INIT (cdata_hd->lst_head),
		.bt_type  = bt_type,
	};
	memcpy (cdata_hd->bdaddr_data, bdaddr, l);

	nm_assert (cdata_hd->bt_type == bt_type);

	return cdata_hd;
}

static guint
_conn_data_head_hash (gconstpointer ptr)
{
	const ConnDataHead *cdata_hd = ptr;
	NMHashState h;

	nm_hash_init (&h, 520317467u);
	nm_hash_update_val (&h, (NMBluetoothCapabilities) cdata_hd->bt_type);
	nm_hash_update_str (&h, cdata_hd->bdaddr);
	return nm_hash_complete (&h);
}

static gboolean
_conn_data_head_equal (gconstpointer a, gconstpointer b)
{
	const ConnDataHead *cdata_hd_a = a;
	const ConnDataHead *cdata_hd_b = b;

	return     cdata_hd_a->bt_type == cdata_hd_b->bt_type
	        && nm_streq (cdata_hd_a->bdaddr, cdata_hd_b->bdaddr);
}

static ConnDataHead *
_conn_track_find_head (NMBluezManager *self,
                       NMBluetoothCapabilities bt_type,
                       const char *bdaddr)
{
	ConnDataHead cdata_hd = {
		.bt_type = bt_type,
		.bdaddr  = bdaddr,
	};

	return g_hash_table_lookup (NM_BLUEZ_MANAGER_GET_PRIVATE (self)->conn_data_heads, &cdata_hd);
}

static ConnDataElem *
_conn_track_find_elem (NMBluezManager *self,
                       NMSettingsConnection *sett_conn)
{
	G_STATIC_ASSERT (G_STRUCT_OFFSET (ConnDataElem, sett_conn) == 0);

	return g_hash_table_lookup (NM_BLUEZ_MANAGER_GET_PRIVATE (self)->conn_data_elems, &sett_conn);
}

static gboolean
_conn_track_is_relevant_connection (NMConnection *connection,
                                    NMBluetoothCapabilities *out_bt_type,
                                    const char **out_bdaddr)
{
	NMSettingBluetooth *s_bt;
	NMBluetoothCapabilities bt_type;
	const char *bdaddr;
	const char *b_type;

	s_bt = nm_connection_get_setting_bluetooth (connection);
	if (!s_bt)
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_BLUETOOTH_SETTING_NAME))
		return FALSE;

	bdaddr = nm_setting_bluetooth_get_bdaddr (s_bt);
	if (!bdaddr)
		return FALSE;

	b_type = nm_setting_bluetooth_get_connection_type (s_bt);

	if (nm_streq (b_type, NM_SETTING_BLUETOOTH_TYPE_DUN))
		bt_type = NM_BT_CAPABILITY_DUN;
	else if (nm_streq (b_type, NM_SETTING_BLUETOOTH_TYPE_PANU))
		bt_type = NM_BT_CAPABILITY_NAP;
	else
		return FALSE;

	NM_SET_OUT (out_bt_type, bt_type);
	NM_SET_OUT (out_bdaddr, bdaddr);
	return TRUE;
}

static gboolean
_conn_track_is_relevant_sett_conn (NMSettingsConnection *sett_conn,
                                   NMBluetoothCapabilities *out_bt_type,
                                   const char **out_bdaddr)
{
	NMConnection *connection;

	connection = nm_settings_connection_get_connection (sett_conn);
	if (!connection)
		return FALSE;

	return _conn_track_is_relevant_connection (connection, out_bt_type, out_bdaddr);
}

static gboolean
_conn_track_is_relevant_for_sett_conn (NMSettingsConnection *sett_conn,
                                       NMBluetoothCapabilities bt_type,
                                       const char *bdaddr)
{
	NMBluetoothCapabilities x_bt_type;
	const char *x_bdaddr;

	return    bdaddr
	       && _conn_track_is_relevant_sett_conn (sett_conn, &x_bt_type, &x_bdaddr)
	       && x_bt_type == bt_type
	       && nm_streq (x_bdaddr, bdaddr);
}

static void
_conn_track_schedule_notify (NMBluezManager *self,
                             NMBluetoothCapabilities bt_type,
                             const char *bdaddr)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);
	GHashTableIter iter;
	BzDBusObj *bzobj;

	g_hash_table_iter_init (&iter, priv->bzobjs);
	while (g_hash_table_iter_next (&iter, (gpointer *) &bzobj, NULL)) {
		gboolean device_is_usable;

		device_is_usable = _bzobjs_device_is_usable (bzobj, NULL, NULL);
		if (bzobj->x_device_is_usable != device_is_usable)
			_process_change_idle_schedule (self, bzobj);
	}
}

static void
_conn_track_update (NMBluezManager *self,
                    NMSettingsConnection *sett_conn,
                    gboolean track,
                    gboolean *out_changed,
                    gboolean *out_changed_usable,
                    ConnDataElem **out_conn_data_elem)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);
	ConnDataHead *cdata_hd;
	ConnDataElem *cdata_el;
	ConnDataElem *cdata_el_remove = NULL;
	NMBluetoothCapabilities bt_type;
	const char *bdaddr;
	gboolean changed = FALSE;
	gboolean changed_usable = FALSE;
	char sbuf_cap[100];

	nm_assert (NM_IS_SETTINGS_CONNECTION (sett_conn));

	cdata_el = _conn_track_find_elem (self, sett_conn);

	if (track)
		track = _conn_track_is_relevant_sett_conn (sett_conn, &bt_type, &bdaddr);

	if (!track) {
		cdata_el_remove = g_steal_pointer (&cdata_el);
		goto out_remove;
	}

	if (cdata_el) {
		cdata_hd = cdata_el->cdata_hd;
		if (   cdata_hd->bt_type != bt_type
	        || !nm_streq (cdata_hd->bdaddr, bdaddr))
			cdata_el_remove = g_steal_pointer (&cdata_el);
	}

	if (!cdata_el) {
		_LOGT ("connecton: track for %s, %s: %s (%s)",
		       nm_bluetooth_capability_to_string (bt_type, sbuf_cap, sizeof (sbuf_cap)),
		       bdaddr,
		       nm_settings_connection_get_uuid (sett_conn),
		       nm_settings_connection_get_id (sett_conn));
		changed = TRUE;
		cdata_hd = _conn_track_find_head (self, bt_type, bdaddr);
		if (!cdata_hd) {
			changed_usable = TRUE;
			cdata_hd = _conn_data_head_new (bt_type, bdaddr);
			if (!g_hash_table_add (priv->conn_data_heads, cdata_hd))
				nm_assert_not_reached ();
			_conn_track_schedule_notify (self, bt_type, bdaddr);
		}
		cdata_el = g_slice_new (ConnDataElem);
		cdata_el->sett_conn = sett_conn;
		cdata_el->cdata_hd = cdata_hd;
		c_list_link_tail (&cdata_hd->lst_head, &cdata_el->lst);
		if (!g_hash_table_add (priv->conn_data_elems, cdata_el))
			nm_assert_not_reached ();
	}

out_remove:
	if (cdata_el_remove) {
		GHashTableIter iter;
		BzDBusObj *bzobj;

		_LOGT ("connecton: untrack for %s, %s: %s (%s)",
		       nm_bluetooth_capability_to_string (cdata_el_remove->cdata_hd->bt_type, sbuf_cap, sizeof (sbuf_cap)),
		       cdata_el_remove->cdata_hd->bdaddr,
		       nm_settings_connection_get_uuid (sett_conn),
		       nm_settings_connection_get_id (sett_conn));

		g_hash_table_iter_init (&iter, priv->bzobjs);
		while (g_hash_table_iter_next (&iter, (gpointer *) &bzobj, NULL)) {
			if (bzobj->x_device.panu_connection == sett_conn)
				bzobj->x_device.panu_connection = NULL;
		}

		changed = TRUE;
		cdata_hd = cdata_el_remove->cdata_hd;
		c_list_unlink_stale (&cdata_el_remove->lst);
		if (!g_hash_table_remove (priv->conn_data_elems, cdata_el_remove))
			nm_assert_not_reached ();
		if (c_list_is_empty (&cdata_hd->lst_head)) {
			changed_usable = TRUE;
			_conn_track_schedule_notify (self, cdata_hd->bt_type, cdata_hd->bdaddr);
			if (!g_hash_table_remove (priv->conn_data_heads, cdata_hd))
				nm_assert_not_reached ();
		}
	}

	NM_SET_OUT (out_changed, changed);
	NM_SET_OUT (out_changed_usable, changed_usable);
	NM_SET_OUT (out_conn_data_elem, cdata_el);
}

/*****************************************************************************/

static void
cp_connection_added (NMSettings *settings,
                     NMSettingsConnection *sett_conn,
                     NMBluezManager *self)
{
	_conn_track_update (self, sett_conn, TRUE, NULL, NULL, NULL);
}

static void
cp_connection_updated (NMSettings *settings,
                       NMSettingsConnection *sett_conn,
                       guint update_reason_u,
                       NMBluezManager *self)
{
	_conn_track_update (self, sett_conn, TRUE, NULL, NULL, NULL);
}

static void
cp_connection_removed (NMSettings *settings,
                       NMSettingsConnection *sett_conn,
                       NMBluezManager *self)
{
	_conn_track_update (self, sett_conn, FALSE, NULL, NULL, NULL);
}

/*****************************************************************************/

static NMBluezManager *
_network_server_get_bluez_manager (const NMBtVTableNetworkServer *vtable_network_server)
{
	NMBluezManager *self;

	self = (NMBluezManager *) (((char *) vtable_network_server) - G_STRUCT_OFFSET (NMBluezManager, _priv.vtable_network_server));

	g_return_val_if_fail (NM_IS_BLUEZ_MANAGER (self), NULL);

	return self;
}

static BzDBusObj *
_network_server_find_has_device (NMBluezManagerPrivate *priv,
                                 NMDevice *device)
{
	BzDBusObj *bzobj;

	c_list_for_each_entry (bzobj, &priv->network_server_lst_head, x_network_server.lst) {
		if (bzobj->x_network_server.device_br == device)
			return bzobj;
	}
	return NULL;
}

static BzDBusObj *
_network_server_find_available (NMBluezManagerPrivate *priv,
                                const char *addr,
                                NMDevice *device_accept_busy)
{
	BzDBusObj *bzobj;

	c_list_for_each_entry (bzobj, &priv->network_server_lst_head, x_network_server.lst) {
		if (bzobj->x_network_server.device_br) {
			if (bzobj->x_network_server.device_br != device_accept_busy)
				continue;
		}
		if (   addr
		    && !nm_streq (addr, bzobj->d_adapter.address))
			continue;
		nm_assert (!bzobj->x_network_server.r_req_data);
		return bzobj;
	}
	return NULL;
}

static gboolean
_network_server_vt_is_available (const NMBtVTableNetworkServer *vtable,
                                 const char *addr,
                                 NMDevice *device_accept_busy)
{
	NMBluezManager *self = _network_server_get_bluez_manager (vtable);
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	return !!_network_server_find_available (priv, addr, device_accept_busy);
}

static void
_network_server_register_cb (GObject *source_object,
                             GAsyncResult *res,
                             gpointer user_data)
{
	gs_unref_variant GVariant *ret = NULL;
	gs_free_error GError *error = NULL;
	BzDBusObj *bzobj;

	ret = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source_object), res, &error);
	if (   !ret
	    && nm_utils_error_is_cancelled (error))
		return;

	bzobj = user_data;

	if (!ret) {
		_LOGT ("NAP: [%s]: registering failed: %s", bzobj->object_path, error->message);
	} else
		_LOGT ("NAP: [%s]: registration successful", bzobj->object_path);

	g_clear_object (&bzobj->x_network_server.r_req_data->int_cancellable);
	_network_server_register_req_data_complete (g_steal_pointer (&bzobj->x_network_server.r_req_data), error);
}

static void
_network_server_register_cancelled_cb (GCancellable *cancellable,
                                       BzDBusObj *bzobj)
{
	_network_server_unregister_bridge (bzobj->self, bzobj, "registration cancelled");
}

static gboolean
_network_server_vt_register_bridge (const NMBtVTableNetworkServer *vtable,
                                    const char *addr,
                                    NMDevice *device,
                                    GCancellable *cancellable,
                                    NMBtVTableRegisterCallback callback,
                                    gpointer callback_user_data,
                                    GError **error)
{
	NMBluezManager *self = _network_server_get_bluez_manager (vtable);
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);
	NetworkServerRegisterReqData *r_req_data;
	BzDBusObj *bzobj;
	const char *ifname;

	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);
	g_return_val_if_fail (G_IS_CANCELLABLE (cancellable), FALSE);

	nm_assert (!g_cancellable_is_cancelled (cancellable));
	nm_assert (!_network_server_find_has_device (priv, device));

	ifname = nm_device_get_iface (device);
	g_return_val_if_fail (ifname, FALSE);

	g_return_val_if_fail (ifname, FALSE);

	bzobj = _network_server_find_available (priv, addr, NULL);
	if (!bzobj) {
		/* The device checked that a network server is available, before
		 * starting the activation, but for some reason it no longer is.
		 * Indicate that the activation should not proceed. */
		if (addr) {
			nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN,
			                    "adapter %s is not available for %s",
			                    addr, ifname);
		} else {
			nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN,
			                    "no adapter available for %s",
			                    ifname);
		}
		return FALSE;
	}

	_LOGD ("NAP: [%s]: registering \"%s\" on adapter %s",
	       bzobj->object_path,
	       ifname,
	       bzobj->d_adapter.address);

	r_req_data = g_slice_new (NetworkServerRegisterReqData);
	*r_req_data = (NetworkServerRegisterReqData) {
		.int_cancellable     = g_cancellable_new (),
		.ext_cancellable     = g_object_ref (cancellable),
		.callback            = callback,
		.callback_user_data  = callback_user_data,
		.ext_cancelled_id    = g_signal_connect (cancellable,
		                                         "cancelled",
		                                         G_CALLBACK (_network_server_register_cancelled_cb),
		                                         bzobj),
	};

	bzobj->x_network_server.device_br = g_object_ref (device);
	bzobj->x_network_server.r_req_data = r_req_data;

	g_dbus_connection_call (priv->dbus_connection,
	                        priv->name_owner,
	                        bzobj->object_path,
	                        NM_BLUEZ5_NETWORK_SERVER_INTERFACE,
	                        "Register",
	                        g_variant_new ("(ss)",
	                                       BLUETOOTH_CONNECT_NAP,
	                                       ifname),
	                        NULL,
	                        G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                        -1,
	                        bzobj->x_network_server.r_req_data->int_cancellable,
	                        _network_server_register_cb,
	                        bzobj);
	return TRUE;
}

static void
_network_server_unregister_bridge_complete_on_idle_cb (gpointer user_data,
                                                       GCancellable *cancellable)
{
	gs_free_error GError *error = NULL;
	gs_free char *reason  = NULL;
	NetworkServerRegisterReqData *r_req_data;

	nm_utils_user_data_unpack (user_data, &r_req_data, &reason);

	nm_utils_error_set (&error, NM_UTILS_ERROR_UNKNOWN,
	                    "registration was aborted due to %s",
	                    reason);
	_network_server_register_req_data_complete (r_req_data, error);
}

static void
_network_server_unregister_bridge (NMBluezManager *self,
                                   BzDBusObj *bzobj,
                                   const char *reason)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);
	_nm_unused gs_unref_object NMDevice *device = NULL;
	NetworkServerRegisterReqData *r_req_data;

	nm_assert (NM_IS_DEVICE (bzobj->x_network_server.device_br));

	_LOGD ("NAP: [%s]: unregistering \"%s\" (%s)",
	       bzobj->object_path,
	       nm_device_get_iface (bzobj->x_network_server.device_br),
	       reason);

	device = g_steal_pointer (&bzobj->x_network_server.device_br);

	r_req_data = g_steal_pointer (&bzobj->x_network_server.r_req_data);

	if (priv->name_owner) {
		gs_unref_object GCancellable *cancellable = NULL;

		cancellable = g_cancellable_new ();

		nm_shutdown_wait_obj_register_cancellable_full (cancellable,
		                                                g_strdup_printf ("bt-unregister-nap[%s]", bzobj->object_path),
		                                                TRUE);

		g_dbus_connection_call (priv->dbus_connection,
		                        priv->name_owner,
		                        bzobj->object_path,
		                        NM_BLUEZ5_NETWORK_SERVER_INTERFACE,
		                        "Unregister",
		                        g_variant_new ("(s)", BLUETOOTH_CONNECT_NAP),
		                        NULL,
		                        G_DBUS_CALL_FLAGS_NO_AUTO_START,
		                        -1,
		                        cancellable,
		                        _dbus_call_complete_cb_nop,
		                        NULL);
	}

	if (r_req_data) {
		nm_clear_g_cancellable (&r_req_data->int_cancellable);
		nm_utils_invoke_on_idle (r_req_data->ext_cancellable,
		                         _network_server_unregister_bridge_complete_on_idle_cb,
		                         nm_utils_user_data_pack (r_req_data, g_strdup (reason)));
	}

	_nm_device_bridge_notify_unregister_bt_nap (device, reason);
}

static gboolean
_network_server_vt_unregister_bridge (const NMBtVTableNetworkServer *vtable,
                                      NMDevice *device)
{
	NMBluezManager *self = _network_server_get_bluez_manager (vtable);
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);
	BzDBusObj *bzobj;

	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);

	bzobj = _network_server_find_has_device (priv, device);
	if (bzobj)
		_network_server_unregister_bridge (self, bzobj, "disconnecting");

	return TRUE;
}

static void
_network_server_process_change (BzDBusObj *bzobj,
                                gboolean *out_emit_device_availability_changed)
{
	NMBluezManager *self = bzobj->self;
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);
	gboolean network_server_is_usable;
	gboolean emit_device_availability_changed = FALSE;

	network_server_is_usable = _bzobjs_network_server_is_usable (bzobj, TRUE);

	if (!network_server_is_usable) {

		if (!c_list_is_empty (&bzobj->x_network_server.lst)) {
			emit_device_availability_changed = TRUE;
			c_list_unlink (&bzobj->x_network_server.lst);
		}

		nm_clear_g_free (&bzobj->x_network_server.adapter_address);

		if (bzobj->x_network_server.device_br) {
			_network_server_unregister_bridge (self,
			                                   bzobj,
			                                     _bzobjs_network_server_is_usable (bzobj, FALSE)
			                                   ? "adapter disabled"
			                                   : "adapter disappeared");
		}

	} else {

		if (!nm_streq0 (bzobj->x_network_server.adapter_address, bzobj->d_adapter.address)) {
			emit_device_availability_changed = TRUE;
			g_free (bzobj->x_network_server.adapter_address);
			bzobj->x_network_server.adapter_address = g_strdup (bzobj->d_adapter.address);
		}

		if (c_list_is_empty (&bzobj->x_network_server.lst)) {
			emit_device_availability_changed = TRUE;
			c_list_link_tail (&priv->network_server_lst_head, &bzobj->x_network_server.lst);
		}

	}

	if (emit_device_availability_changed)
		NM_SET_OUT (out_emit_device_availability_changed, TRUE);
}

/*****************************************************************************/

static void
_conn_create_panu_connection (NMBluezManager *self,
                              BzDBusObj *bzobj)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);
	gs_unref_object NMConnection *connection = NULL;
	NMSettingsConnection *added;
	NMSetting *setting;
	gs_free char *id = NULL;
	char uuid[37];
	gs_free_error GError *error = NULL;

	nm_utils_uuid_generate_buf (uuid);
	id = g_strdup_printf (_("%s Network"), bzobj->d_device.name);

	connection = nm_simple_connection_new ();

	setting = nm_setting_connection_new ();
	g_object_set (setting,
	              NM_SETTING_CONNECTION_ID, id,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_BLUETOOTH_SETTING_NAME,
	              NULL);
	nm_connection_add_setting (connection, setting);

	setting = nm_setting_bluetooth_new ();
	g_object_set (setting,
	              NM_SETTING_BLUETOOTH_BDADDR, bzobj->d_device.address,
	              NM_SETTING_BLUETOOTH_TYPE, NM_SETTING_BLUETOOTH_TYPE_PANU,
	              NULL);
	nm_connection_add_setting (connection, setting);

	if (!nm_connection_normalize (connection, NULL, NULL, &error)) {
		_LOGE ("connection: couldn't generate a connection for NAP device: %s",
		       error->message);
		g_return_if_reached ();
	}

	nm_assert (_conn_track_is_relevant_connection (connection, NULL, NULL));

	_LOGT ("connection: create in-memory PANU connection %s (%s) for device \"%s\" (%s)",
	       uuid,
	       id,
	       bzobj->d_device.name,
	       bzobj->d_device.address);

	nm_settings_add_connection (priv->settings,
	                            connection,
	                            NM_SETTINGS_CONNECTION_PERSIST_MODE_IN_MEMORY_ONLY,
	                            NM_SETTINGS_CONNECTION_ADD_REASON_NONE,
	                            NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED,
	                            &added,
	                            &error);
	if (!added) {
		_LOGW ("connection: couldn't add new Bluetooth connection for NAP device: '%s' (%s): %s",
		       id, uuid, error->message);
		return;
	}

	if (   !_conn_track_is_relevant_for_sett_conn (added, NM_BT_CAPABILITY_NAP, bzobj->d_device.address)
	    || !_conn_track_find_elem (self, added)
	    || bzobj->x_device.panu_connection) {
		_LOGE ("connection: something went wrong creating PANU connection %s (%s) for device '%s'",
		       uuid, id, bzobj->d_device.address);
		g_return_if_reached ();
	}

	bzobj->x_device.panu_connection = added;
}

/*****************************************************************************/

static void
_device_state_changed_cb (NMDevice *device,
                          guint new_state_u,
                          guint old_state_u,
                          guint reason_u,
                          gpointer user_data)
{
	BzDBusObj *bzobj = user_data;

	if (!_bzobjs_device_is_usable (bzobj, NULL, NULL)) {
		/* the device got unusable? Need to revisit it... */
		_process_change_idle_schedule (bzobj->self, bzobj);
	}
}

static void
_device_process_change (BzDBusObj *bzobj)
{
	NMBluezManager *self = bzobj->self;
	gs_unref_object NMDeviceBt *device_added = NULL;
	gs_unref_object NMDeviceBt *device_deleted = NULL;
	gboolean device_is_usable;
	gboolean create_panu_connection = FALSE;

	device_is_usable = _bzobjs_device_is_usable (bzobj, NULL, &create_panu_connection);

	if (create_panu_connection) {
		bzobj->x_device_panu_connection_allow_create = FALSE;
		_conn_create_panu_connection (self, bzobj);
		device_is_usable = _bzobjs_device_is_usable (bzobj, NULL, NULL);
	} else {
		if (   device_is_usable
		    && bzobj->x_device_panu_connection_allow_create
		    && NM_FLAGS_HAS (bzobj->d_device_capabilities, NM_BT_CAPABILITY_NAP)
		    && _conn_track_find_head (self, NM_BT_CAPABILITY_NAP, bzobj->d_device.address) ) {
			/* We have a useable device and also a panu-connection. We block future attemps
			 * to generate a connection. */
			bzobj->x_device_panu_connection_allow_create = FALSE;
		}
		if (bzobj->x_device.panu_connection) {
			if (!NM_FLAGS_HAS (nm_settings_connection_get_flags (bzobj->x_device.panu_connection),
			                   NM_SETTINGS_CONNECTION_INT_FLAGS_NM_GENERATED)) {
				/* the connection that we generated earlier still exists, but it's not longer the same
				 * as it was when we created it. Forget about it, so that we don't delete the profile later... */
				bzobj->x_device.panu_connection = NULL;
			} else {
				if (   !device_is_usable
				    || !_conn_track_is_relevant_for_sett_conn (bzobj->x_device.panu_connection,
				                                               NM_BT_CAPABILITY_NAP,
				                                               bzobj->d_device.address)) {
					_LOGT ("connection: delete in-memory PANU connection %s (%s) as device %s",
					       nm_settings_connection_get_uuid (bzobj->x_device.panu_connection),
					       nm_settings_connection_get_id (bzobj->x_device.panu_connection),
					       !device_is_usable ? "is now unusable" : "no longer matches");
					bzobj->x_device_panu_connection_allow_create = TRUE;
					nm_settings_connection_delete (g_steal_pointer (&bzobj->x_device.panu_connection), FALSE);
				}
			}
		}
	}

	bzobj->x_device_is_connected =    device_is_usable
	                               && _bzobjs_device_is_connected (bzobj);

	bzobj->x_device_is_usable = device_is_usable;

	if (bzobj->x_device.device_bt) {
		const char *device_to_delete_msg;

		if (!device_is_usable)
			device_to_delete_msg = "device became unusable";
		else if (!_nm_device_bt_for_same_device (bzobj->x_device.device_bt,
		                                         bzobj->object_path,
		                                         bzobj->d_device.address,
		                                         NULL,
		                                         bzobj->d_device_capabilities))
			device_to_delete_msg = "device is no longer compatible";
		else
			device_to_delete_msg = NULL;

		if (device_to_delete_msg) {
			nm_clear_g_signal_handler (bzobj->x_device.device_bt, &bzobj->x_device.device_bt_signal_id);

			device_deleted = g_steal_pointer (&bzobj->x_device.device_bt);

			_LOGD ("[%s]: drop device because %s",
			       bzobj->object_path,
			       device_to_delete_msg);

			_connect_disconnect (self, bzobj, device_to_delete_msg);
		}
	}

	if (device_is_usable) {
		if (!bzobj->x_device.device_bt) {
			bzobj->x_device.device_bt = nm_device_bt_new (self,
			                                              bzobj->object_path,
			                                              bzobj->d_device.address,
			                                              bzobj->d_device.name,
			                                              bzobj->d_device_capabilities);
			device_added = g_object_ref (bzobj->x_device.device_bt);
			bzobj->x_device.device_bt_signal_id = g_signal_connect (device_added,
			                                                        NM_DEVICE_STATE_CHANGED,
			                                                        G_CALLBACK (_device_state_changed_cb),
			                                                        bzobj);
		} else
			_nm_device_bt_notify_set_name (bzobj->x_device.device_bt, bzobj->d_device.name);

		_nm_device_bt_notify_set_connected (bzobj->x_device.device_bt, bzobj->x_device_is_connected);
	}

	if (   bzobj->x_device.c_req_data
	    && !bzobj->x_device.c_req_data->int_cancellable
	    && bzobj->x_device_is_connected) {
		gs_free char *device_name = g_steal_pointer (&bzobj->x_device.c_req_data->device_name);

		_device_connect_req_data_complete (g_steal_pointer (&bzobj->x_device.c_req_data),
		                                   self,
		                                   device_name,
		                                   NULL);
	}

	if (device_added)
		g_signal_emit_by_name (self, NM_DEVICE_FACTORY_DEVICE_ADDED, device_added);

	if (device_deleted)
		_nm_device_bt_notify_removed (device_deleted);
}

/*****************************************************************************/

static void
_process_change_idle_all (NMBluezManager *self,
                          gboolean *out_emit_device_availability_changed)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);
	BzDBusObj *bzobj;

	while ((bzobj = c_list_first_entry (&priv->process_change_lst_head, BzDBusObj, process_change_lst))) {

		c_list_unlink (&bzobj->process_change_lst);

		_LOG_bzobj (bzobj, "before-processing");

		_device_process_change (bzobj);

		_network_server_process_change (bzobj, out_emit_device_availability_changed);

		_LOG_bzobj (bzobj, "after-processing");

		_bzobjs_del_if_dead (bzobj);
	}

	nm_clear_g_source (&priv->process_change_idle_id);
}

static gboolean
_process_change_idle_cb (gpointer user_data)
{
	NMBluezManager *self = user_data;
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);
	gboolean emit_device_availability_changed = FALSE;

	_process_change_idle_all (self, &emit_device_availability_changed);

	if (emit_device_availability_changed)
		nm_manager_notify_device_availibility_maybe_changed (priv->manager);

	return G_SOURCE_CONTINUE;
}

static void
_process_change_idle_schedule (NMBluezManager *self,
                               BzDBusObj *bzobj)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	nm_c_list_move_tail (&priv->process_change_lst_head, &bzobj->process_change_lst);
	if (priv->process_change_idle_id == 0)
		priv->process_change_idle_id = g_idle_add_full (G_PRIORITY_DEFAULT_IDLE + 1, _process_change_idle_cb, self, NULL);
}

static void
_dbus_process_changes (NMBluezManager *self,
                       BzDBusObj *bzobj,
                       const char *log_reason)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);
	gboolean network_server_is_usable;
	gboolean adapter_is_usable_for_device;
	gboolean device_is_usable;
	gboolean changes = FALSE;
	gboolean recheck_devices_for_adapter = FALSE;

	nm_assert (bzobj);

	_LOG_bzobj (bzobj, log_reason);

	device_is_usable = _bzobjs_device_is_usable (bzobj, NULL, NULL);

	if (bzobj->x_device_is_usable != device_is_usable)
		changes = TRUE;
	else if (bzobj->x_device.device_bt) {
		if (!device_is_usable)
			changes = TRUE;
		else {
			if (   bzobj->x_device_is_connected != _bzobjs_device_is_connected (bzobj)
			    || !_nm_device_bt_for_same_device (bzobj->x_device.device_bt,
			                                       bzobj->object_path,
			                                       bzobj->d_device.address,
			                                       bzobj->d_device.name,
			                                       bzobj->d_device_capabilities))
				changes = TRUE;
		}
	}

	adapter_is_usable_for_device = _bzobjs_adapter_is_usable_for_device (bzobj);
	if (adapter_is_usable_for_device != bzobj->was_usable_adapter_for_device_before) {
		/* this function does not modify bzobj in any other cases except here.
		 * Usually changes are processed delayed, in the idle handler.
		 *
		 * But the bzobj->was_usable_adapter_for_device_before only exists to know whether
		 * we need to re-check device availability. It is correct to set the flag
		 * here, right before we checked. */
		bzobj->was_usable_adapter_for_device_before = adapter_is_usable_for_device;
		recheck_devices_for_adapter = TRUE;
		changes = TRUE;
	}

	if (!changes) {
		network_server_is_usable = _bzobjs_network_server_is_usable (bzobj, TRUE);

		if (network_server_is_usable != (!c_list_is_empty (&bzobj->x_network_server.lst)))
			changes = TRUE;
		else if (   bzobj->x_network_server.device_br
		         && !network_server_is_usable)
			changes = TRUE;
		else if (!nm_streq0 (bzobj->d_has_adapter_iface ? bzobj->d_adapter.address : NULL,
		                     bzobj->x_network_server.adapter_address))
			changes = TRUE;
	}

	if (changes)
		_process_change_idle_schedule (self, bzobj);

	if (recheck_devices_for_adapter) {
		GHashTableIter iter;
		BzDBusObj *bzobj2;

		/* we got a change to the availability of an adapter. We might need to recheck
		 * all devices that use this adapter... */
		g_hash_table_iter_init (&iter, priv->bzobjs);
		while (g_hash_table_iter_next (&iter, (gpointer *) &bzobj2, NULL)) {
			if (bzobj2 == bzobj)
				continue;
			if (!nm_streq0 (bzobj2->d_device.adapter, bzobj->object_path))
				continue;
			if (c_list_is_empty (&bzobj2->process_change_lst))
				_dbus_process_changes (self, bzobj2, "adapter-changed");
			else
				nm_c_list_move_tail (&priv->process_change_lst_head, &bzobj2->process_change_lst);
		}
	}

	_bzobjs_del_if_dead (bzobj);
}

/*****************************************************************************/

#define ALL_RELEVANT_INTERFACE_NAMES NM_MAKE_STRV (NM_BLUEZ5_ADAPTER_INTERFACE, \
                                                   NM_BLUEZ5_DEVICE_INTERFACE, \
                                                   NM_BLUEZ5_NETWORK_INTERFACE, \
                                                   NM_BLUEZ5_NETWORK_SERVER_INTERFACE)

static gboolean
_dbus_handle_properties_changed (NMBluezManager *self,
                                 const char *object_path,
                                 const char *interface_name,
                                 GVariant *changed_properties,
                                 const char *const*invalidated_properties,
                                 BzDBusObj **inout_bzobj)
{
	BzDBusObj *bzobj = NULL;
	gboolean changed = FALSE;
	const char *property_name;
	GVariant *property_value;
	GVariantIter iter_prop;
	gsize i;

	if (!invalidated_properties)
		invalidated_properties = NM_PTRARRAY_EMPTY (const char *);

	nm_assert (g_variant_is_of_type (changed_properties, G_VARIANT_TYPE ("a{sv}")));

	if (inout_bzobj) {
		bzobj = *inout_bzobj;
		nm_assert (!bzobj || nm_streq (object_path, bzobj->object_path));
	}

	if (changed_properties)
		g_variant_iter_init (&iter_prop, changed_properties);

	if (nm_streq (interface_name, NM_BLUEZ5_ADAPTER_INTERFACE)) {
		_bzobjs_init (self, &bzobj, object_path);
		if (!bzobj->d_has_adapter_iface) {
			changed = TRUE;
			bzobj->d_has_adapter_iface = TRUE;
		}

		while (   changed_properties
		       && g_variant_iter_next (&iter_prop, "{&sv}", &property_name, &property_value)) {
			_nm_unused gs_unref_variant GVariant *property_value_free = property_value;

			if (nm_streq (property_name, "Address")) {
				gs_free char *s =   g_variant_is_of_type (property_value, G_VARIANT_TYPE_STRING)
				                  ? nm_utils_hwaddr_canonical (g_variant_get_string (property_value, NULL), ETH_ALEN)
				                  : NULL;

				if (!nm_streq0 (bzobj->d_adapter.address, s)) {
					changed = TRUE;
					nm_clear_g_free (&bzobj->d_adapter.address);
					bzobj->d_adapter.address = g_steal_pointer (&s);
				}
				continue;
			}
			if (nm_streq (property_name, "Powered")) {
				bool v =    g_variant_is_of_type (property_value, G_VARIANT_TYPE_BOOLEAN)
				         && g_variant_get_boolean (property_value);

				if (bzobj->d_adapter_powered != v) {
					changed = TRUE;
					bzobj->d_adapter_powered = v;
				}
				continue;
			}
		}

		for (i = 0; (property_name = invalidated_properties[i]); i++) {
			if (nm_streq (property_name, "Address")) {
				if (bzobj->d_adapter.address) {
					changed = TRUE;
					nm_clear_g_free (&bzobj->d_adapter.address);
				}
				continue;
			}
			if (nm_streq (property_name, "Powered")) {
				if (bzobj->d_adapter_powered) {
					changed = TRUE;
					bzobj->d_adapter_powered = FALSE;
				}
				continue;
			}
		}

	} else if (nm_streq (interface_name, NM_BLUEZ5_DEVICE_INTERFACE)) {
		_bzobjs_init (self, &bzobj, object_path);
		if (!bzobj->d_has_device_iface) {
			changed = TRUE;
			bzobj->d_has_device_iface = TRUE;
		}

		while (   changed_properties
		       && g_variant_iter_next (&iter_prop, "{&sv}", &property_name, &property_value)) {
			_nm_unused gs_unref_variant GVariant *property_value_free = property_value;

			if (nm_streq (property_name, "Address")) {
				gs_free char *s =   g_variant_is_of_type (property_value, G_VARIANT_TYPE_STRING)
				                  ? nm_utils_hwaddr_canonical (g_variant_get_string (property_value, NULL), ETH_ALEN)
				                  : NULL;

				if (!nm_streq0 (bzobj->d_device.address, s)) {
					changed = TRUE;
					nm_clear_g_free (&bzobj->d_device.address);
					bzobj->d_device.address = g_steal_pointer (&s);
				}
				continue;
			}
			if (nm_streq (property_name, "Name")) {
				const char *s =   g_variant_is_of_type (property_value, G_VARIANT_TYPE_STRING)
				                ? g_variant_get_string (property_value, NULL)
				                : NULL;

				if (!nm_streq0 (bzobj->d_device.name, s)) {
					changed = TRUE;
					nm_clear_g_free (&bzobj->d_device.name);
					bzobj->d_device.name = g_strdup (s);
				}
				continue;
			}
			if (nm_streq (property_name, "Adapter")) {
				const char *s =   g_variant_is_of_type (property_value, G_VARIANT_TYPE_OBJECT_PATH)
				                ? g_variant_get_string (property_value, NULL)
				                : NULL;

				if (!nm_streq0 (bzobj->d_device.adapter, s)) {
					changed = TRUE;
					nm_clear_g_free (&bzobj->d_device.adapter);
					bzobj->d_device.adapter = g_strdup (s);
				}
				continue;
			}
			if (nm_streq (property_name, "UUIDs")) {
				NMBluetoothCapabilities capabilities = NM_BT_CAPABILITY_NONE;

				if (g_variant_is_of_type (property_value, G_VARIANT_TYPE_STRING_ARRAY)) {
					gs_free const char **s = g_variant_get_strv (property_value, NULL);

					capabilities = convert_uuids_to_capabilities (s);
				}
				if (bzobj->d_device_capabilities != capabilities) {
					changed = TRUE;
					bzobj->d_device_capabilities = capabilities;
					nm_assert (bzobj->d_device_capabilities == capabilities);
				}
				continue;
			}
			if (nm_streq (property_name, "Connected")) {
				bool v =    g_variant_is_of_type (property_value, G_VARIANT_TYPE_BOOLEAN)
				         && g_variant_get_boolean (property_value);

				if (bzobj->d_device_connected != v) {
					changed = TRUE;
					bzobj->d_device_connected = v;
				}
				continue;
			}
			if (nm_streq (property_name, "Paired")) {
				bool v =    g_variant_is_of_type (property_value, G_VARIANT_TYPE_BOOLEAN)
				         && g_variant_get_boolean (property_value);

				if (bzobj->d_device_paired != v) {
					changed = TRUE;
					bzobj->d_device_paired = v;
				}
				continue;
			}
		}

		for (i = 0; (property_name = invalidated_properties[i]); i++) {
			if (nm_streq (property_name, "Address")) {
				if (bzobj->d_device.address) {
					changed = TRUE;
					nm_clear_g_free (&bzobj->d_device.address);
				}
				continue;
			}
			if (nm_streq (property_name, "Name")) {
				if (bzobj->d_device.name) {
					changed = TRUE;
					nm_clear_g_free (&bzobj->d_device.name);
				}
				continue;
			}
			if (nm_streq (property_name, "Adapter")) {
				if (bzobj->d_device.adapter) {
					changed = TRUE;
					nm_clear_g_free (&bzobj->d_device.adapter);
				}
				continue;
			}
			if (nm_streq (property_name, "UUIDs")) {
				if (bzobj->d_device_capabilities != NM_BT_CAPABILITY_NONE) {
					changed = TRUE;
					bzobj->d_device_capabilities = NM_BT_CAPABILITY_NONE;
				}
				continue;
			}
			if (nm_streq (property_name, "Connected")) {
				if (bzobj->d_device_connected) {
					changed = TRUE;
					bzobj->d_device_connected = FALSE;
				}
				continue;
			}
			if (nm_streq (property_name, "Paired")) {
				if (bzobj->d_device_paired) {
					changed = TRUE;
					bzobj->d_device_paired = FALSE;
				}
				continue;
			}
		}

	} else if (nm_streq (interface_name, NM_BLUEZ5_NETWORK_INTERFACE)) {
		_bzobjs_init (self, &bzobj, object_path);
		if (!bzobj->d_has_network_iface) {
			changed = TRUE;
			bzobj->d_has_network_iface = TRUE;
		}

		while (   changed_properties
		       && g_variant_iter_next (&iter_prop, "{&sv}", &property_name, &property_value)) {
			_nm_unused gs_unref_variant GVariant *property_value_free = property_value;

			if (nm_streq (property_name, "Interface")) {
				const char *s =   g_variant_is_of_type (property_value, G_VARIANT_TYPE_STRING)
				                ? g_variant_get_string (property_value, NULL)
				                : NULL;

				if (!nm_streq0 (bzobj->d_network.interface, s)) {
					changed = TRUE;
					nm_clear_g_free (&bzobj->d_network.interface);
					bzobj->d_network.interface = g_strdup (s);
				}
				continue;
			}
			if (nm_streq (property_name, "Connected")) {
				bool v =    g_variant_is_of_type (property_value, G_VARIANT_TYPE_BOOLEAN)
				         && g_variant_get_boolean (property_value);

				if (bzobj->d_network_connected != v) {
					changed = TRUE;
					bzobj->d_network_connected = v;
				}
				continue;
			}
		}

		for (i = 0; (property_name = invalidated_properties[i]); i++) {
			if (nm_streq (property_name, "Interface")) {
				if (bzobj->d_network.interface) {
					changed = TRUE;
					nm_clear_g_free (&bzobj->d_network.interface);
				}
				continue;
			}
			if (nm_streq (property_name, "Connected")) {
				if (bzobj->d_network_connected) {
					changed = TRUE;
					bzobj->d_network_connected = FALSE;
				}
				continue;
			}
		}

	} else if (nm_streq (interface_name, NM_BLUEZ5_NETWORK_SERVER_INTERFACE)) {
		_bzobjs_init (self, &bzobj, object_path);
		if (!bzobj->d_has_network_server_iface) {
			changed = TRUE;
			bzobj->d_has_network_server_iface = TRUE;
		}
	}

	nm_assert (!changed || bzobj);

	if (inout_bzobj)
		*inout_bzobj = bzobj;

	return changed;
}

static void
_dbus_handle_interface_added (NMBluezManager *self,
                              const char *object_path,
                              GVariant *ifaces,
                              gboolean initial_get_managed_objects)
{
	BzDBusObj *bzobj = NULL;
	gboolean changed = FALSE;
	const char *interface_name;
	GVariant *changed_properties;
	GVariantIter iter_ifaces;

	nm_assert (g_variant_is_of_type (ifaces, G_VARIANT_TYPE ("a{sa{sv}}")));

	g_variant_iter_init (&iter_ifaces, ifaces);
	while (g_variant_iter_next (&iter_ifaces, "{&s@a{sv}}", &interface_name, &changed_properties)) {
		_nm_unused gs_unref_variant GVariant *changed_properties_free = changed_properties;

		if (_dbus_handle_properties_changed (self, object_path, interface_name, changed_properties, NULL, &bzobj))
			changed = TRUE;
	}

	if (changed) {
		_dbus_process_changes (self,
		                       bzobj,
		                         initial_get_managed_objects
		                       ? "dbus-init"
		                       : "dbus-iface-added");
	}
}

static gboolean
_dbus_handle_interface_removed (NMBluezManager *self,
                                const char *object_path,
                                BzDBusObj **inout_bzobj,
                                const char *const*removed_interfaces)
{
	gboolean changed = FALSE;
	BzDBusObj *bzobj;
	gsize i;

	if (   inout_bzobj
	    && *inout_bzobj) {
		bzobj = *inout_bzobj;
		nm_assert (bzobj == _bzobjs_get (self, object_path));
	} else {
		bzobj = _bzobjs_get (self, object_path);
		if (!bzobj)
			return FALSE;
		NM_SET_OUT (inout_bzobj, bzobj);
	}

	for (i = 0; removed_interfaces[i]; i++) {
		const char *interface_name = removed_interfaces[i];

		if (nm_streq (interface_name, NM_BLUEZ5_ADAPTER_INTERFACE)) {
			if (bzobj->d_has_adapter_iface) {
				changed = TRUE;
				bzobj->d_has_adapter_iface = FALSE;
			}
			if (bzobj->d_adapter.address) {
				changed = TRUE;
				nm_clear_g_free (&bzobj->d_adapter.address);
			}
			if (bzobj->d_adapter_powered) {
				changed = TRUE;
				bzobj->d_adapter_powered = FALSE;
			}
		} else if (nm_streq (interface_name, NM_BLUEZ5_DEVICE_INTERFACE)) {
			if (bzobj->d_has_device_iface) {
				changed = TRUE;
				bzobj->d_has_device_iface = FALSE;
			}
			if (bzobj->d_device.address) {
				changed = TRUE;
				nm_clear_g_free (&bzobj->d_device.address);
			}
			if (bzobj->d_device.name) {
				changed = TRUE;
				nm_clear_g_free (&bzobj->d_device.name);
			}
			if (bzobj->d_device.adapter) {
				changed = TRUE;
				nm_clear_g_free (&bzobj->d_device.adapter);
			}
			if (bzobj->d_device_capabilities != NM_BT_CAPABILITY_NONE) {
				changed = TRUE;
				bzobj->d_device_capabilities = NM_BT_CAPABILITY_NONE;
			}
			if (bzobj->d_device_connected) {
				changed = TRUE;
				bzobj->d_device_connected = FALSE;
			}
			if (bzobj->d_device_paired) {
				changed = TRUE;
				bzobj->d_device_paired = FALSE;
			}
		} else if (nm_streq (interface_name, NM_BLUEZ5_NETWORK_INTERFACE)) {
			if (bzobj->d_has_network_iface) {
				changed = TRUE;
				bzobj->d_has_network_iface = FALSE;
			}
			if (bzobj->d_network.interface) {
				changed = TRUE;
				nm_clear_g_free (&bzobj->d_network.interface);
			}
			if (bzobj->d_network_connected) {
				changed = TRUE;
				bzobj->d_network_connected = FALSE;
			}
		} else if (nm_streq (interface_name, NM_BLUEZ5_NETWORK_SERVER_INTERFACE)) {
			if (bzobj->d_has_network_server_iface) {
				changed = TRUE;
				bzobj->d_has_network_server_iface = FALSE;
			}
		}
	}

	return changed;
}

static void
_dbus_managed_objects_changed_cb (GDBusConnection *connection,
                                  const char *sender_name,
                                  const char *arg_object_path,
                                  const char *interface_name,
                                  const char *signal_name,
                                  GVariant *parameters,
                                  gpointer user_data)
{
	NMBluezManager *self = user_data;
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);
	BzDBusObj *bzobj = NULL;
	gboolean changed;

	nm_assert (nm_streq0 (interface_name, DBUS_INTERFACE_OBJECT_MANAGER));

	if (priv->get_managed_objects_cancellable) {
		/* we still wait for the initial GetManagedObjects(). Ignore the event. */
		return;
	}

	if (nm_streq (signal_name, "InterfacesAdded")) {
		gs_unref_variant GVariant *interfaces_and_properties = NULL;
		const char *object_path;

		if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(oa{sa{sv}})")))
			return;

		g_variant_get (parameters,
		               "(&o@a{sa{sv}})",
		               &object_path,
		               &interfaces_and_properties);

		_dbus_handle_interface_added (self, object_path, interfaces_and_properties, FALSE);
		return;
	}

	if (nm_streq (signal_name, "InterfacesRemoved")) {
		gs_free const char **interfaces = NULL;
		const char *object_path;

		if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(oas)")))
			return;

		g_variant_get (parameters,
		               "(&o^a&s)",
		               &object_path,
		               &interfaces);

		changed = _dbus_handle_interface_removed (self, object_path, &bzobj, interfaces);
		if (changed)
			_dbus_process_changes (self, bzobj, "dbus-iface-removed");
		return;
	}
}

static void
_dbus_properties_changed_cb (GDBusConnection *connection,
                             const char *sender_name,
                             const char *object_path,
                             const char *signal_interface_name,
                             const char *signal_name,
                             GVariant *parameters,
                             gpointer user_data)
{
	NMBluezManager *self = user_data;
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);
	const char *interface_name;
	gs_unref_variant GVariant *changed_properties = NULL;
	gs_free const char **invalidated_properties = NULL;
	BzDBusObj *bzobj = NULL;

	if (priv->get_managed_objects_cancellable) {
		/* we still wait for the initial GetManagedObjects(). Ignore the event. */
		return;
	}

	if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(sa{sv}as)")))
		return;

	g_variant_get (parameters,
	               "(&s@a{sv}^a&s)",
	               &interface_name,
	               &changed_properties,
	               &invalidated_properties);

	if (_dbus_handle_properties_changed (self, object_path, interface_name, changed_properties, invalidated_properties, &bzobj))
		_dbus_process_changes (self, bzobj, "dbus-property-changed");
}

static void
_dbus_get_managed_objects_cb (GVariant *result,
                              GError *error,
                              gpointer user_data)
{
	NMBluezManager *self;
	NMBluezManagerPrivate *priv;
	GVariantIter iter;
	const char *object_path;
	GVariant *ifaces;

	if (   !result
	    && nm_utils_error_is_cancelled (error))
		return;

	self = user_data;
	priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	g_clear_object (&priv->get_managed_objects_cancellable);

	if (!result) {
		_LOGT ("initial GetManagedObjects() call failed: %s", error->message);
		_cleanup_for_name_owner (self);
		return;
	}

	_LOGT ("initial GetManagedObjects call succeeded");

	g_variant_iter_init (&iter, result);
	while (g_variant_iter_next (&iter, "{&o@a{sa{sv}}}", &object_path, &ifaces)) {
		_nm_unused gs_unref_variant GVariant *ifaces_free = ifaces;

		_dbus_handle_interface_added (self, object_path, ifaces, TRUE);
	}
}

/*****************************************************************************/

static void
_cleanup_for_name_owner (NMBluezManager *self)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);
	gboolean emit_device_availability_changed = FALSE;
	GHashTableIter iter;
	BzDBusObj *bzobj;
	gboolean first = TRUE;

	nm_clear_g_cancellable (&priv->get_managed_objects_cancellable);

	nm_clear_g_dbus_connection_signal (priv->dbus_connection,
	                                   &priv->managed_objects_changed_id);
	nm_clear_g_dbus_connection_signal (priv->dbus_connection,
	                                   &priv->properties_changed_id);

	nm_clear_g_free (&priv->name_owner);

	g_hash_table_iter_init (&iter, priv->bzobjs);
	while (g_hash_table_iter_next (&iter, (gpointer *) &bzobj, NULL)) {
		if (first) {
			first = FALSE;
			_LOGT ("drop all objects form D-Bus cache...");
		}
		_dbus_handle_interface_removed (self,
		                                bzobj->object_path,
		                                &bzobj,
		                                ALL_RELEVANT_INTERFACE_NAMES);
		nm_c_list_move_tail (&priv->process_change_lst_head, &bzobj->process_change_lst);
	}
	_process_change_idle_all (self, &emit_device_availability_changed);
	nm_assert (g_hash_table_size (priv->bzobjs) == 0);

	if (emit_device_availability_changed)
		nm_manager_notify_device_availibility_maybe_changed (priv->manager);
}

static void
name_owner_changed (NMBluezManager *self,
                    const char *owner)
{
	_nm_unused gs_unref_object NMBluezManager *self_keep_alive = g_object_ref (self);
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	owner = nm_str_not_empty (owner);

	if (!owner)
		_LOGT ("D-Bus name for bluez has no owner");
	else
		_LOGT ("D-Bus name for bluez has owner %s", owner);

	nm_clear_g_cancellable (&priv->name_owner_get_cancellable);

	if (nm_streq0 (priv->name_owner, owner))
		return;

	_cleanup_for_name_owner (self);

	if (!owner)
		return;

	priv->name_owner = g_strdup (owner);

	priv->get_managed_objects_cancellable = g_cancellable_new ();

	priv->managed_objects_changed_id = nm_dbus_connection_signal_subscribe_object_manager (priv->dbus_connection,
	                                                                                       priv->name_owner,
	                                                                                       NM_BLUEZ_MANAGER_PATH,
	                                                                                       NULL,
	                                                                                       _dbus_managed_objects_changed_cb,
	                                                                                       self,
	                                                                                       NULL);

	priv->properties_changed_id = nm_dbus_connection_signal_subscribe_properties_changed (priv->dbus_connection,
	                                                                                      priv->name_owner,
	                                                                                      NULL,
	                                                                                      NULL,
	                                                                                      _dbus_properties_changed_cb,
	                                                                                      self,
	                                                                                      NULL);

	nm_dbus_connection_call_get_managed_objects (priv->dbus_connection,
	                                             priv->name_owner,
	                                             NM_BLUEZ_MANAGER_PATH,
	                                             G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                                             20000,
	                                             priv->get_managed_objects_cancellable,
	                                             _dbus_get_managed_objects_cb,
	                                             self);
}

static void
name_owner_changed_cb (GDBusConnection *connection,
                       const char *sender_name,
                       const char *object_path,
                       const char *interface_name,
                       const char *signal_name,
                       GVariant *parameters,
                       gpointer user_data)
{
	NMBluezManager *self = user_data;
	const char *new_owner;

	if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(sss)")))
		return;

	g_variant_get (parameters,
	               "(&s&s&s)",
	               NULL,
	               NULL,
	               &new_owner);

	name_owner_changed (self, new_owner);
}

static void
name_owner_get_cb (const char *name_owner,
                   GError *error,
                   gpointer user_data)
{
	if (   name_owner
	    || !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		name_owner_changed (user_data, name_owner);
}

/*****************************************************************************/

static void
_cleanup_all (NMBluezManager *self)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	priv->settings_registered = FALSE;

	g_signal_handlers_disconnect_by_func (priv->settings, cp_connection_added, self);
	g_signal_handlers_disconnect_by_func (priv->settings, cp_connection_updated, self);
	g_signal_handlers_disconnect_by_func (priv->settings, cp_connection_removed, self);

	g_hash_table_remove_all (priv->conn_data_elems);
	g_hash_table_remove_all (priv->conn_data_heads);

	_cleanup_for_name_owner (self);

	nm_clear_g_cancellable (&priv->name_owner_get_cancellable);

	nm_clear_g_dbus_connection_signal (priv->dbus_connection,
	                                   &priv->name_owner_changed_id);
}

static void
start (NMDeviceFactory *factory)
{
	NMBluezManager *self;
	NMBluezManagerPrivate *priv;
	NMSettingsConnection *const*sett_conns;
	guint n_sett_conns;
	guint i;

	g_return_if_fail (NM_IS_BLUEZ_MANAGER (factory));

	self = NM_BLUEZ_MANAGER (factory);
	priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	_cleanup_all (self);

	if (!priv->dbus_connection) {
		_LOGI ("no D-Bus connection available");
		return;
	}

	g_signal_connect (priv->settings, NM_SETTINGS_SIGNAL_CONNECTION_ADDED,   G_CALLBACK (cp_connection_added),   self);
	g_signal_connect (priv->settings, NM_SETTINGS_SIGNAL_CONNECTION_UPDATED, G_CALLBACK (cp_connection_updated), self);
	g_signal_connect (priv->settings, NM_SETTINGS_SIGNAL_CONNECTION_REMOVED, G_CALLBACK (cp_connection_removed), self);

	priv->settings_registered = TRUE;

	sett_conns = nm_settings_get_connections (priv->settings, &n_sett_conns);
	for (i = 0; i < n_sett_conns; i++)
		_conn_track_update (self, sett_conns[i], TRUE, NULL, NULL, NULL);

	priv->name_owner_changed_id = nm_dbus_connection_signal_subscribe_name_owner_changed (priv->dbus_connection,
	                                                                                      NM_BLUEZ_SERVICE,
	                                                                                      name_owner_changed_cb,
	                                                                                      self,
	                                                                                      NULL);

	priv->name_owner_get_cancellable = g_cancellable_new ();

	nm_dbus_connection_call_get_name_owner (priv->dbus_connection,
	                                        NM_BLUEZ_SERVICE,
	                                        10000,
	                                        priv->name_owner_get_cancellable,
	                                        name_owner_get_cb,
	                                        self);
}

/*****************************************************************************/

static void
_connect_returned (NMBluezManager *self,
                   BzDBusObj *bzobj,
                   NMBluetoothCapabilities bt_type,
                   const char *device_name,
                   NMBluez5DunContext *dun_context,
                   GError *error)
{
	char sbuf_cap[100];

	if (error) {
		nm_assert (!device_name);
		nm_assert (!dun_context);

		_LOGI ("%s [%s]: connect failed: %s",
		       nm_bluetooth_capability_to_string (bzobj->x_device_connect_bt_type, sbuf_cap, sizeof (sbuf_cap)),
		       bzobj->object_path,
		       error->message);

		_device_connect_req_data_complete (g_steal_pointer (&bzobj->x_device.c_req_data),
		                                   self,
		                                   NULL,
		                                   error);
		_connect_disconnect (self, bzobj, "cleanup after connect failure");
		return;
	}

	nm_assert (bzobj->x_device_connect_bt_type == bt_type);
	nm_assert (device_name);
	nm_assert ((bt_type == NM_BT_CAPABILITY_DUN) == (!!dun_context));
	nm_assert (bzobj->x_device.c_req_data);

	g_clear_object (&bzobj->x_device.c_req_data->int_cancellable);

	bzobj->x_device.connect_dun_context = dun_context;

	_LOGD ("%s [%s]: connect successful to device %s",
	       nm_bluetooth_capability_to_string (bzobj->x_device_connect_bt_type, sbuf_cap, sizeof (sbuf_cap)),
	       bzobj->object_path,
	       device_name);

	/* we already have another over-all timer running. But after we connected the device,
	 * we still need to wait for bluez to acknowledge the connected state (via D-Bus, for NAP).
	 * For DUN profiles we likely are already fully connected by now.
	 *
	 * Anyway, schedule another timeout that is possibly shorter than the overall, original
	 * timeout. Now this should go down fast. */
	bzobj->x_device.c_req_data->timeout_wait_connect_id = g_timeout_add (5000,
	                                                                     _connect_timeout_wait_connected_cb,
	                                                                     bzobj),
	bzobj->x_device.c_req_data->device_name = g_strdup (device_name);

	if (   _bzobjs_device_is_usable (bzobj, NULL, NULL)
	    && _bzobjs_device_is_connected (bzobj)) {
		/* We are now connected. Schedule the task that completes the state. */
		_process_change_idle_schedule (self, bzobj);
	}
}

#if WITH_BLUEZ5_DUN
static void
_connect_dun_notify_tty_hangup_cb (NMBluez5DunContext *context,
                                   gpointer user_data)
{
	BzDBusObj *bzobj = user_data;

	_connect_disconnect (bzobj->self,
	                     bzobj,
	                     "DUN connection hung up");
}

static void
_connect_dun_step2_cb (NMBluez5DunContext *context,
                       const char *rfcomm_dev,
                       GError *error,
                       gpointer user_data)
{
	BzDBusObj *bzobj;

	if (nm_utils_error_is_cancelled (error))
		return;

	bzobj = user_data;

	if (rfcomm_dev) {
		/* We want to early notifiy about the rfcomm path. That is because we might still delay
		 * to signal full activation longer (asynchronously). But the earliest time the callback
		 * is invoked with the rfcomm path, we just created the device synchronously.
		 *
		 * By already notifying the caller about the path early, it avoids a race where ModemManager
		 * would find the modem before the bluetooth code considers the profile fully activated. */

		nm_assert (!error);
		nm_assert (bzobj->x_device.c_req_data);

		if (!g_cancellable_is_cancelled (bzobj->x_device.c_req_data->ext_cancellable))
			bzobj->x_device.c_req_data->callback (bzobj->self, FALSE, rfcomm_dev, NULL, bzobj->x_device.c_req_data->callback_user_data);

		if (!context) {
			/* No context set. This means, we just got notified about the rfcomm path and need to wait
			 * longer, for the next callback. */
			return;
		}
	}

	_connect_returned (bzobj->self, bzobj, NM_BT_CAPABILITY_DUN, rfcomm_dev, context, error);
}

static void
_connect_dun_step1_cb (GObject *source_object,
                       GAsyncResult *res,
                       gpointer user_data)
{
	gs_unref_variant GVariant *ret = NULL;
	gs_free_error GError *error = NULL;
	BzDBusObj *bzobj_adapter;
	BzDBusObj *bzobj;

	ret = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source_object), res, &error);

	if (   !ret
	    && nm_utils_error_is_cancelled (error))
		return;

	bzobj = user_data;

	if (error) {
		_LOGT ("DUN: [%s]: bluetooth device connect failed: %s", bzobj->object_path, error->message);
		/* we actually ignore this error. Let's try, maybe we still can connect via DUN. */
		g_clear_error (&error);
	} else
		_LOGT ("DUN: [%s]: bluetooth device connected successfully", bzobj->object_path);

	if (!_bzobjs_device_is_usable (bzobj, &bzobj_adapter, NULL)) {
		nm_utils_error_set (&error, NM_UTILS_ERROR_UNKNOWN,
		                    "device %s is not usable for DUN after connect",
		                    bzobj->object_path);
		_connect_returned (bzobj->self, bzobj, NM_BT_CAPABILITY_DUN, NULL, NULL, error);
		return;
	}

	if (!nm_bluez5_dun_connect (bzobj_adapter->d_adapter.address,
	                            bzobj->d_device.address,
	                            bzobj->x_device.c_req_data->int_cancellable,
	                            _connect_dun_step2_cb,
	                            bzobj,
	                            _connect_dun_notify_tty_hangup_cb,
	                            bzobj,
	                            &error)) {
		_connect_returned (bzobj->self, bzobj, NM_BT_CAPABILITY_DUN, NULL, NULL, error);
		return;
	}
}
#endif

static void
_connect_nap_cb (GObject *source_object,
                 GAsyncResult *res,
                 gpointer user_data)
{
	gs_unref_variant GVariant *ret = NULL;
	const char *network_iface_name = NULL;
	gs_free_error GError *error = NULL;
	BzDBusObj *bzobj;

	ret = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source_object), res, &error);

	if (   !ret
	    && nm_utils_error_is_cancelled (error))
		return;

	if (ret)
		g_variant_get (ret, "(&s)", &network_iface_name);

	bzobj = user_data;

	_connect_returned (bzobj->self, bzobj, NM_BT_CAPABILITY_NAP, network_iface_name, NULL, error);
}

static void
_connect_cancelled_cb (GCancellable *cancellable,
                       BzDBusObj *bzobj)
{
	_connect_disconnect (bzobj->self, bzobj, "connect cancelled");
}

static gboolean
_connect_timeout_wait_connected_cb (gpointer user_data)
{
	BzDBusObj *bzobj = user_data;

	bzobj->x_device.c_req_data->timeout_wait_connect_id = 0;
	_connect_disconnect (bzobj->self, bzobj, "timeout waiting for connected");
	return G_SOURCE_REMOVE;
}

static gboolean
_connect_timeout_cb (gpointer user_data)
{
	BzDBusObj *bzobj = user_data;

	bzobj->x_device.c_req_data->timeout_id = 0;
	_connect_disconnect (bzobj->self, bzobj, "timeout connecting");
	return G_SOURCE_REMOVE;
}

static void
_connect_disconnect (NMBluezManager *self,
                     BzDBusObj *bzobj,
                     const char *reason)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);
	DeviceConnectReqData *c_req_data;
	char sbuf_cap[100];
	gboolean bt_type;

	if (bzobj->x_device_connect_bt_type == NM_BT_CAPABILITY_NONE) {
		nm_assert (!bzobj->x_device.c_req_data);
		return;
	}

	bt_type = bzobj->x_device_connect_bt_type;
	nm_assert (NM_IN_SET (bt_type, NM_BT_CAPABILITY_DUN, NM_BT_CAPABILITY_NAP));
	bzobj->x_device_connect_bt_type = NM_BT_CAPABILITY_NONE;

	c_req_data = g_steal_pointer (&bzobj->x_device.c_req_data);

	_LOGD ("%s [%s]: disconnect due to %s",
	       nm_bluetooth_capability_to_string (bt_type, sbuf_cap, sizeof (sbuf_cap)),
	       bzobj->object_path,
	       reason);

	if (c_req_data)
		nm_clear_g_cancellable (&c_req_data->int_cancellable);

	if (bt_type == NM_BT_CAPABILITY_DUN) {
		/* For DUN devices, we also called org.bluez.Device1.Connect() (because in order
		 * for nm_bluez5_dun_connect() to succeed, we need to be already connected *why??).
		 *
		 * But upon disconnect we don't call Disconnect() because we don't know whether somebody
		 * else also uses the bluetooth device for other purposes. During disconnect we only
		 * terminate the DUN connection, but don't disconnect entirely. I think that's the
		 * best we can do. */
#if WITH_BLUEZ5_DUN
		nm_clear_pointer (&bzobj->x_device.connect_dun_context, nm_bluez5_dun_disconnect);
#else
		nm_assert_not_reached ();
#endif
	} else {
		if (priv->name_owner) {
			gs_unref_object GCancellable *cancellable = NULL;

			cancellable = g_cancellable_new ();

			nm_shutdown_wait_obj_register_cancellable_full (cancellable,
			                                                g_strdup_printf ("bt-disconnect-nap[%s]", bzobj->object_path),
			                                                TRUE);

			g_dbus_connection_call (priv->dbus_connection,
			                        priv->name_owner,
			                        bzobj->object_path,
			                        NM_BLUEZ5_NETWORK_INTERFACE,
			                        "Disconnect",
			                        g_variant_new("()"),
			                        NULL,
			                        G_DBUS_CALL_FLAGS_NO_AUTO_START,
			                        -1,
			                        cancellable,
			                        _dbus_call_complete_cb_nop,
			                        NULL);
		}
	}

	if (c_req_data) {
		gs_free_error GError *error = NULL;

		nm_utils_error_set (&error,
		                    NM_UTILS_ERROR_UNKNOWN,
		                    "connect aborted due to %s",
		                    reason);
		_device_connect_req_data_complete (c_req_data, self, NULL, error);
	}
}

gboolean
nm_bluez_manager_connect (NMBluezManager *self,
                          const char *object_path,
                          NMBluetoothCapabilities connection_bt_type,
                          int timeout_msec,
                          GCancellable *cancellable,
                          NMBluezManagerConnectCb callback,
                          gpointer callback_user_data,
                          GError **error)
{
	gs_unref_object GCancellable *int_cancellable = NULL;
	DeviceConnectReqData *c_req_data;
	NMBluezManagerPrivate *priv;
	BzDBusObj *bzobj;
	char sbuf_cap[100];

	g_return_val_if_fail (NM_IS_BLUEZ_MANAGER (self), FALSE);
	g_return_val_if_fail (NM_IN_SET (connection_bt_type, NM_BT_CAPABILITY_DUN,
	                                                     NM_BT_CAPABILITY_NAP), FALSE);
	g_return_val_if_fail (callback, FALSE);

	nm_assert (timeout_msec > 0);

	priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	bzobj = _bzobjs_get (self, object_path);

	if (!bzobj) {
		nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN,
		                    "device %s does not exist",
		                    object_path);
		return FALSE;
	}

	if (!_bzobjs_device_is_usable (bzobj, NULL, NULL)) {
		nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN,
		                    "device %s is not usable",
		                    object_path);
		return FALSE;
	}

	if (!NM_FLAGS_ALL (bzobj->d_device_capabilities, connection_bt_type)) {
		nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN,
		                    "device %s has not the required capabilities",
		                    object_path);
		return FALSE;
	}

#if !WITH_BLUEZ5_DUN
	if (connection_bt_type == NM_BT_CAPABILITY_DUN) {
		nm_utils_error_set (error, NM_UTILS_ERROR_UNKNOWN,
		                    "DUN is not supported");
		return FALSE;
	}
#endif

	_connect_disconnect (self, bzobj, "new activation");

	_LOGD ("%s [%s]: connecting...",
	       nm_bluetooth_capability_to_string (connection_bt_type, sbuf_cap, sizeof (sbuf_cap)),
	       bzobj->object_path);

	int_cancellable = g_cancellable_new();

#if WITH_BLUEZ5_DUN
	if (connection_bt_type == NM_BT_CAPABILITY_DUN) {
		g_dbus_connection_call (priv->dbus_connection,
		                        priv->name_owner,
		                        bzobj->object_path,
		                        NM_BLUEZ5_DEVICE_INTERFACE,
		                        "Connect",
		                        NULL,
		                        NULL,
		                        G_DBUS_CALL_FLAGS_NO_AUTO_START,
		                        timeout_msec,
		                        int_cancellable,
		                        _connect_dun_step1_cb,
		                        bzobj);
	} else
#endif
	{
		nm_assert (connection_bt_type == NM_BT_CAPABILITY_NAP);
		g_dbus_connection_call (priv->dbus_connection,
		                        priv->name_owner,
		                        bzobj->object_path,
		                        NM_BLUEZ5_NETWORK_INTERFACE,
		                        "Connect",
		                        g_variant_new ("(s)", BLUETOOTH_CONNECT_NAP),
		                        G_VARIANT_TYPE ("(s)"),
		                        G_DBUS_CALL_FLAGS_NO_AUTO_START,
		                        timeout_msec,
		                        int_cancellable,
		                        _connect_nap_cb,
		                        bzobj);
	}

	c_req_data = g_slice_new (DeviceConnectReqData);
	*c_req_data = (DeviceConnectReqData) {
		.int_cancellable     = g_steal_pointer (&int_cancellable),
		.ext_cancellable     = g_object_ref (cancellable),
		.callback            = callback,
		.callback_user_data  = callback_user_data,
		.ext_cancelled_id    = g_signal_connect (cancellable,
		                                         "cancelled",
		                                         G_CALLBACK (_connect_cancelled_cb),
		                                         bzobj),
		.timeout_id          = g_timeout_add (timeout_msec,
		                                      _connect_timeout_cb,
		                                      bzobj),
	};

	bzobj->x_device_connect_bt_type = connection_bt_type;
	bzobj->x_device.c_req_data = c_req_data;

	return TRUE;
}

void
nm_bluez_manager_disconnect (NMBluezManager *self,
                             const char *object_path)
{
	BzDBusObj *bzobj;

	g_return_if_fail (NM_IS_BLUEZ_MANAGER (self));
	g_return_if_fail (object_path);

	bzobj = _bzobjs_get (self, object_path);
	if (!bzobj)
		return;

	_connect_disconnect (self, bzobj, "disconnected by user");
}

/*****************************************************************************/

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	*out_ignore = TRUE;
	g_return_val_if_fail (plink->type == NM_LINK_TYPE_BNEP, NULL);
	return NULL;
}

static gboolean
match_connection (NMDeviceFactory *factory,
                  NMConnection *connection)
{
	const char *type = nm_connection_get_connection_type (connection);

	nm_assert (nm_streq (type, NM_SETTING_BLUETOOTH_SETTING_NAME));

	if (_nm_connection_get_setting_bluetooth_for_nap (connection))
		return FALSE;    /* handled by the bridge factory */

	return TRUE;
}

/*****************************************************************************/

static void
nm_bluez_manager_init (NMBluezManager *self)
{
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	priv->vtable_network_server = (NMBtVTableNetworkServer) {
		.is_available      = _network_server_vt_is_available,
		.register_bridge   = _network_server_vt_register_bridge,
		.unregister_bridge = _network_server_vt_unregister_bridge,
	};

	c_list_init (&priv->network_server_lst_head);
	c_list_init (&priv->process_change_lst_head);

	priv->conn_data_heads = g_hash_table_new_full (_conn_data_head_hash, _conn_data_head_equal, g_free, NULL);
	priv->conn_data_elems = g_hash_table_new_full (nm_pdirect_hash, nm_pdirect_equal, nm_g_slice_free_fcn (ConnDataElem), NULL);

	priv->bzobjs = g_hash_table_new_full (nm_pstr_hash, nm_pstr_equal, (GDestroyNotify) _bz_dbus_obj_free, NULL);

	priv->manager = g_object_ref (NM_MANAGER_GET);
	priv->settings = g_object_ref (NM_SETTINGS_GET);
	priv->dbus_connection = nm_g_object_ref (NM_MAIN_DBUS_CONNECTION_GET);

	g_atomic_pointer_compare_and_exchange (&nm_bt_vtable_network_server, NULL, &priv->vtable_network_server);
}

static void
dispose (GObject *object)
{
	NMBluezManager *self = NM_BLUEZ_MANAGER (object);
	NMBluezManagerPrivate *priv = NM_BLUEZ_MANAGER_GET_PRIVATE (self);

	/* FIXME(shutdown): we need a nm_device_factory_stop() hook to first unregister all
	 *   BzDBusObj instances and do necessary cleanup actions (like disconnecting devices
	 *   or deleting panu_connection). */

	nm_assert (c_list_is_empty (&priv->network_server_lst_head));
	nm_assert (c_list_is_empty (&priv->process_change_lst_head));
	nm_assert (priv->process_change_idle_id == 0);

	g_atomic_pointer_compare_and_exchange (&nm_bt_vtable_network_server, &priv->vtable_network_server, NULL);

	_cleanup_all (self);

	G_OBJECT_CLASS (nm_bluez_manager_parent_class)->dispose (object);

	g_clear_object (&priv->settings);
	g_clear_object (&priv->manager);
	g_clear_object (&priv->dbus_connection);

	nm_clear_pointer (&priv->bzobjs, g_hash_table_destroy);
}

static void
nm_bluez_manager_class_init (NMBluezManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceFactoryClass *factory_class = NM_DEVICE_FACTORY_CLASS (klass);

	object_class->dispose     = dispose;

	factory_class->get_supported_types = get_supported_types;
	factory_class->create_device       = create_device;
	factory_class->match_connection    = match_connection;
	factory_class->start               = start;
}
