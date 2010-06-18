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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2010 Red Hat, Inc.
 */

#include <dbus/dbus-glib.h>

#include "nm-marshal.h"
#include "nm-setting-connection.h"
#include "nm-device-interface.h"
#include "nm-logging.h"
#include "nm-properties-changed-signal.h"
#include "nm-rfkill.h"

static void impl_device_disconnect (NMDeviceInterface *device,
                                    DBusGMethodInvocation *context);

#include "nm-device-interface-glue.h"

GQuark
nm_device_interface_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-device-interface-error");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_device_interface_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Connection is already activating. */
			ENUM_ENTRY (NM_DEVICE_INTERFACE_ERROR_CONNECTION_ACTIVATING, "ConnectionActivating"),
			/* Connection is invalid for this device. */
			ENUM_ENTRY (NM_DEVICE_INTERFACE_ERROR_CONNECTION_INVALID, "ConnectionInvalid"),
			/* Operation could not be performed because the device is not active. */
			ENUM_ENTRY (NM_DEVICE_INTERFACE_ERROR_NOT_ACTIVE, "NotActive"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMDeviceInterfaceError", values);
	}
	return etype;
}


static void
nm_device_interface_init (gpointer g_iface)
{
	GType iface_type = G_TYPE_FROM_INTERFACE (g_iface);
	static gboolean initialized = FALSE;

	if (initialized)
		return;

	/* Properties */
	g_object_interface_install_property
		(g_iface,
		 g_param_spec_string (NM_DEVICE_INTERFACE_UDI,
							  "UDI",
							  "Unique Device Identifier",
							  NULL,
							  G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_interface_install_property
		(g_iface,
		 g_param_spec_string (NM_DEVICE_INTERFACE_IFACE,
							  "Interface",
							  "Interface",
							  NULL,
							  G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_interface_install_property
		(g_iface,
		 g_param_spec_string (NM_DEVICE_INTERFACE_IP_IFACE,
		                      "IP Interface",
		                      "IP Interface",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_interface_install_property
		(g_iface,
		 g_param_spec_string (NM_DEVICE_INTERFACE_DRIVER,
							  "Driver",
							  "Driver",
							  NULL,
							  G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	
	g_object_interface_install_property
		(g_iface,
		 g_param_spec_uint (NM_DEVICE_INTERFACE_CAPABILITIES,
							"Capabilities",
							"Capabilities",
							0, G_MAXUINT32, NM_DEVICE_CAP_NONE,
							G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_interface_install_property
		(g_iface,
		 g_param_spec_uint (NM_DEVICE_INTERFACE_IP4_ADDRESS,
							"IP4 address",
							"IP4 address",
							0, G_MAXUINT32, 0, /* FIXME */
							G_PARAM_READWRITE));

	g_object_interface_install_property
		(g_iface,
		 g_param_spec_boxed (NM_DEVICE_INTERFACE_IP4_CONFIG,
							  "IP4 Config",
							  "IP4 Config",
							  DBUS_TYPE_G_OBJECT_PATH,
							  G_PARAM_READWRITE));

	g_object_interface_install_property
		(g_iface,
		 g_param_spec_boxed (NM_DEVICE_INTERFACE_DHCP4_CONFIG,
							  "DHCP4 Config",
							  "DHCP4 Config",
							  DBUS_TYPE_G_OBJECT_PATH,
							  G_PARAM_READWRITE));

	g_object_interface_install_property
		(g_iface,
		 g_param_spec_boxed (NM_DEVICE_INTERFACE_IP6_CONFIG,
							  "IP6 Config",
							  "IP6 Config",
							  DBUS_TYPE_G_OBJECT_PATH,
							  G_PARAM_READWRITE));

	g_object_interface_install_property
		(g_iface,
		 g_param_spec_boxed (NM_DEVICE_INTERFACE_DHCP6_CONFIG,
							  "DHCP6 Config",
							  "DHCP6 Config",
							  DBUS_TYPE_G_OBJECT_PATH,
							  G_PARAM_READWRITE));

	g_object_interface_install_property
		(g_iface,
		 g_param_spec_uint (NM_DEVICE_INTERFACE_STATE,
							"State",
							"State",
							0, G_MAXUINT32, NM_DEVICE_STATE_UNKNOWN,
							G_PARAM_READABLE));

	g_object_interface_install_property
		(g_iface,
		 g_param_spec_uint (NM_DEVICE_INTERFACE_DEVICE_TYPE,
							"DeviceType",
							"DeviceType",
							0, G_MAXUINT32, NM_DEVICE_TYPE_UNKNOWN,
							G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | NM_PROPERTY_PARAM_NO_EXPORT));

	g_object_interface_install_property
		(g_iface, g_param_spec_boolean (NM_DEVICE_INTERFACE_MANAGED,
	                                   "Managed",
	                                   "Managed",
	                                   FALSE,
	                                   G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_interface_install_property
		(g_iface, g_param_spec_boolean (NM_DEVICE_INTERFACE_FIRMWARE_MISSING,
	                                   "FirmwareMissing",
	                                   "Firmware missing",
	                                   FALSE,
	                                   G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_interface_install_property
		(g_iface,
		 g_param_spec_string (NM_DEVICE_INTERFACE_TYPE_DESC,
							  "Type Description",
							  "Device type description",
							  NULL,
							  G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | NM_PROPERTY_PARAM_NO_EXPORT));

	g_object_interface_install_property
		(g_iface, g_param_spec_uint (NM_DEVICE_INTERFACE_RFKILL_TYPE,
	                                 "Rfkill Type",
	                                 "Type of rfkill switch (if any) supported by this device",
	                                 RFKILL_TYPE_WLAN,
	                                 RFKILL_TYPE_MAX,
	                                 RFKILL_TYPE_UNKNOWN,
	                                 G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | NM_PROPERTY_PARAM_NO_EXPORT));

	g_object_interface_install_property
		(g_iface,
		 g_param_spec_int (NM_DEVICE_INTERFACE_IFINDEX,
							"Ifindex",
							"Ifindex",
							0, G_MAXINT, 0,
							G_PARAM_READABLE | NM_PROPERTY_PARAM_NO_EXPORT));

	/* Signals */
	g_signal_new ("state-changed",
				  iface_type,
				  G_SIGNAL_RUN_FIRST,
				  G_STRUCT_OFFSET (NMDeviceInterface, state_changed),
				  NULL, NULL,
				  _nm_marshal_VOID__UINT_UINT_UINT,
				  G_TYPE_NONE, 3,
				  G_TYPE_UINT, G_TYPE_UINT, G_TYPE_UINT);

	g_signal_new (NM_DEVICE_INTERFACE_DISCONNECT_REQUEST,
	              iface_type,
	              G_SIGNAL_RUN_FIRST,
	              0, NULL, NULL,
	              g_cclosure_marshal_VOID__POINTER,
	              G_TYPE_NONE, 1, G_TYPE_POINTER);

	dbus_g_object_type_install_info (iface_type,
									 &dbus_glib_nm_device_interface_object_info);

	dbus_g_error_domain_register (NM_DEVICE_INTERFACE_ERROR,
	                              NULL,
	                              NM_TYPE_DEVICE_INTERFACE_ERROR);

	initialized = TRUE;
}


GType
nm_device_interface_get_type (void)
{
	static GType device_interface_type = 0;

	if (!device_interface_type) {
		const GTypeInfo device_interface_info = {
			sizeof (NMDeviceInterface), /* class_size */
			nm_device_interface_init,   /* base_init */
			NULL,		/* base_finalize */
			NULL,
			NULL,		/* class_finalize */
			NULL,		/* class_data */
			0,
			0,              /* n_preallocs */
			NULL
		};

		device_interface_type = g_type_register_static (G_TYPE_INTERFACE,
														"NMDeviceInterface",
														&device_interface_info, 0);

		g_type_interface_add_prerequisite (device_interface_type, G_TYPE_OBJECT);
	}

	return device_interface_type;
}

/* FIXME: This should be public and nm_device_get_iface() should be removed. */
static char *
nm_device_interface_get_iface (NMDeviceInterface *device)
{
	char *iface = NULL;

	g_return_val_if_fail (NM_IS_DEVICE_INTERFACE (device), NULL);

	g_object_get (device, NM_DEVICE_INTERFACE_IFACE, &iface, NULL);

	return iface;
}

gboolean
nm_device_interface_check_connection_compatible (NMDeviceInterface *device,
                                                 NMConnection *connection,
                                                 GError **error)
{
	g_return_val_if_fail (NM_IS_DEVICE_INTERFACE (device), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);
	g_return_val_if_fail (error != NULL, FALSE);
	g_return_val_if_fail (*error == NULL, FALSE);

	if (NM_DEVICE_INTERFACE_GET_INTERFACE (device)->check_connection_compatible)
		return NM_DEVICE_INTERFACE_GET_INTERFACE (device)->check_connection_compatible (device, connection, error);
	return TRUE;
}

gboolean
nm_device_interface_activate (NMDeviceInterface *device,
                              NMActRequest *req,
                              GError **error)
{
	gboolean success;
	NMConnection *connection;
	NMSettingConnection *s_con;
	char *iface;

	g_return_val_if_fail (NM_IS_DEVICE_INTERFACE (device), FALSE);
	g_return_val_if_fail (NM_IS_ACT_REQUEST (req), FALSE);

	connection = nm_act_request_get_connection (req);
	g_assert (connection);
	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	iface = nm_device_interface_get_iface (device);
	nm_log_info (LOGD_DEVICE, "Activation (%s) starting connection '%s'", iface,
			     nm_setting_connection_get_id (s_con));
	g_free (iface);

	success = NM_DEVICE_INTERFACE_GET_INTERFACE (device)->activate (device, req, error);
	if (!success)
		g_assert (*error);

	return success;
}

gboolean
nm_device_interface_disconnect (NMDeviceInterface *device,
                                GError **error)
{
	gboolean success = FALSE;

	g_return_val_if_fail (NM_IS_DEVICE_INTERFACE (device), FALSE);

	switch (nm_device_interface_get_state (device)) {
	case NM_DEVICE_STATE_UNKNOWN:
	case NM_DEVICE_STATE_UNMANAGED:
	case NM_DEVICE_STATE_UNAVAILABLE:
	case NM_DEVICE_STATE_DISCONNECTED:
		g_set_error_literal (error,
		                     NM_DEVICE_INTERFACE_ERROR,
		                     NM_DEVICE_INTERFACE_ERROR_NOT_ACTIVE,
		                     "Cannot disconnect an inactive device.");
		break;
	default:
		success = NM_DEVICE_INTERFACE_GET_INTERFACE (device)->disconnect (device, error);
		break;
	}

	return success;
}

static void
impl_device_disconnect (NMDeviceInterface *device,
                        DBusGMethodInvocation *context)
{
	g_signal_emit_by_name (device, NM_DEVICE_INTERFACE_DISCONNECT_REQUEST, context);
}

void
nm_device_interface_deactivate (NMDeviceInterface *device, NMDeviceStateReason reason)
{
	g_return_if_fail (NM_IS_DEVICE_INTERFACE (device));

	NM_DEVICE_INTERFACE_GET_INTERFACE (device)->deactivate (device, reason);
}

NMDeviceState
nm_device_interface_get_state (NMDeviceInterface *device)
{
	NMDeviceState state;

	g_object_get (G_OBJECT (device), "state", &state, NULL);
	return state;
}

gboolean
nm_device_interface_spec_match_list (NMDeviceInterface *device,
                                     const GSList *specs)
{
	g_return_val_if_fail (NM_IS_DEVICE_INTERFACE (device), FALSE);

	if (NM_DEVICE_INTERFACE_GET_INTERFACE (device)->spec_match_list)
		return NM_DEVICE_INTERFACE_GET_INTERFACE (device)->spec_match_list (device, specs);
	return FALSE;
}

NMConnection *
nm_device_interface_connection_match_config (NMDeviceInterface *device,
                                             const GSList *connections)
{
	g_return_val_if_fail (NM_IS_DEVICE_INTERFACE (device), NULL);

	if (NM_DEVICE_INTERFACE_GET_INTERFACE (device)->connection_match_config)
		return NM_DEVICE_INTERFACE_GET_INTERFACE (device)->connection_match_config (device, connections);
	return NULL;
}

gboolean
nm_device_interface_can_assume_connection (NMDeviceInterface *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_INTERFACE (device), FALSE);

	return !!NM_DEVICE_INTERFACE_GET_INTERFACE (device)->connection_match_config;
}

void
nm_device_interface_set_enabled (NMDeviceInterface *device, gboolean enabled)
{
	g_return_if_fail (NM_IS_DEVICE_INTERFACE (device));

	if (NM_DEVICE_INTERFACE_GET_INTERFACE (device)->set_enabled)
		NM_DEVICE_INTERFACE_GET_INTERFACE (device)->set_enabled (device, enabled);
}

gboolean
nm_device_interface_get_enabled (NMDeviceInterface *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_INTERFACE (device), FALSE);

	if (NM_DEVICE_INTERFACE_GET_INTERFACE (device)->get_enabled)
		return NM_DEVICE_INTERFACE_GET_INTERFACE (device)->get_enabled (device);
	return TRUE;
}

