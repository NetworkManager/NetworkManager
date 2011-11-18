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
		 g_param_spec_boxed (NM_DEVICE_INTERFACE_ACTIVE_CONNECTION,
		                     "ActiveConnection",
		                     "ActiveConnection",
		                     DBUS_TYPE_G_OBJECT_PATH,
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

static void
impl_device_disconnect (NMDeviceInterface *device,
                        DBusGMethodInvocation *context)
{
	g_signal_emit_by_name (device, NM_DEVICE_INTERFACE_DISCONNECT_REQUEST, context);
}

