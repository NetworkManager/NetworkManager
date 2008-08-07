/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include "nm-marshal.h"
#include "nm-setting-connection.h"
#include "nm-device-interface.h"
#include "nm-utils.h"

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
							  "Udi",
							  "HAL Udi",
							  NULL,
							  G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_interface_install_property
		(g_iface,
		 g_param_spec_string (NM_DEVICE_INTERFACE_IFACE,
							  "Interface",
							  "Interface",
							  NULL,
							  G_PARAM_READWRITE | G_PARAM_CONSTRUCT));

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
		 g_param_spec_object (NM_DEVICE_INTERFACE_IP4_CONFIG,
							  "IP4 Config",
							  "IP4 Config",
							  G_TYPE_OBJECT,
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
							G_PARAM_READABLE));

	g_object_interface_install_property
		(g_iface, g_param_spec_boolean (NM_DEVICE_INTERFACE_MANAGED,
	                                   "Managed",
	                                   "Managed",
	                                   TRUE,
	                                   G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/* Signals */
	g_signal_new ("state-changed",
				  iface_type,
				  G_SIGNAL_RUN_FIRST,
				  G_STRUCT_OFFSET (NMDeviceInterface, state_changed),
				  NULL, NULL,
				  nm_marshal_VOID__UINT_UINT_UINT,
				  G_TYPE_NONE, 3,
				  G_TYPE_UINT, G_TYPE_UINT, G_TYPE_UINT);

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
	nm_info ("Activation (%s) starting connection '%s'", iface, s_con->id);
	g_free (iface);

	success = NM_DEVICE_INTERFACE_GET_INTERFACE (device)->activate (device, req, error);
	if (!success)
		g_assert (*error);

	return success;
}

void
nm_device_interface_deactivate (NMDeviceInterface *device)
{
	g_return_if_fail (NM_IS_DEVICE_INTERFACE (device));

	NM_DEVICE_INTERFACE_GET_INTERFACE (device)->deactivate (device);
}

NMDeviceState
nm_device_interface_get_state (NMDeviceInterface *device)
{
	NMDeviceState state;

	g_object_get (G_OBJECT (device), "state", &state, NULL);
	return state;
}

