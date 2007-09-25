
#include "nm-device-interface.h"
#include "nm-ip4-config.h"
#include "nm-manager.h"
#include "nm-utils.h"

static gboolean impl_device_activate (NMDeviceInterface *device,
                                      const char *service_name,
                                      const char *connection_path,
                                      const char *specific_object,
                                      GError **err);

static gboolean impl_device_deactivate (NMDeviceInterface *device, GError **err);

#include "nm-device-interface-glue.h"

GQuark
nm_device_interface_error_quark (void)
{
  static GQuark quark = 0;
  if (!quark)
    quark = g_quark_from_static_string ("nm_device_interface_error");
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
			ENUM_ENTRY (NM_DEVICE_INTERFACE_ERROR_UNKNOWN_CONNECTION, "UnknownConnection"),
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
		 g_param_spec_uint (NM_DEVICE_INTERFACE_INDEX,
							"Index",
							"Index",
							0, G_MAXUINT32, 0, /* FIXME */
							G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_interface_install_property
		(g_iface,
		 g_param_spec_string (NM_DEVICE_INTERFACE_IFACE,
							  "Interface",
							  "Interface",
							  NULL,
							  G_PARAM_READABLE));

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
							0, G_MAXUINT32, DEVICE_TYPE_UNKNOWN,
							G_PARAM_READABLE));

	g_object_interface_install_property
		(g_iface,
		 g_param_spec_boolean (NM_DEVICE_INTERFACE_CARRIER,
							   "Carrier",
							   "Carrier",
							   FALSE,
							   G_PARAM_READABLE));

	/* Signals */
	g_signal_new ("state-changed",
				  iface_type,
				  G_SIGNAL_RUN_FIRST,
				  G_STRUCT_OFFSET (NMDeviceInterface, state_changed),
				  NULL, NULL,
				  g_cclosure_marshal_VOID__UINT,
				  G_TYPE_NONE, 1,
				  G_TYPE_UINT);

	g_signal_new ("carrier-changed",
				  iface_type,
				  G_SIGNAL_RUN_FIRST,
				  G_STRUCT_OFFSET (NMDeviceInterface, carrier_changed),
				  NULL, NULL,
				  g_cclosure_marshal_VOID__BOOLEAN,
				  G_TYPE_NONE, 1,
				  G_TYPE_BOOLEAN);

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

/* Pass _either_ connection_path or connection.  Passing 'connection' is
 * meant for internal use only.
 */
void
nm_device_interface_activate (NMDeviceInterface *device,
                              const char *service_name,
                              const char *connection_path,
                              NMConnection *connection,
                              const char *specific_object,
                              gboolean user_requested)
{
	g_return_if_fail (NM_IS_DEVICE_INTERFACE (device));

	NM_DEVICE_INTERFACE_GET_INTERFACE (device)->activate (device,
	                                                      service_name,
	                                                      connection_path,
	                                                      connection,
	                                                      specific_object,
	                                                      user_requested);
}

static gboolean
impl_device_activate (NMDeviceInterface *device,
                      const char *service_name,
                      const char *connection_path,
                      const char *specific_object,
                      GError **err)
{
	NMManager *manager = nm_manager_get ();
	NMDevice *old_dev = NULL;
	GSList *iter;

	// FIXME: remove when multiple active device support has landed
	switch (nm_manager_get_state (manager)) {
	case NM_STATE_CONNECTED:
		old_dev = nm_manager_get_active_device (manager);
		break;
	case NM_STATE_CONNECTING:
		for (iter = nm_manager_get_devices (manager); iter; iter = iter->next) {
			if (nm_device_is_activating (NM_DEVICE (iter->data))) {
				old_dev = NM_DEVICE (iter->data);
				break;
			}
		}
		break;
	case NM_STATE_DISCONNECTED:
		/* Check for devices that have deferred activation requests */
		for (iter = nm_manager_get_devices (manager); iter; iter = iter->next) {
			NMActRequest *req = nm_device_get_act_request (NM_DEVICE (iter->data));

			if (req && nm_act_request_is_deferred (req)) {
				old_dev = NM_DEVICE (iter->data);
				break;
			}
		}
		break;
	default:
		break;
	}
	g_object_unref (manager);

	nm_info ("User request for activation of %s.", nm_device_get_iface (NM_DEVICE (device)));

	if (old_dev)
		nm_device_interface_deactivate (NM_DEVICE_INTERFACE (old_dev));

	nm_device_interface_activate (device,
	                              service_name,
	                              connection_path,
	                              NULL,
	                              specific_object,
	                              TRUE);
	return TRUE;
}

void
nm_device_interface_deactivate (NMDeviceInterface *device)
{
	g_return_if_fail (NM_IS_DEVICE_INTERFACE (device));

	NM_DEVICE_INTERFACE_GET_INTERFACE (device)->deactivate (device);
}

static gboolean
impl_device_deactivate (NMDeviceInterface *device, GError **err)
{
	g_return_val_if_fail (NM_IS_DEVICE_INTERFACE (device), FALSE);

	nm_device_interface_deactivate (device);

	return TRUE;
}
