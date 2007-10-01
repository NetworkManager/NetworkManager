
#ifndef NM_DEVICE_INTERFACE_H
#define NM_DEVICE_INTERFACE_H

#include <glib-object.h>
#include "NetworkManager.h"
#include "nm-connection.h"
#include "nm-activation-request.h"

#define NM_TYPE_DEVICE_INTERFACE      (nm_device_interface_get_type ())
#define NM_DEVICE_INTERFACE(obj)      (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_INTERFACE, NMDeviceInterface))
#define NM_IS_DEVICE_INTERFACE(obj)   (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_INTERFACE))
#define NM_DEVICE_INTERFACE_GET_INTERFACE(obj) (G_TYPE_INSTANCE_GET_INTERFACE ((obj), NM_TYPE_DEVICE_INTERFACE, NMDeviceInterface))

typedef enum
{
	NM_DEVICE_INTERFACE_ERROR_UNKNOWN_CONNECTION = 0,
} NMDeviceInterfaceError;

#define NM_DEVICE_INTERFACE_ERROR (nm_device_interface_error_quark ())
#define NM_DEVICE_INTERFACE_TYPE_ERROR (nm_device_interface_error_get_type ()) 

#define NM_DEVICE_INTERFACE_UDI "udi"
#define NM_DEVICE_INTERFACE_IFACE "interface"
#define NM_DEVICE_INTERFACE_INDEX "index"
#define NM_DEVICE_INTERFACE_DRIVER "driver"
#define NM_DEVICE_INTERFACE_CAPABILITIES "capabilities"
#define NM_DEVICE_INTERFACE_IP4_ADDRESS "ip4_address"
#define NM_DEVICE_INTERFACE_IP4_CONFIG "ip4_config"
#define NM_DEVICE_INTERFACE_STATE "state"
#define NM_DEVICE_INTERFACE_DEVICE_TYPE "device_type" /* ugh */
#define NM_DEVICE_INTERFACE_CARRIER "carrier"

typedef enum {
	NM_DEVICE_INTERFACE_PROP_FIRST = 0x1000,

	NM_DEVICE_INTERFACE_PROP_UDI = NM_DEVICE_INTERFACE_PROP_FIRST,
	NM_DEVICE_INTERFACE_PROP_INDEX,
	NM_DEVICE_INTERFACE_PROP_IFACE,
	NM_DEVICE_INTERFACE_PROP_DRIVER,
	NM_DEVICE_INTERFACE_PROP_CAPABILITIES,
	NM_DEVICE_INTERFACE_PROP_IP4_ADDRESS,
	NM_DEVICE_INTERFACE_PROP_IP4_CONFIG,
	NM_DEVICE_INTERFACE_PROP_STATE,
	NM_DEVICE_INTERFACE_PROP_DEVICE_TYPE,
	NM_DEVICE_INTERFACE_PROP_CARRIER
} NMDeviceInterfaceProp;


typedef struct _NMDeviceInterface NMDeviceInterface;

struct _NMDeviceInterface {
	GTypeInterface g_iface;

	/* Methods */
	gboolean (*activate) (NMDeviceInterface *device,
			      NMActRequest *req);

	void (*deactivate) (NMDeviceInterface *device);

	/* Signals */
	void (*state_changed) (NMDeviceInterface *device, NMDeviceState state);
	void (*carrier_changed) (NMDeviceInterface *device, gboolean carrier_on);
};

GQuark nm_device_interface_error_quark (void);
GType nm_device_interface_error_get_type (void);

GType nm_device_interface_get_type (void);

gboolean nm_device_interface_activate (NMDeviceInterface *device,
				       NMActRequest *req);

void nm_device_interface_deactivate (NMDeviceInterface *device);

#endif /* NM_DEVICE_INTERFACE_H */
