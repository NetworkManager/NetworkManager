
#ifndef NM_DEVICE_INTERFACE_H
#define NM_DEVICE_INTERFACE_H

#include <glib-object.h>
#include "NetworkManager.h"

#define NM_TYPE_DEVICE_INTERFACE      (nm_device_interface_get_type ())
#define NM_DEVICE_INTERFACE(obj)      (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_INTERFACE, NmDeviceInterface))
#define NM_IS_DEVICE_INTERFACE(obj)   (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_INTERFACE))
#define NM_DEVICE_INTERFACE_GET_INTERFACE(obj) (G_TYPE_INSTANCE_GET_INTERFACE ((obj), NM_TYPE_DEVICE_INTERFACE, NMDeviceInterface))


#define NM_DEVICE_INTERFACE_UDI "udi"
#define NM_DEVICE_INTERFACE_IFACE "interface"
#define NM_DEVICE_INTERFACE_DRIVER "driver"
#define NM_DEVICE_INTERFACE_CAPABILITIES "capabilities"
#define NM_DEVICE_INTERFACE_IP4_ADDRESS "ip4_address"
#define NM_DEVICE_INTERFACE_USE_DHCP "use_dhcp"
#define NM_DEVICE_INTERFACE_STATE "state"
#define NM_DEVICE_INTERFACE_APP_DATA "app_data" /* Ugh */
#define NM_DEVICE_INTERFACE_DEVICE_TYPE "device_type" /* ugh */

typedef enum {
	NM_DEVICE_INTERFACE_PROP_FIRST = 0x1000,

	NM_DEVICE_INTERFACE_PROP_UDI = NM_DEVICE_INTERFACE_PROP_FIRST,
	NM_DEVICE_INTERFACE_PROP_IFACE,
	NM_DEVICE_INTERFACE_PROP_DRIVER,
	NM_DEVICE_INTERFACE_PROP_CAPABILITIES,
	NM_DEVICE_INTERFACE_PROP_IP4_ADDRESS,
	NM_DEVICE_INTERFACE_PROP_USE_DHCP,
	NM_DEVICE_INTERFACE_PROP_STATE,
	NM_DEVICE_INTERFACE_PROP_APP_DATA,
	NM_DEVICE_INTERFACE_PROP_DEVICE_TYPE
} NMDeviceInterfaceProp;


typedef struct _NMDeviceInterface NMDeviceInterface;

struct _NMDeviceInterface {
	GTypeInterface g_iface;

	/* Methods */
	void (*deactivate) (NMDeviceInterface *device);

	/* Signals */
	void (*state_changed) (NMDeviceInterface *device, NMDeviceState state);
	void (*carrier_changed) (NMDeviceInterface *device, gboolean carrier_on);
};

GType nm_device_interface_get_type (void);


#endif /* NM_DEVICE_INTERFACE_H */
