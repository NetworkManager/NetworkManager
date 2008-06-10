#ifndef NM_DEVICE_ETHERNET_H
#define NM_DEVICE_ETHERNET_H

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_ETHERNET            (nm_device_ethernet_get_type ())
#define NM_DEVICE_ETHERNET(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_ETHERNET, NMDeviceEthernet))
#define NM_DEVICE_ETHERNET_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_ETHERNET, NMDeviceEthernetClass))
#define NM_IS_DEVICE_ETHERNET(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_ETHERNET))
#define NM_IS_DEVICE_ETHERNET_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_DEVICE_ETHERNET))
#define NM_DEVICE_ETHERNET_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_ETHERNET, NMDeviceEthernetClass))

#define NM_DEVICE_ETHERNET_HW_ADDRESS  "hw-address"
#define NM_DEVICE_ETHERNET_SPEED       "speed"
#define NM_DEVICE_ETHERNET_CARRIER     "carrier"

typedef struct {
	NMDevice parent;
} NMDeviceEthernet;

typedef struct {
	NMDeviceClass parent;
} NMDeviceEthernetClass;

GType nm_device_ethernet_get_type (void);

GObject *nm_device_ethernet_new (DBusGConnection *connection, const char *path);

const char * nm_device_ethernet_get_hw_address (NMDeviceEthernet *device);
guint32      nm_device_ethernet_get_speed   (NMDeviceEthernet *device);
gboolean     nm_device_ethernet_get_carrier (NMDeviceEthernet *device);

G_END_DECLS

#endif /* NM_DEVICE_ETHERNET_H */
