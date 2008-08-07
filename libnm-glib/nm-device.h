#ifndef NM_DEVICE_H
#define NM_DEVICE_H

#include <glib/gtypes.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include "nm-object.h"
#include "NetworkManager.h"
#include "nm-ip4-config.h"
#include "nm-dhcp4-config.h"
#include "nm-connection.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE            (nm_device_get_type ())
#define NM_DEVICE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE, NMDevice))
#define NM_DEVICE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE, NMDeviceClass))
#define NM_IS_DEVICE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE))
#define NM_IS_DEVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_DEVICE))
#define NM_DEVICE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE, NMDeviceClass))

#define NM_DEVICE_UDI "udi"
#define NM_DEVICE_INTERFACE "interface"
#define NM_DEVICE_DRIVER "driver"
#define NM_DEVICE_CAPABILITIES "capabilities"
#define NM_DEVICE_MANAGED "managed"
#define NM_DEVICE_IP4_CONFIG "ip4-config"
#define NM_DEVICE_DHCP4_CONFIG "dhcp4-config"
#define NM_DEVICE_STATE "state"
#define NM_DEVICE_VENDOR "vendor"
#define NM_DEVICE_PRODUCT "product"

typedef struct {
	NMObject parent;
} NMDevice;

typedef struct {
	NMObjectClass parent;

	/* Signals */
	void (*state_changed) (NMDevice *device,
	                       NMDeviceState new_state,
	                       NMDeviceState old_state,
	                       NMDeviceStateReason reason);
} NMDeviceClass;

GType nm_device_get_type (void);

GObject * nm_device_new (DBusGConnection *connection, const char *path);

const char *  nm_device_get_iface          (NMDevice *device);
const char *  nm_device_get_udi            (NMDevice *device);
const char *  nm_device_get_driver         (NMDevice *device);
guint32       nm_device_get_capabilities   (NMDevice *device);
gboolean      nm_device_get_managed        (NMDevice *device);
NMIP4Config * nm_device_get_ip4_config     (NMDevice *device);
NMDHCP4Config * nm_device_get_dhcp4_config (NMDevice *device);
NMDeviceState nm_device_get_state          (NMDevice *device);
const char *  nm_device_get_product        (NMDevice *device);
const char *  nm_device_get_vendor         (NMDevice *device);

G_END_DECLS

#endif /* NM_DEVICE_H */
