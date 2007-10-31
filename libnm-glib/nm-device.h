#ifndef NM_DEVICE_H
#define NM_DEVICE_H

#include <glib/gtypes.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include "nm-object.h"
#include "NetworkManager.h"
#include "nm-ip4-config.h"
#include "nm-connection.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE            (nm_device_get_type ())
#define NM_DEVICE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE, NMDevice))
#define NM_DEVICE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE, NMDeviceClass))
#define NM_IS_DEVICE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE))
#define NM_IS_DEVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_DEVICE))
#define NM_DEVICE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE, NMDeviceClass))

typedef struct {
	NMObject parent;
} NMDevice;

typedef struct {
	NMObjectClass parent;

	/* Signals */
	void (*state_changed) (NMDevice *device, NMDeviceState state);
	void (*carrier_changed) (NMDevice *device, gboolean carrier);
} NMDeviceClass;

GType nm_device_get_type (void);

NMDevice    *nm_device_new               (DBusGConnection *connection,
										  const char *path);

void         nm_device_deactivate        (NMDevice *device);

char         *nm_device_get_iface        (NMDevice *device);
char         *nm_device_get_udi          (NMDevice *device);
char         *nm_device_get_driver       (NMDevice *device);
guint32       nm_device_get_capabilities (NMDevice *device);
guint32       nm_device_get_ip4_address  (NMDevice *device);
NMIP4Config  *nm_device_get_ip4_config   (NMDevice *device);
NMDeviceState nm_device_get_state        (NMDevice *device);
char         *nm_device_get_product      (NMDevice *device);
char         *nm_device_get_vendor       (NMDevice *device);
gboolean      nm_device_get_carrier      (NMDevice *device);

NMDeviceType  nm_device_type_for_path    (DBusGConnection *connection,
										  const char *path);

G_END_DECLS

#endif /* NM_DEVICE_H */
