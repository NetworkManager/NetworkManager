#ifndef NM_MANAGER_H
#define NM_MANAGER_H 1

#include <glib/gtypes.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include "nm-device.h"

#define NM_TYPE_MANAGER            (nm_manager_get_type ())
#define NM_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_MANAGER, NMManager))
#define NM_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_MANAGER, NMManagerClass))
#define NM_IS_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_MANAGER))
#define NM_IS_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_MANAGER))
#define NM_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_MANAGER, NMManagerClass))

#define NM_MANAGER_STATE "state"
#define NM_MANAGER_WIRELESS_ENABLED "wireless-enabled"

typedef struct {
	GObject parent;
} NMManager;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*device_added) (NMManager *manager, NMDevice *device);
	void (*device_removed) (NMManager *manager, NMDevice *device);
	void (*state_change) (NMManager *manager, guint state);

	void (*connection_added) (NMManager *manager, NMConnection *connection);
	void (*connection_removed) (NMManager *manager, NMConnection *connection);
} NMManagerClass;

GType nm_manager_get_type (void);

NMManager *nm_manager_new (void);

/* Device handling */

void nm_manager_add_device (NMManager *manager, NMDevice *device);
void nm_manager_remove_device (NMManager *manager, NMDevice *device);
GSList *nm_manager_get_devices (NMManager *manager);
NMDevice *nm_manager_get_device_by_iface (NMManager *manager, const char *iface);
NMDevice *nm_manager_get_device_by_index (NMManager *manager, int idx);
NMDevice *nm_manager_get_device_by_udi (NMManager *manager, const char *udi);

NMDevice *nm_manager_get_active_device (NMManager *manager);

/* State handling */

NMState nm_manager_get_state (NMManager *manager);
gboolean nm_manager_wireless_enabled (NMManager *manager);
void nm_manager_sleep (NMManager *manager, gboolean sleep);

/* Connections */

GSList *nm_manager_get_user_connections    (NMManager *manager);
void    nm_manager_update_user_connections (NMManager *manager,
                                            GSList *connections,
                                            gboolean reset);

GSList *nm_manager_get_system_connections    (NMManager *manager);
void    nm_manager_update_system_connections (NMManager *manager,
                                              GSList *connections,
                                              gboolean reset);

#endif /* NM_MANAGER_H */
