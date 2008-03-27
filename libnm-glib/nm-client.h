/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_CLIENT_H
#define NM_CLIENT_H

#include <glib/gtypes.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include <NetworkManager.h>
#include "nm-object.h"
#include "nm-device.h"
#include "nm-active-connection.h"

G_BEGIN_DECLS

#define NM_TYPE_CLIENT            (nm_client_get_type ())
#define NM_CLIENT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_CLIENT, NMClient))
#define NM_CLIENT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_CLIENT, NMClientClass))
#define NM_IS_CLIENT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_CLIENT))
#define NM_IS_CLIENT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_CLIENT))
#define NM_CLIENT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_CLIENT, NMClientClass))

#define NM_CLIENT_STATE "state"
#define NM_CLIENT_MANAGER_RUNNING "manager-running"
#define NM_CLIENT_WIRELESS_ENABLED "wireless-enabled"
#define NM_CLIENT_WIRELESS_HARDWARE_ENABLED "wireless-hardware-enabled"
#define NM_CLIENT_ACTIVE_CONNECTIONS "active-connections"

typedef struct {
	NMObject parent;
} NMClient;

typedef struct {
	NMObjectClass parent;

	/* Signals */
	void (*device_added) (NMClient *client, NMDevice *device);
	void (*device_removed) (NMClient *client, NMDevice *device);
} NMClientClass;

GType nm_client_get_type (void);

NMClient *nm_client_new (void);

const GPtrArray *nm_client_get_devices    (NMClient *client);
NMDevice *nm_client_get_device_by_path    (NMClient *client, const char *object_path);

typedef void (*NMClientActivateDeviceFn) (gpointer user_data, GError *error);

void nm_client_activate_connection (NMClient *client,
						  const char *service_name,
						  const char *connection_path,
						  NMDevice *device,
						  const char *specific_object,
						  NMClientActivateDeviceFn callback,
						  gpointer user_data);

void nm_client_deactivate_connection (NMClient *client, NMActiveConnection *active);

gboolean  nm_client_wireless_get_enabled (NMClient *client);
void      nm_client_wireless_set_enabled (NMClient *client, gboolean enabled);
gboolean  nm_client_wireless_hardware_get_enabled (NMClient *client);
NMState   nm_client_get_state            (NMClient *client);
gboolean  nm_client_get_manager_running  (NMClient *client);
const GPtrArray *nm_client_get_active_connections (NMClient *client);
void      nm_client_sleep                (NMClient *client, gboolean sleep);

G_END_DECLS

#endif /* NM_CLIENT_H */
