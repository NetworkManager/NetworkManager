/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_CLIENT_H
#define NM_CLIENT_H 1

#include <glib/gtypes.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include <NetworkManager.h>
#include "nm-object.h"
#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_CLIENT            (nm_client_get_type ())
#define NM_CLIENT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_CLIENT, NMClient))
#define NM_CLIENT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_CLIENT, NMClientClass))
#define NM_IS_CLIENT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_CLIENT))
#define NM_IS_CLIENT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_CLIENT))
#define NM_CLIENT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_CLIENT, NMClientClass))

typedef struct {
	NMObject parent;
} NMClient;

typedef struct {
	NMObjectClass parent;

	/* Signals */
	void (*manager_running) (NMClient *client, gboolean running);
	void (*device_added) (NMClient *client, NMDevice *device);
	void (*device_removed) (NMClient *client, NMDevice *device);
	void (*state_change) (NMClient *client, NMState state);
} NMClientClass;

GType nm_client_get_type (void);


NMClient *nm_client_new                  (void);

gboolean  nm_client_manager_is_running    (NMClient *client);
GSList   *nm_client_get_devices           (NMClient *client);
NMDevice *nm_client_get_device_by_path    (NMClient *client,
                                           const char *object_path);

typedef struct NMClientActiveConnection {
	char *service_name;
	char *connection_path;
	char *specific_object;
	GSList *devices;        /* list of NMDevice objects */
} NMClientActiveConnection;

GSList *  nm_client_get_active_connections (NMClient *client);
void      nm_client_free_active_connection_element (NMClientActiveConnection *elt);

typedef void (*NMClientActivateDeviceFn) (gpointer user_data, GError *error);

void nm_client_activate_device (NMClient *client,
						  NMDevice *device,
						  const char *service_name,
						  const char *connection_path,
						  const char *specific_object,
						  NMClientActivateDeviceFn callback,
						  gpointer user_data);

gboolean  nm_client_wireless_get_enabled (NMClient *client);
void      nm_client_wireless_set_enabled (NMClient *client, gboolean enabled);
NMState   nm_client_get_state            (NMClient *client);
void      nm_client_sleep                (NMClient *client, gboolean sleep);

G_END_DECLS

#endif /* NM_CLIENT_H */
