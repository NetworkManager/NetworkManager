#ifndef NM_ACTIVE_CONNECTION_H
#define NM_ACTIVE_CONNECTION_H

#include <glib/gtypes.h>
#include <glib-object.h>
#include "nm-object.h"
#include <nm-connection.h>
#include <NetworkManager.h>

G_BEGIN_DECLS

#define NM_TYPE_ACTIVE_CONNECTION            (nm_active_connection_get_type ())
#define NM_ACTIVE_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_ACTIVE_CONNECTION, NMActiveConnection))
#define NM_ACTIVE_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_ACTIVE_CONNECTION, NMActiveConnectionClass))
#define NM_IS_ACTIVE_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_ACTIVE_CONNECTION))
#define NM_IS_ACTIVE_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_ACTIVE_CONNECTION))
#define NM_ACTIVE_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_ACTIVE_CONNECTION, NMActiveConnectionClass))

#define NM_ACTIVE_CONNECTION_SERVICE_NAME        "service-name"
#define NM_ACTIVE_CONNECTION_CONNECTION          "connection"
#define NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT     "specific-object"
#define NM_ACTIVE_CONNECTION_DEVICES             "devices"
#define NM_ACTIVE_CONNECTION_STATE               "state"
#define NM_ACTIVE_CONNECTION_DEFAULT             "default"

typedef struct {
	NMObject parent;
} NMActiveConnection;

typedef struct {
	NMObjectClass parent;
} NMActiveConnectionClass;

GType nm_active_connection_get_type (void);

GObject *nm_active_connection_new (DBusGConnection *connection, const char *path);

const char * nm_active_connection_get_service_name        (NMActiveConnection *connection);
NMConnectionScope nm_active_connection_get_scope          (NMActiveConnection *connection);
const char * nm_active_connection_get_connection          (NMActiveConnection *connection);
const char * nm_active_connection_get_specific_object     (NMActiveConnection *connection);
const GPtrArray *nm_active_connection_get_devices         (NMActiveConnection *connection);
NMActiveConnectionState nm_active_connection_get_state    (NMActiveConnection *connection);
gboolean nm_active_connection_get_default                 (NMActiveConnection *connection);

G_END_DECLS

#endif /* NM_ACTIVE_CONNECTION_H */
