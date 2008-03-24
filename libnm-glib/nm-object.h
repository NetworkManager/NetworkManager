#ifndef NM_OBJECT_H
#define NM_OBJECT_H

#include <glib/gtypes.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>

G_BEGIN_DECLS

#define NM_TYPE_OBJECT            (nm_object_get_type ())
#define NM_OBJECT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_OBJECT, NMObject))
#define NM_OBJECT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_OBJECT, NMObjectClass))
#define NM_IS_OBJECT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_OBJECT))
#define NM_IS_OBJECT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_OBJECT))
#define NM_OBJECT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_OBJECT, NMObjectClass))

#define NM_OBJECT_DBUS_CONNECTION "dbus-connection"
#define NM_OBJECT_DBUS_PATH "dbus-path"

typedef struct {
	GObject parent;
} NMObject;

typedef struct {
	GObjectClass parent;
} NMObjectClass;

GType nm_object_get_type (void);

DBusGConnection *nm_object_get_connection (NMObject *object);
const char      *nm_object_get_path       (NMObject *object);

G_END_DECLS

#endif /* NM_OBJECT_H */
