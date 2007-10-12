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

#define NM_OBJECT_CONNECTION "connection"
#define NM_OBJECT_PATH "path"

typedef struct {
	GObject parent;
} NMObject;

typedef struct {
	GObjectClass parent;
} NMObjectClass;

GType nm_object_get_type (void);

DBusGConnection *nm_object_get_connection (NMObject *object);
const char      *nm_object_get_path       (NMObject *object);

void             nm_object_handle_properties_changed (NMObject *object,
						      DBusGProxy *proxy);

/* DBus property accessors */

gboolean nm_object_get_property (NMObject *object,
								 const char *interface,
								 const char *prop_name,
								 GValue *value);

void nm_object_set_property (NMObject *object,
							 const char *interface,
							 const char *prop_name,
							 GValue *value);

char *nm_object_get_string_property (NMObject *object,
									 const char *interface,
									 const char *prop_name);

char *nm_object_get_object_path_property (NMObject *object,
										  const char *interface,
										  const char *prop_name);

gint32 nm_object_get_int_property (NMObject *object,
								   const char *interface,
								   const char *prop_name);

guint32 nm_object_get_uint_property (NMObject *object,
									 const char *interface,
									 const char *prop_name);

gboolean nm_object_get_boolean_property (NMObject *object,
										const char *interface,
										const char *prop_name);

gint8 nm_object_get_byte_property (NMObject *object,
								   const char *interface,
								   const char *prop_name);

gdouble nm_object_get_double_property (NMObject *object,
									   const char *interface,
									   const char *prop_name);

GByteArray *nm_object_get_byte_array_property (NMObject *object,
											   const char *interface,
											   const char *prop_name);


G_END_DECLS

#endif /* NM_OBJECT_H */
