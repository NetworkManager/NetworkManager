#ifndef NM_OBJECT_PRIVATE_H
#define NM_OBJECT_PRIVATE_H

#include <glib.h>
#include <glib-object.h>
#include "nm-object.h"

typedef gboolean (*PropChangedMarshalFunc) (NMObject *, GParamSpec *, GValue *, gpointer);
typedef GObject * (*NMObjectCreatorFunc) (DBusGConnection *, const char *);

typedef struct {
	const char *name;
	PropChangedMarshalFunc func;
	gpointer field;
} NMPropertiesChangedInfo;


void             _nm_object_handle_properties_changed (NMObject *object,
                                                      DBusGProxy *proxy,
                                                      const NMPropertiesChangedInfo *info);

gboolean _nm_object_demarshal_generic (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field);

void _nm_object_queue_notify (NMObject *object, const char *property);

/* DBus property accessors */

gboolean _nm_object_get_property (NMObject *object,
								 const char *interface,
								 const char *prop_name,
								 GValue *value);

void _nm_object_set_property (NMObject *object,
							 const char *interface,
							 const char *prop_name,
							 GValue *value);

char *_nm_object_get_string_property (NMObject *object,
									 const char *interface,
									 const char *prop_name);

char *_nm_object_get_object_path_property (NMObject *object,
										  const char *interface,
										  const char *prop_name);

gint32 _nm_object_get_int_property (NMObject *object,
								   const char *interface,
								   const char *prop_name);

guint32 _nm_object_get_uint_property (NMObject *object,
									 const char *interface,
									 const char *prop_name);

gboolean _nm_object_get_boolean_property (NMObject *object,
										const char *interface,
										const char *prop_name);

gint8 _nm_object_get_byte_property (NMObject *object,
								   const char *interface,
								   const char *prop_name);

gdouble _nm_object_get_double_property (NMObject *object,
									   const char *interface,
									   const char *prop_name);

GByteArray *_nm_object_get_byte_array_property (NMObject *object,
											   const char *interface,
											   const char *prop_name);

static inline const GPtrArray *
handle_ptr_array_return (GPtrArray *array)
{
	/* zero-length is special-case; return NULL */
	if (!array || !array->len)
		return NULL;
	return array;
}

#endif /* NM_OBJECT_PRIVATE_H */
