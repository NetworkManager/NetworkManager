#ifndef NM_TYPES_H
#define NM_TYPES_H

#include <glib.h>
#include <glib-object.h>

#define NM_TYPE_SSID  (nm_ssid_get_type ())
GType     nm_ssid_get_type (void) G_GNUC_CONST;

#define NM_TYPE_UINT_ARRAY  (nm_uint_array_get_type ())
GType     nm_uint_array_get_type (void) G_GNUC_CONST;

#define NM_TYPE_STRING_ARRAY  (nm_string_array_get_type ())
GType     nm_string_array_get_type (void) G_GNUC_CONST;

#define NM_TYPE_OBJECT_ARRAY  (nm_object_array_get_type ())
GType     nm_object_array_get_type (void) G_GNUC_CONST;

#endif /* NM_TYPES_H */
