
#ifndef NM_TYPES_PRIVATE_H
#define NM_TYPES_PRIVATE_H

#include <dbus/dbus-glib.h>
#include "nm-types.h"
#include "nm-object-private.h"

gboolean nm_ssid_demarshal (GValue *value, GByteArray **dest);
gboolean nm_uint_array_demarshal (GValue *value, GArray **dest);
gboolean nm_string_array_demarshal (GValue *value, GPtrArray **dest);
gboolean nm_object_array_demarshal (GValue *value,
                                    GPtrArray **dest,
                                    DBusGConnection *connection,
                                    NMObjectCreatorFunc func);


#endif /* NM_TYPES_PRIVATE_H */
