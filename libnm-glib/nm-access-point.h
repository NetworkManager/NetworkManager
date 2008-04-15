#ifndef NM_ACCESS_POINT_H
#define NM_ACCESS_POINT_H

#include <glib/gtypes.h>
#include <glib-object.h>
#include <NetworkManager.h>
#include "nm-object.h"

G_BEGIN_DECLS

#define NM_TYPE_ACCESS_POINT            (nm_access_point_get_type ())
#define NM_ACCESS_POINT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_ACCESS_POINT, NMAccessPoint))
#define NM_ACCESS_POINT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_ACCESS_POINT, NMAccessPointClass))
#define NM_IS_ACCESS_POINT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_ACCESS_POINT))
#define NM_IS_ACCESS_POINT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_ACCESS_POINT))
#define NM_ACCESS_POINT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_ACCESS_POINT, NMAccessPointClass))

#define NM_ACCESS_POINT_FLAGS      "flags"
#define NM_ACCESS_POINT_WPA_FLAGS  "wpa-flags"
#define NM_ACCESS_POINT_RSN_FLAGS  "rsn-flags"
#define NM_ACCESS_POINT_SSID       "ssid"
#define NM_ACCESS_POINT_FREQUENCY  "frequency"
#define NM_ACCESS_POINT_HW_ADDRESS "hw-address"
#define NM_ACCESS_POINT_MODE       "mode"
#define NM_ACCESS_POINT_MAX_BITRATE   "max-bitrate"
#define NM_ACCESS_POINT_STRENGTH   "strength"

typedef struct {
	NMObject parent;
} NMAccessPoint;

typedef struct {
	NMObjectClass parent;
} NMAccessPointClass;

GType nm_access_point_get_type (void);

GObject *nm_access_point_new (DBusGConnection *connection, const char *path);

guint32      nm_access_point_get_flags        (NMAccessPoint *ap);
guint32      nm_access_point_get_wpa_flags    (NMAccessPoint *ap);
guint32      nm_access_point_get_rsn_flags    (NMAccessPoint *ap);
const GByteArray * nm_access_point_get_ssid   (NMAccessPoint *ap);
guint32      nm_access_point_get_frequency    (NMAccessPoint *ap);
const char * nm_access_point_get_hw_address   (NMAccessPoint *ap);
NM80211Mode  nm_access_point_get_mode         (NMAccessPoint *ap);
guint32      nm_access_point_get_max_bitrate  (NMAccessPoint *ap);
guint8       nm_access_point_get_strength     (NMAccessPoint *ap);

G_END_DECLS

#endif /* NM_ACCESS_POINT_H */
