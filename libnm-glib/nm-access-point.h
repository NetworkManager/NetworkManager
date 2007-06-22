#ifndef NM_ACCESS_POINT_H
#define NM_ACCESS_POINT_H

#define NM_TYPE_ACCESS_POINT            (nm_access_point_get_type ())
#define NM_ACCESS_POINT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_ACCESS_POINT, NMAccessPoint))
#define NM_ACCESS_POINT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_ACCESS_POINT, NMAccessPointClass))
#define NM_IS_ACCESS_POINT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_ACCESS_POINT))
#define NM_IS_ACCESS_POINT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_ACCESS_POINT))
#define NM_ACCESS_POINT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_ACCESS_POINT, NMAccessPointClass))

#include <glib/gtypes.h>
#include <glib-object.h>
#include "nm-object.h"

typedef struct {
	NMObject parent;
} NMAccessPoint;

typedef struct {
	NMObjectClass parent;

	/* Signals */
	void (*strength_changed) (NMAccessPoint *ap, gint8 strength);
} NMAccessPointClass;

GType nm_access_point_get_type (void);

NMAccessPoint *nm_access_point_new (DBusGConnection *connection, const char *path);

guint32   nm_access_point_get_capabilities (NMAccessPoint *ap);
gboolean  nm_access_point_is_encrypted     (NMAccessPoint *ap);
char     *nm_access_point_get_essid        (NMAccessPoint *ap);
gdouble   nm_access_point_get_frequency    (NMAccessPoint *ap);
char     *nm_access_point_get_hw_address   (NMAccessPoint *ap);
int       nm_access_point_get_mode         (NMAccessPoint *ap);
guint32   nm_access_point_get_rate         (NMAccessPoint *ap);
int       nm_access_point_get_strength     (NMAccessPoint *ap);

#endif /* NM_ACCESS_POINT_H */
