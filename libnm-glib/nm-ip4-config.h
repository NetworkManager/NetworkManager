#ifndef NM_IP4_CONFIG_H
#define NM_IP4_CONFIG_H

#include <glib/gtypes.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include "nm-object.h"

G_BEGIN_DECLS

#define NM_TYPE_IP4_CONFIG            (nm_ip4_config_get_type ())
#define NM_IP4_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_IP4_CONFIG, NMIP4Config))
#define NM_IP4_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_IP4_CONFIG, NMIP4ConfigClass))
#define NM_IS_IP4_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_IP4_CONFIG))
#define NM_IS_IP4_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_IP4_CONFIG))
#define NM_IP4_CONFIG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_IP4_CONFIG, NMIP4ConfigClass))

typedef struct {
	NMObject parent;
} NMIP4Config;

typedef struct {
	NMObjectClass parent;
} NMIP4ConfigClass;

#define NM_IP4_CONFIG_ADDRESSES "addresses"
#define NM_IP4_CONFIG_HOSTNAME "hostname"
#define NM_IP4_CONFIG_NAMESERVERS "nameservers"
#define NM_IP4_CONFIG_DOMAINS "domains"
#define NM_IP4_CONFIG_ROUTES "routes"

GType nm_ip4_config_get_type (void);

GObject *nm_ip4_config_new (DBusGConnection *connection, const char *object_path);

const GSList *   nm_ip4_config_get_addresses   (NMIP4Config *config);
const char *     nm_ip4_config_get_hostname    (NMIP4Config *config);
const GArray *   nm_ip4_config_get_nameservers (NMIP4Config *config);
const GPtrArray *nm_ip4_config_get_domains     (NMIP4Config *config);
const GSList *   nm_ip4_config_get_routes      (NMIP4Config *config);

G_END_DECLS

#endif /* NM_IP4_CONFIG_H */
