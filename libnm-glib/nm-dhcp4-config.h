#ifndef NM_DHCP4_CONFIG_H
#define NM_DHCP4_CONFIG_H

#include <glib/gtypes.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include "nm-object.h"

G_BEGIN_DECLS

#define NM_TYPE_DHCP4_CONFIG            (nm_dhcp4_config_get_type ())
#define NM_DHCP4_CONFIG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DHCP4_CONFIG, NMDHCP4Config))
#define NM_DHCP4_CONFIG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DHCP4_CONFIG, NMDHCP4ConfigClass))
#define NM_IS_DHCP4_CONFIG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DHCP4_CONFIG))
#define NM_IS_DHCP4_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_DHCP4_CONFIG))

typedef struct {
	NMObject parent;
} NMDHCP4Config;

typedef struct {
	NMObjectClass parent;
} NMDHCP4ConfigClass;

#define NM_DHCP4_CONFIG_OPTIONS "options"

GType nm_dhcp4_config_get_type (void);

GObject *nm_dhcp4_config_new (DBusGConnection *connection, const char *object_path);

GHashTable * nm_dhcp4_config_get_options (NMDHCP4Config *config);

const char * nm_dhcp4_config_get_one_option (NMDHCP4Config *config, const char *option);

G_END_DECLS

#endif /* NM_DHCP4_CONFIG_H */
