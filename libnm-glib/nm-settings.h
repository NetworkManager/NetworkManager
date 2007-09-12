
#ifndef NM_SETTINGS_H
#define NM_SETTINGS_H 1

#include <glib-object.h>
#include <dbus/dbus-glib.h>

G_BEGIN_DECLS

#define NM_TYPE_CONNECTION_SETTINGS            (nm_connection_settings_get_type ())
#define NM_CONNECTION_SETTINGS(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_CONNECTION_SETTINGS, NMConnectionSettings))
#define NM_CONNECTION_SETTINGS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_CONNECTION_SETTINGS, NMConnectionSettingsClass))
#define NM_IS_CONNECTION_SETTINGS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_CONNECTION_SETTINGS))
#define NM_IS_CONNECTION_SETTINGS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_CONNECTION_SETTINGS))
#define NM_CONNECTION_SETTINGS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_CONNECTION_SETTINGS, NMConnectionSettingsClass))

typedef struct {
	GObject parent;

	/* private */
	char * dbus_path;
} NMConnectionSettings;

typedef struct {
	GObjectClass parent_class;

	/* virtual methods */
	gchar * (* get_id) (NMConnectionSettings *connection);
	GHashTable * (* get_settings) (NMConnectionSettings *connection);
	GHashTable * (* get_secrets) (NMConnectionSettings *connection, const gchar *setting_name);

	/* signals */
	void (* updated) (NMConnectionSettings *connection, GHashTable *settings);
	void (* removed) (NMConnectionSettings *connection);
} NMConnectionSettingsClass;

GType  nm_connection_settings_get_type (void);
void
nm_connection_settings_register_object (NMConnectionSettings *connection,
                                        DBusGConnection *dbus_connection);
const char *nm_connection_settings_get_dbus_object_path (NMConnectionSettings *connection);


void   nm_connection_settings_signal_updated (NMConnectionSettings *connection, GHashTable *settings);
void   nm_connection_settings_signal_removed (NMConnectionSettings *connection);

#define NM_TYPE_SETTINGS            (nm_settings_get_type ())
#define NM_SETTINGS(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTINGS, NMSettings))
#define NM_SETTINGS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTINGS, NMSettingsClass))
#define NM_IS_SETTINGS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTINGS))
#define NM_IS_SETTINGS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SETTINGS))
#define NM_SETTINGS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTINGS, NMSettingsClass))

typedef struct {
	GObject parent;
} NMSettings;

typedef struct {
	GObjectClass parent_class;

	/* virtual methods */
	GPtrArray * (* list_connections) (NMSettings *settings);

	/* signals */
	void (* new_connection) (NMSettings *settings, NMConnectionSettings *connection);
} NMSettingsClass;

GType nm_settings_get_type (void);

void  nm_settings_signal_new_connection (NMSettings *settings, NMConnectionSettings *connection);

G_END_DECLS

#endif
