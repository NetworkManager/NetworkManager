
#ifndef __NM_SETTINGS_H__
#define __NM_SETTINGS_H__

#include <glib-object.h>
#include <dbus/dbus-glib.h>

G_BEGIN_DECLS

#define NM_SETTINGS_ERROR nm_settings_error_quark ()
GQuark nm_settings_error_quark (void);

#define NM_TYPE_EXPORTED_CONNECTION            (nm_exported_connection_get_type ())
#define NM_EXPORTED_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_EXPORTED_CONNECTION, NMExportedConnection))
#define NM_EXPORTED_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_EXPORTED_CONNECTION, NMExportedConnectionClass))
#define NM_IS_EXPORTED_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_EXPORTED_CONNECTION))
#define NM_IS_EXPORTED_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_EXPORTED_CONNECTION))
#define NM_EXPORTED_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_EXPORTED_CONNECTION, NMExportedConnectionClass))

#define NM_EXPORTED_CONNECTION_CONNECTION "connection"

typedef struct {
	GObject parent;
} NMExportedConnection;

typedef struct {
	GObjectClass parent_class;

	/* virtual methods */
	const gchar *(* get_id) (NMExportedConnection *connection);
	GHashTable * (* get_settings) (NMExportedConnection *connection);
	void         (* get_secrets) (NMExportedConnection *connection,
	                              const gchar *setting_name,
	                              const gchar **hints,
	                              gboolean request_new,
	                              DBusGMethodInvocation *context);

	/* signals */
	void (* updated) (NMExportedConnection *connection, GHashTable *settings);
	void (* removed) (NMExportedConnection *connection);
} NMExportedConnectionClass;

GType nm_exported_connection_get_type (void);

void nm_exported_connection_register_object (NMExportedConnection *connection,
                                             NMConnectionScope scope,
                                             DBusGConnection *dbus_connection);

NMConnection *nm_exported_connection_get_connection (NMExportedConnection *connection);

const char *nm_exported_connection_get_id (NMExportedConnection *connection);

void nm_exported_connection_signal_updated (NMExportedConnection *connection, GHashTable *settings);
void nm_exported_connection_signal_removed (NMExportedConnection *connection);



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
	void (* new_connection) (NMSettings *settings, NMExportedConnection *connection);
} NMSettingsClass;

GType nm_settings_get_type (void);

void  nm_settings_signal_new_connection (NMSettings *settings, NMExportedConnection *connection);

G_END_DECLS

#endif
