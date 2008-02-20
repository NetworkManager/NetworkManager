#include <NetworkManager.h>
#include <nm-utils.h>
#include <nm-setting-connection.h>
#include "nm-settings.h"


GQuark
nm_settings_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-settings-error-quark");
	return quark;
}

/*
 * NMSettings implementation
 */

static gboolean impl_settings_list_connections (NMSettings *settings, GPtrArray **connections, GError **error);

#include "nm-settings-glue.h"

#define SETTINGS_CLASS(o) (NM_SETTINGS_CLASS (G_OBJECT_GET_CLASS (o)))

G_DEFINE_TYPE (NMSettings, nm_settings, G_TYPE_OBJECT)

enum {
	S_NEW_CONNECTION,

	S_LAST_SIGNAL
};

static guint settings_signals[S_LAST_SIGNAL] = { 0 };

static gboolean
impl_settings_list_connections (NMSettings *settings, GPtrArray **connections, GError **error)
{
	g_return_val_if_fail (NM_IS_SETTINGS (settings), FALSE);

	if (!SETTINGS_CLASS (settings)->list_connections) {
		g_set_error (error, NM_SETTINGS_ERROR, 1,
		             "%s.%d - Missing implementation for Settings::list_connections.",
		             __FILE__, __LINE__);
		return FALSE;
	}

	*connections = SETTINGS_CLASS (settings)->list_connections (settings);

	return TRUE;
}

static void
nm_settings_init (NMSettings *settings)
{
}

static void
nm_settings_finalize (GObject *object)
{
	G_OBJECT_CLASS (nm_settings_parent_class)->finalize (object);
}

static void
nm_settings_class_init (NMSettingsClass *settings_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (settings_class);

	/* virtual methods */
	object_class->finalize = nm_settings_finalize;

	settings_class->list_connections = NULL;

	/* signals */
	settings_signals[S_NEW_CONNECTION] =
		g_signal_new ("new-connection",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (NMSettingsClass, new_connection),
			      NULL, NULL,
			      g_cclosure_marshal_VOID__OBJECT,
			      G_TYPE_NONE, 1,
			      G_TYPE_OBJECT);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (settings_class),
					 &dbus_glib_nm_settings_object_info);
}

void
nm_settings_signal_new_connection (NMSettings *settings, NMExportedConnection *connection)
{
	g_return_if_fail (NM_IS_SETTINGS (settings));
	g_return_if_fail (NM_IS_EXPORTED_CONNECTION (connection));

	g_signal_emit (settings, settings_signals[S_NEW_CONNECTION], 0, connection);
}

/*
 * NMExportedConnection implementation
 */

static gboolean impl_exported_connection_get_id (NMExportedConnection *connection,
						 gchar **id,
						 GError **error);
static gboolean impl_exported_connection_get_settings (NMExportedConnection *connection,
						       GHashTable **settings,
						       GError **error);
static void impl_exported_connection_get_secrets (NMExportedConnection *connection,
						      const gchar *setting_name,
						      const gchar **hints,
						      gboolean request_new,
						      DBusGMethodInvocation *context);

#include "nm-exported-connection-glue.h"

#define EXPORTED_CONNECTION_CLASS(o) (NM_EXPORTED_CONNECTION_CLASS (G_OBJECT_GET_CLASS (o)))

G_DEFINE_TYPE (NMExportedConnection, nm_exported_connection, G_TYPE_OBJECT)

enum {
	EC_UPDATED,
	EC_REMOVED,

	EC_LAST_SIGNAL
};

static guint connection_signals[EC_LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_CONNECTION,

	LAST_PROP
};

typedef struct {
	NMConnection *wrapped;
} NMExportedConnectionPrivate;

#define NM_EXPORTED_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                               NM_TYPE_EXPORTED_CONNECTION, \
                                               NMExportedConnectionPrivate))


static gboolean
impl_exported_connection_get_id (NMExportedConnection *connection,
                                 gchar **id,
                                 GError **error)
{
	NMExportedConnectionPrivate *priv;

	g_return_val_if_fail (NM_IS_EXPORTED_CONNECTION (connection), FALSE);

	priv = NM_EXPORTED_CONNECTION_GET_PRIVATE (connection);
	if (!EXPORTED_CONNECTION_CLASS (connection)->get_id) {
		NMSettingConnection *s_con;

		s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (priv->wrapped, NM_TYPE_SETTING_CONNECTION));
		if (!s_con || !s_con->id) {
			g_set_error (error, NM_SETTINGS_ERROR, 1,
			             "%s.%d - Invalid connection.",
			             __FILE__, __LINE__);
			return FALSE;
		}

		*id = g_strdup (s_con->id);
	} else {
		*id = EXPORTED_CONNECTION_CLASS (connection)->get_id (connection);
	}

	return TRUE;
}

static gboolean
impl_exported_connection_get_settings (NMExportedConnection *connection,
				       GHashTable **settings,
				       GError **error)
{
	NMExportedConnectionPrivate *priv;

	g_return_val_if_fail (NM_IS_EXPORTED_CONNECTION (connection), FALSE);

	priv = NM_EXPORTED_CONNECTION_GET_PRIVATE (connection);

	if (!EXPORTED_CONNECTION_CLASS (connection)->get_settings)
		*settings = nm_connection_to_hash (priv->wrapped);
	else
		*settings = EXPORTED_CONNECTION_CLASS (connection)->get_settings (connection);

	return TRUE;
}

static void
impl_exported_connection_get_secrets (NMExportedConnection *connection,
                                      const gchar *setting_name,
                                      const gchar **hints,
                                      gboolean request_new,
                                      DBusGMethodInvocation *context)
{
	GError *error = NULL;

	if (!NM_IS_EXPORTED_CONNECTION (connection)) {
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d - Invalid connection in ConnectionSettings::get_secrets.",
		             __FILE__, __LINE__);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	if (!EXPORTED_CONNECTION_CLASS (connection)->get_secrets) {
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d - Missing implementation for ConnectionSettings::get_secrets.",
		             __FILE__, __LINE__);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	EXPORTED_CONNECTION_CLASS (connection)->get_secrets (connection, setting_name, hints, request_new, context);
}

static void
nm_exported_connection_init (NMExportedConnection *connection)
{
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMExportedConnectionPrivate *priv = NM_EXPORTED_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_CONNECTION:
		if (priv->wrapped)
			g_object_unref (priv->wrapped);
		priv->wrapped = g_value_get_object (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
		    GValue *value, GParamSpec *pspec)
{
	NMExportedConnection *exported = NM_EXPORTED_CONNECTION (object);

	switch (prop_id) {
	case PROP_CONNECTION:
		g_value_set_object (value, nm_exported_connection_get_connection (exported));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_exported_connection_dispose (GObject *object)
{
	NMExportedConnectionPrivate *priv = NM_EXPORTED_CONNECTION_GET_PRIVATE (object);

	if (priv->wrapped) {
		g_object_unref (priv->wrapped);
		priv->wrapped = NULL;
	}

	G_OBJECT_CLASS (nm_exported_connection_parent_class)->dispose (object);
}

#define DBUS_TYPE_G_STRING_VARIANT_HASHTABLE (dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE))
#define DBUS_TYPE_G_DICT_OF_DICTS (dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, DBUS_TYPE_G_STRING_VARIANT_HASHTABLE))

static void
nm_exported_connection_class_init (NMExportedConnectionClass *exported_connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (exported_connection_class);

	g_type_class_add_private (object_class, sizeof (NMExportedConnectionPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = nm_exported_connection_dispose;

	exported_connection_class->get_id = NULL;
	exported_connection_class->get_settings = NULL;
	exported_connection_class->get_secrets = NULL;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_CONNECTION,
		 g_param_spec_object (NM_EXPORTED_CONNECTION_CONNECTION,
						      "Connection",
						      "Wrapped connection",
						      NM_TYPE_CONNECTION,
						      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/* signals */
	connection_signals[EC_UPDATED] =
		g_signal_new ("updated",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (NMExportedConnectionClass, updated),
			      NULL, NULL,
			      g_cclosure_marshal_VOID__POINTER,
			      G_TYPE_NONE, 1,
			      DBUS_TYPE_G_DICT_OF_DICTS);

	connection_signals[EC_REMOVED] =
		g_signal_new ("removed",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (NMExportedConnectionClass, removed),
			      NULL, NULL,
			      g_cclosure_marshal_VOID__VOID,
			      G_TYPE_NONE, 0);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (exported_connection_class),
	                                 &dbus_glib_nm_exported_connection_object_info);
}

NMConnection *
nm_exported_connection_get_connection (NMExportedConnection *connection)
{
	g_return_val_if_fail (NM_IS_EXPORTED_CONNECTION (connection), NULL);

	return NM_EXPORTED_CONNECTION_GET_PRIVATE (connection)->wrapped;
}

void
nm_exported_connection_register_object (NMExportedConnection *connection,
                                        NMConnectionScope scope,
                                        DBusGConnection *dbus_connection)
{
	NMExportedConnectionPrivate *priv;
	static GStaticMutex mutex = G_STATIC_MUTEX_INIT;
	static guint32 ec_counter = 0;
	char *path;

	g_return_if_fail (NM_IS_EXPORTED_CONNECTION (connection));
	g_return_if_fail (dbus_connection != NULL);

	priv = NM_EXPORTED_CONNECTION_GET_PRIVATE (connection);

	g_static_mutex_lock (&mutex);
	path = g_strdup_printf ("%s/%u", NM_DBUS_PATH_SETTINGS, ec_counter++);
	g_static_mutex_unlock (&mutex);

	nm_connection_set_path (priv->wrapped, path);
	nm_connection_set_scope (priv->wrapped, scope);

	dbus_g_connection_register_g_object (dbus_connection,
	                                     path,
	                                     G_OBJECT (connection));
	g_free (path);
}

void
nm_exported_connection_signal_updated (NMExportedConnection *connection, GHashTable *settings)
{
	g_return_if_fail (NM_IS_EXPORTED_CONNECTION (connection));

	g_signal_emit (connection, connection_signals[EC_UPDATED], 0, settings);
}

void
nm_exported_connection_signal_removed (NMExportedConnection *connection)
{
	g_return_if_fail (NM_IS_EXPORTED_CONNECTION (connection));

	g_signal_emit (connection, connection_signals[EC_REMOVED], 0);
}
