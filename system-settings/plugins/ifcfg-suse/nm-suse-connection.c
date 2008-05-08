/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <string.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <NetworkManager.h>
#include "nm-suse-connection.h"
#include "parser.h"

G_DEFINE_TYPE (NMSuseConnection, nm_suse_connection, NM_TYPE_EXPORTED_CONNECTION)

#define NM_SUSE_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SUSE_CONNECTION, NMSuseConnectionPrivate))

typedef struct {
	GFileMonitor *monitor;
	guint monitor_id;

	const char *iface;
	NMDeviceType dev_type;
	char *filename;
} NMSuseConnectionPrivate;

static void
file_changed (GFileMonitor *monitor,
		    GFile *file,
		    GFile *other_file,
		    GFileMonitorEvent event_type,
		    gpointer user_data)
{
	NMExportedConnection *exported = NM_EXPORTED_CONNECTION (user_data);
	NMSuseConnectionPrivate *priv = NM_SUSE_CONNECTION_GET_PRIVATE (exported);
	NMConnection *new_connection;
	GHashTable *new_settings;

	switch (event_type) {
	case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:
		new_connection = parse_ifcfg (priv->iface, priv->dev_type);
		if (new_connection) {
			new_settings = nm_connection_to_hash (new_connection);
			nm_exported_connection_update (exported, new_settings);
			g_hash_table_destroy (new_settings);
			g_object_unref (new_connection);
		} else
			nm_exported_connection_delete (exported);
		break;
	case G_FILE_MONITOR_EVENT_DELETED:
		nm_exported_connection_delete (exported);
		break;
	default:
		break;
	}
}

NMSuseConnection *
nm_suse_connection_new (const char *iface, NMDeviceType dev_type)
{
	NMConnection *connection;
	GFile *file;
	GFileMonitor *monitor;
	NMSuseConnection *exported;
	NMSuseConnectionPrivate *priv;

	g_return_val_if_fail (iface != NULL, NULL);

	connection = parse_ifcfg (iface, dev_type);
	if (!connection)
		return NULL;

	exported = (NMSuseConnection *) g_object_new (NM_TYPE_SUSE_CONNECTION,
										 NM_EXPORTED_CONNECTION_CONNECTION, connection,
										 NULL);
	g_object_unref (connection);
	if (!exported)
		return NULL;

	priv = NM_SUSE_CONNECTION_GET_PRIVATE (exported);

	priv->iface = g_strdup (iface);
	priv->dev_type = dev_type;
	priv->filename = g_strdup_printf (SYSCONFDIR "/sysconfig/network/ifcfg-%s", iface);

	file = g_file_new_for_path (priv->filename);
	monitor = g_file_monitor_file (file, G_FILE_MONITOR_NONE, NULL, NULL);
	g_object_unref (file);

	if (monitor) {
		priv->monitor_id = g_signal_connect (monitor, "changed", G_CALLBACK (file_changed), exported);
		priv->monitor = monitor;
	}

	return exported;
}

static GHashTable *
get_settings (NMExportedConnection *exported)
{
	return nm_connection_to_hash (nm_exported_connection_get_connection (exported));
}

static const char *
get_id (NMExportedConnection *exported)
{
	return NM_SUSE_CONNECTION_GET_PRIVATE (exported)->filename;
}

/* GObject */

static void
nm_suse_connection_init (NMSuseConnection *connection)
{
}

static void
finalize (GObject *object)
{
	NMSuseConnectionPrivate *priv = NM_SUSE_CONNECTION_GET_PRIVATE (object);

	if (priv->monitor) {
		if (priv->monitor_id)
			g_signal_handler_disconnect (priv->monitor, priv->monitor_id);

		g_file_monitor_cancel (priv->monitor);
		g_object_unref (priv->monitor);
	}

	g_free (priv->filename);

	G_OBJECT_CLASS (nm_suse_connection_parent_class)->finalize (object);
}

static void
nm_suse_connection_class_init (NMSuseConnectionClass *suse_connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (suse_connection_class);
	NMExportedConnectionClass *connection_class = NM_EXPORTED_CONNECTION_CLASS (suse_connection_class);

	g_type_class_add_private (suse_connection_class, sizeof (NMSuseConnectionPrivate));

	/* Virtual methods */
	object_class->finalize = finalize;

	connection_class->get_settings = get_settings;
	connection_class->get_id       = get_id;
}
