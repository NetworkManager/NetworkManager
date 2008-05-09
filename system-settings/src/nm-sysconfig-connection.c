/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <NetworkManager.h>
#include "nm-sysconfig-connection.h"
#include "nm-polkit-helpers.h"

G_DEFINE_ABSTRACT_TYPE (NMSysconfigConnection, nm_sysconfig_connection, NM_TYPE_EXPORTED_CONNECTION)

#define NM_SYSCONFIG_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SYSCONFIG_CONNECTION, NMSysconfigConnectionPrivate))

typedef struct {
	DBusGConnection *dbus_connection;
	PolKitContext *pol_ctx;
} NMSysconfigConnectionPrivate;

static gboolean
update (NMExportedConnection *exported,
	   GHashTable *new_settings,
	   GError **err)
{
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (exported);
	DBusGMethodInvocation *context;

	context = g_object_get_data (G_OBJECT (exported), NM_EXPORTED_CONNECTION_DBUS_METHOD_INVOCATION);
	g_return_val_if_fail (context != NULL, FALSE);

	return check_polkit_privileges (priv->dbus_connection, priv->pol_ctx, context, err);
}

static gboolean
delete (NMExportedConnection *exported, GError **err)
{
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (exported);
	DBusGMethodInvocation *context;

	context = g_object_get_data (G_OBJECT (exported), NM_EXPORTED_CONNECTION_DBUS_METHOD_INVOCATION);
	g_return_val_if_fail (context != NULL, FALSE);

	return check_polkit_privileges (priv->dbus_connection, priv->pol_ctx, context, err);
}

/* GObject */

static void
nm_sysconfig_connection_init (NMSysconfigConnection *self)
{
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (self);
	GError *err = NULL;

	priv->dbus_connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
	if (err) {
		g_warning ("Could not get DBus connection: %s", err->message);
		g_error_free (err);
	}

	priv->pol_ctx = create_polkit_context ();
}

static void
finalize (GObject *object)
{
	NMSysconfigConnectionPrivate *priv = NM_SYSCONFIG_CONNECTION_GET_PRIVATE (object);

	if (priv->pol_ctx)
		polkit_context_unref (priv->pol_ctx);

	if (priv->dbus_connection)
		dbus_g_connection_unref (priv->dbus_connection);

	G_OBJECT_CLASS (nm_sysconfig_connection_parent_class)->finalize (object);
}

static void
nm_sysconfig_connection_class_init (NMSysconfigConnectionClass *sysconfig_connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (sysconfig_connection_class);
	NMExportedConnectionClass *connection_class = NM_EXPORTED_CONNECTION_CLASS (sysconfig_connection_class);

	g_type_class_add_private (sysconfig_connection_class, sizeof (NMSysconfigConnectionPrivate));

	/* Virtual methods */
	object_class->finalize = finalize;

	connection_class->update = update;
	connection_class->delete = delete;
}
