/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2007 - 2008 Novell, Inc.
 * Copyright 2007 - 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-simple-connection.h"

#include "nm-setting-private.h"

/**
 * SECTION:nm-simple-connection
 * @short_description: An unmanaged connection
 *
 * An #NMSimpleConnection does not directly represent a D-Bus-exported connection,
 * but might be used in the process of creating a new one.
 **/

/*****************************************************************************/

static void nm_simple_connection_interface_init (NMConnectionInterface *iface);

G_DEFINE_TYPE_WITH_CODE (NMSimpleConnection, nm_simple_connection, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (NM_TYPE_CONNECTION, nm_simple_connection_interface_init);
                         )

/*****************************************************************************/

static void
nm_simple_connection_init (NMSimpleConnection *self)
{
}

/**
 * nm_simple_connection_new:
 *
 * Creates a new #NMSimpleConnection object with no #NMSetting objects.
 *
 * Returns: (transfer full): the new empty #NMConnection object
 **/
NMConnection *
nm_simple_connection_new (void)
{
	return (NMConnection *) g_object_new (NM_TYPE_SIMPLE_CONNECTION, NULL);
}

/**
 * _nm_simple_connection_new_from_dbus:
 * @dict: a #GVariant of type %NM_VARIANT_TYPE_CONNECTION describing the connection
 * @error: on unsuccessful return, an error
 *
 * Creates a new #NMSimpleConnection from a hash table describing the
 * connection.  See nm_connection_to_dbus() for a description of the expected
 * hash table.
 *
 * Returns: (transfer full): the new #NMSimpleConnection object, populated with
 * settings created from the values in the hash table, or %NULL if there was
 * an error.
 **/
NMConnection *
_nm_simple_connection_new_from_dbus (GVariant *dict, NMSettingParseFlags parse_flags, GError **error)
{
	NMConnection *connection;

	g_return_val_if_fail (dict != NULL, NULL);
	g_return_val_if_fail (g_variant_is_of_type (dict, NM_VARIANT_TYPE_CONNECTION), NULL);
	g_return_val_if_fail (!NM_FLAGS_ANY (parse_flags, ~NM_SETTING_PARSE_FLAGS_ALL), NULL);
	g_return_val_if_fail (!NM_FLAGS_ALL (parse_flags, NM_SETTING_PARSE_FLAGS_STRICT | NM_SETTING_PARSE_FLAGS_BEST_EFFORT), NULL);

	connection = nm_simple_connection_new ();
	if (!_nm_connection_replace_settings (connection, dict, parse_flags, error))
		g_clear_object (&connection);
	return connection;
}

/**
 * nm_simple_connection_new_from_dbus:
 * @dict: a #GVariant of type %NM_VARIANT_TYPE_CONNECTION describing the connection
 * @error: on unsuccessful return, an error
 *
 * Creates a new #NMSimpleConnection from a hash table describing the
 * connection and normalize the connection.  See nm_connection_to_dbus() for a
 * description of the expected hash table.
 *
 * Returns: (transfer full): the new #NMSimpleConnection object, populated with
 * settings created from the values in the hash table, or %NULL if the
 * connection failed to normalize.
 **/
NMConnection *
nm_simple_connection_new_from_dbus (GVariant *dict, GError **error)
{
	return _nm_simple_connection_new_from_dbus (dict,
	                                            NM_SETTING_PARSE_FLAGS_NORMALIZE,
	                                            error);
}

/**
 * nm_simple_connection_new_clone:
 * @connection: the #NMConnection to clone
 *
 * Clones an #NMConnection as an #NMSimpleConnection.
 *
 * Returns: (transfer full): a new #NMConnection containing the same settings
 * and properties as the source #NMConnection
 **/
NMConnection *
nm_simple_connection_new_clone (NMConnection *connection)
{
	NMConnection *clone;
	const char *path;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	clone = nm_simple_connection_new ();

	path = nm_connection_get_path (connection);
	if (path)
		nm_connection_set_path (clone, path);

	nm_connection_replace_settings_from_connection (clone, connection);

	return clone;
}

static void
dispose (GObject *object)
{
#if NM_MORE_ASSERTS
	g_signal_handlers_disconnect_by_data (object, (gpointer) &_nmtst_connection_unchanging_user_data);
#endif

	nm_connection_clear_secrets (NM_CONNECTION (object));

	G_OBJECT_CLASS (nm_simple_connection_parent_class)->dispose (object);
}

static void
nm_simple_connection_class_init (NMSimpleConnectionClass *simple_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (simple_class);

	object_class->dispose = dispose;
}

static void
nm_simple_connection_interface_init (NMConnectionInterface *iface)
{
}
