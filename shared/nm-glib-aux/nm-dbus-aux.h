/* NetworkManager -- Network link manager
 *
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
 * (C) Copyright 2019 Red Hat, Inc.
 */

#ifndef __NM_DBUS_AUX_H__
#define __NM_DBUS_AUX_H__

#include "nm-std-aux/nm-dbus-compat.h"

/*****************************************************************************/

static inline gboolean
nm_clear_g_dbus_connection_signal (GDBusConnection *dbus_connection,
                                   guint *id)
{
	guint v;

	if (   id
	    && (v = *id)) {
		*id = 0;
		g_dbus_connection_signal_unsubscribe (dbus_connection, v);
		return TRUE;
	}
	return FALSE;
}

/*****************************************************************************/

static inline void
nm_dbus_connection_call_start_service_by_name (GDBusConnection *dbus_connection,
                                               const char *name,
                                               int timeout_msec,
                                               GCancellable *cancellable,
                                               GAsyncReadyCallback  callback,
                                               gpointer user_data)
{
	g_dbus_connection_call (dbus_connection,
	                        DBUS_SERVICE_DBUS,
	                        DBUS_PATH_DBUS,
	                        DBUS_INTERFACE_DBUS,
	                        "StartServiceByName",
	                        g_variant_new ("(su)", name, 0u),
	                        G_VARIANT_TYPE ("(u)"),
	                        G_DBUS_CALL_FLAGS_NONE,
	                        timeout_msec,
	                        cancellable,
	                        callback,
	                        user_data);
}

/*****************************************************************************/

static inline guint
nm_dbus_connection_signal_subscribe_name_owner_changed (GDBusConnection *dbus_connection,
                                                        const char *service_name,
                                                        GDBusSignalCallback callback,
                                                        gpointer user_data,
                                                        GDestroyNotify user_data_free_func)

{
	return g_dbus_connection_signal_subscribe (dbus_connection,
	                                           DBUS_SERVICE_DBUS,
	                                           DBUS_INTERFACE_DBUS,
	                                           "NameOwnerChanged",
	                                           DBUS_PATH_DBUS,
	                                           service_name,
	                                           G_DBUS_SIGNAL_FLAGS_NONE,
	                                           callback,
	                                           user_data,
	                                           user_data_free_func);
}

typedef void (*NMDBusConnectionCallGetNameOwnerCb) (const char *name_owner,
                                                    GError *error,
                                                    gpointer user_data);

void nm_dbus_connection_call_get_name_owner (GDBusConnection *dbus_connection,
                                              const char *service_name,
                                              int timeout_msec,
                                              GCancellable *cancellable,
                                              NMDBusConnectionCallGetNameOwnerCb callback,
                                              gpointer user_data);

/*****************************************************************************/

#endif /* __NM_DBUS_AUX_H__ */
