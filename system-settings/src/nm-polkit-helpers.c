/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2008 Novell, Inc.
 * (C) Copyright 2008 Red Hat, Inc.
 */

#include <nm-dbus-settings.h>
#include "nm-polkit-helpers.h"
#include "nm-system-config-error.h"

static gboolean
pk_io_watch_have_data (GIOChannel *channel, GIOCondition condition, gpointer user_data)
{
	int fd;
	PolKitContext *pk_context = (PolKitContext *) user_data;

	fd = g_io_channel_unix_get_fd (channel);
	polkit_context_io_func (pk_context, fd);
	
	return TRUE;
}

static int
pk_io_add_watch (PolKitContext *pk_context, int fd)
{
	guint id = 0;
	GIOChannel *channel;
	
	channel = g_io_channel_unix_new (fd);
	if (channel == NULL)
		goto out;
	id = g_io_add_watch (channel, G_IO_IN, pk_io_watch_have_data, pk_context);
	if (id == 0) {
		g_io_channel_unref (channel);
		goto out;
	}
	g_io_channel_unref (channel);

 out:
	return id;
}

static void
pk_io_remove_watch (PolKitContext *pk_context, int watch_id)
{
	g_source_remove (watch_id);
}

PolKitContext *
create_polkit_context (void)
{
	static PolKitContext *global_context = NULL;
	PolKitError *err;

	if (G_LIKELY (global_context))
		return polkit_context_ref (global_context);

	global_context = polkit_context_new ();
	polkit_context_set_io_watch_functions (global_context, pk_io_add_watch, pk_io_remove_watch);
	err = NULL;
	if (!polkit_context_init (global_context, &err)) {
		g_warning ("Cannot initialize libpolkit: %s",
		           err ? polkit_error_get_error_message (err) : "unknown error");
		if (err)
			polkit_error_free (err);

		/* PK 0.6's polkit_context_init() unrefs the global_context on failure */
#if (POLKIT_VERSION_MAJOR == 0) && (POLKIT_VERSION_MINOR >= 7)
		polkit_context_unref (global_context);
#endif
		global_context = NULL;
	}

	return global_context;
}

gboolean
check_polkit_privileges (DBusGConnection *dbus_connection,
					PolKitContext *pol_ctx,
					DBusGMethodInvocation *context,
					GError **err)
{
	DBusError dbus_error;
	char *sender;
	PolKitCaller *pk_caller;
	PolKitAction *pk_action;
	PolKitResult pk_result;

	dbus_error_init (&dbus_error);
	sender = dbus_g_method_get_sender (context);
	pk_caller = polkit_caller_new_from_dbus_name (dbus_g_connection_get_connection (dbus_connection),
										 sender,
										 &dbus_error);
	g_free (sender);

	if (dbus_error_is_set (&dbus_error)) {
		*err = g_error_new (NM_SYSCONFIG_SETTINGS_ERROR,
						NM_SYSCONFIG_SETTINGS_ERROR_NOT_PRIVILEGED,
						"Error getting information about caller: %s: %s",
						dbus_error.name, dbus_error.message);
		dbus_error_free (&dbus_error);

		if (pk_caller)
			polkit_caller_unref (pk_caller);

		return FALSE;
	}

	pk_action = polkit_action_new ();
	polkit_action_set_action_id (pk_action, NM_SYSCONFIG_POLICY_ACTION);

#if (POLKIT_VERSION_MAJOR == 0) && (POLKIT_VERSION_MINOR < 7)
	pk_result = polkit_context_can_caller_do_action (pol_ctx, pk_action, pk_caller);
#else
	pk_result = polkit_context_is_caller_authorized (pol_ctx, pk_action, pk_caller, TRUE, NULL);
#endif
	polkit_caller_unref (pk_caller);
	polkit_action_unref (pk_action);

	if (pk_result != POLKIT_RESULT_YES) {
		*err = g_error_new (NM_SYSCONFIG_SETTINGS_ERROR,
						NM_SYSCONFIG_SETTINGS_ERROR_NOT_PRIVILEGED,
						"%s %s",
						NM_SYSCONFIG_POLICY_ACTION,
						polkit_result_to_string_representation (pk_result));
		return FALSE;
	}

	return TRUE;
}
