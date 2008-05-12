/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include "nm-polkit-helpers.h"
#include <nm-dbus-settings.h>

GQuark
nm_sysconfig_settings_error_quark (void)
{
	static GQuark ret = 0;

	if (ret == 0)
		ret = g_quark_from_static_string ("nm_sysconfig_settings_error");

	return ret;
}

#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_sysconfig_settings_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			ENUM_ENTRY (NM_SYSCONFIG_SETTINGS_ERROR_GENERAL, "GeneralError"),
			ENUM_ENTRY (NM_SYSCONFIG_SETTINGS_ERROR_NOT_PRIVILEGED, "NotPrivileged"),
			ENUM_ENTRY (NM_SYSCONFIG_SETTINGS_ERROR_INVALID_CONNECTION, "InvalidConnection"),
			{ 0, 0, 0 }
		};

		etype = g_enum_register_static ("NMSysconfigSettingsError", values);
	}

	return etype;
}

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
	PolKitContext *pol_ctx;
	PolKitError *err = NULL;

	pol_ctx = polkit_context_new ();
	polkit_context_set_io_watch_functions (pol_ctx, pk_io_add_watch, pk_io_remove_watch);
	if (!polkit_context_init (pol_ctx, &err)) {
		g_warning ("Cannot initialize libpolkit: %s", polkit_error_get_error_message (err));
		polkit_error_free (err);

		polkit_context_unref (pol_ctx);
		pol_ctx = NULL;
	}

	return pol_ctx;
}

gboolean
check_polkit_privileges (DBusGConnection *dbus_connection,
					PolKitContext *pol_ctx,
					DBusGMethodInvocation *context,
					GError **err)
{
	DBusError dbus_error;
	const char *sender;
	PolKitCaller *pk_caller;
	PolKitAction *pk_action;
	PolKitResult pk_result;

	dbus_error_init (&dbus_error);
	sender = dbus_g_method_get_sender (context);
	pk_caller = polkit_caller_new_from_dbus_name (dbus_g_connection_get_connection (dbus_connection),
										 sender,
										 &dbus_error);
	if (!pk_caller) {
		*err = g_error_new (NM_SYSCONFIG_SETTINGS_ERROR,
						NM_SYSCONFIG_SETTINGS_ERROR_NOT_PRIVILEGED,
						"Error getting information about caller: %s: %s",
						dbus_error.name, dbus_error.message);
		dbus_error_free (&dbus_error);
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
