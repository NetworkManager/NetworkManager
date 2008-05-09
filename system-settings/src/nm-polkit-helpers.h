/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_POLKIT_HELPERS_H
#define NM_POLKIT_HELPERS_H

#include <polkit-dbus/polkit-dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#define NM_SYSCONFIG_POLICY_ACTION "org.freedesktop.network-manager-settings.system.modify"

enum {
	NM_SYSCONFIG_SETTINGS_ERROR_GENERAL = 0,
	NM_SYSCONFIG_SETTINGS_ERROR_NOT_PRIVILEGED,
	NM_SYSCONFIG_SETTINGS_ERROR_INVALID_CONNECTION
};

#define NM_SYSCONFIG_SETTINGS_ERROR (nm_sysconfig_settings_error_quark ())
#define NM_TYPE_SYSCONFIG_SETTINGS_ERROR (nm_sysconfig_settings_error_get_type ())

GQuark nm_sysconfig_settings_error_quark    (void);
GType  nm_sysconfig_settings_error_get_type (void);

PolKitContext *create_polkit_context   (void);
gboolean       check_polkit_privileges (DBusGConnection *dbus_connection,
								PolKitContext *pol_ctx,
								DBusGMethodInvocation *context,
								GError **err);

#endif /* NM_POLKIT_HELPERS_H */
