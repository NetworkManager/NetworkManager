/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * (C) Copyright 2008 - 2010 Red Hat, Inc.
 */

#ifndef NM_POLKIT_H
#define NM_POLKIT_H

#include <config.h>

#define NM_SYSCONFIG_POLICY_ACTION_CONNECTION_MODIFY    "org.freedesktop.network-manager-settings.system.modify"
#define NM_SYSCONFIG_POLICY_ACTION_WIFI_SHARE_PROTECTED "org.freedesktop.network-manager-settings.system.wifi.share.protected"
#define NM_SYSCONFIG_POLICY_ACTION_WIFI_SHARE_OPEN      "org.freedesktop.network-manager-settings.system.wifi.share.open"
#define NM_SYSCONFIG_POLICY_ACTION_HOSTNAME_MODIFY      "org.freedesktop.network-manager-settings.system.hostname.modify"

#if HAVE_POLKIT
#include <polkit/polkit.h>
#else

/* Stub out PolicyKit's internal data structures: */
#include <glib-object.h>
#include <gio/gio.h>

typedef enum {
  POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE = 0,
  POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION = (1 << 0),
} PolkitCheckAuthorizationFlags;

typedef void PolkitSubject;

static inline PolkitSubject *
polkit_system_bus_name_new (const gchar *name)
{
	return (PolkitSubject *) 0x1;
}

/* PolkitAuthority */
#define POLKIT_TYPE_AUTHORITY          (polkit_authority_get_type())
#define POLKIT_AUTHORITY(o)            (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_TYPE_AUTHORITY, PolkitAuthority))

typedef struct {
	GObject parent_instance;
} PolkitAuthority;

typedef struct {
	GObjectClass parent_class;
} PolkitAuthorityClass;

GType polkit_authority_get_type (void);

/* PolkitAuthorizationResult */
#define POLKIT_TYPE_AUTHORIZATION_RESULT          (polkit_authorization_result_get_type())
#define POLKIT_AUTHORIZATION_RESULT(o)            (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_TYPE_AUTHORIZATION_RESULT, PolkitAuthorizationResult))

typedef struct {
	GObject parent_instance;
} PolkitAuthorizationResult;

typedef struct {
	GObjectClass parent_class;
} PolkitAuthorizationResultClass;

GType polkit_authorization_result_get_type (void);

static inline PolkitAuthority *
polkit_authority_get (void)
{
	return (PolkitAuthority *) g_object_new (POLKIT_TYPE_AUTHORITY, NULL);
}

static inline void
polkit_authority_check_authorization (PolkitAuthority               *authority,
                                      PolkitSubject                 *subject,
                                      const gchar                   *action_id,
                                      gpointer                       details,
                                      PolkitCheckAuthorizationFlags  flags,
                                      GCancellable                  *cancellable,
                                      GAsyncReadyCallback            callback,
                                      gpointer                       user_data)
{
	GSimpleAsyncResult *dummy_result;

	dummy_result = g_simple_async_result_new(G_OBJECT (authority), callback, user_data, NULL);
	g_simple_async_result_complete_in_idle (dummy_result);
}

static inline PolkitAuthorizationResult *
polkit_authority_check_authorization_finish (PolkitAuthority *authority,
                                             GAsyncResult    *res,
                                             GError         **error)
{
	return (PolkitAuthorizationResult *) g_object_new (POLKIT_TYPE_AUTHORIZATION_RESULT, NULL);
}

/* From polkitauthority.h */
static inline gboolean
polkit_authorization_result_get_is_authorized (PolkitAuthorizationResult *result)
{
	return TRUE;
}

static inline gboolean
polkit_authorization_result_get_is_challenge  (PolkitAuthorizationResult *result)
{
	return FALSE;
}

#endif /* HAVE_POLKIT */


#if !HAVE_POLKIT || !HAVE_POLKIT_AUTHORITY_GET_SYNC
/* Fix for polkit 0.97 and later and when polkit is disabled */
static inline PolkitAuthority *
polkit_authority_get_sync (GCancellable *cancellable, GError **error)
{
	PolkitAuthority *authority;

	authority = polkit_authority_get ();
	if (!authority)
		g_set_error (error, 0, 0, "failed to get the PolicyKit authority");
	return authority;
}
#endif /* !HAVE_POLKIT || !HAVE_POLKIT_AUTHORITY_GET_SYNC */

#endif /* NM_POLKIT_H */
