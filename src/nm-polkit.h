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

/* Fix for polkit 0.97 and later */
#if !HAVE_POLKIT_AUTHORITY_GET_SYNC
PolkitAuthority *
polkit_authority_get_sync (GCancellable *cancellable, GError **error);
#endif /* !HAVE_POLKIT_AUTHORITY_GET_SYNC */


#else /* ! HAVE_POLKIT */
/* Stubs for the polkit api, that always allow the requested operation. */

#include <glib-object.h>
#include <gio/gio.h>

/* Stub out PolicyKit's internal data structures: */

/* ... PolkitSubject
   In Polkit this is an interface, not a class, but to make it easier for
   me to create instances of it, here it is just a class. */
#define POLKIT_TYPE_SUBJECT          (polkit_subject_get_type())
#define POLKIT_SUBJECT(o)            (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_TYPE_SUBJECT, PolkitSubject))
#define POLKIT_SUBJECT_CLASS(k)      (G_TYPE_CHECK_CLASS_CAST((k), POLKIT_TYPE_SUBJECT, PolkitSubjectClass))
#define POLKIT_SUBJECT_GET_CLASS(o)  (G_TYPE_INSTANCE_GET_CLASS ((o), POLKIT_TYPE_SUBJECT, PolkitSubjectClass))
#define POLKIT_IS_SUBJECT(o)         (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_TYPE_SUBJECT))
#define POLKIT_IS_SUBJECT_CLASS(k)   (G_TYPE_CHECK_CLASS_TYPE ((k), POLKIT_TYPE_SUBJECT))
typedef struct _PolkitSubject PolkitSubject;
typedef struct _PolkitSubjectClass PolkitSubjectClass;
struct _PolkitSubject
{
	GObject parent_instance;
};
struct _PolkitSubjectClass
{
	GObjectClass parent_class;
};
GType polkit_subject_get_type (void);

/* ... PolkitAuthority */
#define POLKIT_TYPE_AUTHORITY          (polkit_authority_get_type())
#define POLKIT_AUTHORITY(o)            (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_TYPE_AUTHORITY, PolkitAuthority))
#define POLKIT_AUTHORITY_CLASS(k)      (G_TYPE_CHECK_CLASS_CAST((k), POLKIT_TYPE_AUTHORITY, PolkitAuthorityClass))
#define POLKIT_AUTHORITY_GET_CLASS(o)  (G_TYPE_INSTANCE_GET_CLASS ((o), POLKIT_TYPE_AUTHORITY, PolkitAuthorityClass))
#define POLKIT_IS_AUTHORITY(o)         (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_TYPE_AUTHORITY))
#define POLKIT_IS_AUTHORITY_CLASS(k)   (G_TYPE_CHECK_CLASS_TYPE ((k), POLKIT_TYPE_AUTHORITY))
typedef struct _PolkitAuthority PolkitAuthority;
typedef struct _PolkitAuthorityClass PolkitAuthorityClass;
struct _PolkitAuthority
{
	GObject parent_instance;
};
struct _PolkitAuthorityClass
{
	GObjectClass parent_class;
};
GType polkit_authority_get_type (void);

/* ... PolkitAuthorizationResult */
#define POLKIT_TYPE_AUTHORIZATION_RESULT          (polkit_authorization_result_get_type())
#define POLKIT_AUTHORIZATION_RESULT(o)            (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_TYPE_AUTHORIZATION_RESULT, PolkitAuthorizationResult))
#define POLKIT_AUTHORIZATION_RESULT_CLASS(k)      (G_TYPE_CHECK_CLASS_CAST((k), POLKIT_TYPE_AUTHORIZATION_RESULT, PolkitAuthorizationResultClass))
#define POLKIT_AUTHORIZATION_RESULT_GET_CLASS(o)  (G_TYPE_INSTANCE_GET_CLASS ((o), POLKIT_TYPE_AUTHORIZATION_RESULT, PolkitAuthorizationResultClass))
#define POLKIT_IS_AUTHORIZATION_RESULT(o)         (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_TYPE_AUTHORIZATION_RESULT))
#define POLKIT_IS_AUTHORIZATION_RESULT_CLASS(k)   (G_TYPE_CHECK_CLASS_TYPE ((k), POLKIT_TYPE_AUTHORIZATION_RESULT))
typedef struct _PolkitAuthorizationResult PolkitAuthorizationResult;
typedef struct _PolkitAuthorizationResultClass PolkitAuthorizationResultClass;
struct _PolkitAuthorizationResult
{
	GObject parent_instance;
};
struct _PolkitAuthorizationResultClass
{
	GObjectClass parent_class;
};
GType polkit_authorization_result_get_type (void);


/* From polkitcheckauthorizationflags.h */
typedef enum
{
  POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE = 0,
  POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION = (1<<0),
} PolkitCheckAuthorizationFlags;

/* From polkitauthority.h */
PolkitAuthority *polkit_authority_get (void);

PolkitAuthority *
polkit_authority_get_sync (GCancellable *cancellable, GError **error);

void polkit_authority_check_authorization (PolkitAuthority               *authority,
                                           PolkitSubject                 *subject,
                                           const gchar                   *action_id,
                                           gpointer                       details,
                                           PolkitCheckAuthorizationFlags  flags,
                                           GCancellable                  *cancellable,
                                           GAsyncReadyCallback            callback,
                                           gpointer                       user_data);

PolkitAuthorizationResult *polkit_authority_check_authorization_finish (PolkitAuthority *authority,
                                                                        GAsyncResult    *res,
                                                                        GError         **error);

/* From polkitauthorizationresult.h */
gboolean polkit_authorization_result_get_is_authorized (PolkitAuthorizationResult *result);
gboolean polkit_authorization_result_get_is_challenge  (PolkitAuthorizationResult *result);

/* From polkitsystembusname.h */
PolkitSubject *polkit_system_bus_name_new (const gchar *name);

#endif /* HAVE_POLKIT */

#endif /* NM_POLKIT_H */
