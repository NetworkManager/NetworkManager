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

#include "nm-polkit.h"

#if !HAVE_POLKIT

G_DEFINE_TYPE (PolkitSubject, polkit_subject, G_TYPE_OBJECT);
G_DEFINE_TYPE (PolkitAuthority, polkit_authority, G_TYPE_OBJECT);
G_DEFINE_TYPE (PolkitAuthorizationResult, polkit_authorization_result, G_TYPE_OBJECT);
static void polkit_subject_init (PolkitSubject *self) { }
static void polkit_authority_init (PolkitAuthority *self) { }
static void polkit_authorization_result_init (PolkitAuthorizationResult *self) { }
static void polkit_subject_class_init (PolkitSubjectClass *klass) { }
static void polkit_authority_class_init (PolkitAuthorityClass *klass) { }
static void polkit_authorization_result_class_init (PolkitAuthorizationResultClass *klass) { }

PolkitAuthority *polkit_authority_get (void)
{
	return POLKIT_AUTHORITY (g_object_new (POLKIT_TYPE_AUTHORITY, NULL));
}

void polkit_authority_check_authorization (PolkitAuthority               *authority,
                                           PolkitSubject                 *subject,
                                           const gchar                   *action_id,
                                           gpointer                       details,
                                           PolkitCheckAuthorizationFlags  flags,
                                           GCancellable                  *cancellable,
                                           GAsyncReadyCallback            callback,
                                           gpointer                       user_data)
{
	GSimpleAsyncResult *dummy_result = g_simple_async_result_new(G_OBJECT (authority),
	                                                             callback,
	                                                             user_data,
	                                                             NULL);
	/* This will invoke the callback from the idle loop. The callback won't
	   look at the contents of dummy_result, it will merely pass it into
	   ..._finish() */
	g_simple_async_result_complete_in_idle (dummy_result);
}

PolkitAuthorizationResult *polkit_authority_check_authorization_finish (PolkitAuthority *authority,
                                                                        GAsyncResult    *res,
                                                                        GError         **error)
{
	/* Again, the contents of the returned object don't matter, as the caller
	   will only use it via ..._get_is_authorized and ..._get_is_challenge,
	   below. */
	return POLKIT_AUTHORIZATION_RESULT (g_object_new (POLKIT_TYPE_AUTHORIZATION_RESULT, NULL));
}
gboolean polkit_authorization_result_get_is_authorized (PolkitAuthorizationResult *result)
{
	return TRUE;
}
gboolean polkit_authorization_result_get_is_challenge  (PolkitAuthorizationResult *result)
{
	return FALSE;
}

PolkitSubject *polkit_system_bus_name_new (const gchar *name)
{
	/* The contents of the returned object don't matter, as the caller will
	   merely pass it as a parameter to polkit_authority_check_authorization. */
	return POLKIT_SUBJECT (g_object_new (POLKIT_TYPE_SUBJECT, NULL));
}

#endif /* !HAVE_POLKIT */


#if !HAVE_POLKIT || !HAVE_POLKIT_AUTHORITY_GET_SYNC

PolkitAuthority *
polkit_authority_get_sync (GCancellable *cancellable, GError **error)
{
	PolkitAuthority *authority;

	authority = polkit_authority_get ();
	if (!authority)
		g_set_error (error, 0, 0, "failed to get the PolicyKit authority");
	return authority;
}

#endif /* !HAVE_POLKIT || !HAVE_POLKIT_AUTHORITY_GET_SYNC */
