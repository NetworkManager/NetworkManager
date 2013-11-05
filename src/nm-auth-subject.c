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
 * Copyright (C) 2013 Red Hat, Inc.
 */

/**
 * SECTION:nm-auth-subject
 * @short_description: Encapsulates authentication information about a requestor
 *
 * #NMAuthSubject encpasulates identifying information about an entity that
 * makes requests, like process identifier and user UID.
 */

#include <config.h>
#include <glib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#if WITH_POLKIT
#include <polkit/polkit.h>
#endif

#include "nm-auth-subject.h"
#include "nm-dbus-manager.h"

G_DEFINE_TYPE (NMAuthSubject, nm_auth_subject, G_TYPE_OBJECT)

#define NM_AUTH_SUBJECT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_AUTH_SUBJECT, NMAuthSubjectPrivate))

typedef struct {
	gulong pid;
	gulong uid;
	char *dbus_sender;

#if WITH_POLKIT
	PolkitSubject *pk_subject;
#endif
} NMAuthSubjectPrivate;

static NMAuthSubject *
_new_common (DBusGMethodInvocation *context,
             DBusConnection *connection,
             DBusMessage *message,
             gboolean internal)
{
	NMAuthSubject *subject;
	NMAuthSubjectPrivate *priv;
	NMDBusManager *dbus_mgr;
	gboolean success = FALSE;

	g_return_val_if_fail (context || (connection && message) || internal, NULL);
	if (internal)
		g_return_val_if_fail (context == NULL && connection == NULL && message == NULL, NULL);

	subject = NM_AUTH_SUBJECT (g_object_new (NM_TYPE_AUTH_SUBJECT, NULL));
	priv = NM_AUTH_SUBJECT_GET_PRIVATE (subject);

	dbus_mgr = nm_dbus_manager_get ();

	if (internal) {
		priv->uid = 0;
		priv->pid = 0;
		return subject;
	}

	if (context) {
		success = nm_dbus_manager_get_caller_info (dbus_mgr,
		                                           context,
		                                           &priv->dbus_sender,
		                                           &priv->uid,
		                                           &priv->pid);
	} else if (message) {
		success = nm_dbus_manager_get_caller_info_from_message (dbus_mgr,
		                                                        connection,
		                                                        message,
		                                                        &priv->dbus_sender,
		                                                        &priv->uid,
		                                                        &priv->pid);
	} else
		g_assert_not_reached ();

	if (!success) {
		g_object_unref (subject);
		return NULL;
	}

	g_assert (priv->dbus_sender);
	g_assert_cmpuint (priv->pid, !=, 0);

#if WITH_POLKIT
	/* FIXME: should we use polkit_unix_session_new() to store the session ID
	 * of a short-lived process, so that the process can exit but we can still
	 * ask that user for authorization?
	 */
	priv->pk_subject = polkit_unix_process_new_for_owner (priv->pid, 0, priv->uid);
	if (!priv->pk_subject)
		return NULL;
#endif

	return subject;
}


NMAuthSubject *
nm_auth_subject_new_from_context (DBusGMethodInvocation *context)
{
	return _new_common (context, NULL, NULL, FALSE);
}

NMAuthSubject *
nm_auth_subject_new_from_message (DBusConnection *connection,
                                  DBusMessage *message)
{
	return _new_common (NULL, connection, message, FALSE);
}

/**
 * nm_auth_subject_new_internal():
 *
 * Creates a new auth subject representing the NetworkManager process itself.
 *
 * Returns: the new #NMAuthSubject
 */
NMAuthSubject *
nm_auth_subject_new_internal (void)
{
	return _new_common (NULL, NULL, NULL, TRUE);
}

/**************************************************************/

gulong
nm_auth_subject_get_uid (NMAuthSubject *subject)
{
	return NM_AUTH_SUBJECT_GET_PRIVATE (subject)->uid;
}

gulong
nm_auth_subject_get_pid (NMAuthSubject *subject)
{
	return NM_AUTH_SUBJECT_GET_PRIVATE (subject)->pid;
}

const char *
nm_auth_subject_get_dbus_sender (NMAuthSubject *subject)
{
	return NM_AUTH_SUBJECT_GET_PRIVATE (subject)->dbus_sender;
}

gboolean
nm_auth_subject_get_internal (NMAuthSubject *subject)
{
	/* internal requests will have no dbus sender */
	return NM_AUTH_SUBJECT_GET_PRIVATE (subject)->dbus_sender ? FALSE : TRUE;
}

#if WITH_POLKIT
PolkitSubject *
nm_auth_subject_get_polkit_subject (NMAuthSubject *subject)
{
	return NM_AUTH_SUBJECT_GET_PRIVATE (subject)->pk_subject;
}
#endif

/******************************************************************/

static void
nm_auth_subject_init (NMAuthSubject *self)
{
	NMAuthSubjectPrivate *priv = NM_AUTH_SUBJECT_GET_PRIVATE (self);

	priv->pid = G_MAXULONG;
	priv->uid = G_MAXULONG;
}

static void
finalize (GObject *object)
{
	NMAuthSubjectPrivate *priv = NM_AUTH_SUBJECT_GET_PRIVATE (object);

	g_free (priv->dbus_sender);

#if WITH_POLKIT
	if (priv->pk_subject)
		g_object_unref (priv->pk_subject);
#endif

	G_OBJECT_CLASS (nm_auth_subject_parent_class)->finalize (object);
}

static void
nm_auth_subject_class_init (NMAuthSubjectClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMAuthSubjectPrivate));

	/* virtual methods */
	object_class->finalize = finalize;
}
