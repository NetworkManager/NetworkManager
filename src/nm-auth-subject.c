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
 * Copyright (C) 2013 - 2014 Red Hat, Inc.
 */

/**
 * SECTION:nm-auth-subject
 * @short_description: Encapsulates authentication information about a requestor
 *
 * #NMAuthSubject encpasulates identifying information about an entity that
 * makes requests, like process identifier and user UID.
 */

#include "nm-default.h"

#include "nm-auth-subject.h"

#include <stdlib.h>

#include "nm-dbus-manager.h"

enum {
	PROP_0,
	PROP_SUBJECT_TYPE,
	PROP_UNIX_PROCESS_DBUS_SENDER,
	PROP_UNIX_PROCESS_PID,
	PROP_UNIX_PROCESS_UID,

	PROP_LAST,
};

typedef struct {
	NMAuthSubjectType subject_type;
	struct {
		gulong pid;
		gulong uid;
		guint64 start_time;
		char *dbus_sender;
	} unix_process;
} NMAuthSubjectPrivate;

struct _NMAuthSubject {
	GObject parent;
	NMAuthSubjectPrivate _priv;
};

struct _NMAuthSubjectClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMAuthSubject, nm_auth_subject, G_TYPE_OBJECT)

#define NM_AUTH_SUBJECT_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMAuthSubject, NM_IS_AUTH_SUBJECT)

/*****************************************************************************/

#define CHECK_SUBJECT(self, error_value) \
	NMAuthSubjectPrivate *priv; \
	g_return_val_if_fail (NM_IS_AUTH_SUBJECT (self), error_value); \
	priv = NM_AUTH_SUBJECT_GET_PRIVATE (self); \

#define CHECK_SUBJECT_TYPED(self, expected_subject_type, error_value) \
	CHECK_SUBJECT (self, error_value); \
	g_return_val_if_fail (priv->subject_type == (expected_subject_type), error_value);

const char *
nm_auth_subject_to_string (NMAuthSubject *self, char *buf, gsize buf_len)
{
	CHECK_SUBJECT (self, NULL);

	switch (priv->subject_type) {
	case NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS:
		g_snprintf (buf, buf_len, "unix-process[pid=%lu, uid=%lu, start=%llu]",
		            (unsigned long) priv->unix_process.pid,
		            (unsigned long) priv->unix_process.uid,
		            (unsigned long long) priv->unix_process.start_time);
		break;
	case NM_AUTH_SUBJECT_TYPE_INTERNAL:
		g_strlcpy (buf, "internal", buf_len);
		break;
	default:
		g_strlcpy (buf, "invalid", buf_len);
		break;
	}
	return buf;
}

/* returns a floating variant */
GVariant *
nm_auth_subject_unix_process_to_polkit_gvariant (NMAuthSubject *self)
{
	GVariantBuilder builder;
	GVariant *dict;
	GVariant *ret;
	CHECK_SUBJECT_TYPED (self, NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS, NULL);

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));
	g_variant_builder_add (&builder, "{sv}", "pid",
	                       g_variant_new_uint32 (priv->unix_process.pid));
	g_variant_builder_add (&builder, "{sv}", "start-time",
	                       g_variant_new_uint64 (priv->unix_process.start_time));
	g_variant_builder_add (&builder, "{sv}", "uid",
	                       g_variant_new_int32 (priv->unix_process.uid));
	dict = g_variant_builder_end (&builder);
	ret = g_variant_new ("(s@a{sv})", "unix-process", dict);
	return ret;
}

NMAuthSubjectType
nm_auth_subject_get_subject_type (NMAuthSubject *subject)
{
	CHECK_SUBJECT (subject, NM_AUTH_SUBJECT_TYPE_INVALID);

	return priv->subject_type;
}

gboolean
nm_auth_subject_is_internal (NMAuthSubject *subject)
{
	return nm_auth_subject_get_subject_type (subject) == NM_AUTH_SUBJECT_TYPE_INTERNAL;
}

gboolean
nm_auth_subject_is_unix_process (NMAuthSubject *subject)
{
	return nm_auth_subject_get_subject_type (subject) == NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS;
}

gulong
nm_auth_subject_get_unix_process_pid (NMAuthSubject *subject)
{
	CHECK_SUBJECT_TYPED (subject, NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS, G_MAXULONG);

	return priv->unix_process.pid;
}

gulong
nm_auth_subject_get_unix_process_uid (NMAuthSubject *subject)
{
	CHECK_SUBJECT_TYPED (subject, NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS, G_MAXULONG);

	return priv->unix_process.uid;
}

const char *
nm_auth_subject_get_unix_process_dbus_sender (NMAuthSubject *subject)
{
	CHECK_SUBJECT_TYPED (subject, NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS, NULL);

	return priv->unix_process.dbus_sender;
}

/*****************************************************************************/

static NMAuthSubject *
_new_unix_process (GDBusMethodInvocation *context,
                   GDBusConnection *connection,
                   GDBusMessage *message)
{
	NMAuthSubject *self;
	const char *dbus_sender = NULL;
	gulong uid = 0;
	gulong pid = 0;
	gboolean success;

	g_return_val_if_fail (context || (connection && message), NULL);

	if (context) {
		success = nm_dbus_manager_get_caller_info (nm_dbus_manager_get (),
		                                           context,
		                                           &dbus_sender,
		                                           &uid,
		                                           &pid);
	} else {
		nm_assert (message);
		success = nm_dbus_manager_get_caller_info_from_message (nm_dbus_manager_get (),
		                                                        connection,
		                                                        message,
		                                                        &dbus_sender,
		                                                        &uid,
		                                                        &pid);
	}

	if (!success)
		return NULL;

	g_return_val_if_fail (dbus_sender && *dbus_sender, NULL);
	/* polkit glib library stores uid and pid as int. There might be some
	 * pitfalls if the id ever happens to be larger then that. Just assert against
	 * it here. */
	g_return_val_if_fail (uid <= MIN (G_MAXINT, G_MAXINT32), NULL);
	g_return_val_if_fail (pid > 0 && pid <= MIN (G_MAXINT, G_MAXINT32), NULL);

	self = NM_AUTH_SUBJECT (g_object_new (NM_TYPE_AUTH_SUBJECT,
	                                      NM_AUTH_SUBJECT_SUBJECT_TYPE, (int) NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS,
	                                      NM_AUTH_SUBJECT_UNIX_PROCESS_DBUS_SENDER, dbus_sender,
	                                      NM_AUTH_SUBJECT_UNIX_PROCESS_PID, (gulong) pid,
	                                      NM_AUTH_SUBJECT_UNIX_PROCESS_UID, (gulong) uid,
	                                      NULL));

	if (NM_AUTH_SUBJECT_GET_PRIVATE (self)->subject_type != NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS) {
		/* this most likely happened because the process is gone (start_time==0).
		 * Either that is not assert-worthy, or constructed() already asserted.
		 * Just return NULL. */
		g_clear_object (&self);
	}
	return self;
}

NMAuthSubject *
nm_auth_subject_new_unix_process_from_context (GDBusMethodInvocation *context)
{
	return _new_unix_process (context, NULL, NULL);
}

NMAuthSubject *
nm_auth_subject_new_unix_process_from_message (GDBusConnection *connection,
                                               GDBusMessage *message)
{
	return _new_unix_process (NULL, connection, message);
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
	return NM_AUTH_SUBJECT (g_object_new (NM_TYPE_AUTH_SUBJECT,
	                                      NM_AUTH_SUBJECT_SUBJECT_TYPE, (int) NM_AUTH_SUBJECT_TYPE_INTERNAL,
	                                      NULL));
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	NMAuthSubjectPrivate *priv = NM_AUTH_SUBJECT_GET_PRIVATE ((NMAuthSubject *) object);

	switch (prop_id) {
	case PROP_SUBJECT_TYPE:
		g_value_set_int (value, priv->subject_type);
		break;
	case PROP_UNIX_PROCESS_DBUS_SENDER:
		g_value_set_string (value, priv->unix_process.dbus_sender);
		break;
	case PROP_UNIX_PROCESS_PID:
		g_value_set_ulong (value, priv->unix_process.pid);
		break;
	case PROP_UNIX_PROCESS_UID:
		g_value_set_ulong (value, priv->unix_process.uid);
		break;
	default:
		 G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		 break;
	}
}

static void
set_property (GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
	NMAuthSubjectPrivate *priv = NM_AUTH_SUBJECT_GET_PRIVATE ((NMAuthSubject *) object);
	NMAuthSubjectType subject_type;
	int i;
	const char *str;
	gulong id;

	switch (prop_id) {
	case PROP_SUBJECT_TYPE:
		/* construct-only */
		i = g_value_get_int (value);
		g_return_if_fail (NM_IN_SET (i, (int) NM_AUTH_SUBJECT_TYPE_INTERNAL, (int) NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS));
		subject_type = i;
		priv->subject_type |= subject_type;
		g_return_if_fail (priv->subject_type == subject_type);
		break;
	case PROP_UNIX_PROCESS_DBUS_SENDER:
		/* construct-only */
		if ((str = g_value_get_string (value))) {
			priv->subject_type |= NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS;
			g_return_if_fail (priv->subject_type == NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS);
			priv->unix_process.dbus_sender = g_strdup (str);
		}
		break;
	case PROP_UNIX_PROCESS_PID:
		/* construct-only */
		if ((id = g_value_get_ulong (value)) != G_MAXULONG) {
			priv->subject_type |= NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS;
			g_return_if_fail (priv->subject_type == NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS);
			priv->unix_process.pid = id;
		}
		break;
	case PROP_UNIX_PROCESS_UID:
		/* construct-only */
		if ((id = g_value_get_ulong (value)) != G_MAXULONG) {
			priv->subject_type |= NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS;
			g_return_if_fail (priv->subject_type == NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS);
			priv->unix_process.uid = id;
		}
		break;
	default:
		 G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		 break;
	}
}

static void
_clear_private (NMAuthSubject *self)
{
	NMAuthSubjectPrivate *priv = NM_AUTH_SUBJECT_GET_PRIVATE (self);

	priv->subject_type = NM_AUTH_SUBJECT_TYPE_INVALID;
	priv->unix_process.pid = G_MAXULONG;
	priv->unix_process.uid = G_MAXULONG;
	g_clear_pointer (&priv->unix_process.dbus_sender, g_free);
}

static void
nm_auth_subject_init (NMAuthSubject *self)
{
	_clear_private (self);
}

static void
constructed (GObject *object)
{
	NMAuthSubject *self = NM_AUTH_SUBJECT (object);
	NMAuthSubjectPrivate *priv = NM_AUTH_SUBJECT_GET_PRIVATE (self);

	/* validate that the created instance. */

	switch (priv->subject_type) {
	case NM_AUTH_SUBJECT_TYPE_INTERNAL:
		priv->unix_process.pid = G_MAXULONG;
		priv->unix_process.uid = 0;  /* internal uses 'root' user */
		return;
	case NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS:
		/* Ensure pid and uid to be representable as int32.
		 * DBUS treats them as uint32, polkit library as int. */
		if (priv->unix_process.pid > MIN (G_MAXINT, G_MAXINT32))
			break;
		if (priv->unix_process.uid > MIN (G_MAXINT, G_MAXINT32)) {
			/* for uid==-1, libpolkit-gobject-1 detects the user based on the process id.
			 * Don't bother and require the user id as parameter. */
			break;
		}
		if (!priv->unix_process.dbus_sender || !*priv->unix_process.dbus_sender)
			break;

		priv->unix_process.start_time = nm_utils_get_start_time_for_pid (priv->unix_process.pid, NULL, NULL);

		if (!priv->unix_process.start_time) {
			/* Is the process already gone? Then fail creation of the auth subject
			 * by clearing the type. */
			if (kill (priv->unix_process.pid, 0) != 0)
				_clear_private (self);

			/* Otherwise, although we didn't detect a start_time, the process is still around.
			 * That could be due to procfs mounted with hidepid. So just accept the request.
			 *
			 * Polkit on the other side, will accept 0 and try to lookup /proc/$PID/stat
			 * itself (and if it fails to do so, assume a start-time of 0 and proceed).
			 * The only combination that would fail here, is when NM is able to read the
			 * start-time, but polkit is not. */
		}
		return;
	default:
		break;
	}

	_clear_private (self);
	g_return_if_reached ();
}

static void
finalize (GObject *object)
{
	_clear_private ((NMAuthSubject *) object);

	G_OBJECT_CLASS (nm_auth_subject_parent_class)->finalize (object);
}

static void
nm_auth_subject_class_init (NMAuthSubjectClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->constructed = constructed;
	object_class->finalize = finalize;

	g_object_class_install_property
	    (object_class, PROP_SUBJECT_TYPE,
	     g_param_spec_int (NM_AUTH_SUBJECT_SUBJECT_TYPE, "", "",
	                       NM_AUTH_SUBJECT_TYPE_INVALID,
	                       NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS,
	                       NM_AUTH_SUBJECT_TYPE_INVALID,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT_ONLY |
	                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	    (object_class, PROP_UNIX_PROCESS_DBUS_SENDER,
	     g_param_spec_string (NM_AUTH_SUBJECT_UNIX_PROCESS_DBUS_SENDER, "", "",
	                          NULL,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	     (object_class, PROP_UNIX_PROCESS_PID,
	      g_param_spec_ulong (NM_AUTH_SUBJECT_UNIX_PROCESS_PID, "", "",
	                          0, G_MAXULONG, G_MAXULONG,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	     (object_class, PROP_UNIX_PROCESS_UID,
	      g_param_spec_ulong (NM_AUTH_SUBJECT_UNIX_PROCESS_UID, "", "",
	                          0, G_MAXULONG, G_MAXULONG,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS));

}
