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

#ifndef __NETWORKMANAGER_AUTH_SUBJECT_H__
#define __NETWORKMANAGER_AUTH_SUBJECT_H__

#define NM_TYPE_AUTH_SUBJECT            (nm_auth_subject_get_type ())
#define NM_AUTH_SUBJECT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_AUTH_SUBJECT, NMAuthSubject))
#define NM_AUTH_SUBJECT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_AUTH_SUBJECT, NMAuthSubjectClass))
#define NM_IS_AUTH_SUBJECT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_AUTH_SUBJECT))
#define NM_IS_AUTH_SUBJECT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_AUTH_SUBJECT))
#define NM_AUTH_SUBJECT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_AUTH_SUBJECT, NMAuthSubjectClass))

typedef enum {
	NM_AUTH_SUBJECT_TYPE_INVALID      = 0,
	NM_AUTH_SUBJECT_TYPE_INTERNAL     = 1,
	NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS = 2,
} NMAuthSubjectType;

#define NM_AUTH_SUBJECT_SUBJECT_TYPE               "subject-type"
#define NM_AUTH_SUBJECT_UNIX_PROCESS_DBUS_SENDER   "unix-process-dbus-sender"
#define NM_AUTH_SUBJECT_UNIX_PROCESS_PID           "unix-process-pid"
#define NM_AUTH_SUBJECT_UNIX_PROCESS_UID           "unix-process-uid"

struct _NMAuthSubject {
	GObject parent;
};

typedef struct {
	GObjectClass parent;
} NMAuthSubjectClass;

GType nm_auth_subject_get_type (void);

NMAuthSubject *nm_auth_subject_new_internal (void);

NMAuthSubject *nm_auth_subject_new_unix_process_from_context (GDBusMethodInvocation *context);

NMAuthSubject *nm_auth_subject_new_unix_process_from_message (GDBusConnection *connection, GDBusMessage *message);


NMAuthSubjectType nm_auth_subject_get_subject_type (NMAuthSubject *subject);


gboolean nm_auth_subject_is_internal (NMAuthSubject *subject);


gboolean nm_auth_subject_is_unix_process (NMAuthSubject *subject);

gulong nm_auth_subject_get_unix_process_pid (NMAuthSubject *subject);

const char *nm_auth_subject_get_unix_process_dbus_sender (NMAuthSubject *subject);


gulong nm_auth_subject_get_unix_process_uid (NMAuthSubject *subject);


const char *nm_auth_subject_to_string (NMAuthSubject *self, char *buf, gsize buf_len);

#if WITH_POLKIT

GVariant *  nm_auth_subject_unix_process_to_polkit_gvariant (NMAuthSubject *self);

#endif

#endif /* __NETWORKMANAGER_AUTH_SUBJECT_H__ */
