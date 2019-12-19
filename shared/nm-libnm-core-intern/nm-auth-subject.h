// SPDX-License-Identifier: GPL-2.0+
/*
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

typedef struct _NMAuthSubjectClass NMAuthSubjectClass;
typedef struct _NMAuthSubject NMAuthSubject;

GType nm_auth_subject_get_type (void);

NMAuthSubject *nm_auth_subject_new_internal (void);

NMAuthSubject *nm_auth_subject_new_unix_process (const char *dbus_sender, gulong pid, gulong uid);

NMAuthSubject *nm_auth_subject_new_unix_process_self (void);

NMAuthSubjectType nm_auth_subject_get_subject_type (NMAuthSubject *subject);

gboolean nm_auth_subject_is_internal (NMAuthSubject *subject);

gboolean nm_auth_subject_is_unix_process (NMAuthSubject *subject);

gulong nm_auth_subject_get_unix_process_pid (NMAuthSubject *subject);

const char *nm_auth_subject_get_unix_process_dbus_sender (NMAuthSubject *subject);

gulong nm_auth_subject_get_unix_process_uid (NMAuthSubject *subject);

const char *nm_auth_subject_to_string (NMAuthSubject *self, char *buf, gsize buf_len);

GVariant *  nm_auth_subject_unix_process_to_polkit_gvariant (NMAuthSubject *self);

#endif /* __NETWORKMANAGER_AUTH_SUBJECT_H__ */
