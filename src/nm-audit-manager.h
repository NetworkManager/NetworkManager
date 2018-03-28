/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager audit support
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
 * Copyright 2015 Red Hat, Inc.
 */

#ifndef __NM_AUDIT_MANAGER_H__
#define __NM_AUDIT_MANAGER_H__

#include "nm-connection.h"
#include "devices/nm-device.h"
#include "nm-types.h"

#define NM_TYPE_AUDIT_MANAGER            (nm_audit_manager_get_type ())
#define NM_AUDIT_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_AUDIT_MANAGER, NMAuditManager))
#define NM_AUDIT_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_AUDIT_MANAGER, NMAuditManagerClass))
#define NM_IS_AUDIT_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_AUDIT_MANAGER))
#define NM_IS_AUDIT_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_AUDIT_MANAGER))
#define NM_AUDIT_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_AUDIT_MANAGER, NMAuditManagerClass))

typedef struct _NMAuditManagerClass NMAuditManagerClass;

#define NM_AUDIT_OP_CONN_ADD                "connection-add"
#define NM_AUDIT_OP_CONN_DELETE             "connection-delete"
#define NM_AUDIT_OP_CONN_UPDATE             "connection-update"
#define NM_AUDIT_OP_CONN_ACTIVATE           "connection-activate"
#define NM_AUDIT_OP_CONN_ADD_ACTIVATE       "connection-add-activate"
#define NM_AUDIT_OP_CONN_DEACTIVATE         "connection-deactivate"
#define NM_AUDIT_OP_CONN_CLEAR_SECRETS      "connection-clear-secrets"

#define NM_AUDIT_OP_RELOAD                  "reload"
#define NM_AUDIT_OP_SLEEP_CONTROL           "sleep-control"
#define NM_AUDIT_OP_NET_CONTROL             "networking-control"
#define NM_AUDIT_OP_RADIO_CONTROL           "radio-control"
#define NM_AUDIT_OP_STATISTICS              "statistics"

#define NM_AUDIT_OP_DEVICE_AUTOCONNECT      "device-autoconnect"
#define NM_AUDIT_OP_DEVICE_DISCONNECT       "device-disconnect"
#define NM_AUDIT_OP_DEVICE_DELETE           "device-delete"
#define NM_AUDIT_OP_DEVICE_MANAGED          "device-managed"
#define NM_AUDIT_OP_DEVICE_REAPPLY          "device-reapply"

#define NM_AUDIT_OP_CHECKPOINT_CREATE       "checkpoint-create"
#define NM_AUDIT_OP_CHECKPOINT_ROLLBACK     "checkpoint-rollback"
#define NM_AUDIT_OP_CHECKPOINT_DESTROY      "checkpoint-destroy"
#define NM_AUDIT_OP_CHECKPOINT_ADJUST_ROLLBACK_TIMEOUT "checkpoint-adjust-rollback-timeout"

GType nm_audit_manager_get_type (void);
NMAuditManager *nm_audit_manager_get (void);
gboolean nm_audit_manager_audit_enabled (NMAuditManager *self);

#define nm_audit_log_connection_op(op, connection, result, args, subject_context, reason) \
	G_STMT_START { \
		NMAuditManager *_audit = nm_audit_manager_get (); \
		\
		if (nm_audit_manager_audit_enabled (_audit)) { \
			_nm_audit_manager_log_connection_op (_audit, __FILE__, __LINE__, G_STRFUNC, \
			                                     (op), (connection), (result), (args), (subject_context), \
			                                     (reason)); \
		} \
	} G_STMT_END

#define nm_audit_log_control_op(op, arg, result, subject_context, reason) \
	G_STMT_START { \
		NMAuditManager *_audit = nm_audit_manager_get (); \
		\
		if (nm_audit_manager_audit_enabled (_audit)) { \
			_nm_audit_manager_log_generic_op (_audit, __FILE__, __LINE__, G_STRFUNC, \
			                                  (op), (arg), (result), (subject_context), (reason)); \
		} \
	} G_STMT_END

#define nm_audit_log_device_op(op, device, result, args, subject_context, reason) \
	G_STMT_START { \
		NMAuditManager *_audit = nm_audit_manager_get (); \
		\
		if (nm_audit_manager_audit_enabled (_audit)) { \
			_nm_audit_manager_log_device_op (_audit, __FILE__, __LINE__, G_STRFUNC, \
			                                 (op), (device), (result), (args), (subject_context), (reason)); \
		} \
	} G_STMT_END

#define nm_audit_log_checkpoint_op(op, arg, result, subject_context, reason) \
	G_STMT_START { \
		NMAuditManager *_audit = nm_audit_manager_get (); \
		\
		if (nm_audit_manager_audit_enabled (_audit)) { \
			_nm_audit_manager_log_generic_op (_audit, __FILE__, __LINE__, G_STRFUNC, \
			                                  (op), (arg), (result), (subject_context), (reason)); \
		} \
	} G_STMT_END

void _nm_audit_manager_log_connection_op (NMAuditManager *self, const char *file, guint line,
                                          const char *func, const char *op, NMSettingsConnection *connection,
                                          gboolean result, const char *args, gpointer subject_context,
                                          const char *reason);

void _nm_audit_manager_log_generic_op    (NMAuditManager *self, const char *file, guint line,
                                          const char *func, const char *op, const char *arg,
                                          gboolean result, gpointer subject_context, const char *reason);

void _nm_audit_manager_log_device_op     (NMAuditManager *self, const char *file, guint line,
                                          const char *func, const char *op, NMDevice *device,
                                          gboolean result, const char *args, gpointer subject_context,
                                          const char *reason);

#endif /* __NM_AUDIT_MANAGER_H__ */
