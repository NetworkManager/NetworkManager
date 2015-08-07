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

#include "config.h"

#include <errno.h>
#include <string.h>
#if HAVE_LIBAUDIT
#include <libaudit.h>
#endif

#include "gsystem-local-alloc.h"
#include "nm-audit-manager.h"
#include "nm-glib.h"
#include "nm-auth-subject.h"
#include "nm-config.h"
#include "nm-logging.h"
#include "nm-macros-internal.h"

#define AUDIT_LOG_LEVEL LOGL_INFO

typedef enum {
       BACKEND_LOG    = (1 << 0),
       BACKEND_AUDITD = (1 << 1),
       _BACKEND_LAST,
       BACKEND_ALL    = ((_BACKEND_LAST - 1) << 1) - 1,
} AuditBackend;

typedef struct {
       const char *name;
       GValue value;
       gboolean need_encoding;
       AuditBackend backends;
} AuditField;

#if HAVE_LIBAUDIT
typedef struct {
	NMConfig *config;
	int auditd_fd;
} NMAuditManagerPrivate;

#define NM_AUDIT_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_AUDIT_MANAGER, NMAuditManagerPrivate))
#endif

G_DEFINE_TYPE (NMAuditManager, nm_audit_manager, G_TYPE_OBJECT)

NM_DEFINE_SINGLETON_GETTER (NMAuditManager, nm_audit_manager_get, NM_TYPE_AUDIT_MANAGER);

static void
_audit_field_init_string (AuditField *field, const char *name, const char *str,
                          gboolean need_encoding, AuditBackend backends)
{
	field->name = name;
	field->need_encoding = need_encoding;
	field->backends = backends;
	g_value_init (&field->value, G_TYPE_STRING);
	g_value_set_static_string (&field->value, str);
}

static void
_audit_field_init_uint (AuditField *field, const char *name, uint val,
                        AuditBackend backends)
{
	field->name = name;
	field->backends = backends;
	g_value_init (&field->value, G_TYPE_UINT);
	g_value_set_uint (&field->value, val);
}

static char *
build_message (GPtrArray *fields, AuditBackend backend)
{
	GString *string;
	AuditField *field;
	gboolean first = TRUE;
	guint i;

	string = g_string_new (NULL);

	for (i = 0; i < fields->len; i++) {
		field = fields->pdata[i];

		if (!NM_FLAGS_HAS (field->backends, backend))
			continue;

		if (first)
			first = FALSE;
		else
			g_string_append_c (string, ' ');

		if (G_VALUE_HOLDS_STRING (&field->value)) {
			const char *str = g_value_get_string (&field->value);

#if HAVE_LIBAUDIT
			if (backend == BACKEND_AUDITD) {
				if (field->need_encoding) {
					char *value;

					value = audit_encode_nv_string (field->name, str, 0);
					g_string_append (string, value);
					g_free (value);
				} else
					g_string_append_printf (string, "%s=%s", field->name, str);
				continue;
			}
#endif /* HAVE_LIBAUDIT */
			g_string_append_printf (string, "%s=\"%s\"", field->name, str);
		} else if (G_VALUE_HOLDS_UINT (&field->value)) {
			g_string_append_printf (string, "%s=%u", field->name,
			                        g_value_get_uint (&field->value));
		} else
			g_assert_not_reached ();
	}
	return g_string_free (string, FALSE);
}


static void
nm_audit_log (NMAuditManager *self, GPtrArray *fields, const char *file,
              guint line, const char *func, gboolean success)
{
#if HAVE_LIBAUDIT
	NMAuditManagerPrivate *priv;
#endif
	char *msg;

	g_return_if_fail (NM_IS_AUDIT_MANAGER (self));

#if HAVE_LIBAUDIT
	priv = NM_AUDIT_MANAGER_GET_PRIVATE (self);

	if (priv->auditd_fd >= 0) {
		msg = build_message (fields, BACKEND_AUDITD);
		audit_log_user_message (priv->auditd_fd, AUDIT_USYS_CONFIG, msg,
		                        NULL, NULL, NULL, success);
		g_free (msg);
	}
#endif

	if (nm_logging_enabled (AUDIT_LOG_LEVEL, LOGD_AUDIT)) {
		msg = build_message (fields, BACKEND_LOG);
		_nm_log_impl (file, line, func, AUDIT_LOG_LEVEL, LOGD_AUDIT, 0, "%s", msg);
		g_free (msg);
	}
}

static void
_audit_log_helper (NMAuditManager *self, GPtrArray *fields, const char *file,
                   guint line, const char *func, const char *op, gboolean result,
                   NMAuthSubject *subject, const char *reason)
{
	AuditField op_field = { }, pid_field = { }, uid_field = { };
	AuditField result_field = { }, reason_field = { };
	gulong pid, uid;

	_audit_field_init_string (&op_field, "op", op, FALSE, BACKEND_ALL);
	g_ptr_array_insert (fields, 0, &op_field);

	if (subject && nm_auth_subject_is_unix_process (subject)) {
		pid = nm_auth_subject_get_unix_process_pid (subject);
		uid = nm_auth_subject_get_unix_process_uid (subject);
		if (pid != G_MAXULONG) {
			_audit_field_init_uint (&pid_field, "pid", pid, BACKEND_ALL);
			g_ptr_array_add (fields, &pid_field);
		}
		if (uid != G_MAXULONG) {
			_audit_field_init_uint (&uid_field, "uid", uid, BACKEND_ALL);
			g_ptr_array_add (fields, &uid_field);
		}
	}

	_audit_field_init_string (&result_field, "result", result ? "success" : "fail",
	                          FALSE, BACKEND_ALL);
	g_ptr_array_add (fields, &result_field);

	if (reason) {
		_audit_field_init_string (&reason_field, "reason", reason, FALSE, BACKEND_LOG);
		g_ptr_array_add (fields, &reason_field);
	}

	nm_audit_log (self, fields, file, line, func, result);
}

gboolean
nm_audit_manager_audit_enabled (NMAuditManager *self)
{
#if HAVE_LIBAUDIT
	NMAuditManagerPrivate *priv = NM_AUDIT_MANAGER_GET_PRIVATE (self);

	if (priv->auditd_fd >= 0)
		return TRUE;
#endif

	return nm_logging_enabled (AUDIT_LOG_LEVEL, LOGD_AUDIT);
}

void
_nm_audit_manager_log_connection_op (NMAuditManager *self, const char *file, guint line,
                                     const char *func, const char *op, NMConnection *connection,
                                     gboolean result, NMAuthSubject *subject, const char *reason)
{
	gs_unref_ptrarray GPtrArray *fields = NULL;
	AuditField uuid_field = { }, name_field = { };

	g_return_if_fail (op);
	g_return_if_fail (connection || !strcmp (op, NM_AUDIT_OP_CONN_ADD));

	fields = g_ptr_array_new ();

	if (connection) {
		_audit_field_init_string (&uuid_field, "uuid", nm_connection_get_uuid (connection),
		                          FALSE, BACKEND_ALL);
		g_ptr_array_add (fields, &uuid_field);

		_audit_field_init_string (&name_field, "name", nm_connection_get_id (connection),
		                          TRUE, BACKEND_ALL);
		g_ptr_array_add (fields, &name_field);
	}

	_audit_log_helper (self, fields, file, line, func, op, result, subject, reason);
}

void
_nm_audit_manager_log_control_op (NMAuditManager *self, const char *file, guint line,
                                  const char *func, const char *op, const char *arg,
                                  gboolean result, NMAuthSubject *subject,
                                  const char *reason)
{
	gs_unref_ptrarray GPtrArray *fields = NULL;
	AuditField arg_field = { };

	g_return_if_fail (op);
	g_return_if_fail (arg);

	fields = g_ptr_array_new ();

	_audit_field_init_string (&arg_field, "arg", arg, TRUE, BACKEND_ALL);
	g_ptr_array_add (fields, &arg_field);

	_audit_log_helper (self, fields, file, line, func, op, result, subject, reason);
}

void
_nm_audit_manager_log_device_op (NMAuditManager *self, const char *file, guint line,
                                 const char *func, const char *op, NMDevice *device,
                                 gboolean result, NMAuthSubject *subject,
                                 const char *reason)
{
	gs_unref_ptrarray GPtrArray *fields = NULL;
	AuditField interface_field = { }, ifindex_field = { };
	int ifindex;

	g_return_if_fail (op);
	g_return_if_fail (device);

	fields = g_ptr_array_new ();

	_audit_field_init_string (&interface_field, "interface", nm_device_get_ip_iface (device),
	                          TRUE, BACKEND_ALL);
	g_ptr_array_add (fields, &interface_field);

	ifindex = nm_device_get_ip_ifindex (device);
	if (ifindex > 0) {
		_audit_field_init_uint (&ifindex_field, "ifindex", ifindex, BACKEND_ALL);
		g_ptr_array_add (fields, &ifindex_field);
	}

	_audit_log_helper (self, fields, file, line, func, op, result, subject, reason);
}

#if HAVE_LIBAUDIT
static void
init_auditd (NMAuditManager *self)
{
	NMAuditManagerPrivate *priv = NM_AUDIT_MANAGER_GET_PRIVATE (self);
	NMConfigData *data = nm_config_get_data (priv->config);

	if (nm_config_data_get_value_boolean (data, NM_CONFIG_KEYFILE_GROUP_LOGGING,
	                                      NM_CONFIG_KEYFILE_KEY_AUDIT,
	                                      NM_CONFIG_DEFAULT_LOGGING_AUDIT)) {
		if (priv->auditd_fd < 0) {
			priv->auditd_fd = audit_open ();
			if (priv->auditd_fd < 0) {
				nm_log_err (LOGD_CORE, "failed to open auditd socket: %s",
				            strerror (errno));
			} else
				nm_log_dbg (LOGD_CORE, "audit socket created");
		}
	} else {
		if (priv->auditd_fd >= 0) {
			audit_close (priv->auditd_fd);
			priv->auditd_fd = -1;
			nm_log_dbg (LOGD_CORE, "audit socket closed");
		}
	}
}

static void
config_changed_cb (NMConfig *config,
                   NMConfigData *config_data,
                   NMConfigChangeFlags changes,
                   NMConfigData *old_data,
                   NMAuditManager *self)
{
	if (NM_FLAGS_HAS (changes, NM_CONFIG_CHANGE_VALUES))
		init_auditd (self);
}
#endif

static void
nm_audit_manager_init (NMAuditManager *self)
{
#if HAVE_LIBAUDIT
	NMAuditManagerPrivate *priv = NM_AUDIT_MANAGER_GET_PRIVATE (self);

	priv->config = g_object_ref (nm_config_get ());
	g_signal_connect (G_OBJECT (priv->config),
	                  NM_CONFIG_SIGNAL_CONFIG_CHANGED,
	                  G_CALLBACK (config_changed_cb),
	                  self);
	priv->auditd_fd = -1;

	init_auditd (self);
#endif
}

static void
dispose (GObject *object)
{
#if HAVE_LIBAUDIT
	NMAuditManager *self = NM_AUDIT_MANAGER (object);
	NMAuditManagerPrivate *priv = NM_AUDIT_MANAGER_GET_PRIVATE (self);

	if (priv->config) {
		g_signal_handlers_disconnect_by_func (priv->config, config_changed_cb, self);
		g_clear_object (&priv->config);
	}

	 if (priv->auditd_fd >= 0) {
		audit_close (priv->auditd_fd);
		priv->auditd_fd = -1;
	}
#endif

	G_OBJECT_CLASS (nm_audit_manager_parent_class)->dispose (object);
}

static void
nm_audit_manager_class_init (NMAuditManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

#if HAVE_LIBAUDIT
	g_type_class_add_private (klass, sizeof (NMAuditManagerPrivate));
#endif

	/* virtual methods */
	object_class->dispose = dispose;
}

