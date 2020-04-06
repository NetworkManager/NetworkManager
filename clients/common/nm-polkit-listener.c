// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

/**
 * SECTION:nm-polkit-listener
 * @short_description: A polkit agent listener
 *
 * #NMPolkitListener is the polkit agent listener used by nmcli and nmtui.
 * http://www.freedesktop.org/software/polkit/docs/latest/index.html
 *
 * For an example polkit agent you can look at polkit source tree:
 * http://cgit.freedesktop.org/polkit/tree/src/polkitagent/polkitagenttextlistener.c
 * http://cgit.freedesktop.org/polkit/tree/src/programs/pkttyagent.c
 * or LXDE polkit agent:
 * http://git.lxde.org/gitweb/?p=debian/lxpolkit.git;a=blob;f=src/lxpolkit-listener.c
 * https://github.com/lxde/lxqt-policykit/tree/master/src
 */

#include "nm-default.h"

#include "nm-polkit-listener.h"

#include <gio/gio.h>
#include <pwd.h>
#include <fcntl.h>

#include "nm-glib-aux/nm-dbus-aux.h"
#include "nm-glib-aux/nm-secret-utils.h"
#include "nm-glib-aux/nm-io-utils.h"
#include "nm-libnm-core-intern/nm-auth-subject.h"
#include "c-list/src/c-list.h"

#define LOGIND_BUS_NAME                     "org.freedesktop.login1"
#define POLKIT_BUS_NAME                     "org.freedesktop.PolicyKit1"

#define POLKIT_AUTHORITY_OBJ_PATH           "/org/freedesktop/PolicyKit1/Authority"
#define POLKIT_AUTHORITY_IFACE_NAME         "org.freedesktop.PolicyKit1.Authority"

#define POLKIT_AGENT_OBJ_PATH               "/org/freedesktop/PolicyKit1/AuthenticationAgent"
#define POLKIT_AGENT_DBUS_INTERFACE         "org.freedesktop.PolicyKit1.AuthenticationAgent"

#define LOGIND_OBJ_PATH                     "/org/freedesktop/login1"
#define LOGIND_MANAGER_INTERFACE            "org.freedesktop.login1.Manager"

#define NM_POLKIT_LISTENER_DBUS_CONNECTION  "dbus-connection"
#define NM_POLKIT_LISTENER_SESSION_AGENT    "session-agent"

#define POLKIT_DBUS_ERROR_FAILED            "org.freedesktop.PolicyKit1.Error.Failed"

/*****************************************************************************/

enum {
	REGISTERED,
	REQUEST_SYNC,
	ERROR,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

struct _NMPolkitListener {
	GObject parent;
	GDBusConnection *dbus_connection;
	char *name_owner;
	GCancellable *cancellable;
	GMainContext *main_context;
	CList request_lst_head;
	guint pk_auth_agent_reg_id;
	guint name_owner_changed_id;
	bool session_agent:1;
};

struct _NMPolkitListenerClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMPolkitListener, nm_polkit_listener, G_TYPE_OBJECT);

/*****************************************************************************/

typedef struct {
	CList request_lst;

	NMPolkitListener *listener;
	char *action_id;
	char *message;
	char *username;
	char *cookie;
	GString *in_buffer;
	GString *out_buffer;
	size_t out_buffer_offset;

	int child_stdout;
	int child_stdin;
	GSource *child_stdout_watch_source;
	GSource *child_stdin_watch_source;
	GDBusMethodInvocation *dbus_invocation;
} AuthRequest;

static const GDBusInterfaceInfo interface_info = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
	POLKIT_AGENT_DBUS_INTERFACE,
	.methods = NM_DEFINE_GDBUS_METHOD_INFOS (
		NM_DEFINE_GDBUS_METHOD_INFO (
			"BeginAuthentication",
			.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
				NM_DEFINE_GDBUS_ARG_INFO ("action_id", "s"),
				NM_DEFINE_GDBUS_ARG_INFO ("message", "s"),
				NM_DEFINE_GDBUS_ARG_INFO ("icon_name", "s"),
				NM_DEFINE_GDBUS_ARG_INFO ("details", "a{ss}"),
				NM_DEFINE_GDBUS_ARG_INFO ("cookie", "s"),
				NM_DEFINE_GDBUS_ARG_INFO ("identities", "a(sa{sv})"),
			),
		),
		NM_DEFINE_GDBUS_METHOD_INFO (
			"CancelAuthentication",
			.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
				NM_DEFINE_GDBUS_ARG_INFO ("cookie", "s"),
			),
		),
	),
);

static void
remove_request (AuthRequest *request)
{
	c_list_unlink (&request->request_lst);

	nm_clear_g_free (&request->action_id);
	nm_clear_g_free (&request->message);
	nm_clear_g_free (&request->username);
	nm_clear_g_free (&request->cookie);
	nm_clear_g_source_inst (&request->child_stdout_watch_source);
	nm_clear_g_source_inst (&request->child_stdin_watch_source);

	nm_explicit_bzero (request->out_buffer->str,
	                   request->out_buffer->len);
	g_string_free (request->out_buffer, TRUE);
	g_string_free (request->in_buffer, TRUE);

	if (request->child_stdout != -1) {
		nm_close (request->child_stdout);
		request->child_stdout = -1;
	}

	if (request->child_stdin != -1) {
		nm_close (request->child_stdin);
		request->child_stdin = -1;
	}

	g_slice_free (AuthRequest, request);
}

static const char *
uid_to_name (uid_t uid)
{
	const char *name = NULL;
	struct passwd *passwd;

	passwd = getpwuid (uid);
	if (passwd != NULL)
		name = passwd->pw_name;
	return name;
}

static gboolean
find_identity (uid_t uid, gpointer user_data)
{
	return nm_streq0 (user_data, uid_to_name (uid));
}

static gboolean
first_identity (uid_t uid, gpointer user_data)
{
	return true;
}

static gint64
_choose_identity (GVariant *identities,
                  gboolean (*predicate) (uid_t uid, gpointer user_data),
                  gpointer user_data)
{
	GVariantIter identity_iter;
	GVariantIter *identity_details_iter;
	GVariant *unix_id_variant;
	uid_t unix_id;

	g_return_val_if_fail (predicate != NULL, FALSE);

	g_variant_iter_init (&identity_iter, identities);

	while (g_variant_iter_loop (&identity_iter, "(&sa{sv})", NULL, &identity_details_iter)) {
		while (g_variant_iter_loop (identity_details_iter, "{sv}", NULL, &unix_id_variant)) {
			unix_id = g_variant_get_uint32 (unix_id_variant);

			if (predicate (unix_id, user_data)) {
				g_variant_unref (unix_id_variant);
				g_variant_iter_free (identity_details_iter);
				return unix_id;
			}
		}
		g_variant_iter_free (identity_details_iter);
	}
	return -1;
}

static uid_t
choose_identity (GVariant *identities)
{
	const char *user;
	gint64 id;

	/* Choose identity. First try current user, then root, and else
	 * take the first one */
	user = getenv ("USER");

	if ((id = _choose_identity (identities, find_identity, (gpointer) user)) >= 0) {
		return id;
	} else if ((id = _choose_identity (identities, find_identity, "root")) >= 0) {
		return id;
	}

	return _choose_identity (identities, first_identity, NULL);
}

static void
agent_register_cb (GObject *source_object,
                   GAsyncResult *res,
                   gpointer user_data)
{
	NMPolkitListener *listener = NM_POLKIT_LISTENER (user_data);
	GDBusConnection *dbus_connection = G_DBUS_CONNECTION (source_object);
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *ret = NULL;

	ret = g_dbus_connection_call_finish (dbus_connection,
	                                     res,
	                                     &error);

	if (nm_utils_error_is_cancelled (error)) {
		return;
	}

	if (ret) {
		g_signal_emit (listener,
		               signals[REGISTERED],
		               0);
	} else {
		g_signal_emit (listener,
		               signals[ERROR],
		               0,
		               error->message);
	}
}

static void
agent_register (NMPolkitListener *self, const char *session_id)
{
	const char *locale = NULL;
	gs_unref_object NMAuthSubject *subject = NULL;
	GVariant *subject_variant = NULL;

	locale = g_getenv ("LANG");
	if (locale == NULL) {
		locale = "en_US.UTF-8";
	}

	if (self->session_agent) {
		subject = nm_auth_subject_new_unix_session (session_id);
	} else {
		subject = nm_auth_subject_new_unix_process_self ();
	}
	subject_variant = nm_auth_subject_unix_to_polkit_gvariant (subject);

	g_dbus_connection_call (self->dbus_connection,
	                        self->name_owner,
	                        POLKIT_AUTHORITY_OBJ_PATH,
	                        POLKIT_AUTHORITY_IFACE_NAME,
	                        "RegisterAuthenticationAgent",
	                        g_variant_new ("(@(sa{sv})ss)",
	                                       subject_variant,
	                                       locale,
	                                       POLKIT_AGENT_OBJ_PATH),
	                        NULL,
	                        G_DBUS_CALL_FLAGS_NONE,
	                        -1,
	                        self->cancellable,
	                        agent_register_cb,
	                        self);
}

static void
agent_unregister (NMPolkitListener *self)
{
	gs_unref_object NMAuthSubject *subject = NULL;
	GVariant *subject_variant = NULL;

	subject = nm_auth_subject_new_unix_process_self ();
	subject_variant = nm_auth_subject_unix_to_polkit_gvariant (subject);

	g_dbus_connection_call (self->dbus_connection,
	                        self->name_owner,
	                        POLKIT_AUTHORITY_OBJ_PATH,
	                        POLKIT_AUTHORITY_IFACE_NAME,
	                        "UnregisterAuthenticationAgent",
	                        g_variant_new ("(@(sa{sv})s)",
	                                       subject_variant,
	                                       POLKIT_AGENT_OBJ_PATH),
	                        NULL,
	                        G_DBUS_CALL_FLAGS_NONE,
	                        -1,
	                        NULL,
	                        NULL,
	                        self);
}

static void
retrieve_session_id_cb (GObject *source_object,
                        GAsyncResult *res,
                        gpointer user_data)
{
	NMPolkitListener *listener = NM_POLKIT_LISTENER (user_data);
	char *session_id;
	guint32 session_uid;
	nm_auto_free_variant_iter GVariantIter *iter;
	gs_unref_variant GVariant *ret = NULL;
	gs_free_error GError *error = NULL;
	gs_free char *err_str = NULL;
	uid_t uid = getuid ();

	ret = g_dbus_connection_call_finish (listener->dbus_connection,
	                                     res,
	                                     &error);

	if (nm_utils_error_is_cancelled (error)) {
		return;
	}

	if (ret) {
		g_variant_get_child (ret, 0, "a(susso)", &iter);

		while (g_variant_iter_next (iter, "(&su@s@s@o)",
		                            &session_id,
		                            &session_uid,
		                            NULL, NULL, NULL)) {
			if (session_uid == uid) {
				agent_register (listener, session_id);
				return;
			}
		}
		err_str = g_strdup_printf (_("Could not find any session id for uid %d"), uid);
	} else {
		err_str = g_strdup_printf (_("Could not retrieve session id: %s"),
		                                error->message);
	}

	g_signal_emit (listener,
	               signals[ERROR],
	               0,
	               err_str);
}

static void
retrieve_session_id (NMPolkitListener *self)
{
	g_dbus_connection_call (self->dbus_connection,
	                        LOGIND_BUS_NAME,
	                        LOGIND_OBJ_PATH,
	                        LOGIND_MANAGER_INTERFACE,
	                        "ListSessions",
	                        NULL,
	                        G_VARIANT_TYPE ("(a(susso))"),
	                        G_DBUS_CALL_FLAGS_NONE,
	                        -1,
	                        self->cancellable,
	                        retrieve_session_id_cb,
	                        self);
}

static void
complete_authentication (AuthRequest *request,
                         gboolean result)
{
	if (result) {
		g_dbus_method_invocation_return_value (request->dbus_invocation, NULL);
	} else {
		g_dbus_method_invocation_return_dbus_error (request->dbus_invocation,
		                                            "org.freedesktop.PolicyKit1.Error.Failed",
		                                            "");
	}
	remove_request (request);
}

static gboolean
io_watch_can_write (int fd,
                    GIOCondition condition,
                    gpointer user_data)
{
	AuthRequest *request = user_data;
	ssize_t n_written;
	gboolean done = FALSE;

	if (condition & G_IO_HUP ||
	    condition & G_IO_ERR) {
		done = TRUE;
		goto done;
	}

	n_written = write (request->child_stdin,
	                   &request->out_buffer->str[request->out_buffer_offset],
	                   request->out_buffer->len - request->out_buffer_offset);

	if (n_written < 0 && errno != EAGAIN) {
		done = TRUE;
		goto done;
	}

	if (n_written > 0) {
		if ((size_t) n_written == (request->out_buffer->len - request->out_buffer_offset)) {
			done = TRUE;
			goto done;
		}
		request->out_buffer_offset += n_written;
	}

done:
	if (done) {
		nm_explicit_bzero (request->out_buffer->str,
		                   request->out_buffer->len);
		g_string_set_size (request->out_buffer, 0);
		request->out_buffer_offset = 0;
		nm_clear_g_source_inst (&request->child_stdin_watch_source);
	}

	return G_SOURCE_CONTINUE;
}

static void
queue_string_to_helper (AuthRequest *request, const char *response)
{
	g_return_if_fail (response);

	g_string_append (request->out_buffer, response);

	if (   request->out_buffer->len == 0
	    || request->out_buffer->str[request->out_buffer->len - 1] != '\n')
		g_string_append_c (request->out_buffer, '\n');

	if (!request->child_stdin_watch_source) {
		request->child_stdin_watch_source = nm_g_unix_fd_source_new (request->child_stdin,
		                                                             G_IO_OUT | G_IO_ERR | G_IO_HUP,
		                                                             G_PRIORITY_DEFAULT,
		                                                             io_watch_can_write,
		                                                             request,
		                                                             NULL);
		g_source_attach (request->child_stdin_watch_source,
		                 request->listener->main_context);
	}
}

static gboolean
io_watch_have_data (int fd,
                    GIOCondition condition,
                    gpointer user_data)
{
	AuthRequest *request = user_data;
	gs_free char *unescaped = NULL;
	char *response = NULL;
	char* line_terminator = 0;
	gboolean auth_result = FALSE;
	gboolean complete_auth = FALSE;
	ssize_t n_read;

	if (condition & G_IO_HUP ||
	    condition & G_IO_ERR) {
		complete_auth = TRUE;
		auth_result = FALSE;
		goto out;
	}

	n_read = nm_utils_fd_read (fd, request->in_buffer);

	if (n_read == -EAGAIN) {
		return G_SOURCE_CONTINUE;
	}

	if (n_read < 0) {
		complete_auth = TRUE;
		auth_result = FALSE;
		goto out;
	}

	line_terminator = strchr (request->in_buffer->str, '\n');
	if (!line_terminator) {
		return G_SOURCE_CONTINUE;
	}
	*line_terminator = '\0';

	unescaped = g_strcompress (request->in_buffer->str);

	if (NM_STR_HAS_PREFIX (unescaped, "PAM_PROMPT_ECHO")) {
		/* FIXME(cli-async): emit signal and wait for response (blocking) */
		g_signal_emit (request->listener,
		               signals[REQUEST_SYNC],
		               0,
		               request->action_id,
		               request->message,
		               request->username,
		               &response);

		if (response) {
			queue_string_to_helper (request, response);
			nm_free_secret (response);
		} else {
			complete_auth = TRUE;
			auth_result = FALSE;
		}
	} else if (NM_STR_HAS_PREFIX (unescaped, "SUCCESS")) {
		complete_auth = TRUE;
		auth_result = TRUE;
	} else if (NM_STR_HAS_PREFIX (unescaped, "FAILURE")) {
		complete_auth = TRUE;
		auth_result = FALSE;
	} else {
		complete_auth = TRUE;
		auth_result = FALSE;
	}

out:
	g_string_set_size (request->in_buffer, 0);

	if (complete_auth) {
		complete_authentication (request, auth_result);
	}
	return G_SOURCE_CONTINUE;
}

static void
begin_authentication (AuthRequest *request)
{
	int fd_flags;
	char *helper_argv[3];

	helper_argv[0] = POLKIT_PACKAGE_PREFIX "/lib/polkit-1/polkit-agent-helper-1";
	helper_argv[1] = request->username;
	helper_argv[2] = NULL;

	if (!g_spawn_async_with_pipes (NULL,
	                               helper_argv,
	                               NULL,
	                               G_SPAWN_DEFAULT,
	                               NULL,
	                               NULL,
	                               NULL,
	                               &request->child_stdin,
	                               &request->child_stdout,
	                               NULL,
	                               NULL)) {
		/* not findind the PolicyKit setuid helper is a critical error */
		request->child_stdin = -1;
		request->child_stdout = -1;
		g_signal_emit (request->listener,
		               signals[ERROR],
		               0,
		               "The PolicyKit setuid helper 'polkit-agent-helper-1' has not been found");

		complete_authentication (request, FALSE);
		return;
	}

	fd_flags = fcntl (request->child_stdin, F_GETFD, 0);
	fcntl (request->child_stdin, F_SETFL, fd_flags | O_NONBLOCK);

	fd_flags = fcntl (request->child_stdout, F_GETFD, 0);
	fcntl (request->child_stdout, F_SETFL, fd_flags | O_NONBLOCK);

	request->child_stdout_watch_source = nm_g_unix_fd_source_new (request->child_stdout,
	                                                              G_IO_IN | G_IO_ERR | G_IO_HUP,
	                                                              G_PRIORITY_DEFAULT,
	                                                              io_watch_have_data,
	                                                              request,
	                                                              NULL);
	g_source_attach (request->child_stdout_watch_source,
	                 request->listener->main_context);

	/* Write the cookie on stdin so it can't be seen by other processes */
	queue_string_to_helper (request, request->cookie);

	return;
}

static AuthRequest*
get_request (NMPolkitListener *listener,
                    const char *cookie)
{
	AuthRequest *request;

	c_list_for_each_entry (request, &listener->request_lst_head, request_lst) {
		if (nm_streq0 (cookie, request->cookie)) {
			return request;
		}
	}
	return NULL;
}

static AuthRequest*
create_request (NMPolkitListener *listener,
                GDBusMethodInvocation *invocation,
                const char *action_id,
                const char *message,
                const char *username,
                const char *cookie)
{
	AuthRequest *request = g_slice_new0(AuthRequest);

	request->listener = listener;
	request->dbus_invocation = invocation;
	request->action_id = g_strdup (action_id);
	request->message = g_strdup (message);
	request->username = g_strdup (username);
	request->cookie = g_strdup (cookie);
	request->in_buffer = g_string_new ("");

	/* preallocate a large enough buffer so that
	 * secrets don't get reallocated, thus leaked */
	request->out_buffer = g_string_sized_new (1024);

	c_list_link_tail (&listener->request_lst_head, &request->request_lst);
	return request;
}

static void
dbus_method_call_cb (GDBusConnection *connection,
                     const char *sender,
                     const char *object_path,
                     const char *interface_name,
                     const char *method_name,
                     GVariant *parameters,
                     GDBusMethodInvocation *invocation,
                     gpointer user_data)
{
	NMPolkitListener *listener = NM_POLKIT_LISTENER (user_data);
	const char *action_id;
	const char *message;
	const char *cookie;
	AuthRequest *request;
	gs_unref_variant GVariant *identities_gvariant;
	uid_t uid;

	if (nm_streq (method_name, "BeginAuthentication")) {
		g_variant_get (parameters,
		               "(&s&s&s@a{ss}&s@a(sa{sv}))",
		               &action_id,
		               &message,
		               NULL,
		               NULL,
		               &cookie,
		               &identities_gvariant);

		uid = choose_identity (identities_gvariant);

		request = create_request (listener,
		                          invocation,
		                          action_id,
		                          message,
		                          uid_to_name (uid),
		                          cookie);
		begin_authentication (request);
		return;
	}

	if (nm_streq (method_name, "CancelAuthentication")) {
		g_variant_get (parameters,
		               "&s",
		               &cookie);
		request = get_request (listener, cookie);

		if (!request) {
			gs_free char *msg = NULL;

			msg = g_strdup_printf ("No pending authentication request for cookie '%s'",
			                       cookie);
			g_dbus_method_invocation_return_dbus_error (invocation,
			                                            POLKIT_DBUS_ERROR_FAILED,
			                                            msg);
			return;
		}

		/* Complete a cancelled request with success. */
		complete_authentication (request, TRUE);
		return;
	}

	g_dbus_method_invocation_return_error (invocation,
	                                       G_DBUS_ERROR,
	                                       G_DBUS_ERROR_UNKNOWN_METHOD,
	                                       "Unknown method %s",
	                                       method_name);
}

static gboolean
export_dbus_iface (NMPolkitListener *self, GError **error)
{
	GDBusInterfaceVTable interface_vtable = {
		.method_call = dbus_method_call_cb,
		.set_property = NULL,
		.get_property = NULL,
	};

	g_return_val_if_fail (NM_IS_POLKIT_LISTENER (self), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	/* Agent listener iface has been exported already */
	if (self->pk_auth_agent_reg_id) {
		return TRUE;
	}

	self->pk_auth_agent_reg_id =
		g_dbus_connection_register_object (self->dbus_connection,
		                                   POLKIT_AGENT_OBJ_PATH,
		                                   (GDBusInterfaceInfo*) &interface_info,
		                                   &interface_vtable,
		                                   self,
		                                   NULL,
		                                   error);
	if (!self->pk_auth_agent_reg_id) {
		g_signal_emit (self,
		               signals[ERROR],
		               0,
		               "Could not register as a PolicyKit Authentication Agent");
	}
	return self->pk_auth_agent_reg_id;
}

static void
name_owner_changed (NMPolkitListener *self,
                    const char *name_owner)
{
	gs_free_error GError *error = NULL;

	name_owner = nm_str_not_empty (name_owner);

	if (nm_streq0 (self->name_owner, name_owner)) {
		return;
	}

	g_free (self->name_owner);
	self->name_owner = g_strdup (name_owner);

	if (!self->name_owner) {
		return;
	}

	if (export_dbus_iface (self, &error)) {
		if (self->session_agent) {
			retrieve_session_id (self);
		} else {
			agent_register (self, NULL);
		}
	} else {
		g_signal_emit (self,
		               signals[ERROR],
		               0,
		               "Could not export the PolicyKit Authentication Agent DBus interface");
	}
}

static void
name_owner_changed_cb (GDBusConnection *connection,
                       const char *sender_name,
                       const char *object_path,
                       const char *interface_name,
                       const char *signal_name,
                       GVariant *parameters,
                       gpointer user_data)
{
	NMPolkitListener *self = user_data;
	const char *new_owner;

	if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(sss)"))) {
		return;
	}

	g_variant_get (parameters,
	               "(&s&s&s)",
	               NULL,
	               NULL,
	               &new_owner);

	name_owner_changed (self, new_owner);
}

static void
get_name_owner_cb (const char *name_owner,
                   GError *error,
                   gpointer user_data)
{
	if (!name_owner && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		return;
	}
	name_owner_changed (user_data, name_owner);
}

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMPolkitListener,
	PROP_DBUS_CONNECTION,
	PROP_SESSION_AGENT,
);

static void
set_property (GObject *object,
              guint prop_id,
              const GValue *value,
              GParamSpec *pspec)
{
	NMPolkitListener *self = NM_POLKIT_LISTENER (object);

	switch (prop_id) {
	case PROP_DBUS_CONNECTION:
		self->dbus_connection = g_value_dup_object (value);
		break;
	case PROP_SESSION_AGENT:
		self->session_agent = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_polkit_listener_init (NMPolkitListener *self)
{
	c_list_init (&self->request_lst_head);
	self->main_context = g_main_context_ref_thread_default ();
}

static void
constructed (GObject *object)
{
	NMPolkitListener *self = NM_POLKIT_LISTENER (object);

	self->cancellable = g_cancellable_new ();

	self->name_owner_changed_id =
	    nm_dbus_connection_signal_subscribe_name_owner_changed (self->dbus_connection,
	                                                            POLKIT_BUS_NAME,
	                                                            name_owner_changed_cb,
	                                                            self,
	                                                            NULL);

	nm_dbus_connection_call_get_name_owner (self->dbus_connection,
	                                        POLKIT_BUS_NAME,
	                                        -1,
	                                        self->cancellable,
	                                        get_name_owner_cb,
	                                        self);

	G_OBJECT_CLASS (nm_polkit_listener_parent_class)->constructed (object);
}

/**
 * nm_polkit_listener_new:
 * @dbus_connection: a open DBus connection
 * @session_agent: TRUE if a session agent is wanted, FALSE for a process agent
 *
 * Creates a new #NMPolkitListener and registers it as a polkit agent.
 *
 * Returns: a new #NMPolkitListener
 */
NMPolkitListener *
nm_polkit_listener_new (GDBusConnection *dbus_connection, gboolean session_agent)
{
	return g_object_new (NM_TYPE_POLKIT_LISTENER,
	                     NM_POLKIT_LISTENER_DBUS_CONNECTION, dbus_connection,
	                     NM_POLKIT_LISTENER_SESSION_AGENT, session_agent,
	                     NULL);
}

static void
dispose (GObject *object)
{
	NMPolkitListener *self = NM_POLKIT_LISTENER (object);
	AuthRequest *request;

	nm_clear_g_cancellable (&self->cancellable);

	while ((request = c_list_first_entry (&self->request_lst_head, AuthRequest, request_lst))) {
		remove_request (request);
	}

	if (self->dbus_connection) {
		nm_clear_g_dbus_connection_signal (self->dbus_connection,
		                                   &self->name_owner_changed_id);
		g_dbus_connection_unregister_object (self->dbus_connection,
		                                     self->pk_auth_agent_reg_id);
		agent_unregister (self);
		nm_clear_g_free (&self->name_owner);
		g_clear_object (&self->dbus_connection);
	}

	nm_clear_pointer (&self->main_context, g_main_context_unref);

	G_OBJECT_CLASS (nm_polkit_listener_parent_class)->dispose (object);
}

static void
nm_polkit_listener_class_init (NMPolkitListenerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->set_property = set_property;
	object_class->constructed = constructed;
	object_class->dispose = dispose;

	obj_properties[PROP_DBUS_CONNECTION] =
	    g_param_spec_object (NM_POLKIT_LISTENER_DBUS_CONNECTION, "", "",
	                         G_TYPE_DBUS_CONNECTION,
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_WRITABLE |
	                         G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_SESSION_AGENT] =
	    g_param_spec_boolean (NM_POLKIT_LISTENER_SESSION_AGENT, "", "",
	                          FALSE,
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_WRITABLE |
	                          G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class,
	                                   _PROPERTY_ENUMS_LAST,
	                                   obj_properties);

	signals[REQUEST_SYNC] =
	    g_signal_new (NM_POLKIT_LISTENER_SIGNAL_REQUEST_SYNC,
	                  NM_TYPE_POLKIT_LISTENER,
	                  G_SIGNAL_RUN_LAST,
	                  0,
	                  NULL,
	                  NULL,
	                  NULL,
	                  G_TYPE_STRING,
	                  3,
	                  G_TYPE_STRING,
	                  G_TYPE_STRING,
	                  G_TYPE_STRING);

	signals[REGISTERED] =
	    g_signal_new (NM_POLKIT_LISTENER_SIGNAL_REGISTERED,
	                  NM_TYPE_POLKIT_LISTENER,
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL,
	                  NULL,
	                  NULL,
	                  G_TYPE_NONE,
	                  0);

	signals[ERROR] =
	    g_signal_new (NM_POLKIT_LISTENER_SIGNAL_ERROR,
	                  NM_TYPE_POLKIT_LISTENER,
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL,
	                  NULL,
	                  NULL,
	                  G_TYPE_NONE,
	                  1,
	                  G_TYPE_STRING);
}
