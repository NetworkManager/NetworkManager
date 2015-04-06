/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2014 Red Hat, Inc.
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

#include "config.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <glib/gi18n-lib.h>

#include "nm-glib.h"
#include "nm-polkit-listener.h"

G_DEFINE_TYPE (NMPolkitListener, nm_polkit_listener, POLKIT_AGENT_TYPE_LISTENER)

#define NM_POLKIT_LISTENER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_POLKIT_LISTENER, NMPolkitListenerPrivate))

typedef struct {
	gpointer reg_handle;  /* handle of polkit agent registration */

	GSimpleAsyncResult *simple;
	PolkitAgentSession *active_session;
	gulong cancel_id;
	GCancellable *cancellable;

	char *action_id;
	char *message;
	char *icon_name;
	char *identity;

	/* callbacks */
	NMPolkitListenerOnRequestFunc on_request_callback;
	NMPolkitListenerOnShowInfoFunc on_show_info_callback;
	NMPolkitListenerOnShowErrorFunc on_show_error_callback;
	NMPolkitListenerOnCompletedFunc on_completed_callback;
	gpointer request_callback_data;
} NMPolkitListenerPrivate;


static void
on_request (PolkitAgentSession *session,
            const char *request,
            gboolean echo_on,
            gpointer user_data)
{
	NMPolkitListenerPrivate *priv = NM_POLKIT_LISTENER_GET_PRIVATE (user_data);
	char *response = NULL;

	if (priv->on_request_callback) {
		response = priv->on_request_callback (request, priv->action_id,
		                                      priv->message, priv->icon_name,
		                                      priv->identity, echo_on,
		                                      priv->request_callback_data);
	}

	if (response) {
		polkit_agent_session_response (session, response);
		g_free (response);
	} else {
		//FIXME: polkit_agent_session_cancel() should emit "completed", but it doesn't work for me ???
		//polkit_agent_session_cancel (session);
		polkit_agent_session_response (session, "");
	}
}

static void
on_show_info (PolkitAgentSession *session,
              const char *text,
              gpointer user_data)
{
	NMPolkitListenerPrivate *priv = NM_POLKIT_LISTENER_GET_PRIVATE (user_data);

	if (priv->on_show_info_callback)
		priv->on_show_info_callback (text);
}

static void
on_show_error (PolkitAgentSession *session,
               const char *text,
               gpointer user_data)
{
	NMPolkitListenerPrivate *priv = NM_POLKIT_LISTENER_GET_PRIVATE (user_data);

	if (priv->on_show_error_callback)
		priv->on_show_error_callback (text);
}

static void
on_completed (PolkitAgentSession *session,
              gboolean gained_authorization,
              gpointer user_data)
{
	NMPolkitListenerPrivate *priv = NM_POLKIT_LISTENER_GET_PRIVATE (user_data);

	if (priv->on_completed_callback)
		priv->on_completed_callback (gained_authorization);

	g_simple_async_result_complete_in_idle (priv->simple);

	g_object_unref (priv->simple);
	g_object_unref (priv->active_session);
	if (priv->cancellable) {
		g_cancellable_disconnect (priv->cancellable, priv->cancel_id);
		g_object_unref (priv->cancellable);
	}

	priv->simple = NULL;
	priv->active_session = NULL;
	priv->cancel_id = 0;

	g_clear_pointer (&priv->action_id, g_free);
	g_clear_pointer (&priv->message, g_free);
	g_clear_pointer (&priv->icon_name, g_free);
	g_clear_pointer (&priv->identity, g_free);
}

static void
on_cancelled (GCancellable *cancellable, gpointer user_data)
{
	NMPolkitListenerPrivate *priv = NM_POLKIT_LISTENER_GET_PRIVATE (user_data);

	polkit_agent_session_cancel (priv->active_session);
}

static gint
compare_users (gconstpointer a, gconstpointer b)
{
	char *user;
	int ret;

	if (POLKIT_IS_UNIX_USER (a))
		user = g_strdup (polkit_unix_user_get_name (POLKIT_UNIX_USER (a)));
	else
		user = polkit_identity_to_string (POLKIT_IDENTITY (a));

	ret = g_strcmp0 ((const char *) user, (const char *) b);
	g_free (user);
	return ret;
}

static PolkitIdentity *
choose_identity (GList *identities)
{
	const char *user;
	GList *elem;

	/* Choose identity. First try current user, then root, and else
	 * take the firts one */
	user = getenv("USER");
	elem = g_list_find_custom (identities, user, (GCompareFunc) compare_users);
	if (!elem) {
		elem = g_list_find_custom (identities, "root", (GCompareFunc) compare_users);
		if (!elem)
			elem = identities;
	}

	return elem->data;
}

static void
initiate_authentication (PolkitAgentListener  *listener,
                         const char           *action_id,
                         const char           *message,
                         const char           *icon_name,
                         PolkitDetails        *details,
                         const char           *cookie,
                         GList                *identities,
                         GCancellable         *cancellable,
                         GAsyncReadyCallback   callback,
                         gpointer              user_data)
{
	NMPolkitListenerPrivate *priv = NM_POLKIT_LISTENER_GET_PRIVATE (listener);
	GSimpleAsyncResult *simple;
	PolkitIdentity *identity;

	simple = g_simple_async_result_new (G_OBJECT (listener),
	                                    callback,
	                                    user_data,
	                                    initiate_authentication);
	if (priv->active_session != NULL) {
		g_simple_async_result_set_error (simple,
		                                 POLKIT_ERROR,
		                                 POLKIT_ERROR_FAILED,
		                                 _("An authentication session is already underway."));
		g_simple_async_result_complete_in_idle (simple);
		g_object_unref (simple);
		return;
	}

	/* Choose identity */
	identity = choose_identity (identities);

	priv->active_session = polkit_agent_session_new (identity, cookie);
	g_signal_connect (priv->active_session,
	                  "completed",
	                  G_CALLBACK (on_completed),
	                  listener);
	g_signal_connect (priv->active_session,
	                  "request",
	                  G_CALLBACK (on_request),
	                  listener);
	g_signal_connect (priv->active_session,
	                  "show-info",
	                  G_CALLBACK (on_show_info),
	                  listener);
	g_signal_connect (priv->active_session,
	                  "show-error",
	                  G_CALLBACK (on_show_error),
	                  listener);

	priv->action_id = g_strdup (action_id);
	priv->message = g_strdup (message);
	priv->icon_name = g_strdup (icon_name);
	if (POLKIT_IS_UNIX_USER (identity))
		priv->identity = g_strdup (polkit_unix_user_get_name (POLKIT_UNIX_USER (identity)));
	else
		priv->identity = polkit_identity_to_string (identity);

	priv->simple = simple;
	priv->cancellable = g_object_ref (cancellable);
	priv->cancel_id = g_cancellable_connect (cancellable,
	                                         G_CALLBACK (on_cancelled),
	                                         listener,
	                                         NULL);

	polkit_agent_session_initiate (priv->active_session);
}

static gboolean
initiate_authentication_finish (PolkitAgentListener *listener,
                                GAsyncResult *result,
                                GError **error)
{
	return !g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (result), error);
}


static void
nm_polkit_listener_init (NMPolkitListener *agent)
{
}

static void
nm_polkit_listener_finalize (GObject *object)
{
	NMPolkitListenerPrivate *priv = NM_POLKIT_LISTENER_GET_PRIVATE (object);

	if (priv->reg_handle)
		polkit_agent_listener_unregister (priv->reg_handle);

	g_free (priv->action_id);
	g_free (priv->message);
	g_free (priv->icon_name);
	g_free (priv->identity);

	G_OBJECT_CLASS (nm_polkit_listener_parent_class)->finalize (object);
}

static void
nm_polkit_listener_class_init (NMPolkitListenerClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	PolkitAgentListenerClass *pkal_class = POLKIT_AGENT_LISTENER_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMPolkitListenerPrivate));

	gobject_class->finalize = nm_polkit_listener_finalize;

	pkal_class->initiate_authentication = initiate_authentication;
	pkal_class->initiate_authentication_finish = initiate_authentication_finish;
}

/**
 * nm_polkit_listener_new:
 * @for_session: %TRUE for registering the polkit agent for the user session,
 *   %FALSE for registering it for the running process
 * @error: location to store error, or %NULL
 *
 * Creates a new #NMPolkitListener and registers it as a polkit agent.
 *
 * Returns: a new #NMPolkitListener
 */
PolkitAgentListener *
nm_polkit_listener_new (gboolean for_session, GError **error)
{
	PolkitAgentListener *listener;
	PolkitSubject* session;
	NMPolkitListenerPrivate *priv;

	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	listener = g_object_new (NM_TYPE_POLKIT_LISTENER, NULL);
	priv = NM_POLKIT_LISTENER_GET_PRIVATE (listener);

	if (for_session)
		session = polkit_unix_session_new_for_process_sync (getpid (), NULL, NULL);
	else
		session = polkit_unix_process_new_for_owner (getpid (), 0, getuid ());

	priv->reg_handle = polkit_agent_listener_register (listener, POLKIT_AGENT_REGISTER_FLAGS_NONE,
	                                                   session, NULL, NULL, error);
	if (!priv->reg_handle) {
		g_object_unref (listener);
		g_object_unref (session);
		return NULL;
	}

	return listener;
}

/**
 * nm_polkit_listener_set_request_callback:
 * @self: a #NMPolkitListener object
 * @request_callback: callback to install for polkit requests
 * @request_callback_data: usaer data passed to request_callback when it is called
 *
 * Set a callback for "request" signal. The callback will be invoked when polkit
 * requests an authorization.
 */
void
nm_polkit_listener_set_request_callback (NMPolkitListener *self,
                                         NMPolkitListenerOnRequestFunc request_callback,
                                         gpointer request_callback_data)
{
	NMPolkitListenerPrivate *priv;

	g_return_if_fail (NM_IS_POLKIT_LISTENER (self));

	priv = NM_POLKIT_LISTENER_GET_PRIVATE (self);

	priv->on_request_callback = request_callback;
	priv->request_callback_data = request_callback_data;
}

/**
 * nm_polkit_listener_set_show_info_callback:
 * @self: a #NMPolkitListener object
 * @show_info_callback: callback to install for polkit show info trigger
 *
 * Set a callback for "show-info" signal. The callback will be invoked when polkit
 * has an info text to display.
 */
void
nm_polkit_listener_set_show_info_callback (NMPolkitListener *self,
                                           NMPolkitListenerOnShowInfoFunc show_info_callback)
{
	g_return_if_fail (NM_IS_POLKIT_LISTENER (self));

	NM_POLKIT_LISTENER_GET_PRIVATE (self)->on_show_info_callback = show_info_callback;
}

/**
 * nm_polkit_listener_set_show_error_callback:
 * @self: a #NMPolkitListener object
 * @show_error_callback: callback to install for polkit show error trigger
 *
 * Set a callback for "show-error" signal. The callback will be invoked when polkit
 * has an error text to display.
 */
void
nm_polkit_listener_set_show_error_callback (NMPolkitListener *self,
                                            NMPolkitListenerOnShowErrorFunc show_error_callback)
{
	g_return_if_fail (NM_IS_POLKIT_LISTENER (self));

	NM_POLKIT_LISTENER_GET_PRIVATE (self)->on_show_error_callback = show_error_callback;
}

/**
 * nm_polkit_listener_set_completed_callback:
 * @self: a #NMPolkitListener object
 * @completed_callback: callback to install for polkit completing authorization
 *
 * Set a callback for "completed" signal. The callback will be invoked when polkit
 * completed the request.
 */
void
nm_polkit_listener_set_completed_callback (NMPolkitListener *self,
                                           NMPolkitListenerOnCompletedFunc completed_callback)
{
	g_return_if_fail (NM_IS_POLKIT_LISTENER (self));

	NM_POLKIT_LISTENER_GET_PRIVATE (self)->on_completed_callback = completed_callback;
}
