// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef __NM_POLKIT_LISTENER_H__
#define __NM_POLKIT_LISTENER_H__

#if WITH_POLKIT_AGENT

typedef struct _NMPolkitListener NMPolkitListener;
typedef struct _NMPolkitListenerClass NMPolkitListenerClass;

typedef struct {

	/*
	 * @request: the request asked by polkit agent
	 * @action_id: the action_id of the polkit request
	 * @message: the message of the polkit request
	 * @icon_name: the icon name of the polkit request
	 * @user: user name
	 * @echo_on: whether the response to the request should be echoed to the screen
	 * @user_data: user data for the callback
	 *
	 * Called as a result of a request by polkit. The function should obtain response
	 * to the request from user, i.e. get the password required.
	 */
	char *(*on_request) (NMPolkitListener *self,
	                     const char *request,
	                     const char *action_id,
	                     const char *message,
	                     const char *icon_name,
	                     const char *user,
	                     gboolean echo_on,
	                     gpointer user_data);

	/*
	 * @text: the info text from polkit
	 *
	 * Called as a result of show-info signal by polkit.
	 */
	void (*on_show_info) (NMPolkitListener *self,
	                      const char *text,
	                      gpointer user_data);

	/*
	 * @text: the error text from polkit
	 *
	 * Called as a result of show-error signal by polkit.
	 */
	void (*on_show_error) (NMPolkitListener *self,
	                       const char *text,
	                       gpointer user_data);

	/*
	 * @gained_authorization: whether the authorization was successful
	 *
	 * Called as a result of completed signal by polkit.
	 */
	void (*on_completed) (NMPolkitListener *self,
	                      gboolean gained_authorization,
	                      gpointer user_data);
} NMPolkitListenVtable;

/*****************************************************************************/

#define POLKIT_AGENT_I_KNOW_API_IS_SUBJECT_TO_CHANGE
#include <polkitagent/polkitagent.h>

#define NM_TYPE_POLKIT_LISTENER            (nm_polkit_listener_get_type ())
#define NM_POLKIT_LISTENER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_POLKIT_LISTENER, NMPolkitListener))
#define NM_POLKIT_LISTENER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_POLKIT_LISTENER, NMPolkitListenerClass))
#define NM_IS_POLKIT_LISTENER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_POLKIT_LISTENER))
#define NM_IS_POLKIT_LISTENER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_POLKIT_LISTENER))
#define NM_POLKIT_LISTENER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_POLKIT_LISTENER, NMPolkitListenerClass))

/**
 * NMPolkitListenerOnRequestFunc:
 * @request: the request asked by polkit agent
 * @action_id: the action_id of the polkit request
 * @message: the message of the polkit request
 * @icon_name: the icon name of the polkit request
 * @user: user name
 * @echo_on: whether the response to the request should be echoed to the screen
 * @user_data: user data for the callback
 *
 * Called as a result of a request by polkit. The function should obtain response
 * to the request from user, i.e. get the password required.
 */
typedef char * (*NMPolkitListenerOnRequestFunc) (const char *request,
                                                 const char *action_id,
                                                 const char *message,
                                                 const char *icon_name,
                                                 const char *user,
                                                 gboolean echo_on,
                                                 gpointer user_data);
/**
 * NMPolkitListenerOnShowInfoFunc:
 * @text: the info text from polkit
 *
 * Called as a result of show-info signal by polkit.
 */
typedef void (*NMPolkitListenerOnShowInfoFunc) (const char *text);
/**
 * NMPolkitListenerOnShowErrorFunc:
 * @text: the error text from polkit
 *
 * Called as a result of show-error signal by polkit.
 */
typedef void (*NMPolkitListenerOnShowErrorFunc) (const char *text);
/**
 * NMPolkitListenerCompletedFunc:
 * @gained_authorization: whether the authorization was successful
 *
 * Called as a result of completed signal by polkit.
 */
typedef void (*NMPolkitListenerOnCompletedFunc) (gboolean gained_authorization);

struct _NMPolkitListener {
	PolkitAgentListener parent;
};

struct _NMPolkitListenerClass {
	PolkitAgentListenerClass parent;
};

GType nm_polkit_listener_get_type (void);

NMPolkitListener *nm_polkit_listener_new (gboolean for_session,
                                          GError **error);

void nm_polkit_listener_set_vtable (NMPolkitListener *self,
                                    const NMPolkitListenVtable *vtable,
                                    gpointer user_data);

#endif

#endif /* __NM_POLKIT_LISTENER_H__ */
