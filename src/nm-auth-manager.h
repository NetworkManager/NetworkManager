// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef NM_AUTH_MANAGER_H
#define NM_AUTH_MANAGER_H

#include "nm-auth-subject.h"

/*****************************************************************************/

typedef enum {
	NM_AUTH_CALL_RESULT_UNKNOWN = NM_CLIENT_PERMISSION_RESULT_UNKNOWN,
	NM_AUTH_CALL_RESULT_YES     = NM_CLIENT_PERMISSION_RESULT_YES,
	NM_AUTH_CALL_RESULT_AUTH    = NM_CLIENT_PERMISSION_RESULT_AUTH,
	NM_AUTH_CALL_RESULT_NO      = NM_CLIENT_PERMISSION_RESULT_NO,
} NMAuthCallResult;

static inline NMClientPermissionResult
nm_auth_call_result_to_client (NMAuthCallResult result)
{
	return (NMClientPermissionResult) result;
}

static inline NMAuthCallResult
nm_auth_call_result_eval (gboolean is_authorized,
                          gboolean is_challenge,
                          GError *error)
{
	if (error)
		return NM_AUTH_CALL_RESULT_UNKNOWN;
	if (is_authorized)
		return NM_AUTH_CALL_RESULT_YES;
	if (is_challenge)
		return NM_AUTH_CALL_RESULT_AUTH;
	return NM_AUTH_CALL_RESULT_NO;
}

/*****************************************************************************/

#define NM_TYPE_AUTH_MANAGER            (nm_auth_manager_get_type ())
#define NM_AUTH_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_AUTH_MANAGER, NMAuthManager))
#define NM_AUTH_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_AUTH_MANAGER, NMAuthManagerClass))
#define NM_IS_AUTH_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_AUTH_MANAGER))
#define NM_IS_AUTH_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_AUTH_MANAGER))
#define NM_AUTH_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_AUTH_MANAGER, NMAuthManagerClass))

#define NM_AUTH_MANAGER_POLKIT_ENABLED "polkit-enabled"

#define NM_AUTH_MANAGER_SIGNAL_CHANGED "changed"

typedef struct _NMAuthManager NMAuthManager;
typedef struct _NMAuthManagerClass NMAuthManagerClass;

GType nm_auth_manager_get_type (void);

NMAuthManager *nm_auth_manager_setup (gboolean polkit_enabled);
NMAuthManager *nm_auth_manager_get (void);

void nm_auth_manager_force_shutdown (NMAuthManager *self);

gboolean nm_auth_manager_get_polkit_enabled (NMAuthManager *self);

/*****************************************************************************/

typedef struct _NMAuthManagerCallId NMAuthManagerCallId;

typedef void (*NMAuthManagerCheckAuthorizationCallback) (NMAuthManager *self,
                                                         NMAuthManagerCallId *call_id,
                                                         gboolean is_authorized,
                                                         gboolean is_challenge,
                                                         GError *error,
                                                         gpointer user_data);

NMAuthManagerCallId *nm_auth_manager_check_authorization (NMAuthManager *self,
                                                          NMAuthSubject *subject,
                                                          const char *action_id,
                                                          gboolean allow_user_interaction,
                                                          NMAuthManagerCheckAuthorizationCallback callback,
                                                          gpointer user_data);

void nm_auth_manager_check_authorization_cancel (NMAuthManagerCallId *call_id);

#endif /* NM_AUTH_MANAGER_H */
