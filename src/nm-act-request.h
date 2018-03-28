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
 * (C) Copyright 2005 - 2012 Red Hat, Inc.
 */

#ifndef __NM_ACT_REQUEST_H__
#define __NM_ACT_REQUEST_H__

#include "nm-connection.h"
#include "nm-active-connection.h"

#define NM_TYPE_ACT_REQUEST            (nm_act_request_get_type ())
#define NM_ACT_REQUEST(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_ACT_REQUEST, NMActRequest))
#define NM_ACT_REQUEST_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_ACT_REQUEST, NMActRequestClass))
#define NM_IS_ACT_REQUEST(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_ACT_REQUEST))
#define NM_IS_ACT_REQUEST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_ACT_REQUEST))
#define NM_ACT_REQUEST_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_ACT_REQUEST, NMActRequestClass))

struct _NMActRequestGetSecretsCallId;
typedef struct _NMActRequestGetSecretsCallId NMActRequestGetSecretsCallId;

GType nm_act_request_get_type (void);

NMActRequest *nm_act_request_new          (NMSettingsConnection *settings_connection,
                                           NMConnection *applied_connection,
                                           const char *specific_object,
                                           NMAuthSubject *subject,
                                           NMActivationType activation_type,
                                           NMActivationReason activation_reason,
                                           NMDevice *device);

NMSettingsConnection *nm_act_request_get_settings_connection (NMActRequest *req);

NMConnection         *nm_act_request_get_applied_connection (NMActRequest *req);

gboolean              nm_act_request_get_shared (NMActRequest *req);

void                  nm_act_request_set_shared (NMActRequest *req, gboolean shared);

void                  nm_act_request_add_share_rule (NMActRequest *req,
                                                     const char *table,
                                                     const char *rule);

/* Secrets handling */

typedef void (*NMActRequestSecretsFunc) (NMActRequest *req,
                                         NMActRequestGetSecretsCallId *call_id,
                                         NMSettingsConnection *connection,
                                         GError *error,
                                         gpointer user_data);

NMActRequestGetSecretsCallId *nm_act_request_get_secrets (NMActRequest *req,
                                                          gboolean take_ref,
                                                          const char *setting_name,
                                                          NMSecretAgentGetSecretsFlags flags,
                                                          const char *hint,
                                                          NMActRequestSecretsFunc callback,
                                                          gpointer callback_data);

void nm_act_request_cancel_secrets (NMActRequest *req, NMActRequestGetSecretsCallId *call_id);
void nm_act_request_clear_secrets (NMActRequest *self);

#endif /* __NM_ACT_REQUEST_H__ */

