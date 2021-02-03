/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2005 - 2012 Red Hat, Inc.
 */

#ifndef __NM_ACT_REQUEST_H__
#define __NM_ACT_REQUEST_H__

#include "nm-connection.h"
#include "nm-active-connection.h"

#define NM_TYPE_ACT_REQUEST (nm_act_request_get_type())
#define NM_ACT_REQUEST(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_ACT_REQUEST, NMActRequest))
#define NM_ACT_REQUEST_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_ACT_REQUEST, NMActRequestClass))
#define NM_IS_ACT_REQUEST(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_ACT_REQUEST))
#define NM_IS_ACT_REQUEST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_ACT_REQUEST))
#define NM_ACT_REQUEST_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_ACT_REQUEST, NMActRequestClass))

struct _NMActRequestGetSecretsCallId;
typedef struct _NMActRequestGetSecretsCallId NMActRequestGetSecretsCallId;

GType nm_act_request_get_type(void);

NMActRequest *nm_act_request_new(NMSettingsConnection * settings_connection,
                                 NMConnection *         applied_connection,
                                 const char *           specific_object,
                                 NMAuthSubject *        subject,
                                 NMActivationType       activation_type,
                                 NMActivationReason     activation_reason,
                                 NMActivationStateFlags initial_state_flags,
                                 NMDevice *             device);

NMSettingsConnection *nm_act_request_get_settings_connection(NMActRequest *req);

NMConnection *nm_act_request_get_applied_connection(NMActRequest *req);

/*****************************************************************************/

struct _NMUtilsShareRules;

struct _NMUtilsShareRules *nm_act_request_get_shared(NMActRequest *req);

void nm_act_request_set_shared(NMActRequest *req, struct _NMUtilsShareRules *rules);

/*****************************************************************************/

/* Secrets handling */

typedef void (*NMActRequestSecretsFunc)(NMActRequest *                req,
                                        NMActRequestGetSecretsCallId *call_id,
                                        NMSettingsConnection *        connection,
                                        GError *                      error,
                                        gpointer                      user_data);

NMActRequestGetSecretsCallId *nm_act_request_get_secrets(NMActRequest *               req,
                                                         gboolean                     take_ref,
                                                         const char *                 setting_name,
                                                         NMSecretAgentGetSecretsFlags flags,
                                                         const char *const *          hints,
                                                         NMActRequestSecretsFunc      callback,
                                                         gpointer callback_data);

void nm_act_request_cancel_secrets(NMActRequest *req, NMActRequestGetSecretsCallId *call_id);
void nm_act_request_clear_secrets(NMActRequest *self);

#endif /* __NM_ACT_REQUEST_H__ */
