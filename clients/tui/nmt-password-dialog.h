// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_PASSWORD_DIALOG_H
#define NMT_PASSWORD_DIALOG_H

#include "nmt-newt.h"

#define NMT_TYPE_PASSWORD_DIALOG            (nmt_password_dialog_get_type ())
#define NMT_PASSWORD_DIALOG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_PASSWORD_DIALOG, NmtPasswordDialog))
#define NMT_PASSWORD_DIALOG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_PASSWORD_DIALOG, NmtPasswordDialogClass))
#define NMT_IS_PASSWORD_DIALOG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_PASSWORD_DIALOG))
#define NMT_IS_PASSWORD_DIALOG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_PASSWORD_DIALOG))
#define NMT_PASSWORD_DIALOG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_PASSWORD_DIALOG, NmtPasswordDialogClass))

typedef struct {
	NmtNewtForm parent;

} NmtPasswordDialog;

typedef struct {
	NmtNewtFormClass parent;

} NmtPasswordDialogClass;

GType nmt_password_dialog_get_type (void);

NmtNewtForm *nmt_password_dialog_new            (const char        *request_id,
                                                 const char        *title,
                                                 const char        *prompt,
                                                 GPtrArray         *secrets);

gboolean     nmt_password_dialog_succeeded      (NmtPasswordDialog *dialog);

const char  *nmt_password_dialog_get_request_id (NmtPasswordDialog *dialog);
GPtrArray   *nmt_password_dialog_get_secrets    (NmtPasswordDialog *dialog);

#endif /* NMT_PASSWORD_DIALOG_H */
