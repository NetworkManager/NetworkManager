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
 * Copyright 2013 Red Hat, Inc.
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
