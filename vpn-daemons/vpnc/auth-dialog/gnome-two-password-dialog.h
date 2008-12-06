/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */

/* gnome-two-password-dialog.h - A use password prompting dialog widget
                                 asking for two passwords. Based of
                                 gnome-password-dialog.[ch] from libgnomeui

   Copyright (C) 1999, 2000 Eazel, Inc.
   Copyright (C) 2005, Red Hat, Inc.

   The Gnome Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Authors: Ramiro Estrugo <ramiro@eazel.com>
*/

#ifndef VPN_PASSWORD_DIALOG_H
#define VPN_PASSWORD_DIALOG_H

#include <gtk/gtkdialog.h>

G_BEGIN_DECLS

#define VPN_TYPE_PASSWORD_DIALOG            (vpn_password_dialog_get_type ())
#define VPN_PASSWORD_DIALOG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), VPN_TYPE_PASSWORD_DIALOG, VpnPasswordDialog))
#define VPN_PASSWORD_DIALOG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), VPN_TYPE_PASSWORD_DIALOG, VpnPasswordDialogClass))
#define VPN_IS_PASSWORD_DIALOG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), VPN_TYPE_PASSWORD_DIALOG))
#define VPN_IS_PASSWORD_DIALOG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), VPN_TYPE_PASSWORD_DIALOG))

typedef struct VpnPasswordDialog        VpnPasswordDialog;
typedef struct VpnPasswordDialogClass   VpnPasswordDialogClass;

struct VpnPasswordDialog {
	GtkDialog parent;
};

struct VpnPasswordDialogClass {
	GtkDialogClass parent_class;
};

typedef enum {
	VPN_PASSWORD_REMEMBER_NOTHING,
	VPN_PASSWORD_REMEMBER_SESSION,
	VPN_PASSWORD_REMEMBER_FOREVER
} VpnPasswordRemember;


GType      vpn_password_dialog_get_type              (void);
GtkWidget* vpn_password_dialog_new                   (const char *title,
                                                      const char *message,
                                                      const char *password);

gboolean   vpn_password_dialog_run_and_block         (VpnPasswordDialog *dialog);

/* Attribute mutators */
void vpn_password_dialog_set_show_password            (VpnPasswordDialog *dialog,
                                                       gboolean show);
void vpn_password_dialog_focus_password               (VpnPasswordDialog *dialog);
void vpn_password_dialog_set_password                 (VpnPasswordDialog *dialog,
                                                       const char *password);

void vpn_password_dialog_set_show_password_secondary  (VpnPasswordDialog *dialog,
                                                       gboolean show);
void vpn_password_dialog_focus_password_secondary     (VpnPasswordDialog *dialog);
void vpn_password_dialog_set_password_secondary       (VpnPasswordDialog *dialog,
                                                       const char *password_secondary);
void vpn_password_dialog_set_password_secondary_label (VpnPasswordDialog *dialog,
                                                       const char *label);

void vpn_password_dialog_set_show_remember            (VpnPasswordDialog *dialog,
                                                       gboolean show_remember);
void vpn_password_dialog_set_remember                 (VpnPasswordDialog *dialog,
                                                       VpnPasswordRemember remember);
VpnPasswordRemember vpn_password_dialog_get_remember  (VpnPasswordDialog *dialog);

/* Attribute accessors */
const char *vpn_password_dialog_get_password                (VpnPasswordDialog *dialog);

const char *vpn_password_dialog_get_password_secondary      (VpnPasswordDialog *dialog);

G_END_DECLS

#endif /* VPN_PASSWORD_DIALOG_H */
