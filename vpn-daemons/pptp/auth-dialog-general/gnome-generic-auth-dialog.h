/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */

/* gnome-generic-auth-dialog.h - A use a dialog widget with a combo 
 *                               selection box to choose a sub-widget
 *                               which in turn then provides appropriate
 *                               widgets for a particular type of 
 *                               authentication
                                 Based of gnome-two-password-dialog.[ch] 
                                 from the Gnome Library.

   This is free software; you can redistribute it and/or modify it under 
   the terms of the GNU Library General Public License as published by 
   the Free Software Foundation; either version 2 of the License, or 
   (at your option) any later version.

   This software is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Authors: Antony J Mee <eemynotna at gmail dot com>
*/

#ifndef GNOME_GENERIC_AUTH_DIALOG_H
#define GNOME_GENERIC_AUTH_DIALOG_H

#include <gtk/gtkdialog.h>

G_BEGIN_DECLS

#define GNOME_TYPE_GENERIC_AUTH_DIALOG            (gnome_generic_auth_dialog_get_type ())
#define GNOME_GENERIC_AUTH_DIALOG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), GNOME_TYPE_GENERIC_AUTH_DIALOG, GnomeGenericAuthDialog))
#define GNOME_GENERIC_AUTH_DIALOG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), GNOME_TYPE_GENERIC_AUTH_DIALOG, GnomeGenericAuthDialogClass))
#define GNOME_IS_GENERIC_AUTH_DIALOG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GNOME_TYPE_GENERIC_AUTH_DIALOG))
#define GNOME_IS_GENERIC_AUTH_DIALOG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), GNOME_TYPE_GENERIC_AUTH_DIALOG))

typedef struct GnomeGenericAuthDialog        GnomeGenericAuthDialog;
typedef struct GnomeGenericAuthDialogClass   GnomeGenericAuthDialogClass;
typedef struct GnomeGenericAuthDialogDetails GnomeGenericAuthDialogDetails;

struct GnomeGenericAuthDialog
{
	GtkDialog gtk_dialog;

	GnomeGenericAuthDialogDetails *details;
};

struct GnomeGenericAuthDialogClass
{
	GtkDialogClass parent_class;
};

typedef enum {
	GNOME_GENERIC_AUTH_DIALOG_REMEMBER_NOTHING,
	GNOME_GENERIC_AUTH_DIALOG_REMEMBER_SESSION,
	GNOME_GENERIC_AUTH_DIALOG_REMEMBER_FOREVER
} GnomeGenericAuthDialogRemember;


GType    gnome_generic_auth_dialog_get_type (void);
GtkWidget *gnome_generic_auth_dialog_new (const char	*dialog_title,
                			   const char	*message,
			                   const char   *user,
			                   const char   *domain,
			                   const char   *server,
			                   const char   *protocol,
			                   guint32       port,
                			   const char **allowed_types);

gboolean   gnome_generic_auth_dialog_run_and_block           (GnomeGenericAuthDialog *dialog);

/* Attribute mutators */
gboolean gnome_generic_auth_dialog_set_auth_type (GnomeGenericAuthDialog  *dialog, const char *auth_type);
gboolean gnome_generic_auth_dialog_set_user (GnomeGenericAuthDialog  *dialog, const char *user);
gboolean gnome_generic_auth_dialog_set_server (GnomeGenericAuthDialog  *dialog, const char *server);
gboolean gnome_generic_auth_dialog_set_domain (GnomeGenericAuthDialog  *dialog, const char *domain);
gboolean gnome_generic_auth_dialog_set_protocol (GnomeGenericAuthDialog  *dialog, const char *protocol);
gboolean gnome_generic_auth_dialog_set_port (GnomeGenericAuthDialog  *dialog, guint32 port);

//void gnome_generic_auth_dialog_set_allowed_auth_types   (GnomeGenericAuthDialog  *dialog,
//							                     GSList  *allowed_auth_types);

void gnome_generic_auth_dialog_set_show_remember  (GnomeGenericAuthDialog *dialog,
										            gboolean show_remember);
void gnome_generic_auth_dialog_set_remember       (GnomeGenericAuthDialog *dialog,
										           GnomeGenericAuthDialogRemember remember);
GnomeGenericAuthDialogRemember gnome_generic_auth_dialog_get_remember (GnomeGenericAuthDialog *dialog);

/* Attribute accessors */
const char *gnome_generic_auth_dialog_get_auth_type           (GnomeGenericAuthDialog *dialog);
const char *gnome_generic_auth_dialog_get_user              (GnomeGenericAuthDialog *dialog);
const char *gnome_generic_auth_dialog_get_domain              (GnomeGenericAuthDialog *dialog);
const char *gnome_generic_auth_dialog_get_server              (GnomeGenericAuthDialog *dialog);
const char *gnome_generic_auth_dialog_get_protocol              (GnomeGenericAuthDialog *dialog);
guint32     gnome_generic_auth_dialog_get_port              (GnomeGenericAuthDialog *dialog);
GSList     *gnome_generic_auth_dialog_get_secrets              (GnomeGenericAuthDialog *dialog);

G_END_DECLS

#endif /* GNOME_GENERIC_AUTH_DIALOG_H */
