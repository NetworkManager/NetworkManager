/* menu-info.h: Simple menu item for the Applet to use
 *
 * Jonathan Blandford <jrb@redhat.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2004 Red Hat, Inc.
 */

#ifndef MENU_INFO_H
#define MENU_INFO_H


#include <gtk/gtk.h>
#include "NMWirelessApplet.h"

#define NM_TYPE_MENU_WIRELESS			  (nm_menu_wireless_get_type ())
#define NM_MENU_WIRELESS(widget)		  (G_TYPE_CHECK_INSTANCE_CAST ((widget), NM_TYPE_MENU_WIRELESS, NMMenuWireless))

typedef struct
{
  GtkCheckMenuItemClass parent_class;
} NMMenuWirelessClass;

typedef struct
{
  GtkCheckMenuItem parent;
  GtkWidget *spacer;
  GtkWidget *cell_view;
  GtkWidget *label;
  GtkWidget *security_image;
  GObject *progress_bar;
} NMMenuWireless;


GType      nm_menu_wireless_get_type (void);
GtkWidget *nm_menu_wireless_new      (GtkSizeGroup    *image_size_group,
				      GtkSizeGroup    *encryption_size_group);
void       nm_menu_wireless_update   (NMMenuWireless  *menu_info,
				      WirelessNetwork *network,
				      gboolean         has_encrypted);

/* Helper function; escapes an essid for human readable display. */
char      *nm_menu_wireless_escape_essid_for_display (const char *essid);


#endif /* MENU_INFO_H */
