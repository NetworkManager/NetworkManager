/* menu-info.c - Class to represent the 
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
 * This also uses code from eel-vfs-extentions available under the LGPL:
 *     Authors: Darin Adler <darin@eazel.com>
 * 	    Pavel Cisler <pavel@eazel.com>
 * 	    Mike Fleming  <mfleming@eazel.com>
 *          John Sullivan <sullivan@eazel.com>
 *
 * (C) Copyright 2004 Red Hat, Inc.
 * Copyright (C) 1999, 2000 Eazel, Inc.
 */
#include "menu-info.h"
#include "gtkcellview.h"
#include "gtkcellrendererprogress.h"

G_DEFINE_TYPE (NMMenuWireless, nm_menu_wireless, GTK_TYPE_CHECK_MENU_ITEM);

static void
nm_menu_wireless_init (NMMenuWireless *menu_info)
{
  GtkWidget *hbox;

  gtk_check_menu_item_set_draw_as_radio (GTK_CHECK_MENU_ITEM (menu_info), TRUE);
  hbox = gtk_hbox_new (FALSE, 2);
  menu_info->spacer = gtk_frame_new (NULL);
  gtk_frame_set_shadow_type (GTK_FRAME (menu_info->spacer), GTK_SHADOW_NONE);
  menu_info->label = gtk_label_new (NULL);
  gtk_misc_set_alignment (GTK_MISC (menu_info->label), 0.0, 0.5);
  menu_info->security_image = gtk_image_new ();

  gtk_container_add (GTK_CONTAINER (menu_info), hbox);
  gtk_box_pack_start (GTK_BOX (hbox), menu_info->spacer, FALSE, FALSE, 0);
  gtk_box_pack_start (GTK_BOX (hbox), menu_info->label, TRUE, TRUE, 0);
  menu_info->cell_view = gtk_cell_view_new ();
  menu_info->progress_bar = g_object_new (GTK_TYPE_CELL_RENDERER_PROGRESS,
					  "text", "",
					  NULL);
  gtk_cell_layout_pack_start (GTK_CELL_LAYOUT (menu_info->cell_view),
			      GTK_CELL_RENDERER (menu_info->progress_bar),
			      TRUE);
  gtk_box_pack_start (GTK_BOX (hbox), menu_info->cell_view, FALSE, FALSE, 0);
  gtk_box_pack_end (GTK_BOX (hbox), menu_info->security_image, FALSE, FALSE, 0);

  /* We don't show all the widgets, but we do show a few */
  gtk_widget_show (menu_info->spacer);
  gtk_widget_show (menu_info->label);
  gtk_widget_show (menu_info->cell_view);
  gtk_widget_show (hbox);
}

static void
nm_menu_wireless_class_init (NMMenuWirelessClass *menu_info_class)
{
}

GtkWidget *
nm_menu_wireless_new    (GtkSizeGroup    *image_size_group,
			 GtkSizeGroup    *encryption_size_group)
{
  GtkWidget *retval = g_object_new (nm_menu_wireless_get_type (), NULL);

  gtk_size_group_add_widget (image_size_group,
			     NM_MENU_WIRELESS (retval)->spacer);
  gtk_size_group_add_widget (encryption_size_group,
			     NM_MENU_WIRELESS (retval)->security_image);

  return retval;
}

/* has_encrypted means that the wireless network has an encrypted
 * area, and thus we need to allow for spacing.
 */
void
nm_menu_wireless_update (NMMenuWireless  *menu_info,
			 WirelessNetwork *network,
			 gboolean         has_encrypted)
{
  char *display_essid;

  display_essid = nm_menu_wireless_escape_essid_for_display (network->essid);
  if (network->active)
    {
      char *markup_essid;
      markup_essid = g_markup_printf_escaped ("<b>%s</b>", display_essid);
      gtk_label_set_markup (GTK_LABEL (menu_info->label), markup_essid);
      g_free (markup_essid);
    }
  else
    {
      gtk_label_set_text (GTK_LABEL (menu_info->label), display_essid);
    }

  g_free (display_essid);
  g_object_set (G_OBJECT (menu_info->progress_bar),
		"value", CLAMP ((int) network->strength, 0, 100),
		NULL);

  /* Deal with the encrypted icon */
  g_object_set (menu_info->security_image, "visible", has_encrypted, NULL);

  if (network->encrypted)
    gtk_image_set_from_stock (GTK_IMAGE (menu_info->security_image), "gnome-lockscreen", GTK_ICON_SIZE_MENU);
  else
    gtk_image_set_from_stock (GTK_IMAGE (menu_info->security_image), NULL, GTK_ICON_SIZE_MENU);
}


/* This is copied from eel.
 */
static char *
eel_make_valid_utf8 (const char *name)
{
	GString *string;
	const char *remainder, *invalid;
	int remaining_bytes, valid_bytes;

	string = NULL;
	remainder = name;
	remaining_bytes = strlen (name);

	while (remaining_bytes != 0) {
		if (g_utf8_validate (remainder, remaining_bytes, &invalid)) {
			break;
		}
		valid_bytes = invalid - remainder;

		if (string == NULL) {
			string = g_string_sized_new (remaining_bytes);
		}
		g_string_append_len (string, remainder, valid_bytes);
		g_string_append_c (string, '?');

		remaining_bytes -= valid_bytes + 1;
		remainder = invalid + 1;
	}

	if (string == NULL) {
		return g_strdup (name);
	}

	g_string_append (string, remainder);
	g_string_append (string, _(" (invalid Unicode)"));
	g_assert (g_utf8_validate (string->str, -1, NULL));

	return g_string_free (string, FALSE);
}

char *
nm_menu_wireless_escape_essid_for_display (const char *essid)
{
  if (g_utf8_validate (essid, -1, NULL))
    return g_strdup (essid);
  else
    return eel_make_valid_utf8 (essid);
}
