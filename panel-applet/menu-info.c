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
#include "NMWirelessAppletDbus.h"
#include <config.h>

G_DEFINE_TYPE (NMMenuNetwork, nm_menu_network, GTK_TYPE_CHECK_MENU_ITEM);

static void nm_menu_network_update_image (NMMenuNetwork *menu_network);

static void
nm_menu_network_init (NMMenuNetwork *menu_network)
{
  GtkWidget *hbox;

  gtk_check_menu_item_set_draw_as_radio (GTK_CHECK_MENU_ITEM (menu_network), TRUE);
  hbox = gtk_hbox_new (FALSE, 2);
  menu_network->image = gtk_image_new ();
  gtk_box_pack_start (GTK_BOX (hbox), menu_network->image, FALSE, FALSE, 0);
  menu_network->label = gtk_label_new (NULL);
  gtk_misc_set_alignment (GTK_MISC (menu_network->label), 0.0, 0.5);
  gtk_box_pack_start (GTK_BOX (hbox), menu_network->label, TRUE, TRUE, 0);
  gtk_container_add (GTK_CONTAINER (menu_network), hbox);
  gtk_widget_show_all (hbox);
}


static void
nm_menu_network_style_set (GtkWidget *widget,
			   GtkStyle  *previous_style)
{
  GTK_WIDGET_CLASS (nm_menu_network_parent_class)->style_set (widget, previous_style);

  nm_menu_network_update_image (NM_MENU_NETWORK (widget));
}

static void
nm_menu_network_draw_indicator (GtkCheckMenuItem *check_menu_item,
				GdkRectangle	 *area)
{
  /* Only draw the indicator if we're an ethernet device */
  if (NM_MENU_NETWORK (check_menu_item)->type == DEVICE_TYPE_WIRELESS_ETHERNET)
    GTK_CHECK_MENU_ITEM_CLASS (nm_menu_network_parent_class)->draw_indicator (check_menu_item, area);
}

static void
nm_menu_network_class_init (NMMenuNetworkClass *menu_network)
{
  GtkWidgetClass *widget_class;
  GtkCheckMenuItemClass *check_menu_item_class;

  widget_class = GTK_WIDGET_CLASS (menu_network);
  check_menu_item_class = GTK_CHECK_MENU_ITEM_CLASS (menu_network);

  widget_class->style_set = nm_menu_network_style_set;
  check_menu_item_class->draw_indicator = nm_menu_network_draw_indicator;
}

GtkWidget *
nm_menu_network_new (GtkSizeGroup *image_size_group)
{
  GtkWidget *retval = g_object_new (nm_menu_network_get_type (), NULL);

  gtk_size_group_add_widget (image_size_group,
			     NM_MENU_NETWORK (retval)->image);

  return retval;
}

/* updates the image based on the icon type.  It is called when themes
 * change too as the icon size is theme dependent */
static void
nm_menu_network_update_image (NMMenuNetwork *menu_network)
{
  GtkIconTheme *icon_theme;
  GdkPixbuf *icon;
  const gchar *icon_name = NULL;
  gint size;

  if (menu_network->type == DEVICE_TYPE_WIRED_ETHERNET)
    {
      icon_name = "nm-device-wired";
    }
  else if (menu_network->type == DEVICE_TYPE_WIRELESS_ETHERNET)
    {
      icon_name = "nm-device-wireless";
    }
  else
    {
      gtk_image_set_from_pixbuf (GTK_IMAGE (menu_network->image), NULL);
      return;
    }

  gtk_icon_size_lookup_for_settings (gtk_settings_get_default (),
				     GTK_ICON_SIZE_MENU,
				     &size, NULL);

  icon_theme = gtk_icon_theme_get_default ();
  icon = gtk_icon_theme_load_icon (icon_theme,
				   icon_name,
				   size, 0, NULL);
  gtk_image_set_from_pixbuf (GTK_IMAGE (menu_network->image), icon);
  if (icon)
    g_object_unref (icon);
}

void
nm_menu_network_update (NMMenuNetwork *menu_network,
			NetworkDevice *network,
			gint           n_devices)
{
  char *text;
  const char *network_name;
  gint n_essids;

  menu_network->type = network->type;
  n_essids = g_slist_length (network->networks);
  network_name = network->hal_name ? network->hal_name : network->nm_name;

  switch (menu_network->type)
    {
    case DEVICE_TYPE_WIRED_ETHERNET:
      if (n_devices > 1)
	text = g_strdup_printf (_("Wired Network (%s)"), network_name);
      else
	text = g_strdup (_("Wired Network"));
      break;
    case DEVICE_TYPE_WIRELESS_ETHERNET:
      if (n_devices > 1)
	text = g_strdup_printf (ngettext ("Wireless Network (%s)", "Wireless Networks (%s)", n_essids), network_name);
      else
	text = g_strdup (ngettext ("Wireless Network", "Wireless Networks", n_essids));
      break;
    default:
      g_assert_not_reached ();
      break;
    }
  gtk_label_set_text (GTK_LABEL (menu_network->label), text);
  g_free (text);
  nm_menu_network_update_image (menu_network);

  if (menu_network->type == DEVICE_TYPE_WIRELESS_ETHERNET)
    gtk_widget_set_sensitive (GTK_WIDGET (menu_network), FALSE);
  else
    gtk_widget_set_sensitive (GTK_WIDGET (menu_network), TRUE);
}

/* NMMenuWireless items*/
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
  gtk_label_set_text (GTK_LABEL (menu_info->label), display_essid);
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
